//! Feature extraction: the single extractor used for signing and scanning.
//!
//! Feature kinds are fixed by the spec (`str`, `const`, `callee`, `cfg`,
//! `ops`). Output is sorted and free of addresses, so two runs on the same
//! bytes produce identical records, and ASLR-shifted copies produce identical
//! records.

use std::collections::{BTreeMap, HashMap, HashSet};

use crate::normalize::{is_address, Kind, OpClass};
use crate::recover::RecoveredFunction;
use crate::source::ByteSource;
use crate::spec::{bucket, digest, STR_MAX_LEN, STR_MIN_LEN};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum FeatureKind {
    // Declaration order is the lexicographic order of the spec's kind strings,
    // which is the order the reference implementation sorts records in.
    Callee,
    Cfg,
    Const,
    Ops,
    Str,
}

impl FeatureKind {
    pub fn as_str(self) -> &'static str {
        match self {
            FeatureKind::Callee => "callee",
            FeatureKind::Cfg => "cfg",
            FeatureKind::Const => "const",
            FeatureKind::Ops => "ops",
            FeatureKind::Str => "str",
        }
    }

    pub fn parse(value: &str) -> Option<FeatureKind> {
        match value {
            "callee" => Some(FeatureKind::Callee),
            "cfg" => Some(FeatureKind::Cfg),
            "const" => Some(FeatureKind::Const),
            "ops" => Some(FeatureKind::Ops),
            "str" => Some(FeatureKind::Str),
            _ => None,
        }
    }
}

pub const FEATURE_KINDS: [FeatureKind; 5] = [
    FeatureKind::Str,
    FeatureKind::Const,
    FeatureKind::Callee,
    FeatureKind::Cfg,
    FeatureKind::Ops,
];

/// One comparable fact about a function.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Feature {
    pub kind: FeatureKind,
    pub value: String,
    pub required: bool,
    /// Inherited from a small direct callee ([`inline_evidence`]), not the
    /// function's own. Its key carries [`INHERITED_PREFIX`].
    pub inherited: bool,
}

/// Key prefix of an inherited feature (`inl:str:...`): the matcher credits it
/// against the signature's `str:...` at a discount, never as the function's
/// own evidence.
pub const INHERITED_PREFIX: &str = "inl:";

impl Feature {
    pub fn new(kind: FeatureKind, value: impl Into<String>) -> Feature {
        Feature {
            kind,
            value: value.into(),
            required: true,
            inherited: false,
        }
    }

    pub fn key(&self) -> String {
        let prefix = if self.inherited { INHERITED_PREFIX } else { "" };
        format!("{prefix}{}:{}", self.kind.as_str(), self.value)
    }

    /// The key without the inherited prefix: what a signature names.
    pub fn base_key(&self) -> String {
        format!("{}:{}", self.kind.as_str(), self.value)
    }
}

/// Extract the full feature set for a recovered function: its own features
/// plus the inline-invariant evidence of its small direct callees
/// ([`inline_evidence`]).
pub fn extract<S: ByteSource + ?Sized>(source: &S, func: &RecoveredFunction) -> Vec<Feature> {
    extract_with(source, func, None)
}

/// [`extract`], with the small callees' evidence looked up in `cache` (one
/// image's callees, shared by every function recovered from it).
pub fn extract_with<S: ByteSource + ?Sized>(
    source: &S,
    func: &RecoveredFunction,
    cache: Option<&InlineCache>,
) -> Vec<Feature> {
    let mut features = extract_own(source, func);
    let own: HashSet<String> = features.iter().map(Feature::key).collect();
    let mut inherited: Vec<Feature> = inline_evidence_with(source, func, cache)
        .into_iter()
        .filter(|feature| !own.contains(&feature.base_key()))
        .collect();
    inherited.sort();
    inherited.dedup_by(|left, right| left.key() == right.key());
    features.extend(inherited);
    features.sort();
    features
}

/// A direct callee is "small", and lends its evidence to its callers, when
/// it has at most this many instructions.
pub const MAX_INLINE_CALLEE_INSTRUCTIONS: usize = 80;

/// Direct callees recovered per function for [`inline_evidence`], lowest
/// address first: bounds the cost on functions that call everything.
pub const MAX_INLINE_CALLEES: usize = 32;

/// The `str`, `const`, and `callee` features of `func`'s small direct
/// callees in the image, marked inherited and optional.
///
/// Whether a helper is inlined differs between compilers and optimization
/// levels (gcc -O2 keeps `deflateStateCheck` out of line where clang inlines
/// it; -O0 inlines nothing), and inlining moves the helper's strings,
/// constants, and calls into its caller. A signature taken where the helper
/// was inlined demands those keys; a target that kept the call out of line
/// still carries them, inherited. Inherited keys are candidate-side
/// evidence only: generation signs own features, and the matcher credits an
/// inherited key at a discount, so a caller of a small function does not
/// look like the function itself. Callees are recovered without symbol hints
/// (unwind bounds only), so a signed image and its stripped copy see the same
/// callee bodies.
pub fn inline_evidence<S: ByteSource + ?Sized>(
    source: &S,
    func: &RecoveredFunction,
) -> Vec<Feature> {
    inline_evidence_with(source, func, None)
}

/// The inheritable features of each small callee, per callee address, for
/// one image. A small helper is called from many functions, and every
/// recovered candidate walked each of its callees again (up to
/// [`MAX_INLINE_CALLEES`] bounded recoveries per candidate); the evidence is
/// a function of the image bytes and the callee address alone, so it is
/// computed once.
#[derive(Debug, Default)]
pub struct InlineCache {
    entries: std::sync::RwLock<HashMap<u64, std::sync::Arc<Vec<Feature>>>>,
}

impl InlineCache {
    fn get_or_compute<S: ByteSource + ?Sized>(
        &self,
        source: &S,
        target: u64,
    ) -> std::sync::Arc<Vec<Feature>> {
        if let Some(found) = self.entries.read().expect("inline cache").get(&target) {
            return found.clone();
        }
        let computed = std::sync::Arc::new(callee_evidence(source, target));
        self.entries
            .write()
            .expect("inline cache")
            .insert(target, computed.clone());
        computed
    }
}

/// The inheritable features of the small callee at `target`: empty when it
/// does not recover cleanly within [`MAX_INLINE_CALLEE_INSTRUCTIONS`].
fn callee_evidence<S: ByteSource + ?Sized>(source: &S, target: u64) -> Vec<Feature> {
    // Every block holds at least one instruction, so the block cap stops the
    // walk of a large callee early instead of decoding it whole.
    let limits = crate::recover::RecoveryLimits {
        max_instructions: MAX_INLINE_CALLEE_INSTRUCTIONS,
        max_blocks: MAX_INLINE_CALLEE_INSTRUCTIONS,
        ..Default::default()
    };
    let Ok(callee) = crate::recover::recover(source, target, Some(limits), false) else {
        return Vec::new();
    };
    if callee.degraded || callee.instruction_count() > MAX_INLINE_CALLEE_INSTRUCTIONS {
        return Vec::new();
    }
    extract_own(source, &callee)
        .into_iter()
        .filter(|feature| {
            matches!(
                feature.kind,
                FeatureKind::Str | FeatureKind::Const | FeatureKind::Callee
            )
        })
        .map(|mut feature| {
            feature.required = false;
            feature.inherited = true;
            feature
        })
        .collect()
}

fn inline_evidence_with<S: ByteSource + ?Sized>(
    source: &S,
    func: &RecoveredFunction,
    cache: Option<&InlineCache>,
) -> Vec<Feature> {
    let (start, end) = (func.start(), func.end());
    let mut targets: Vec<u64> = func
        .blocks
        .iter()
        .flat_map(|block| block.insns.iter())
        .filter(|insn| matches!(insn.kind, Kind::Call | Kind::NoreturnCall | Kind::Jump))
        .filter_map(|insn| {
            let target = callee_definition(source, insn.target?, insn.callee.as_deref())?;
            let outside = target < start || target >= end;
            (outside && source.is_executable(target)).then_some(target)
        })
        .collect();
    targets.sort_unstable();
    targets.dedup();
    targets.truncate(MAX_INLINE_CALLEES);
    let mut inherited = Vec::new();
    for target in targets {
        match cache {
            Some(cache) => inherited.extend(cache.get_or_compute(source, target).iter().cloned()),
            None => inherited.extend(callee_evidence(source, target)),
        }
    }
    inherited
}

/// The function a direct call reaches: `None` for an import the image does
/// not define, the export's definition for a call through the PLT to the
/// image's own export (`-fPIC` shared objects call their exports that way),
/// otherwise the call target.
fn callee_definition<S: ByteSource + ?Sized>(
    source: &S,
    target: u64,
    callee: Option<&str>,
) -> Option<u64> {
    let Some(name) = callee else {
        return Some(target);
    };
    for module in source.modules() {
        if let Some((_, address)) = module.exports.iter().find(|(export, _)| export == name) {
            return Some(*address);
        }
    }
    let imported = source
        .modules()
        .iter()
        .any(|module| module.imports.values().any(|import| import == name));
    (!imported).then_some(target)
}

/// The function's own features, without inherited callee evidence.
pub fn extract_own<S: ByteSource + ?Sized>(source: &S, func: &RecoveredFunction) -> Vec<Feature> {
    let mut strings: HashSet<String> = HashSet::new();
    let mut consts: HashSet<u64> = HashSet::new();
    let mut callees: HashSet<String> = HashSet::new();
    let (start, end) = (func.start(), func.end());
    let mut ops: HashMap<OpClass, usize> = HashMap::new();

    for block in &func.blocks {
        for insn in &block.insns {
            if insn.kind == Kind::Ignored {
                continue;
            }
            *ops.entry(insn.op).or_insert(0) += 1;
            for value in &insn.consts {
                // The address test needs the full value: a 64-bit address split
                // into words would no longer be recognisable as one.
                if !is_address(source, insn.addr, insn.size, *value) {
                    consts.extend(const_words(*value));
                }
            }
            for reference in &insn.refs {
                if let Some(text) = string_at(source, reference.addr) {
                    strings.insert(text);
                }
            }
            if let Some(callee) = &insn.callee {
                // A jump that stays inside the function is control flow, not a
                // call: its target is a layout address in our own body.
                let internal = insn.kind == Kind::Jump
                    && insn
                        .target
                        .is_some_and(|target| start <= target && target < end);
                if !internal {
                    callees.insert(callee.clone());
                }
            }
        }
    }

    let mut features: Vec<Feature> = Vec::new();
    let mut string_values: Vec<String> = strings.into_iter().collect();
    string_values.sort();
    features.extend(
        string_values
            .into_iter()
            .map(|value| Feature::new(FeatureKind::Str, value)),
    );

    let mut const_values: Vec<u64> = consts.into_iter().collect();
    const_values.sort_unstable();
    features.extend(
        const_values
            .into_iter()
            .map(|value| Feature::new(FeatureKind::Const, format!("0x{value:x}"))),
    );

    // Portability is a property of the resolved name (an import keeps its
    // `__aeabi_memcpy` spelling), so decide it before canonicalising.
    let mut callee_values: BTreeMap<String, bool> = BTreeMap::new();
    for raw in callees {
        // A PE import (and a call into another module of a process) names
        // its providing DLL, `ucrtbase!memcpy`; ELF never records the
        // library, so its imports are `*!memcpy`. The module is dropped
        // everywhere: the same source calling `memcpy` must give the same
        // key on Linux and Windows. Measured on `corpus/real.py --pe`'s
        // mixed tier, ELF and PE signatures shared no import callee before.
        // An import by ordinal (`ws2_32!#23`) is a number only its DLL
        // gives meaning to, so it keeps the DLL.
        let symbol = match raw.rsplit_once('!') {
            Some((_, symbol)) if !symbol.starts_with('#') => symbol,
            _ => raw.as_str(),
        };
        if let Some(value) = canonical_callee(symbol) {
            let portable = is_portable_name(source, &raw);
            let value = if value.contains('!') {
                value.to_string()
            } else if raw.contains('!') || is_external_import(source, &raw) {
                format!("{EXTERNAL_PREFIX}{value}")
            } else {
                value.to_string()
            };
            *callee_values.entry(value).or_insert(false) |= portable;
        }
    }
    // A local callee's name is gone on a stripped target, so it may add
    // evidence but must never be demanded (or anchor the signature).
    for (value, portable) in callee_values {
        let mut feature = Feature::new(FeatureKind::Callee, value);
        feature.required = portable;
        features.push(feature);
    }

    features.push(Feature::new(
        FeatureKind::Cfg,
        format!("blocks:{}", bucket(func.block_count())),
    ));
    features.push(Feature::new(
        FeatureKind::Cfg,
        format!("edges:{}", bucket(func.edge_count())),
    ));
    features.push(Feature::new(
        FeatureKind::Cfg,
        format!("loops:{}", bucket(func.loop_count())),
    ));

    let mut op_values: Vec<(String, usize)> = ops
        .into_iter()
        .filter(|(_, count)| *count > 0)
        .map(|(op, count)| (op.as_str().to_string(), count))
        .collect();
    op_values.sort();
    features.extend(
        op_values
            .into_iter()
            .map(|(op, count)| Feature::new(FeatureKind::Ops, format!("{op}:{}", bucket(count)))),
    );

    features.sort();
    features
}

/// libgcc / compiler-rt helper suffixes (`__udivsi3`, `__aeabi` aside): the
/// operand modes of an arithmetic operation the target lowers to a call.
const RUNTIME_HELPER_SUFFIXES: [&str; 22] = [
    "si3", "di3", "ti3", "si4", "di4", "ti4", "sf2", "df2", "tf2", "sf3", "df3", "tf3", "sisf",
    "sidf", "disf", "didf", "sfsi", "dfsi", "sfdi", "dfdi", "sitf", "ditf",
];

/// The cross-architecture form of a callee name, or `None` to drop it.
///
/// ARM32 lowers integer division, 64-bit shifts, and soft-float arithmetic to
/// EABI/libgcc helper calls where x86-64 and AArch64 emit one instruction, so
/// those calls are arithmetic, not callees. The EABI memory helpers are the
/// same operation as the libc call other targets make (`__aeabi_memclr` is
/// `memset` with zero).
pub fn canonical_callee(name: &str) -> Option<&str> {
    if let Some(helper) = name.strip_prefix("__aeabi_") {
        return if helper.starts_with("memcpy") {
            Some("memcpy")
        } else if helper.starts_with("memmove") {
            Some("memmove")
        } else if helper.starts_with("memset") || helper.starts_with("memclr") {
            Some("memset")
        } else {
            None
        };
    }
    if name.starts_with("__")
        && name.len() <= 16
        && RUNTIME_HELPER_SUFFIXES
            .iter()
            .any(|suffix| name.ends_with(suffix))
    {
        return None;
    }
    Some(name)
}

/// Marks a call into another image (ELF: the defining library is not
/// recorded), in the spec's `module!import` form with an unknown module.
pub const EXTERNAL_PREFIX: &str = "*!";

/// True for an import the image does not define itself.
///
/// A shared object calls its own exported functions through the PLT too
/// (symbol interposition), so an import relocation alone does not mean
/// "another library": only a name with no definition here is external. Calls
/// to `memcpy`, `malloc`, or `free` occur in unrelated code everywhere, so the
/// matcher treats external callees as low-information evidence.
pub fn is_external_import<S: ByteSource + ?Sized>(source: &S, name: &str) -> bool {
    let imported = source
        .modules()
        .iter()
        .any(|module| module.imports.values().any(|import| import == name));
    imported
        && !source
            .modules()
            .iter()
            .any(|module| module.exports.iter().any(|(export, _)| export == name))
}

/// A callee name that survives stripping: an import (resolved through a
/// relocated slot) or a symbol the image exports dynamically. Names that only
/// `.symtab` provides vanish from a stripped target.
pub fn is_portable_name<S: ByteSource + ?Sized>(source: &S, name: &str) -> bool {
    source.modules().iter().any(|module| {
        module.imports.values().any(|import| import == name)
            || module.exports.iter().any(|(export, _)| export == name)
    })
}

/// Canonical `const` feature values for one materialised constant.
///
/// The same source constant reaches the extractor in different shapes per
/// architecture: x64 and AArch64 sign-extend a 32-bit immediate into a 64-bit
/// register (`0xffffffff94d049bb`) while ARM32 holds it in one 32-bit register
/// (`0x94d049bb`), and a 64-bit value that x64 loads with one `movabs` and
/// AArch64 builds with a `movz`/`movk` chain is two 32-bit registers on ARM32.
/// Recording every constant as 32-bit words makes all of these agree: a value
/// that is the zero- or sign-extension of a 32-bit value is its low word, and
/// any other value is its non-zero high and low words. A zero word carries no
/// evidence and appears when an AArch64 chain is split by an interleaved
/// instruction (`0x9e3779b900000000`), so it is dropped.
pub fn const_words(value: u64) -> impl Iterator<Item = u64> {
    let high = value >> 32;
    let low = value & 0xFFFF_FFFF;
    let extended = high == 0 || (high == 0xFFFF_FFFF && low & 0x8000_0000 != 0);
    let words = if extended {
        [Some(low), None]
    } else {
        [Some(high), Some(low).filter(|word| *word != 0)]
    };
    words.into_iter().flatten()
}

/// Return the string literal at `addr`, or `None` if it is not one.
///
/// Only non-executable memory is considered, so jump-table and code references
/// cannot masquerade as string anchors.
pub fn string_at<S: ByteSource + ?Sized>(source: &S, addr: u64) -> Option<String> {
    string_at_limit(source, addr, STR_MAX_LEN)
}

pub fn string_at_limit<S: ByteSource + ?Sized>(
    source: &S,
    addr: u64,
    limit: usize,
) -> Option<String> {
    if addr == 0 || source.is_executable(addr) {
        return None;
    }
    // Partial read: the literal may end exactly at a section boundary.
    let data = source.read_partial(addr, (limit + 1) * 2);
    if data.is_empty() {
        return None;
    }
    if let Some(narrow) = scan_narrow(&data, limit) {
        return Some(narrow);
    }
    scan_wide(&data, limit)
}

fn scan_narrow(data: &[u8], limit: usize) -> Option<String> {
    let mut chars: Vec<char> = Vec::new();
    let mut terminated = false;
    for (index, byte) in data.iter().enumerate() {
        if *byte == 0 {
            terminated = true;
            break;
        }
        if !(0x20..=0x7E).contains(byte) {
            return None;
        }
        if chars.len() < limit {
            chars.push(char::from(*byte));
        } else {
            // Over-long literal: keep a stable digest of the prefix we read.
            return Some(format!("long:{}", digest(&latin1(&data[..=index]))));
        }
    }
    if !terminated || chars.len() < STR_MIN_LEN {
        return None;
    }
    Some(escape(&chars.into_iter().collect::<String>()))
}

/// Detect UTF-16LE literals: printable ASCII low bytes with zero high bytes.
fn scan_wide(data: &[u8], limit: usize) -> Option<String> {
    let mut chars: Vec<char> = Vec::new();
    let mut truncated = false;
    let mut index = 0usize;
    while index + 1 < data.len() {
        let low = data[index];
        let high = data[index + 1];
        if low == 0 && high == 0 {
            if chars.len() < STR_MIN_LEN {
                return None;
            }
            return Some(format!(
                "w:{}",
                escape(&chars.into_iter().collect::<String>())
            ));
        }
        if high != 0 || !(0x20..=0x7E).contains(&low) {
            return None;
        }
        if chars.len() >= limit {
            truncated = true;
            break;
        }
        chars.push(char::from(low));
        index += 2;
    }
    if truncated {
        return Some(format!("w:long:{}", digest(&latin1(&data[..2 * limit]))));
    }
    None
}

fn escape(text: &str) -> String {
    text.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Interpret bytes as Latin-1 and return the corresponding Rust string.
///
/// Python's over-long literal digest decodes with `latin-1` and then hashes the
/// UTF-8 encoding of that string; mapping each byte to a code point is the
/// same operation.
fn latin1(data: &[u8]) -> String {
    data.iter().map(|byte| char::from(*byte)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arch::Arch;
    use crate::recover::recover;
    use crate::source::{MemorySource, Module, Region};

    /// `f` calls a local helper, an exported function, and an import through
    /// a lazily bound PLT stub, then loops back onto its own (named) entry.
    fn call_fixture() -> MemorySource {
        let mut body = vec![
            0xE8, 0x3B, 0x00, 0x00, 0x00, // 0x1000: call 0x1040 (helper)
            0xE8, 0x46, 0x00, 0x00, 0x00, // 0x1005: call 0x1050 (api)
            0xE8, 0x51, 0x00, 0x00, 0x00, // 0x100a: call 0x1060 (puts@plt)
            0x85, 0xC0, // 0x100f: test eax, eax
            0x74, 0x02, // 0x1011: je 0x1015
            0xEB, 0xEB, // 0x1013: jmp 0x1000
            0xC3, // 0x1015: ret
        ];
        body.resize(0x40, 0xCC);
        // 0x1040: helper: mov eax, 0x12345; ret
        body.extend_from_slice(&[0xB8, 0x45, 0x23, 0x01, 0x00, 0xC3]);
        body.resize(0x50, 0xCC);
        body.push(0xC3); // 0x1050: api
        body.resize(0x60, 0xCC);
        // 0x1060: jmp [rip+0xf9a] (slot 0x2000); push 0
        body.extend_from_slice(&[0xFF, 0x25, 0x9A, 0x0F, 0x00, 0x00, 0x68, 0, 0, 0, 0]);
        let text = Region::new("text", 0x1000, body, true, false);
        // Lazy binding: the slot points back into the stub, not at `puts`.
        let got = Region::new("got", 0x2000, 0x1066u64.to_le_bytes().to_vec(), false, true);
        let functions = HashMap::from([
            (0x1000, "f".to_string()),
            (0x1040, "helper".to_string()),
            (0x1050, "api".to_string()),
        ]);
        let module = Module {
            name: "fixture".to_string(),
            base: 0x1000,
            image_base: 0x1000,
            size: 0x1008,
            path: None,
            exports: vec![("f".to_string(), 0x1000), ("api".to_string(), 0x1050)],
            functions,
            imports: HashMap::from([(0x2000, "puts".to_string())]),
            relocations: None,
        };
        MemorySource::new(
            Arch::X64,
            vec![text, got],
            vec![module],
            vec![(0x1000, 0x1016)],
            Vec::new(),
        )
    }

    #[test]
    fn runtime_helpers_are_arithmetic_and_eabi_memory_calls_are_libc() {
        assert_eq!(canonical_callee("__aeabi_memcpy8"), Some("memcpy"));
        assert_eq!(canonical_callee("__aeabi_memclr4"), Some("memset"));
        assert_eq!(canonical_callee("__aeabi_uidivmod"), None);
        assert_eq!(canonical_callee("__aeabi_dadd"), None);
        assert_eq!(canonical_callee("__udivdi3"), None);
        assert_eq!(canonical_callee("__divti3"), None);
        assert_eq!(
            canonical_callee("__stack_chk_fail"),
            Some("__stack_chk_fail")
        );
        assert_eq!(canonical_callee("luaH_next"), Some("luaH_next"));
    }

    #[test]
    fn callees_are_calls_with_portable_names_required() {
        let source = call_fixture();
        let func = recover(&source, 0x1000, None, true).expect("recover");
        let callees: Vec<(String, bool)> = extract(&source, &func)
            .into_iter()
            .filter(|feature| feature.kind == FeatureKind::Callee)
            .map(|feature| (feature.value, feature.required))
            .collect();
        // The jump back to `f` is a loop, not a callee; `puts` resolves
        // through its relocated slot although the slot holds a stub address;
        // and is external (`*!`); `helper` has only a `.symtab` name, so it
        // is optional.
        assert_eq!(
            callees,
            vec![
                ("*!puts".to_string(), true),
                ("api".to_string(), true),
                ("helper".to_string(), false),
            ]
        );
    }

    #[test]
    fn small_callees_lend_their_evidence_as_optional_features() {
        let source = call_fixture();
        let func = recover(&source, 0x1000, None, true).expect("recover");
        let features = extract(&source, &func);
        // `helper`'s constant is inherited, optional; the helper itself
        // keeps it required.
        assert!(features
            .iter()
            .any(|f| f.key() == "inl:const:0x12345" && !f.required));
        assert!(!extract_own(&source, &func)
            .iter()
            .any(|f| f.value == "0x12345"));
        let helper = recover(&source, 0x1040, None, true).expect("helper");
        assert!(extract(&source, &helper)
            .iter()
            .any(|f| f.key() == "const:0x12345" && f.required));
    }

    fn words(value: u64) -> Vec<u64> {
        const_words(value).collect()
    }

    #[test]
    fn extended_32_bit_constants_are_their_low_word() {
        assert_eq!(words(0xFFFF_FFFF_94D0_49BB), vec![0x94D0_49BB]);
        assert_eq!(words(0x94D0_49BB), vec![0x94D0_49BB]);
        assert_eq!(words(u64::MAX), vec![0xFFFF_FFFF]);
        assert_eq!(words(0x1234), vec![0x1234]);
        assert_eq!(words(0), vec![0]);
    }

    #[test]
    fn wide_constants_split_into_non_zero_words() {
        assert_eq!(words(0x94D0_49BB_1331_11EB), vec![0x94D0_49BB, 0x1331_11EB]);
        assert_eq!(words(0x9E37_79B9_0000_0000), vec![0x9E37_79B9]);
        // A high word of all ones above a non-negative low word is not a sign
        // extension, so both words are evidence.
        assert_eq!(words(0xFFFF_FFFF_0000_0005), vec![0xFFFF_FFFF, 0x5]);
    }

    #[test]
    fn narrow_strings_require_termination_and_length() {
        assert_eq!(scan_narrow(b"abcd\0", 120).as_deref(), Some("abcd"));
        assert_eq!(scan_narrow(b"abc\0", 120), None);
        assert_eq!(scan_narrow(b"abcd", 120), None);
        assert_eq!(scan_narrow(b"ab\x01cd\0", 120), None);
    }

    #[test]
    fn wide_strings_are_tagged() {
        assert_eq!(
            scan_wide(b"a\0b\0c\0d\0\0\0", 120).as_deref(),
            Some("w:abcd")
        );
    }

    #[test]
    fn escapes_quotes_and_backslashes() {
        assert_eq!(
            scan_narrow(b"a\"b\\c\0", 120).as_deref(),
            Some("a\\\"b\\\\c")
        );
    }
}
