//! A bounded work pool over scoped threads, shared by the scanner paths.
//!
//! Results keep index order, so callers stay deterministic (AGENTS.md rule 3)
//! whatever order the jobs finish in. A call made from inside a pool worker
//! runs sequentially: the bench already runs one cell per core, and nesting a
//! second pool under each would only oversubscribe the machine.

use std::cell::Cell;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

thread_local! {
    static IN_WORKER: Cell<bool> = const { Cell::new(false) };
}

/// Worker count: `SIGTOOL_THREADS` when set (1 runs everything on the
/// calling thread, for determinism checks), else every core.
pub fn threads() -> usize {
    std::env::var("SIGTOOL_THREADS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|threads| *threads > 0)
        .unwrap_or_else(|| {
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1)
        })
}

/// Run `job(i)` for every `i < count` on all cores; results in index order.
pub fn map<T: Send, F: Fn(usize) -> T + Sync>(count: usize, job: F) -> Vec<T> {
    let threads = if IN_WORKER.with(Cell::get) {
        1
    } else {
        threads().min(count)
    };
    if threads <= 1 {
        return (0..count).map(job).collect();
    }
    let next = AtomicUsize::new(0);
    let slots: Mutex<Vec<Option<T>>> = Mutex::new((0..count).map(|_| None).collect());
    std::thread::scope(|scope| {
        for _ in 0..threads {
            scope.spawn(|| {
                IN_WORKER.with(|flag| flag.set(true));
                loop {
                    let index = next.fetch_add(1, Ordering::Relaxed);
                    if index >= count {
                        break;
                    }
                    let value = job(index);
                    slots.lock().expect("pool slots")[index] = Some(value);
                }
            });
        }
    });
    slots
        .into_inner()
        .expect("pool slots")
        .into_iter()
        .map(|slot| slot.expect("every job ran"))
        .collect()
}

/// Run two jobs at once (sequentially inside a pool worker).
pub fn join<A: Send, B: Send>(
    left: impl FnOnce() -> A + Send,
    right: impl FnOnce() -> B + Send,
) -> (A, B) {
    if IN_WORKER.with(Cell::get) || threads() == 1 {
        return (left(), right());
    }
    std::thread::scope(|scope| {
        let handle = scope.spawn(|| {
            IN_WORKER.with(|flag| flag.set(true));
            right()
        });
        let a = left();
        (a, handle.join().expect("join worker"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_keeps_index_order_and_nests_sequentially() {
        let outer = map(16, |i| map(4, move |j| i * 10 + j));
        for (i, inner) in outer.iter().enumerate() {
            assert_eq!(inner, &(0..4).map(|j| i * 10 + j).collect::<Vec<_>>());
        }
        assert_eq!(join(|| 1, || 2), (1, 2));
    }
}
