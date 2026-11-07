/*
 * Negative corpus: byte codec and checksum shapes, unrelated to the positive
 * samples. Used only to measure false positives for strong signatures.
 * Freestanding: no libc, no headers.
 */

typedef unsigned char u8;
typedef unsigned int u32;
typedef int i32;
typedef unsigned long usize;

static const char bad_varint[] = "varint sequence overlong";
static const char bad_crc[] = "crc table mismatch";
static const char bad_base64[] = "base64 alphabet violation";
static const char short_input[] = "input shorter than the requested window";

static const char base64_alphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static u32 crc_table[256];

static void crc_init(void) {
    for (u32 index = 0; index < 256; index++) {
        u32 value = index;
        for (u32 bit = 0; bit < 8; bit++) {
            value = (value & 1) ? (value >> 1) ^ 0xEDB88320u : value >> 1;
        }
        crc_table[index] = value;
    }
}

u32 crc32_update(u32 crc, const u8 *data, usize size) {
    crc_init();
    for (usize offset = 0; offset < size; offset++) {
        crc = crc_table[(crc ^ data[offset]) & 0xFFu] ^ (crc >> 8);
    }
    return crc;
}

u32 varint_decode(const u8 *data, usize size, u32 *out) {
    u32 value = 0;
    u32 shift = 0;
    for (usize offset = 0; offset < size && offset < 5; offset++) {
        u8 byte = data[offset];
        value |= (u32)(byte & 0x7Fu) << shift;
        if ((byte & 0x80u) == 0) {
            *out = value;
            return (u32)offset + 1u;
        }
        shift += 7;
    }
    return 0u;
}

i32 base64_value(char c) {
    for (i32 index = 0; index < 64; index++) {
        if (base64_alphabet[index] == c) {
            return index;
        }
    }
    return -1;
}

usize base64_decode(const char *src, usize size, u8 *out) {
    if (size < 4) {
        return 0;
    }
    usize written = 0;
    for (usize offset = 0; offset + 3 < size; offset += 4) {
        i32 a = base64_value(src[offset]);
        i32 b = base64_value(src[offset + 1]);
        i32 c = src[offset + 2] == '=' ? 0 : base64_value(src[offset + 2]);
        i32 d = src[offset + 3] == '=' ? 0 : base64_value(src[offset + 3]);
        if (a < 0 || b < 0 || c < 0 || d < 0) {
            return written;
        }
        u32 packed = ((u32)a << 18) | ((u32)b << 12) | ((u32)c << 6) | (u32)d;
        out[written++] = (u8)(packed >> 16);
        if (src[offset + 2] != '=') {
            out[written++] = (u8)(packed >> 8);
        }
        if (src[offset + 3] != '=') {
            out[written++] = (u8)packed;
        }
    }
    return written;
}

u32 zigzag_encode(i32 value) {
    return ((u32)value << 1) ^ (u32)(value >> 31);
}

i32 zigzag_decode(u32 value) {
    return (i32)((value >> 1) ^ (0u - (value & 1u)));
}

void _start(void) {}
