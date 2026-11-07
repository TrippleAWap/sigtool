/*
 * Corpus sample: parser-shaped code with magic constants, string anchors,
 * error paths, and table lookups. Freestanding: no libc, no headers.
 */

typedef unsigned long usize;
typedef unsigned int u32;
typedef unsigned short u16;
typedef unsigned char u8;

void *memcpy(void *dst, const void *src, usize n) {
    u8 *d = (u8 *)dst;
    const u8 *s = (const u8 *)src;
    for (usize i = 0; i < n; i++) {
        d[i] = s[i];
    }
    return dst;
}

void *memset(void *dst, int value, usize n) {
    u8 *d = (u8 *)dst;
    for (usize i = 0; i < n; i++) {
        d[i] = (u8)value;
    }
    return dst;
}

static const char bad_length[] = "record length below header size";
static const char bad_magic[] = "record magic mismatch";
static const char bad_checksum[] = "record checksum mismatch";
static const char truncated[] = "record payload truncated";

static u32 read_u32le(const u8 *p) {
    return (u32)p[0] | ((u32)p[1] << 8) | ((u32)p[2] << 16) | ((u32)p[3] << 24);
}

static u32 read_u16le(const u8 *p) {
    return (u32)p[0] | ((u32)p[1] << 8);
}

struct record_header {
    u32 magic;
    u32 length;
    u16 flags;
    u16 checksum;
};

int parse_record(const u8 *data, usize size, struct record_header *out) {
    if (size < 12) {
        return -1;
    }
    u32 magic = read_u32le(data);
    if (magic != 0x52454344u) {
        return -2;
    }
    u32 length = read_u32le(data + 4);
    if (length < 12) {
        return -3;
    }
    if (length > size) {
        return -4;
    }
    u32 checksum = 0;
    for (u32 i = 0; i < length; i++) {
        checksum = (checksum << 5) ^ (checksum >> 27) ^ data[i];
    }
    u16 expected = (u16)read_u16le(data + 10);
    if ((u16)checksum != expected) {
        return -5;
    }
    out->magic = magic;
    out->length = length;
    out->flags = (u16)read_u16le(data + 8);
    out->checksum = expected;
    return 0;
}

const char *record_error(int code) {
    switch (code) {
    case -1: return truncated;
    case -2: return bad_magic;
    case -3: return bad_length;
    case -5: return bad_checksum;
    default: return (const char *)0;
    }
}

u32 record_score(const u8 *data, usize size) {
    u32 score = 0;
    for (usize i = 0; i + 3 < size; i += 3) {
        score += read_u32le(data + i) * 0x9E3779B1u;
        score ^= score >> 13;
    }
    return score;
}

int record_copy(u8 *dst, usize dst_size, const u8 *src, usize src_size) {
    if (src_size > dst_size || src_size < 12) {
        return -1;
    }
    memcpy(dst, src, src_size);
    return (int)src_size;
}

void record_reset(struct record_header *header) {
    header->magic = 0x52454344u;
    header->length = 12;
    header->flags = 0x0040;
    header->checksum = 0;
}

void _start(void) {}
