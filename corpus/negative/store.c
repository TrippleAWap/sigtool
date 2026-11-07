/*
 * Negative corpus: fixed-capacity ring buffer and slot store, unrelated to the
 * positive samples. Used only to measure false positives for strong signatures.
 * Freestanding: no libc, no headers.
 */

typedef unsigned char u8;
typedef unsigned int u32;
typedef int i32;
typedef unsigned long usize;

static const char full_buffer[] = "ring buffer is full";
static const char empty_buffer[] = "ring buffer is empty";
static const char bad_slot[] = "slot index outside the table";
static const char duplicate_key[] = "key already present in the table";

struct ring {
    u8 bytes[256];
    u32 read_at;
    u32 write_at;
    u32 count;
};

struct slot {
    u32 key;
    u32 value;
    u8 used;
};

struct table {
    struct slot slots[32];
    u32 live;
};

i32 ring_push(struct ring *ring, u8 value) {
    if (ring->count == 256u) {
        return -1;
    }
    ring->bytes[ring->write_at & 255u] = value;
    ring->write_at++;
    ring->count++;
    return 0;
}

i32 ring_pop(struct ring *ring, u8 *out) {
    if (ring->count == 0u) {
        return -1;
    }
    *out = ring->bytes[ring->read_at & 255u];
    ring->read_at++;
    ring->count--;
    return 0;
}

u32 ring_checksum(const struct ring *ring) {
    u32 checksum = 0x811C9DC5u;
    for (u32 offset = 0; offset < ring->count; offset++) {
        checksum ^= ring->bytes[(ring->read_at + offset) & 255u];
        checksum *= 0x01000193u;
    }
    return checksum;
}

i32 table_insert(struct table *table, u32 key, u32 value) {
    for (u32 index = 0; index < 32u; index++) {
        struct slot *slot = &table->slots[index];
        if (slot->used && slot->key == key) {
            return -2;
        }
        if (!slot->used) {
            slot->key = key;
            slot->value = value;
            slot->used = 1;
            table->live++;
            return 0;
        }
    }
    return -1;
}

i32 table_lookup(const struct table *table, u32 key, u32 *out) {
    for (u32 index = 0; index < 32u; index++) {
        const struct slot *slot = &table->slots[index];
        if (slot->used && slot->key == key) {
            *out = slot->value;
            return 0;
        }
    }
    return -1;
}

i32 table_erase(struct table *table, u32 key) {
    for (u32 index = 0; index < 32u; index++) {
        struct slot *slot = &table->slots[index];
        if (slot->used && slot->key == key) {
            slot->used = 0;
            slot->key = 0;
            slot->value = 0;
            table->live--;
            return 0;
        }
    }
    return -1;
}

void _start(void) {}
