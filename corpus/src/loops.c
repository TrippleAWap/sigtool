/*
 * Corpus sample: arithmetic and control-flow shapes (loops, recursion,
 * multi-way branches, 64-bit mixing). Freestanding.
 */

typedef unsigned long usize;
typedef unsigned long long u64;
typedef int i32;

static const char overflow_text[] = "counter overflowed";
static const char negative_text[] = "counter went negative";
static const char stable_text[] = "counter stable";

i32 counters[64];

static i32 clamp(i32 value, i32 low, i32 high) {
    if (value < low) {
        return low;
    }
    if (value > high) {
        return high;
    }
    return value;
}

i32 accumulate(i32 limit) {
    i32 total = 0;
    for (i32 i = 0; i < limit; i++) {
        total += counters[i & 63] * 3 - i;
    }
    return total;
}

i32 collatz_length(u64 value) {
    i32 steps = 0;
    while (value != 1 && steps < 1024) {
        if (value & 1) {
            value = value * 3 + 1;
        } else {
            value >>= 1;
        }
        steps++;
    }
    return steps;
}

u64 mix64(u64 x) {
    x ^= x >> 30;
    x *= 0xBF58476D1CE4E5B9ull;
    x ^= x >> 27;
    x *= 0x94D049BB133111EBull;
    return x ^ (x >> 31);
}

i32 fibonacci(i32 n) {
    if (n < 2) {
        return n;
    }
    i32 a = 0;
    i32 b = 1;
    for (i32 i = 2; i <= n; i++) {
        i32 next = a + b;
        a = b;
        b = next;
    }
    return b;
}

const char *counter_state(i32 value) {
    if (value > 0x7FFFFF00) {
        return overflow_text;
    }
    if (value < 0) {
        return negative_text;
    }
    if (value < 8) {
        return stable_text;
    }
    return counters[value & 63] ? stable_text : overflow_text;
}

i32 summarize(i32 a, i32 b, i32 c) {
    i32 low = clamp(a, -100, 100);
    i32 mid = clamp(b, low, 200);
    i32 high = clamp(c, mid, 1000);
    return accumulate(low + mid + high) + fibonacci(high & 15);
}

i32 table_walk(i32 index) {
    switch (index & 7) {
    case 0: return 3;
    case 1: return 5;
    case 2: return 7;
    case 3: return 11;
    case 4: return 13;
    case 5: return 17;
    case 6: return 19;
    default: return 23;
    }
}

void _start(void) {}
