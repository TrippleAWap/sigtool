/*
 * Negative corpus: integer math and fixed-point shapes, unrelated to the
 * positive samples. Used only to measure false positives for strong signatures.
 * Freestanding: no libc, no headers, no division (arm32 has no divider in the
 * freestanding link, so every helper works with shifts, adds, and compares).
 */

typedef unsigned int u32;
typedef int i32;
typedef unsigned long long u64;
typedef long long i64;

static const char shift_range[] = "shift amount outside 0..31";
static const char overflow[] = "fixed point multiplication overflowed";
static const char no_solution[] = "no integer solution in range";

u32 gcd_u32(u32 a, u32 b) {
    if (a == 0u) {
        return b;
    }
    if (b == 0u) {
        return a;
    }
    u32 shift = 0;
    while (((a | b) & 1u) == 0u) {
        a >>= 1;
        b >>= 1;
        shift++;
    }
    while ((a & 1u) == 0u) {
        a >>= 1;
    }
    while (b != 0u) {
        while ((b & 1u) == 0u) {
            b >>= 1;
        }
        if (a > b) {
            u32 swap = a;
            a = b;
            b = swap;
        }
        b -= a;
    }
    return a << shift;
}

u32 isqrt_u32(u32 value) {
    u32 result = 0;
    u32 bit = 1u << 30;
    while (bit > value) {
        bit >>= 2;
    }
    while (bit != 0u) {
        if (value >= result + bit) {
            value -= result + bit;
            result = (result >> 1) + bit;
        } else {
            result >>= 1;
        }
        bit >>= 2;
    }
    return result;
}

i32 clamp_i32(i32 value, i32 low, i32 high) {
    if (value < low) {
        return low;
    }
    if (value > high) {
        return high;
    }
    return value;
}

i32 scale_frac(i32 value, i32 numerator, u32 shift) {
    if (shift > 31u) {
        return 0;
    }
    i64 scaled = (i64)value * (i64)numerator;
    return (i32)(scaled >> shift);
}

u64 saturating_add_u64(u64 a, u64 b) {
    u64 sum = a + b;
    if (sum < a) {
        return ~(u64)0;
    }
    return sum;
}

u32 popcount_u32(u32 value) {
    u32 count = 0;
    while (value != 0u) {
        value &= value - 1u;
        count++;
    }
    return count;
}

u32 is_prime_u32(u32 value) {
    if (value < 2u) {
        return 0;
    }
    if ((value & 1u) == 0u) {
        return value == 2u;
    }
    for (u32 divisor = 3u; divisor * divisor <= value; divisor += 2u) {
        /* Trial division by repeated subtraction: no divider on arm32. */
        u32 multiple = divisor;
        while (multiple < value) {
            multiple += divisor;
        }
        if (multiple == value) {
            return 0;
        }
    }
    return 1;
}

void _start(void) {}
