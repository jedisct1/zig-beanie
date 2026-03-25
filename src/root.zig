const std = @import("std");

const sbox_table: [16]u4 = .{ 0, 4, 2, 11, 10, 12, 9, 8, 5, 15, 13, 3, 7, 1, 6, 14 };
const sbox_inv_table: [16]u4 = .{ 0, 13, 2, 11, 1, 8, 14, 12, 7, 6, 4, 3, 5, 10, 15, 9 };
const round_constants: [10]u128 = .{
    0x00000000000000000000000000000000,
    0x000000000000000013198a2e03707344,
    0x0000000000000000a4093822299f31d0,
    0x0000000000000000082efa98ec4e6c89,
    0x0000000000000000452821e638d01377,
    0x0000000000000000be5466cf34e90c6c,
    0x00000000000000007ef84f78fd955cb1,
    0x000000000000000085840851f1ac43aa,
    0x0000000000000000c882d32f25323c54,
    0x000000000000000064a51195e0e3610d,
};

pub fn Beanie(comptime rounds: u4) type {
    comptime std.debug.assert(rounds >= 1 and rounds <= 9);
    const r: usize = rounds;

    return struct {
        round_keys: [r + 1]u32,

        pub fn init(key: u128, tweak: u128) @This() {
            return .{ .round_keys = keyExpansion(tweakKeySchedule(key, tweak)) };
        }

        pub fn encrypt(self: @This(), block: u32) u32 {
            var state = block;
            for (self.round_keys[0 .. r - 1]) |rk| {
                state ^= rk;
                state = applySbox(u32, sbox_table, state);
                state = shiftRows(state);
                state = @as(u32, mixColumn(@truncate(state >> 16))) << 16 | mixColumn(@truncate(state));
            }
            state ^= self.round_keys[r - 1];
            state = applySbox(u32, sbox_table, state);
            state = shiftRows(state);
            state ^= self.round_keys[r];
            return state;
        }

        pub fn decrypt(self: @This(), block: u32) u32 {
            var state = block;
            state ^= self.round_keys[r];
            state = shiftRows(state);
            state = applySbox(u32, sbox_inv_table, state);
            state ^= self.round_keys[r - 1];
            for (0..r - 1) |i| {
                state = @as(u32, mixColumn(@truncate(state >> 16))) << 16 | mixColumn(@truncate(state));
                state = shiftRows(state);
                state = applySbox(u32, sbox_inv_table, state);
                state ^= self.round_keys[r - 2 - i];
            }
            return state;
        }

        pub fn tweakKeySchedule(key: u128, tweak_in: u128) u128 {
            var tweak = tweak_in;
            for (0..r) |round| {
                tweak ^= key;
                tweak ^= round_constants[round];
                tweak = applySbox(u128, sbox_table, tweak);
                tweak = princeMixLayer(tweak);
                tweak = princeShiftRows(tweak);
                tweak = feistel(tweak);
                tweak = scheduleShift(tweak);
            }
            tweak ^= key;
            tweak ^= round_constants[r];
            return tweak;
        }

        pub fn keyExpansion(key: u128) [r + 1]u32 {
            var rk: [r + 1]u32 = undefined;
            rk[0] = @truncate(key >> 96);
            rk[1] = @truncate(key >> 64);
            if (r + 1 > 2) rk[2] = @truncate(key >> 32);
            if (r + 1 > 3) rk[3] = @truncate(key);
            if (r + 1 > 4) rk[4] = rk[0] ^ rk[1];
            if (r + 1 > 5) rk[5] = rk[2] ^ rk[3];
            if (r + 1 > 6) rk[6] = rk[0] ^ rk[2];
            if (r + 1 > 7) rk[7] = rk[1] ^ rk[3];
            if (r + 1 > 8) rk[8] = rk[0] ^ rk[3];
            if (r + 1 > 9) rk[9] = rk[1] ^ rk[2];
            return rk;
        }
    };
}

pub fn BeanieVec(comptime N: comptime_int, comptime rounds: u4) type {
    comptime std.debug.assert(rounds >= 1 and rounds <= 9);
    const r: usize = rounds;
    const Scalar = Beanie(rounds);

    return struct {
        pub const Vec = @Vector(N, u32);
        const ShiftAmt = @Vector(N, u5);

        round_keys: [r + 1]Vec,

        pub fn init(key: u128, tweaks: [N]u128) @This() {
            var rk_arrays: [r + 1][N]u32 = undefined;
            for (0..N) |i| {
                const expanded = Scalar.keyExpansion(Scalar.tweakKeySchedule(key, tweaks[i]));
                for (0..r + 1) |rk_idx| {
                    rk_arrays[rk_idx][i] = expanded[rk_idx];
                }
            }
            var round_keys: [r + 1]Vec = undefined;
            for (0..r + 1) |rk_idx| {
                round_keys[rk_idx] = rk_arrays[rk_idx];
            }
            return .{ .round_keys = round_keys };
        }

        pub fn encrypt(self: @This(), blocks: Vec) Vec {
            var state = blocks;
            for (self.round_keys[0 .. r - 1]) |rk| {
                state ^= rk;
                state = applySboxVec(sbox_table, state);
                state = shiftRowsVec(state);
                state = mixColumnsVec(state);
            }
            state ^= self.round_keys[r - 1];
            state = applySboxVec(sbox_table, state);
            state = shiftRowsVec(state);
            state ^= self.round_keys[r];
            return state;
        }

        pub fn decrypt(self: @This(), blocks: Vec) Vec {
            var state = blocks;
            state ^= self.round_keys[r];
            state = shiftRowsVec(state);
            state = applySboxVec(sbox_inv_table, state);
            state ^= self.round_keys[r - 1];
            for (0..r - 1) |i| {
                state = mixColumnsVec(state);
                state = shiftRowsVec(state);
                state = applySboxVec(sbox_inv_table, state);
                state ^= self.round_keys[r - 2 - i];
            }
            return state;
        }

        fn applySboxVec(table: [16]u4, state: Vec) Vec {
            var result: Vec = @splat(0);
            inline for (0..8) |i| {
                const sh: ShiftAmt = @splat(4 * i);
                const nibble = (state >> sh) & @as(Vec, @splat(0xf));
                var mapped: Vec = @splat(0);
                inline for (0..16) |v| {
                    const mask = nibble == @as(Vec, @splat(@as(u32, v)));
                    mapped |= @select(u32, mask, @as(Vec, @splat(@as(u32, table[v]))), @as(Vec, @splat(0)));
                }
                result |= mapped << sh;
            }
            return result;
        }

        fn shiftRowsVec(state: Vec) Vec {
            const s16: ShiftAmt = @splat(16);
            var result = state & @as(Vec, @splat(0xf0f0f0f0));
            result |= (state & @as(Vec, @splat(0x0f0f0000))) >> s16;
            result |= (state & @as(Vec, @splat(0x00000f0f))) << s16;
            return result;
        }

        fn gfDoubleVec(x: Vec) Vec {
            const s1: ShiftAmt = @splat(1);
            const s3: ShiftAmt = @splat(3);
            return @as(Vec, @splat(@as(u32, 0xf))) & ((x << s1) ^ (((x >> s3) & @as(Vec, @splat(@as(u32, 1)))) * @as(Vec, @splat(@as(u32, 0x3)))));
        }

        fn gfMulVec(x: Vec, comptime y: u4) Vec {
            const xt1 = gfDoubleVec(x);
            const xt2 = gfDoubleVec(xt1);
            const xt3 = gfDoubleVec(xt2);
            var result: Vec = @splat(0);
            if (y & 1 != 0) result ^= x;
            if (y >> 1 & 1 != 0) result ^= xt1;
            if (y >> 2 & 1 != 0) result ^= xt2;
            if (y >> 3 & 1 != 0) result ^= xt3;
            return result;
        }

        fn mixColumnVec(col: Vec) Vec {
            const s12: ShiftAmt = @splat(12);
            const s8: ShiftAmt = @splat(8);
            const s4: ShiftAmt = @splat(4);
            const mask: Vec = @splat(0xf);
            const c0 = (col >> s12) & mask;
            const c1 = (col >> s8) & mask;
            const c2 = (col >> s4) & mask;
            const c3 = col & mask;
            return (gfMulVec(c0, 0x2) ^ gfMulVec(c1, 0x1) ^ gfMulVec(c2, 0x1) ^ gfMulVec(c3, 0x9)) << s12 |
                (gfMulVec(c0, 0x1) ^ gfMulVec(c1, 0x4) ^ gfMulVec(c2, 0xf) ^ gfMulVec(c3, 0x1)) << s8 |
                (gfMulVec(c0, 0xd) ^ gfMulVec(c1, 0x9) ^ gfMulVec(c2, 0x4) ^ gfMulVec(c3, 0x1)) << s4 |
                (gfMulVec(c0, 0x1) ^ gfMulVec(c1, 0xd) ^ gfMulVec(c2, 0x1) ^ gfMulVec(c3, 0x2));
        }

        fn mixColumnsVec(state: Vec) Vec {
            const s16: ShiftAmt = @splat(16);
            const mask16: Vec = @splat(0xffff);
            return mixColumnVec(state >> s16) << s16 | mixColumnVec(state & mask16);
        }
    };
}

fn applySbox(comptime T: type, table: [16]u4, state: T) T {
    var result: T = 0;
    inline for (0..@divExact(@bitSizeOf(T), 4)) |i| {
        const nibble: u4 = @truncate(state >> (4 * i));
        result |= @as(T, table[nibble]) << (4 * i);
    }
    return result;
}

fn shiftRows(state: u32) u32 {
    var result = state & 0xf0f0f0f0;
    result |= (state & 0x0f0f0000) >> 16;
    result |= (state & 0x00000f0f) << 16;
    return result;
}

fn gfMul(x: u4, y: u4) u4 {
    const x8: u8 = x;
    const y8: u8 = y;
    const xt1 = 0xf & ((x8 << 1) ^ (((x8 >> 3) & 1) * 0x3));
    const xt2 = 0xf & ((xt1 << 1) ^ (((xt1 >> 3) & 1) * 0x3));
    const xt3 = 0xf & ((xt2 << 1) ^ (((xt2 >> 3) & 1) * 0x3));
    const b0: u8 = y8 & 1;
    const b1: u8 = (y8 >> 1) & 1;
    const b2: u8 = (y8 >> 2) & 1;
    const b3: u8 = (y8 >> 3) & 1;
    return @truncate(b0 * x8 ^ b1 * xt1 ^ b2 * xt2 ^ b3 * xt3);
}

fn mixColumn(col: u16) u16 {
    const c0: u4 = @truncate(col >> 12);
    const c1: u4 = @truncate(col >> 8);
    const c2: u4 = @truncate(col >> 4);
    const c3: u4 = @truncate(col);
    return @as(u16, gfMul(c0, 0x2) ^ gfMul(c1, 0x1) ^ gfMul(c2, 0x1) ^ gfMul(c3, 0x9)) << 12 |
        @as(u16, gfMul(c0, 0x1) ^ gfMul(c1, 0x4) ^ gfMul(c2, 0xf) ^ gfMul(c3, 0x1)) << 8 |
        @as(u16, gfMul(c0, 0xd) ^ gfMul(c1, 0x9) ^ gfMul(c2, 0x4) ^ gfMul(c3, 0x1)) << 4 |
        @as(u16, gfMul(c0, 0x1) ^ gfMul(c1, 0xd) ^ gfMul(c2, 0x1) ^ gfMul(c3, 0x2));
}

fn princeMix(comptime rotation: u2, col: u16) u16 {
    const masks = [4]u16{ 0b0111, 0b1011, 0b1101, 0b1110 };
    const c = [4]u16{
        (col >> 12) & 0xf,
        (col >> 8) & 0xf,
        (col >> 4) & 0xf,
        col & 0xf,
    };
    var result: u16 = 0;
    inline for (0..4) |row| {
        var nibble: u16 = 0;
        inline for (0..4) |k| {
            nibble ^= c[k] & masks[(rotation + row + k) % 4];
        }
        result |= nibble << (4 * (3 - row));
    }
    return result;
}

fn princeMixLayer(state: u128) u128 {
    return @as(u128, princeMix(0, @truncate(state >> 112))) << 112 |
        @as(u128, princeMix(1, @truncate(state >> 96))) << 96 |
        @as(u128, princeMix(1, @truncate(state >> 80))) << 80 |
        @as(u128, princeMix(0, @truncate(state >> 64))) << 64 |
        @as(u128, princeMix(0, @truncate(state >> 48))) << 48 |
        @as(u128, princeMix(1, @truncate(state >> 32))) << 32 |
        @as(u128, princeMix(1, @truncate(state >> 16))) << 16 |
        @as(u128, princeMix(0, @truncate(state)));
}

fn princeShiftRows(state: u128) u128 {
    var result: u128 = state & 0xF000F000F000F000F000F000F000F000;
    result |= (state & 0x00000F000F000F0000000F000F000F00) << 16;
    result |= (state & 0x0F000000000000000F00000000000000) >> 48;
    result |= (state & 0x0000000000F000F00000000000F000F0) << 32;
    result |= (state & 0x00F000F00000000000F000F000000000) >> 32;
    result |= (state & 0x000000000000000F000000000000000F) << 48;
    result |= (state & 0x000F000F000F0000000F000F000F0000) >> 16;
    return result;
}

fn feistel(state: u128) u128 {
    const mask: u128 = 0xffffffff;
    const shifted = state << 32;
    const xored = state ^ shifted;
    const a = xored & (mask << 96);
    const b = shifted & (mask << 64);
    const c = xored & (mask << 32);
    const d = (state >> 96) & mask;
    return a | b | c | d;
}

fn scheduleShift(state: u128) u128 {
    const hi = state >> 64;
    const lo: u128 = @as(u64, @truncate(state));
    var result: u128 = state & 0xF000F000F000F000F000F000F000F000;
    result |= ((hi & 0x000000000F000F00) << 96);
    result |= ((lo & 0x0F000F0000000000) << 32);
    result |= ((lo & 0x000000000F000F00) << 32);
    result |= ((hi & 0x0F000F0000000000) >> 32);
    result |= ((lo & 0x00F000F000F000F0) << 64);
    result |= (hi & 0x00F000F000F000F0);
    result |= ((hi & 0x000F000F00000000) << 32);
    result |= ((lo & 0x00000000000F000F) << 96);
    result |= ((lo & 0x000F000F00000000) >> 32);
    result |= ((hi & 0x00000000000F000F) << 32);
    return result;
}

const testing = std.testing;

test "substitution" {
    try testing.expectEqual(@as(u32, 0x42bac985), applySbox(u32, sbox_table, 0x12345678));
}

test "inverse substitution" {
    try testing.expectEqual(@as(u32, 0xd2b18ec7), applySbox(u32, sbox_inv_table, 0x12345678));
}

test "substitution roundtrip" {
    try testing.expectEqual(@as(u32, 0x12345678), applySbox(u32, sbox_inv_table, applySbox(u32, sbox_table, 0x12345678)));
}

test "shift rows" {
    try testing.expectEqual(@as(u32, 0x16385274), shiftRows(0x12345678));
}

test "shift rows is involutory" {
    try testing.expectEqual(@as(u32, 0x12345678), shiftRows(shiftRows(0x12345678)));
}

test "mix columns" {
    const state: u32 = 0x12345678;
    try testing.expectEqual(@as(u32, 0x1f43fd89), @as(u32, mixColumn(@truncate(state >> 16))) << 16 | mixColumn(@truncate(state)));
}

test "mix columns is involutory" {
    const s1: u32 = 0x12345678;
    const s2 = @as(u32, mixColumn(@truncate(s1 >> 16))) << 16 | mixColumn(@truncate(s1));
    try testing.expectEqual(s1, @as(u32, mixColumn(@truncate(s2 >> 16))) << 16 | mixColumn(@truncate(s2)));
}

test "wide substitution" {
    try testing.expectEqual(
        @as(u128, 0x042bac985fd3716ee6173df589cab240),
        applySbox(u128, sbox_table, 0x0123456789abcdeffedcba9876543210),
    );
}

test "prince mix layer" {
    try testing.expectEqual(
        @as(u128, 0x3012456789abfcdecfedba9876540321),
        princeMixLayer(0x0123456789abcdeffedcba9876543210),
    );
}

test "prince shift rows" {
    const result = princeShiftRows(0x0123456789abcdeffedcba9876543210);
    try testing.expectEqual(@as(u64, 0x05af49e38d27c16b), @as(u64, @truncate(result >> 64)));
}

test "feistel" {
    try testing.expectEqual(
        @as(u128, 0x88888888fedcba988888888801234567),
        feistel(0x0123456789abcdeffedcba9876543210),
    );
}

test "schedule shift" {
    try testing.expectEqual(
        @as(u128, 0x09d44d908e53ca17f62bb26f71ac35e8),
        scheduleShift(0x0123456789abcdeffedcba9876543210),
    );
}

test "key expansion" {
    try testing.expectEqual([10]u32{
        0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210,
        0x88888888, 0x88888888, 0xffffffff, 0xffffffff,
        0x77777777, 0x77777777,
    }, Beanie(9).keyExpansion(0x0123456789abcdeffedcba9876543210));
}

test "known-answer test" {
    const key: u128 = 0x0123456789abcdeffedcba9876543210;
    const tweak: u128 = 0xdeadbeefcafebabe0123456789abcdef;

    const tk = Beanie(9).tweakKeySchedule(key, tweak);
    try testing.expectEqual(@as(u128, 0x7e13bbaedcea7fea07f371d4e27151e7), tk);

    const rk = Beanie(9).keyExpansion(tk);
    try testing.expectEqual([10]u32{
        0x7e13bbae, 0xdcea7fea, 0x07f371d4, 0xe27151e7,
        0xa2f9c444, 0xe5822033, 0x79e0ca7a, 0x3e9b2e0d,
        0x9c62ea49, 0xdb190e3e,
    }, rk);

    const b = Beanie(9).init(key, tweak);
    try testing.expectEqual(@as(u32, 0x8cc10eab), b.encrypt(0x12345678));
    try testing.expectEqual(@as(u32, 0x12345678), b.decrypt(0x8cc10eab));
}

test "encrypt/decrypt roundtrip all round counts" {
    const key: u128 = 0xdeadbeefcafebabe0123456789abcdef;
    const tweak: u128 = 0x0123456789abcdeffedcba9876543210;
    const plaintext: u32 = 0xdeadbeef;
    inline for (1..10) |rounds| {
        const b = Beanie(rounds).init(key, tweak);
        const ciphertext = b.encrypt(plaintext);
        try testing.expectEqual(plaintext, b.decrypt(ciphertext));
    }
}

test "BeanieVec matches scalar encrypt" {
    const N = 8;
    const key: u128 = 0x0123456789abcdeffedcba9876543210;
    const tweaks = [N]u128{
        0xdeadbeefcafebabe0123456789abcdef,
        0x0000000000000000ffffffffffffffff,
        0xffffffffffffffffffffffffffffffff,
        0x0123456789abcdeffedcba9876543210,
        0xaaaaaaaaaaaaaaaa5555555555555555,
        0x1111111111111111eeeeeeeeeeeeeeee,
        0x00000000000000000000000000000000,
        0xfedcba98765432100123456789abcdef,
    };
    const blocks = [N]u32{ 0x12345678, 0xdeadbeef, 0xcafebabe, 0x00000000, 0xffffffff, 0xabcdef01, 0x99999999, 0x55aa55aa };

    inline for (1..10) |rounds| {
        const bv = BeanieVec(N, rounds).init(key, tweaks);
        const vec_result: [N]u32 = bv.encrypt(blocks);
        for (0..N) |i| {
            const scalar = Beanie(rounds).init(key, tweaks[i]);
            try testing.expectEqual(scalar.encrypt(blocks[i]), vec_result[i]);
        }
    }
}

test "BeanieVec matches scalar decrypt" {
    const N = 8;
    const key: u128 = 0x0123456789abcdeffedcba9876543210;
    const tweaks = [N]u128{
        0xdeadbeefcafebabe0123456789abcdef,
        0x0000000000000000ffffffffffffffff,
        0xffffffffffffffffffffffffffffffff,
        0x0123456789abcdeffedcba9876543210,
        0xaaaaaaaaaaaaaaaa5555555555555555,
        0x1111111111111111eeeeeeeeeeeeeeee,
        0x00000000000000000000000000000000,
        0xfedcba98765432100123456789abcdef,
    };
    const blocks = [N]u32{ 0x8cc10eab, 0xdeadbeef, 0xcafebabe, 0x00000000, 0xffffffff, 0xabcdef01, 0x99999999, 0x55aa55aa };

    inline for (1..10) |rounds| {
        const bv = BeanieVec(N, rounds).init(key, tweaks);
        const vec_result: [N]u32 = bv.decrypt(blocks);
        for (0..N) |i| {
            const scalar = Beanie(rounds).init(key, tweaks[i]);
            try testing.expectEqual(scalar.decrypt(blocks[i]), vec_result[i]);
        }
    }
}

test "BeanieVec encrypt/decrypt roundtrip" {
    const N = 4;
    const key: u128 = 0xdeadbeefcafebabe0123456789abcdef;
    const tweaks = [N]u128{ 0x1, 0x2, 0x3, 0x4 };
    const BV = BeanieVec(N, 9);
    const plaintext: BV.Vec = .{ 0xdeadbeef, 0xcafebabe, 0x12345678, 0xffffffff };
    const bv = BV.init(key, tweaks);
    const ciphertext = bv.encrypt(plaintext);
    try testing.expectEqual(plaintext, bv.decrypt(ciphertext));
}

test "BeanieVec different N values" {
    const key: u128 = 0x0123456789abcdeffedcba9876543210;
    const tweak: u128 = 0xdeadbeefcafebabe0123456789abcdef;
    const scalar = Beanie(9).init(key, tweak);
    const expected = scalar.encrypt(0x12345678);

    inline for (.{ 1, 2, 4, 8, 16 }) |n| {
        const BV = BeanieVec(n, 9);
        const tweaks: [n]u128 = @splat(tweak);
        const blocks: [n]u32 = @splat(0x12345678);
        const bv = BV.init(key, tweaks);
        const result: [n]u32 = bv.encrypt(blocks);
        for (result) |rv| {
            try testing.expectEqual(expected, rv);
        }
    }
}
