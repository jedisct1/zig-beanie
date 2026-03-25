const std = @import("std");

pub const Beanie = struct {
    round_keys: [10]u32,
    rounds: u4,

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

    pub fn init(key: u128, tweak: u128, rounds: u4) Beanie {
        std.debug.assert(rounds >= 1 and rounds <= 9);
        const tk = tweakKeySchedule(key, tweak, rounds);
        return .{
            .round_keys = keyExpansion(tk),
            .rounds = rounds,
        };
    }

    pub fn encrypt(self: Beanie, block: u32) u32 {
        var state = block;
        const r: usize = self.rounds;
        for (self.round_keys[0 .. r - 1]) |rk| {
            state ^= rk;
            state = substitution(state);
            state = shiftRows(state);
            state = mixColumns(state);
        }
        state ^= self.round_keys[r - 1];
        state = substitution(state);
        state = shiftRows(state);
        state ^= self.round_keys[r];
        return state;
    }

    pub fn decrypt(self: Beanie, block: u32) u32 {
        var state = block;
        const r: usize = self.rounds;
        state ^= self.round_keys[r];
        state = shiftRows(state);
        state = inverseSubstitution(state);
        state ^= self.round_keys[r - 1];
        for (0..r - 1) |i| {
            state = mixColumns(state);
            state = shiftRows(state);
            state = inverseSubstitution(state);
            state ^= self.round_keys[r - 2 - i];
        }
        return state;
    }

    pub fn tweakKeySchedule(key: u128, tweak_in: u128, rounds: u4) u128 {
        var tweak = tweak_in;
        const r: usize = rounds;
        for (0..r) |round| {
            tweak ^= key;
            tweak ^= round_constants[round];
            tweak = substitutionWide(tweak);
            tweak = princeMixLayer(tweak);
            tweak = princeShiftRows(tweak);
            tweak = feistel(tweak);
            tweak = scheduleShift(tweak);
        }
        tweak ^= key;
        tweak ^= round_constants[r];
        return tweak;
    }

    pub fn keyExpansion(key: u128) [10]u32 {
        var rk: [10]u32 = undefined;
        rk[0] = @truncate(key >> 96);
        rk[1] = @truncate(key >> 64);
        rk[2] = @truncate(key >> 32);
        rk[3] = @truncate(key);
        rk[4] = rk[0] ^ rk[1];
        rk[5] = rk[2] ^ rk[3];
        rk[6] = rk[0] ^ rk[2];
        rk[7] = rk[1] ^ rk[3];
        rk[8] = rk[0] ^ rk[3];
        rk[9] = rk[1] ^ rk[2];
        return rk;
    }

    fn substitution(state: u32) u32 {
        return applySbox(u32, sbox_table, state);
    }

    fn inverseSubstitution(state: u32) u32 {
        return applySbox(u32, sbox_inv_table, state);
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

    fn gfDouble(x: u8) u8 {
        return 0xf & ((x << 1) ^ (((x >> 3) & 1) * 0x3));
    }

    fn gfMul(x: u4, y: u4) u4 {
        const x8: u8 = x;
        const y8: u8 = y;
        const xt1 = gfDouble(x8);
        const xt2 = gfDouble(xt1);
        const xt3 = gfDouble(xt2);
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

    fn mixColumns(state: u32) u32 {
        return @as(u32, mixColumn(@truncate(state >> 16))) << 16 | mixColumn(@truncate(state));
    }

    fn substitutionWide(state: u128) u128 {
        return applySbox(u128, sbox_table, state);
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
};

const testing = std.testing;

test "substitution" {
    try testing.expectEqual(@as(u32, 0x42bac985), Beanie.substitution(0x12345678));
}

test "inverse substitution" {
    try testing.expectEqual(@as(u32, 0xd2b18ec7), Beanie.inverseSubstitution(0x12345678));
}

test "substitution roundtrip" {
    try testing.expectEqual(@as(u32, 0x12345678), Beanie.inverseSubstitution(Beanie.substitution(0x12345678)));
}

test "shift rows" {
    try testing.expectEqual(@as(u32, 0x16385274), Beanie.shiftRows(0x12345678));
}

test "shift rows is involutory" {
    try testing.expectEqual(@as(u32, 0x12345678), Beanie.shiftRows(Beanie.shiftRows(0x12345678)));
}

test "mix columns" {
    try testing.expectEqual(@as(u32, 0x1f43fd89), Beanie.mixColumns(0x12345678));
}

test "mix columns is involutory" {
    try testing.expectEqual(@as(u32, 0x12345678), Beanie.mixColumns(Beanie.mixColumns(0x12345678)));
}

test "wide substitution" {
    try testing.expectEqual(
        @as(u128, 0x042bac985fd3716ee6173df589cab240),
        Beanie.substitutionWide(0x0123456789abcdeffedcba9876543210),
    );
}

test "prince mix layer" {
    try testing.expectEqual(
        @as(u128, 0x3012456789abfcdecfedba9876540321),
        Beanie.princeMixLayer(0x0123456789abcdeffedcba9876543210),
    );
}

test "prince shift rows" {
    const result = Beanie.princeShiftRows(0x0123456789abcdeffedcba9876543210);
    try testing.expectEqual(@as(u64, 0x05af49e38d27c16b), @as(u64, @truncate(result >> 64)));
}

test "feistel" {
    try testing.expectEqual(
        @as(u128, 0x88888888fedcba988888888801234567),
        Beanie.feistel(0x0123456789abcdeffedcba9876543210),
    );
}

test "schedule shift" {
    try testing.expectEqual(
        @as(u128, 0x09d44d908e53ca17f62bb26f71ac35e8),
        Beanie.scheduleShift(0x0123456789abcdeffedcba9876543210),
    );
}

test "key expansion" {
    try testing.expectEqual([10]u32{
        0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210,
        0x88888888, 0x88888888, 0xffffffff, 0xffffffff,
        0x77777777, 0x77777777,
    }, Beanie.keyExpansion(0x0123456789abcdeffedcba9876543210));
}

test "known-answer test" {
    const key: u128 = 0x0123456789abcdeffedcba9876543210;
    const tweak: u128 = 0xdeadbeefcafebabe0123456789abcdef;

    const tk = Beanie.tweakKeySchedule(key, tweak, 9);
    try testing.expectEqual(@as(u128, 0x7e13bbaedcea7fea07f371d4e27151e7), tk);

    const rk = Beanie.keyExpansion(tk);
    try testing.expectEqual([10]u32{
        0x7e13bbae, 0xdcea7fea, 0x07f371d4, 0xe27151e7,
        0xa2f9c444, 0xe5822033, 0x79e0ca7a, 0x3e9b2e0d,
        0x9c62ea49, 0xdb190e3e,
    }, rk);

    const b = Beanie.init(key, tweak, 9);
    try testing.expectEqual(@as(u32, 0x8cc10eab), b.encrypt(0x12345678));
    try testing.expectEqual(@as(u32, 0x12345678), b.decrypt(0x8cc10eab));
}

test "encrypt/decrypt roundtrip all round counts" {
    const key: u128 = 0xdeadbeefcafebabe0123456789abcdef;
    const tweak: u128 = 0x0123456789abcdeffedcba9876543210;
    const plaintext: u32 = 0xdeadbeef;
    for (1..10) |rounds| {
        const b = Beanie.init(key, tweak, @intCast(rounds));
        const ciphertext = b.encrypt(plaintext);
        try testing.expectEqual(plaintext, b.decrypt(ciphertext));
    }
}
