const std = @import("std");
const Io = std.Io;
const Beanie = @import("beanie").Beanie;

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    var stdout_buffer: [1024]u8 = undefined;
    var stdout_file_writer: Io.File.Writer = .init(.stdout(), io, &stdout_buffer);
    const stdout = &stdout_file_writer.interface;

    const key: u128 = 0x0123456789abcdeffedcba9876543210;
    const tweak: u128 = 0xdeadbeefcafebabe0123456789abcdef;
    const plaintext: u32 = 0x12345678;

    const b = Beanie(9).init(key, tweak);
    const ciphertext = b.encrypt(plaintext);
    const decrypted = b.decrypt(ciphertext);

    try stdout.print("plaintext:  0x{x:0>8}\n", .{plaintext});
    try stdout.print("ciphertext: 0x{x:0>8}\n", .{ciphertext});
    try stdout.print("decrypted:  0x{x:0>8}\n", .{decrypted});
    try stdout.flush();
}
