# zig-beanie

`zig-beanie` is a Zig implementation of BEANIE, the 32-bit tweakable block cipher.

BEANIE was designed for low-latency memory encryption on microcontrollers, where 32-bit words are common and software attacks are a primary concern. This repository provides a small Zig library in `src/root.zig`, a simple CLI example in `src/main.zig`, and in-source tests for the core cipher operations.

But is can have many other applications, especially since it's a perfect match for SIMD implementations.

## Cipher at a glance

- 32-bit block cipher
- tweakable design for memory-encryption style contexts
- 128-bit key and 128-bit tweak in this implementation

## Reference

Simon Gerhalter, Samir Hodzic, Marcel Medwed, Marcel Nageler, Artur Folwarczny, Ventzi Nikov, Jan Hoogerbrugge, Tobias Schneider, Gary McConville, and Maria Eichlseder, "BEANIE - A 32-bit Cipher for Cryptographic Mitigations Against Software Attacks," IACR Transactions on Symmetric Cryptology, 2025(4), pp. 31-69.
