# Nitrox tool
An assembler and disassembler for microcode of Cavium (now Marvell) Nitrox crypto accelerators.

## Getting Started
```sh
$ nitrox.py -d CNPx-MC-BOOT-2.00
```

## Microcode Format
Everything is big-endian unless indicated otherwise.

All Except O8x:
- 1 byte: type
- 31 bytes: version (ASCII, zero padded)
- 4 bytes: number of instructions (size varies)
- 4 bytes: data length in bytes (multiple of 8)
- code section
-- old format (4 bytes per instruction): 15 bits IRAM address, 1 bit parity, 16 bits instruction
-- new format (2 bytes per instruction): 16 bits instruction (little-endian on Nitrox V)
- align to 16 bytes
- data section
- align to 16 bytes
- 256 bytes: signature (unknown format, unused)
- copyright notice (optional, unused)

O8x:
- 4 bytes: unknown
- 44 bytes: version
- the rest is the same

## ISA Overview
- 8x 16-bit general purpose registers, r0..r7
- 16x 16-bit auxiliary registers (Nitrox 1/Lite), a0..b7
- 32x 16-bit auxiliary registers (Nitrox PX/3), a0..d7 (d7 is only used on Nitrox 3 and newer)
- sign flag (result has bit 15 set)
- zero flag (result is zero)
- 32-entry call stack
- peculiarities:
-- no unconditional jump instruction
-- shift instructions on Nitrox 1/Lite are very limited: shr1, shr3, shl3
-- no way to directly load immediate into upper 8 bits on Nitrox 1/Lite

Many instructions have:
- a stall bit (on Nitrox 1/Lite, '^' suffix)
- a bit to update the flags ('.' suffix)

## TODO
- how much SRAM is there exactly? Harvard or Von Neumann architecture? is self-modifying code possible?
- figure out how to configure/program the hardware blocks outside the microcontroller (including DMA and SRAM)
- why are there two different return instructions?
- refactor
- add a little bit of macro support
- how to recover from a call stack overflow? (exceptions?)
- Nitrox II (no products found yet)
- ThunderX2 (no microcode found yet)
