# Nitrox tool
An assembler and disassembler for microcode of Cavium (now Marvell) Nitrox crypto accelerators.

## ISA Overview
- 8x 16-bit general purpose registers, r0..r7
- 16x 16-bit auxiliary registers (Nitrox 1/Lite), a0..b7
- 32x 16-bit auxiliary registers (Nitrox PX/3), a0..d7
- sign flag (result has the uppermost bit set)
- zero flag (result is zero)
- 32-entry call stack
- no unconditional jump instruction

Many instructions have:
- a stall bit (mainly or maybe exclusively on Nitrox 1/Lite, '^' suffix)
- a bit to update the flags ('.' suffix)

## TODO
- how much SRAM is there exactly? Harvard or Von Neumann architecture? is self-modifying code possible?
- figure out how to configure/program the hardware blocks outside the microcontroller (including DMA and SRAM)
- why are there two different return instructions?
- refactor
- add a little bit of macro support
- how to recover from a call stack overflow? (exceptions?)
- Nitrox II (no products found yet)
- ThunderX/Octeon8 (dropped address+parity)
- Nitrox V (changed from big-endian to little-endian)
- ThunderX2 (no microcode found yet)
