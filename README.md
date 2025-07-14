# Ghidra Processor Module for ASMedia's 8051 Variant

ASMedia's 8051-based chips sometimes have expanded CODE / XDATA space, and the firmware that runs on these chips often has code constructs that are difficult for Ghidra to understand.
This processor module is an attempt at making it easier to disassemble and decompile that firmware.

> [!CAUTION]
> This module is a work-in-progress and has not gone through any rigorous testing.
> In particular, the behavior of the CODE bank switching needs to be verified against real hadware, and the binary loader is not yet able to handle USB-to-NVMe bridge firmware images.

Target features of this processor module include:

- Custom SLEIGH specification:
  - [x] Support expanded CODE and XDATA address spaces through handling of the `DPX` and `PSBANK` SFRs.
  - [ ] Custom P-Code operations to enable the analyzer to handle complex firmware-based operations
- Firmware image loader:
  - [ ] Support for raw code binaries and full images with headers:
    - [x] xHC firmware images (ASM1042, ASM1042A, ASM1142, ASM2142/ASM3142, ASM3242, etc.)
    - [x] Promontory firmware images (Promontory, Promontory-LP, Promontory-19, Promontory-21, etc.)
    - [ ] USB-to-NVMe bridge firmware images (ASM236x, ASM246x, etc.)
    - [ ] Autodetecting firmware type:
      - [x] Raw binary
      - [x] xHC flash image
      - [x] Promontory image
      - [ ] USB-to-NVMe flash image
  - [x] Properly map memory spaces based on chip type:
    - [x] Support for CODE bank switching (common bank + paged banks)
    - [x] Support for expanded XDATA space
    - [x] XRAM/MMIO sizes and offsets for different ASMedia chip families
  - [ ] Load data and BSS sections into XRAM from firmware binaries, handling both:
    - [ ] C runtime init-like format
    - [ ] Keil format
- Analysis features:
  - [ ] Cross-reference tracking for CODE/XDATA pointers
  - [ ] Identification of function signatures (switch-case, banked function calls)
  - [ ] Recognition of 32-bit constant loads and multi-byte arithmetic
  - [ ] P-Code emulation helper for complex code constructs
