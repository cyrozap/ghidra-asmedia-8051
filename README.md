# Ghidra Processor Module for ASMedia's 8051 Variant

ASMedia's 8051-based chips sometimes have expanded CODE / XDATA space, and the firmware that runs on these chips often has code constructs that are difficult for Ghidra to understand.
This processor module is an attempt at making it easier to disassemble and decompile that firmware.

> [!CAUTION]
> This module is a work-in-progress and has not gone through any rigorous testing.
> In particular, the behavior of the CODE bank switching needs to be verified against real hadware, and the binary loader is not yet able to handle different firmware image types (raw binary vs. flash image) or allow the user to specify the chip type (bank-switched vs. non-bank-switched).

Target features of this processor module include:

- Seamlessly handle the expanded CODE and XDATA address spaces through handling of the `DPX` and `PSBANK` SFRs.
- Firmware image loader for both raw code binaries and full images with headers, that also is able to properly map the banked firmware code into CODE space.
- Analysis plugin and P-Code emulation helper, to be able to recognize certain constructs in the firmware (e.g., switch statements / jump tables, 32-bit constant loads) and rewrite the P-Code so the disassembler and decompiler can understand it.

Known issues:

- LJMP / LCALL appear to ignore the value of PSBANK, even when set manually, and seem to want to jump back to the common bank.
- The default symbols / labels are no longer being applied to the loaded binary.
