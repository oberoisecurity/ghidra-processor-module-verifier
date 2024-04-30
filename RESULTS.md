# Ghidra Processor Module Verifier Results
This is a list of some of the issues found by Verifier. Feel free to add your own. 

## Ghidra Emulator Bugs
- [IS-5917](https://github.com/NationalSecurityAgency/ghidra/issues/5917)
  - LowlevelError("Bad intra-instruction branch")
- [IS-6505](https://github.com/NationalSecurityAgency/ghidra/issues/6404)
  - Incorrect handling of multi-word writes on little Endian architectures

## Ghidra 6502 Processor Module:
- [PR-5870](https://github.com/NationalSecurityAgency/ghidra/pull/5870)
  - Fix status flags
  - popSR()/pushSR() B and T flags
  - BRK, JSR edge case of stack on byte boundary
  - PLP B and T flags
  - Indirect X and Indirect Y modes
  - Decimal mode support for adc and sbc
  - Numerous non-6502 instructions being disassembled
- [IS-5870](https://github.com/NationalSecurityAgency/ghidra/issues/5871)
  - Incorrect behavior for self-modifing instructions
  - Incorrect behavior for instructions straddling end of address space
    
