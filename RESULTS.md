# Ghidra Processor Module Verifier Results
This is a list of some of the issues found by Verifier. Feel free to add your own. 

## Ghidra Emulator Bugs
- [IS-5917](https://github.com/NationalSecurityAgency/ghidra/issues/5917)
  - LowlevelError("Bad intra-instruction branch")
- [IS-6404](https://github.com/NationalSecurityAgency/ghidra/issues/6404)
  - Incorrect handling of multi-word writes on little Endian architectures
  - `MemoryBank::setValue()` only handles writes that straddle two aligned words correctly when the bank's word size is 8 (`sizeof(uintb)`). Verifier now always uses 8, which avoids this.

## Ghidra 6502 Processor Module:
- [PR-5870](https://github.com/NationalSecurityAgency/ghidra/pull/5870)
  - Fix status flags
  - popSR()/pushSR() B and T flags
  - BRK, JSR edge case of stack on byte boundary
  - PLP B and T flags
  - Indirect X and Indirect Y modes
  - Decimal mode support for adc and sbc
  - Numerous non-6502 instructions being disassembled
- [IS-5871](https://github.com/NationalSecurityAgency/ghidra/issues/5871)
  - Incorrect behavior for self-modifying instructions
  - Incorrect behavior for instructions straddling end of address space
    - Note: earlier versions of Verifier didn't wrap instruction fetches at the end of the address space, which caused some of these failures (e.g. `91` with the opcode at 0xFFFF). That is fixed; re-check before relying on this item.

## Upstream 6502 module (Ghidra 12.2), still open
- `JSR` writes the return address to zero page (`SP-1`) rather than the stack page, and pushes the return address rather than return address - 1 (every `20.json` test fails)
- Status flags are modelled as separate registers, so `P` is not updated by flag-setting instructions (e.g. most `a9.json` LDA immediate tests fail on `P`)
    
