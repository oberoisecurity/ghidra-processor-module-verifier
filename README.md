# Ghidra Processor Module Verifier (Verifier)

Ghidra Processor Module Verifier (Verifier) automates the verification of [Ghidra](https://github.com/NationalSecurityAgency/ghidra) processor modules. Verifier takes as input a compiled Ghidra processor module (.sla) and a JSON file of processor unit tests. It then leverages libsla's p-code emulator to execute each instruction one by one, comparing the emulated result with the expected processor unit test result. A processor unit test is considered successfully if all registers and memory values match the unit test.

This is an early proof-of-concept and I have only tested on the 6502 processor so far. I plan on refactoring as well as improving error handling and output.

## Usage
`verifier --sla-file <path_to_compiled_processor_sla_file> --json-test <path_to_json_unit_test_file>`

Ex.

`./verifier --sla-file ~/ghidra_10.4_PUBLIC/Ghidra/Processors/6502/data/languages/6502.sla --json-test ~/ProcessorTests/6502/v1/00.json`

## JSON Unit Test
Verifier uses the processor unit tests from https://github.com/TomHarte/ProcessorTests. You can use those directly or write your own using the same JSON format. Each JSON file contains an array of independent processor tests. Verifier resets state after each instruction. The unit tests contain initial register state, initial ram state, final register state, final ram state. GPMV does not use the cycles field.

Sample test:
```
    {
    	"name": "3d e 1",
    	"initial": {
    		"pc": 9900,
    		"s": 2191,
    		"p": 171,
    		"a": 25345,
    		"x": 100,
    		"y": 124,
    		"dbr": 26,
    		"d": 50304,
    		"pbr": 111,
    		"e": 1,
    		"ram": [
    			[1751932, 14],
    			[7284398, 187],
    			[7284397, 24],
    			[7284396, 61]
    		]
    	},
    	"final": {
    		"pc": 9903,
    		"s": 2191,
    		"p": 43,
    		"a": 25344,
    		"x": 100,
    		"y": 124,
    		"dbr": 26,
    		"d": 50304,
    		"pbr": 111,
    		"e": 1,
    		"ram": [
    			[1751932, 14],
    			[7284398, 187],
    			[7284397, 24],
    			[7284396, 61]
    		]
    	},
    	"cycles": [
    		[7284396, 61, "dp-remx-"],
    		[7284397, 24, "-p-remx-"],
    		[7284398, 187, "-p-remx-"],
    		[1751932, 14, "d--remx-"]
    	]
    }
```

## Compiling a Ghidra Processor Module (.sla)
Verifier requries a compiled Ghidra processor module as an input. To compile:

1) cd to `<GHIDRA_RELEASE>/support`. This is a release build of Ghidra, not a source checkout.
2) `./sleigh -a ../Ghidra/Processors/<processor family>/`. Review compilation messages.
3) If all goes well you will have a .sla file in `../Ghidra/Processors/<processor family>/data/languages/`

Ex.
```
> /ghidra_10.4_PUBLIC/support$ ./sleigh -a ../Ghidra/Processors/6502/
> openjdk version "17.0.8.1" 2023-08-24
> OpenJDK Runtime Environment (build 17.0.8.1+1-Ubuntu-0ubuntu122.04)
> OpenJDK 64-Bit Server VM (build 17.0.8.1+1-Ubuntu-0ubuntu122.04, mixed mode)
> INFO  Using log config file: jar:file: ~/ghidra_10.4_PUBLIC/Ghidra/Framework/Generic/lib/Generic.jar!/generic.log4j.xml (LoggingInitialization)
> INFO  Using log file: ~/.ghidra/.ghidra_10.4_PUBLIC/application.log (LoggingInitialization)
> Compiling ../Ghidra/Processors/6502/data/languages/6502.slaspec:
> WARN  1 NOP constructors found (SleighCompile)
> WARN  Use -n switch to list each individually (SleighCompile)
> WARN  6502.slaspec:129: Unreferenced table: 'ADDR8' (SleighCompile)

> Compiling ../Ghidra/Processors/6502/data/languages/65c02.slaspec:
> WARN  1 NOP constructors found (SleighCompile)
> WARN  Use -n switch to list each individually (SleighCompile)
> WARN  6502.slaspec:129: Unreferenced table: 'ADDR8' (SleighCompile)

> 2 languages successfully compiled
```

## Issues
- **memory diffing is not correct**. Currently Verifier just checks the expected final result of memory against the emulator's memory. This will catch most bugs, but will not catch issues where the emulator overwrote memory that is not being checked in the unit test. The issue I have is that libsla does not appear to expose an interface to log all memory reads/writes. One option would be to simply read all of the emulator's memory at the end of every test but that will not be possible on larger address spaces.
- the program counter register must be specified at the command line. There isn't anyting in in the .sla file to say which register is the program counter.

## Future Work
JSON unit tests are an easy place to start. From here:

- Lift p-code to SAT\SMT
- Allow for other types of processor modules (Binja? Ida?)
- Take a processor timeless trace as input instead of a unit test

## Build
- `make verifier GHIDRA_TRUNK=<path_to_Ghidra_source_code>` (requires Ghidra's decompiler headers and libsla.a. GHIDRA_TRUNK points to a source clone of Ghidra from trunk, not a release build of Ghidra)

### Build Dependencies
- libboost-dev
- libboost-filesystem-dev
- libboost-program-options-dev
- libboost-regex-dev
- libboost-system-dev
- nlohmann-json3-dev
- libsla

#### Building libsla
libsla is required for compiling Verifier. To build libsla:
1) Checkout Ghidra from trunk. A release build of Ghidra is not sufficient. `git clone https://github.com/NationalSecurityAgency/ghidra` This path will be your GHIDRA_TRUNK directory.
2) CD to the decompiler source directory: `cd ~/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp`
3) Compile: `make libsla.a`

## Results
See [RESULTS.md](RESULTS.md).

## License
Licensed under the Apache 2.0 license. See LICENSE.

## Credits
* libsla - [Ghidra's](https://github.com/NationalSecurityAgency/ghidra) library for SLEIGH
* [TomHarte/ProcessorTests](https://github.com/TomHarte/ProcessorTests/issues) - processor tests, JSON format
