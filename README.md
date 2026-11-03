# Ghidra Processor Module Verifier (Verifier)

Ghidra Processor Module Verifier (Verifier) automates the verification of [Ghidra](https://github.com/NationalSecurityAgency/ghidra) processor modules. Verifier takes as input a compiled Ghidra processor module (.sla) and one or more JSON files of processor unit tests. It then leverages libsla's p-code emulator to execute each instruction one by one, comparing the emulated result with the expected processor unit test result. A processor unit test is considered successful if all registers and memory values match the unit test, and the instruction didn't modify any memory the unit test doesn't list. See [RESULTS.md](RESULTS.md) for issues already found.

Verifier works with both the binary .sla format used by Ghidra 11.1 and later and the older XML .sla format. The .sla, libsla and the headers Verifier is compiled against must all come from the same Ghidra release; see [Build](#build). It has mainly been tested on the 6502 processor so far.

## Usage
```
./verifier
Ghidra Processor Module Verifier:
  -s [ --sla-file ] arg        Path to the compiled processor .sla. Required
  -j [ --json-test ] arg       Path(s) to JSON test file(s). Can also be given
                               as positional arguments. Required
  -p [ --program-counter ] arg Name of the program counter register. Required
  --start-test arg             Index of the first test to run in each file.
                               Optional. 0 if not specified
  --end-test arg               Index one past the last test to run in each file
                               (exclusive). Optional. All tests if not
                               specified
  -t [ --num-threads ] arg     Number of worker threads. 0 uses all cores.
                               Optional. 1 if not specified
  --max-failures arg           Maximum number of test failures allowed before
                               aborting. 0 for unlimited. Optional. 10 if not
                               specified
  --register-map arg           Path to file containing mapping of test
                               registers to Ghidra processor module registers.
                               Optional.
  -c [ --context ] arg         Set a context variable default, e.g. --context
                               TMode=1. May be repeated. Optional.
  --ignore-unlisted-writes     Don't fail tests that modify memory not listed
                               in the expected final state. Optional.
  -q [ --quiet ]               Only print failures and the summary. Optional.
  -h [ --help ]                Help screen
```

Exit status is `0` if every test passed, `1` if any test failed (or a test file couldn't be loaded), and `2` for usage or configuration errors (bad .sla, unknown program counter or register, bad register map, etc.). This makes Verifier usable directly in CI.

Running a whole directory of tests on all cores, printing only failures:

```
./verifier -s 6502.sla -p PC --register-map reg_map.txt -t 0 -q --max-failures 0 ~/65x02/6502/v1/*.json
```

Success example:

```
./verifier --sla-file ~/ghidra/Ghidra/Processors/6502/data/languages/6502.sla --program-counter PC --register-map reg_map.txt -q ~/65x02/6502/v1/ea.json
Ghidra Processor Module Verifier (Verifier)
[*] Settings:
	[*] Compiled SLA file: ~/ghidra/Ghidra/Processors/6502/data/languages/6502.sla
	[*] Default space: RAM (2 byte addresses, little endian)
	[*] JSON test files: 1
	[*] Program counter register: PC
	[*] Register mapping count: 6
	[*] Max allowed failures: 10
	[*] Test range: 0-end
	[*] Threads: 1
	[*] Check unlisted memory writes: yes
[*] ~/65x02/6502/v1/ea.json: Loaded 10000 test cases
[*] Summary: 10000 run, 10000 passed, 0 failed (0.42s)
```

Without `-q` every passing test is also printed (`[+] 0) [ea 99 1d] SUCCESS`).

Failure (on first test) example. The upstream 6502 module's `JSR` writes the return address to zero page instead of the stack page:

```
./verifier --sla-file ~/ghidra/Ghidra/Processors/6502/data/languages/6502.sla --program-counter PC --register-map reg_map.txt --max-failures 1 ~/65x02/6502/v1/20.json
...
[*] ~/65x02/6502/v1/20.json: Loaded 10000 test cases
!! MEMORY ERROR: 317 (0x13d) expected 139 (0x8b), emulator 0 (0x0)
!! MEMORY ERROR: 318 (0x13e) expected 82 (0x52), emulator 155 (0x9b)
!! UNEXPECTED MEMORY WRITE: 61 (0x3d) = 140 (0x8c) (address not in expected final state)
!! UNEXPECTED MEMORY WRITE: 62 (0x3e) = 82 (0x52) (address not in expected final state)
[-] 0) [20 c2 8f] FAIL
Initial State:
	Registers:
		A: 194 (0xc2)
		P: 110 (0x6e)
		PC: 21129 (0x5289)
		S: 62 (0x3e)
		X: 45 (0x2d)
		Y: 62 (0x3e)
	RAM:
		318 (0x13e): 155 (0x9b)
		21129 (0x5289): 32 (0x20)
		21130 (0x528a): 194 (0xc2)
		21131 (0x528b): 143 (0x8f)
		36802 (0x8fc2): 200 (0xc8)

Final (Expected) State:
	Registers:
		A: 194 (0xc2)
		P: 110 (0x6e)
		PC: 36802 (0x8fc2)
		S: 60 (0x3c)
		X: 45 (0x2d)
		Y: 62 (0x3e)
	RAM:
		317 (0x13d): 139 (0x8b)
		318 (0x13e): 82 (0x52)
		21129 (0x5289): 32 (0x20)
		21130 (0x528a): 194 (0xc2)
		21131 (0x528b): 143 (0x8f)
		36802 (0x8fc2): 200 (0xc8)

Emulator:
	Registers:
		A: 194 (0xc2)
		P: 110 (0x6e)
		PC: 36802 (0x8fc2)
		S: 60 (0x3c)
		X: 45 (0x2d)
		Y: 62 (0x3e)
	RAM:
		317 (0x13d): 0 (0x0)
		318 (0x13e): 155 (0x9b)
		21129 (0x5289): 32 (0x20)
		21130 (0x528a): 194 (0xc2)
		21131 (0x528b): 143 (0x8f)
		36802 (0x8fc2): 200 (0xc8)

[-] Max failures encountered (1), aborting
[*] Summary: 1 run, 0 passed, 1 failed (0.28s)
```

The kinds of mismatch reported are:
- `REGISTER ERROR` / `MEMORY ERROR`: a register or memory byte listed in the expected final state has the wrong value.
- `UNEXPECTED MEMORY WRITE`: the instruction changed a byte that isn't listed in the expected final state. Disable with `--ignore-unlisted-writes` if your tests don't list every byte an instruction touches.
- `EMULATOR ERROR`: libsla threw while decoding or executing the instruction (e.g. `Unable to resolve constructor`, `Userop not hooked`). The emulator eagerly decodes the *next* instruction after each one; failing to decode that is not counted as an error, since unit tests usually have arbitrary bytes there.

### JSON Unit Test
Verifier uses the processor unit tests from https://github.com/SingleStepTests/ProcessorTests (formerly TomHarte/ProcessorTests; the 6502/65C02 tests now live in https://github.com/SingleStepTests/65x02). You can use those directly or write your own using the same JSON format. Each JSON file contains an array of independent processor tests. Verifier resets state after each instruction. The unit tests contain initial register state, initial ram state, final register state, final ram state. Memory not listed in the initial state is zero.

Every integer field of `initial`/`final` other than `ram` is treated as a register. Nested objects (e.g. `"regs": {...}`) are flattened. Other fields (`cycles`, and per-state arrays such as `queue` or `prefetch`) are ignored.

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

### Compiling a Ghidra Processor Module (.sla)
Verifier requires a compiled Ghidra processor module as an input. Compile it with the `sleigh` script from the same Ghidra release you built libsla from (see [Build](#build)):

1) cd to `<GHIDRA_RELEASE>/support`
2) `./sleigh -a ../Ghidra/Processors/<processor family>/`. Review compilation messages.
3) If all goes well you will have a .sla file in `../Ghidra/Processors/<processor family>/data/languages/`

Ex.
```
> ~/ghidra_12.2_PUBLIC/support$ ./sleigh -a ../Ghidra/Processors/6502/
...
Compiling ../Ghidra/Processors/6502/data/languages/6502.slaspec:
WARN  1 NOP constructors found (SleighCompile)
WARN  Use -n switch to list each individually (SleighCompile)
WARN  6502.slaspec:119: Unreferenced table 'ADDR8' (SleighCompile)
...
2 languages successfully compiled
```

**Don't mix Ghidra versions.** The .sla format can change between releases, so a .sla compiled by one Ghidra version may be rejected or misread by another version's libsla.

### Register Map
Sometimes the names/casing of Ghidra's processor module's registers don't match the names/casing in the unit tests. In that case you can optionally use the `--register-map` command line argument. The register map is a text file that maps the unit tests register names to their Ghidra equivalents. As an example, for the 6502 processor module:

```
# This is a mapping of your test registers to Ghidra's
# Left should be what the register is named in your test
# Right should be what Ghidra's processor module names it
# example: pc=PC
pc=PC
s=S
a=A
x=X
y=Y
p=P
```
Ghidra's processor module used capitalized register names whereas the unit test used lowercase. The register map file simplifies mapping the unit test register names to match Ghidra's. Lines beginning with a "#" are comments; whitespace around names is ignored. If a test uses a register that doesn't exist in the processor module, Verifier stops before running anything and lists the registers the module has.

### Context Variables
Some processor modules need context variables set before instructions decode correctly (e.g. ARM `TMode`, x86-64 `longMode`/`addrsize`/`opsize`). Ghidra normally takes these from the processor's .pspec. Set them with `--context`, e.g. `--context TMode=1`. Values accept decimal or `0x` hex.

## Issues
- the program counter register must be specified at the command line. There isn't anything in the .sla file to say which register is the program counter. Issue filed with [Ghidra](https://github.com/NationalSecurityAgency/ghidra/issues/5888).
- test memory is loaded into the processor's default code space; Harvard architectures with a separate data space aren't specifically handled.
- memory reads aren't checked (e.g. a read from the wrong address that happens to return the right value).
- refactor backends to be more generic

## Future Work
JSON unit tests are an easy place to start. From here:

- Lift p-code to SAT\SMT
- Allow for other types of processor modules (Binja? Ida?)
- Take a processor timeless trace as input instead of a unit test

## Build
Verifier is built against the decompiler sources that ship inside a Ghidra **release** zip (`Ghidra/Features/Decompiler/src/decompile/cpp`). Use the same release for libsla.a, the headers, and compiling your .sla files.

1) Download and unzip a Ghidra release from https://github.com/NationalSecurityAgency/ghidra/releases (e.g. `ghidra_12.2_PUBLIC`). This directory is your `GHIDRA_TRUNK`.
2) Build libsla from that release's sources:
   ```
   cd ~/ghidra_12.2_PUBLIC/Ghidra/Features/Decompiler/src/decompile/cpp
   make libsla.a
   ```
3) Build Verifier against the same directory:
   ```
   make GHIDRA_TRUNK=~/ghidra_12.2_PUBLIC
   ```
4) Compile your processor module with that release's `support/sleigh` (see [Compiling a Ghidra Processor Module](#compiling-a-ghidra-processor-module-sla)).

For dependencies in non-standard locations: `make GHIDRA_TRUNK=... EXTRA_CXXFLAGS="-I/path/include" EXTRA_LDFLAGS="-L/path/lib"`

### Don't mix libsla versions
libsla.a, the headers in `GHIDRA_TRUNK`, and the .sla must all come from the same Ghidra release. Don't build libsla.a from a git master checkout (or another release) and compile Verifier against a release's headers, or the other way round. The two disagree on the size and layout of classes such as `Sleigh`, so the program compiles and links but corrupts memory at runtime. It typically crashes on exit with `free(): invalid pointer`, and any results it prints can't be trusted.

If you've ever built libsla in a directory from a different version (for example by copying files between Ghidra trees), delete the stale objects so make rebuilds them, then rebuild Verifier:
```
cd <GHIDRA_TRUNK>/Ghidra/Features/Decompiler/src/decompile/cpp
rm -f libsla.a sla_opt/*.o
make libsla.a
cd <verifier>
make clean && make GHIDRA_TRUNK=<GHIDRA_TRUNK>
```

[ci/test.sh](ci/test.sh) does the whole thing end to end (libsla, 6502 .sla, Verifier, a few test suites) and is what CI runs. It builds from the matching Ghidra release tag (`Ghidra_<version>_build`) in git, which holds the same sources as that release's zip.

### Build Dependencies
- a C++17 compiler
- libboost-program-options-dev
- nlohmann-json3-dev
- zlib1g-dev
- libsla (built as above)

## Results
See [RESULTS.md](RESULTS.md).

## License
Licensed under the Apache 2.0 license. See [LICENSE](LICENSE).

## Credits
* libsla - [Ghidra's](https://github.com/NationalSecurityAgency/ghidra) library for SLEIGH
* [SingleStepTests/ProcessorTests](https://github.com/SingleStepTests/ProcessorTests) - processor tests, JSON format
