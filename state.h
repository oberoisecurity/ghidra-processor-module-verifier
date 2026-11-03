//--------------------------------------------------------------------------------------
// File: state.h
//
// Test parameters and state
//
// Copyright (c) Oberoi Security Solutions. All rights reserved.
// Licensed under the Apache 2.0 License.
//--------------------------------------------------------------------------------------

#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <ostream>
#include <string>
#include <vector>

struct TEST_PARAMS
{
    // passed in params
    std::vector<std::string> json_filenames;
    std::string sla_filename;
    std::string register_map_filename;
    std::string program_counter;          // name of the program counter register
    unsigned int max_failures = 10;       // failures allowed before aborting. 0 == unlimited
    size_t start_test = 0;                // first test index (inclusive)
    size_t end_test = SIZE_MAX;           // last test index (exclusive)
    unsigned int num_threads = 1;         // worker threads
    bool quiet = false;                   // only print failures and the summary
    bool check_unlisted_writes = true;    // flag writes to memory not listed in the expected state

    // parsed from register mapping file
    std::map<std::string, std::string> register_map; // test register name -> Ghidra register name

    // context variable defaults (e.g. TMode=1), normally supplied by the .pspec
    std::map<std::string, uint32_t> context;
};

struct TEST_STATE
{
    std::map<std::string, uint64_t> registers;
    std::map<uint64_t, uint8_t> memory;
};

struct TEST_CASE
{
    std::string name;
    TEST_STATE initial;
    TEST_STATE final;
};

struct EMU_RESULT
{
    TEST_STATE state;                          // emulator values for everything in the expected state
    std::map<uint64_t, uint8_t> unlisted_writes; // modified bytes not present in the expected state
    std::string error;                         // non-empty if the emulator threw
};

void print_state(const TEST_STATE &state, std::ostream &out);

// Compare the expected state with the emulator result. Mismatches are written to out.
// Returns true if they match.
bool compare_state(const TEST_STATE &expected, const EMU_RESULT &actual, std::ostream &out);
