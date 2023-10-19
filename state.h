//--------------------------------------------------------------------------------------
// File: state.h
//
// Test parameters and statea
//
// Copyright (c) Oberoi Security Solutions. All rights reserved.
// Licensed under the Apache 2.0 License.
//--------------------------------------------------------------------------------------

#pragma once

#include <string>
#include <map>
using namespace std;

typedef struct _TEST_PARAMS
{
    // passed in params
    string json_filename;
    string sla_filename;
    string register_map_filename;
    string program_counter; // program program_counter
    unsigned int max_failures; // maximum number of failures allowed before aborting test
    unsigned int start_test; // what test number to start on

    // obtained via sla file
    unsigned int word_size;

    // parsed from register mapping file
    map<std::string, std::string> register_map; // mapping of test registers to Ghidra processor module registers

} TEST_PARAMS, *PTEST_PARAMS;

typedef struct _TEST_STATE
{
    map<std::string, unsigned int> registers;
    map<unsigned long long, unsigned char> memory;
} TEST_STATE, *PTEST_STATE;

int print_state(TEST_STATE &a);
int compare_state(TEST_STATE &a, TEST_STATE &b);
