//--------------------------------------------------------------------------------------
// File: main.cpp
//
// Handles command line argument parsing and executing the test
//
// Copyright (c) Oberoi Security Solutions. All rights reserved.
// Licensed under the Apache 2.0 License.
//--------------------------------------------------------------------------------------

#include <iostream>
#include <fstream>
#include <boost/program_options.hpp>
#include <boost/timer/timer.hpp>
#include <map>
#include <exception>
#include <boost/unordered_map.hpp>
#include <boost/filesystem.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/thread_pool.hpp>
#include <boost/thread/thread.hpp>
#include <boost/bind.hpp>
#include "state.h"
#include "sla_util.h"
#include "backends/json.h"
#include "backends/sla_emulator.h"

using namespace std;

void default_test_params(TEST_PARAMS &test_params);
void display_test_params(TEST_PARAMS &test_params);
int parse_register_mapping(string register_mapping_filename, map<std::string, std::string>& register_mapping);
int parallelize_test(TEST_PARAMS &test_params);

int main(int argc, char *argv[])
{
    boost::program_options::options_description desc{"Ghidra Processor Module Verifier"};
    boost::program_options::variables_map args;
    TEST_PARAMS test_params;
    int result = 0;

    default_test_params(test_params);

    cout << "Ghidra Processor Module Verifier (Verifier)" << endl;

    //
    // command line arg parsing
    //

    try
    {
        desc.add_options()
            ("sla-file,s",boost::program_options::value<string>(&test_params.sla_filename), "Path to the compiled processor .sla. Required")
            ("json-test,j", boost::program_options::value<string>(&test_params.json_filename), "Path to json test file. Required")
            ("program-counter,p", boost::program_options::value<string>(&test_params.program_counter), "Name of the program counter register. Required")
            ("start-test", boost::program_options::value<unsigned int>(&test_params.start_test), "First test to start with. Optional. 0 if not specified")
            ("end-test", boost::program_options::value<unsigned int>(&test_params.end_test), "Last test to end with. Optional. MAX_INT if not specified")
            ("num-threads,t", boost::program_options::value<unsigned int>(&test_params.num_threads), "How many threads to use. Optional. 1 if not specified")
            ("max-failures", boost::program_options::value<unsigned int>(&test_params.max_failures), "Maximum numberof test failures allowed before aborting test. Optional. 10 if not specified")
            ("register-map", boost::program_options::value<string>(&test_params.register_map_filename), "Path to file containing mapping of test registers to Ghidra processor module registers. Optional.")
            ("help,h", "Help screen");

        store(parse_command_line(argc, argv, desc), args);
        notify(args);

        if(args.count("help") || argc == 1)
        {
            cout << desc << endl;
            return 0;
        }

        if(args.count("sla-file") == 0)
        {
            cout << "Sla filename is required!" << endl;
            return -1;
        }

        if(args.count("json-test") == 0)
        {
            cout << "JSON test filename is required!" << endl;
            return -1;
        }

        if(args.count("program-counter") == 0)
        {
            cout << "Program counter name is required!" << endl;
            return -1;
        }
    }
    catch (const boost::program_options::error &ex)
    {
        cout << "[-] Error parsing command line: " << ex.what() << endl;
        return -1;
    }

    result = sla_get_word_size(test_params.sla_filename, test_params.word_size);
    if(result != 0)
    {
        cout << "[-] Failed to get word size from " << test_params.sla_filename << "!" << endl;
        return result;
    }

    result = parse_register_mapping(test_params.register_map_filename, test_params.register_map);
    if(result != 0)
    {
        cout << "[-] Failed to parse register map file (" << test_params.register_map_filename << ")!" << endl;
        return -1;
    }

    if(test_params.num_threads == 0)
    {
        cout << "[-] Number of threads must be positive!" << endl;
        return -1;
    }

    display_test_params(test_params);

    result = parallelize_test(test_params);
    if(result != 0)
    {
        cout << "[-] Test failed: " << result << endl;
        return result;
    }

    return 0;
}

// default test params for optional params if not specified at the command line
void default_test_params(TEST_PARAMS &test_params)
{
    test_params.max_failures = 10;
    test_params.start_test = 0;
    test_params.end_test = 0xFFFFFFFF; // if not set will be reduced to num of submitted tests
    test_params.word_size = 0;
    test_params.num_threads = 1;
}

// default test params for optional params if not specified at the command line
void display_test_params(TEST_PARAMS &test_params)
{
    cout << "[*] Settings:" << endl;
    cout << "\t[*] Compiled SLA file: " << test_params.sla_filename << endl;
    cout << "\t[*] JSON Test file: " << test_params.json_filename << endl;
    cout << "\t[*] Program counter register: " << test_params.program_counter << endl;
    cout << "\t[*] Word size: " << test_params.word_size << endl;
    cout << "\t[*] Register Mapping Count: " << test_params.register_map.size() << endl;
    cout << "\t[*] Max allowed failures: " << test_params.max_failures << endl;
    cout << "\t[*] Start test: " << test_params.start_test << endl;
    cout << "\t[*] Register Mapping Count: " << test_params.register_map.size() << endl;
}

int parse_register_mapping(string register_map_filename, map<std::string, std::string>& register_map)
{
    string line;
    string test_reg;
    string ghidra_reg;
    unsigned int equal_pos = 0;
    unsigned int num_reg_mappings = 0;

    if(register_map_filename == "")
    {
        // nothing to do
        return 0;
    }

    boost::filesystem::ifstream file_handler(register_map_filename);

    while (getline(file_handler, line))
    {
        if(line.length() == 0)
        {
            // empty line
            continue;
        }

        if(line[0] == '#' || line[0] == '=')
        {
            // skip comments, invalid
            continue;
        }

        equal_pos = line.find("=");
        if(equal_pos == string::npos)
        {
            // didn't have =
            continue;
        }

        if(equal_pos == line.length() - 1)
        {
            // line ends with = sign
            continue;
        }

        test_reg = line.substr(0, equal_pos);
        ghidra_reg = line.substr(equal_pos + 1, line.length());

        register_map[test_reg] = ghidra_reg;
    }

    num_reg_mappings = register_map.size();
    if(num_reg_mappings == 0)
    {
        return -1;
    }

    return 0;
}
