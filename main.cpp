//--------------------------------------------------------------------------------------
// File: main.cpp
//
// Handles command line argument parsing and executing the test
//
// Copyright (c) Oberoi Security Solutions. All rights reserved.
// Licensed under the Apache 2.0 License.
//--------------------------------------------------------------------------------------

#include <atomic>
#include <chrono>
#include <fstream>
#include <iostream>
#include <set>
#include <stdexcept>
#include <thread>
#include <boost/program_options.hpp>
#include "state.h"
#include "runner.h"
#include "backends/json.h"
#include "backends/sla_emulator.h"

using namespace std;
namespace po = boost::program_options;

// exit codes
const int EXIT_ALL_PASSED = 0;
const int EXIT_TEST_FAILURES = 1;
const int EXIT_USAGE_ERROR = 2;

namespace
{

string trim(const string &s)
{
    const char *ws = " \t\r\n";
    size_t start = s.find_first_not_of(ws);
    if (start == string::npos)
    {
        return "";
    }
    size_t end = s.find_last_not_of(ws);
    return s.substr(start, end - start + 1);
}

// Parse "name=value" into its parts. Returns false if malformed.
bool split_assignment(const string &line, string &name, string &value)
{
    size_t equal_pos = line.find('=');
    if (equal_pos == string::npos)
    {
        return false;
    }
    name = trim(line.substr(0, equal_pos));
    value = trim(line.substr(equal_pos + 1));
    return !name.empty() && !value.empty();
}

// Register map file: one "test_register=ghidra_register" per line. '#' starts a comment.
int parse_register_mapping(const string &register_map_filename, map<string, string> &register_map)
{
    ifstream file(register_map_filename);
    if (!file)
    {
        cout << "[-] Could not open register map file " << register_map_filename << endl;
        return -1;
    }

    string line;
    unsigned int line_number = 0;
    while (getline(file, line))
    {
        line_number++;
        line = trim(line);
        if (line.empty() || line[0] == '#')
        {
            continue;
        }

        string test_reg, ghidra_reg;
        if (!split_assignment(line, test_reg, ghidra_reg))
        {
            cout << "[-] " << register_map_filename << ":" << line_number
                 << ": expected test_register=ghidra_register, got \"" << line << "\"" << endl;
            return -1;
        }
        register_map[test_reg] = ghidra_reg;
    }

    if (register_map.empty())
    {
        cout << "[-] Register map file " << register_map_filename << " contains no mappings" << endl;
        return -1;
    }

    return 0;
}

int parse_context(const vector<string> &assignments, map<string, uint32_t> &context)
{
    for (const string &assignment : assignments)
    {
        string name, value;
        if (!split_assignment(assignment, name, value))
        {
            cout << "[-] Bad --context \"" << assignment << "\", expected name=value" << endl;
            return -1;
        }
        try
        {
            size_t used = 0;
            unsigned long v = stoul(value, &used, 0);
            if (used != value.size() || v > 0xFFFFFFFFUL)
            {
                throw invalid_argument(value);
            }
            context[name] = (uint32_t)v;
        }
        catch (const exception &)
        {
            cout << "[-] Bad --context value \"" << value << "\" for " << name << endl;
            return -1;
        }
    }
    return 0;
}

void display_test_params(const TEST_PARAMS &test_params, const SLA_INFO &info)
{
    cout << "[*] Settings:" << endl;
    cout << "\t[*] Compiled SLA file: " << test_params.sla_filename << endl;
    cout << "\t[*] Default space: " << info.ram_space << " (" << info.addr_size << " byte addresses, "
         << (info.big_endian ? "big" : "little") << " endian)" << endl;
    cout << "\t[*] JSON test files: " << test_params.json_filenames.size() << endl;
    cout << "\t[*] Program counter register: " << test_params.program_counter << endl;
    cout << "\t[*] Register mapping count: " << test_params.register_map.size() << endl;
    for (const auto &[name, value] : test_params.context)
    {
        cout << "\t[*] Context: " << name << "=" << value << endl;
    }
    cout << "\t[*] Max allowed failures: ";
    if (test_params.max_failures == 0)
    {
        cout << "unlimited" << endl;
    }
    else
    {
        cout << test_params.max_failures << endl;
    }
    cout << "\t[*] Test range: " << test_params.start_test << "-";
    if (test_params.end_test == SIZE_MAX)
    {
        cout << "end" << endl;
    }
    else
    {
        cout << test_params.end_test << endl;
    }
    cout << "\t[*] Threads: " << test_params.num_threads << endl;
    cout << "\t[*] Check unlisted memory writes: " << (test_params.check_unlisted_writes ? "yes" : "no") << endl;
}

// Every register referenced by the tests must exist in the processor module
bool validate_registers(const vector<TEST_CASE> &tests, const SlaEmulator &emulator, const string &json_filename)
{
    set<string> used;
    for (const TEST_CASE &test : tests)
    {
        for (const auto &[name, value] : test.initial.registers)
        {
            used.insert(name);
        }
        for (const auto &[name, value] : test.final.registers)
        {
            used.insert(name);
        }
    }

    set<string> missing;
    for (const string &name : used)
    {
        if (!emulator.has_register(name))
        {
            missing.insert(name);
        }
    }

    if (missing.empty())
    {
        return true;
    }

    cout << "[-] " << json_filename << " uses registers that are not in the processor module:";
    for (const string &name : missing)
    {
        cout << " " << name;
    }
    cout << endl << "[-] Use --register-map to map them to Ghidra register names. Available registers:" << endl << "\t";
    size_t column = 0;
    for (const string &name : emulator.register_names())
    {
        if (column > 0 && column + name.size() > 72)
        {
            cout << endl << "\t";
            column = 0;
        }
        cout << name << " ";
        column += name.size() + 1;
    }
    cout << endl;
    return false;
}

}

int main(int argc, char *argv[])
{
    po::options_description desc{"Ghidra Processor Module Verifier"};
    po::positional_options_description positional;
    po::variables_map args;
    TEST_PARAMS test_params;
    vector<string> context_assignments;
    long long end_test = -1;

    cout << "Ghidra Processor Module Verifier (Verifier)" << endl;

    //
    // command line arg parsing
    //

    try
    {
        desc.add_options()
            ("sla-file,s", po::value<string>(&test_params.sla_filename), "Path to the compiled processor .sla. Required")
            ("json-test,j", po::value<vector<string>>(&test_params.json_filenames)->multitoken(), "Path(s) to JSON test file(s). Can also be given as positional arguments. Required")
            ("program-counter,p", po::value<string>(&test_params.program_counter), "Name of the program counter register. Required")
            ("start-test", po::value<size_t>(&test_params.start_test), "Index of the first test to run in each file. Optional. 0 if not specified")
            ("end-test", po::value<long long>(&end_test), "Index one past the last test to run in each file (exclusive). Optional. All tests if not specified")
            ("num-threads,t", po::value<unsigned int>(&test_params.num_threads), "Number of worker threads. 0 uses all cores. Optional. 1 if not specified")
            ("max-failures", po::value<unsigned int>(&test_params.max_failures), "Maximum number of test failures allowed before aborting. 0 for unlimited. Optional. 10 if not specified")
            ("register-map", po::value<string>(&test_params.register_map_filename), "Path to file containing mapping of test registers to Ghidra processor module registers. Optional.")
            ("context,c", po::value<vector<string>>(&context_assignments), "Set a context variable default, e.g. --context TMode=1. May be repeated. Optional.")
            ("ignore-unlisted-writes", "Don't fail tests that modify memory not listed in the expected final state. Optional.")
            ("quiet,q", "Only print failures and the summary. Optional.")
            ("help,h", "Help screen");
        positional.add("json-test", -1);

        po::store(po::command_line_parser(argc, argv).options(desc).positional(positional).run(), args);
        po::notify(args);
    }
    catch (const po::error &ex)
    {
        cout << "[-] Error parsing command line: " << ex.what() << endl;
        return EXIT_USAGE_ERROR;
    }

    if (args.count("help") || argc == 1)
    {
        cout << desc << endl;
        return EXIT_ALL_PASSED;
    }

    if (test_params.sla_filename.empty())
    {
        cout << "[-] Sla filename is required!" << endl;
        return EXIT_USAGE_ERROR;
    }

    if (test_params.json_filenames.empty())
    {
        cout << "[-] JSON test filename is required!" << endl;
        return EXIT_USAGE_ERROR;
    }

    if (test_params.program_counter.empty())
    {
        cout << "[-] Program counter name is required!" << endl;
        return EXIT_USAGE_ERROR;
    }

    if (end_test >= 0)
    {
        if ((size_t)end_test <= test_params.start_test)
        {
            cout << "[-] --end-test must be greater than --start-test" << endl;
            return EXIT_USAGE_ERROR;
        }
        test_params.end_test = (size_t)end_test;
    }

    if (test_params.num_threads == 0)
    {
        test_params.num_threads = max(1u, thread::hardware_concurrency());
    }

    test_params.quiet = args.count("quiet") != 0;
    test_params.check_unlisted_writes = args.count("ignore-unlisted-writes") == 0;

    if (!test_params.register_map_filename.empty() &&
        parse_register_mapping(test_params.register_map_filename, test_params.register_map) != 0)
    {
        return EXIT_USAGE_ERROR;
    }

    if (parse_context(context_assignments, test_params.context) != 0)
    {
        return EXIT_USAGE_ERROR;
    }

    //
    // load the processor module once per worker thread
    //

    SlaEmulator::global_init();

    vector<unique_ptr<SlaEmulator>> workers;
    try
    {
        for (unsigned int i = 0; i < test_params.num_threads; i++)
        {
            workers.emplace_back(new SlaEmulator(test_params));
        }
    }
    catch (const exception &e)
    {
        cout << "[-] Failed to load " << test_params.sla_filename << ": " << e.what() << endl;
        cout << "[-] Check the .sla path, the --program-counter register name and any --context variables." << endl;
        cout << "[-] The .sla must be compiled by the same Ghidra version as libsla." << endl;
        return EXIT_USAGE_ERROR;
    }

    display_test_params(test_params, workers[0]->info());

    //
    // run the tests
    //

    auto start_time = chrono::steady_clock::now();
    atomic<unsigned int> total_failures(0);
    RUN_TOTALS totals;
    bool aborted = false;
    bool load_errors = false;

    for (const string &json_filename : test_params.json_filenames)
    {
        vector<TEST_CASE> tests;
        set<string> skipped_fields;

        if (get_tests(test_params, json_filename, tests, skipped_fields) != 0)
        {
            load_errors = true;
            continue;
        }

        cout << "[*] " << json_filename << ": Loaded " << tests.size() << " test cases" << endl;
        if (!skipped_fields.empty())
        {
            cout << "[*] Ignoring non-integer test fields:";
            for (const string &field : skipped_fields)
            {
                cout << " " << field;
            }
            cout << endl;
        }

        if (test_params.start_test >= tests.size())
        {
            cout << "[*] " << json_filename << ": --start-test is past the last test, skipping" << endl;
            continue;
        }

        if (!validate_registers(tests, *workers[0], json_filename))
        {
            return EXIT_USAGE_ERROR;
        }

        if (!run_tests(test_params, tests, workers, total_failures, totals))
        {
            cout << "[-] Max failures encountered (" << test_params.max_failures << "), aborting" << endl;
            aborted = true;
            break;
        }
    }

    chrono::duration<double> elapsed = chrono::steady_clock::now() - start_time;
    cout << "[*] Summary: " << totals.run << " run, " << totals.passed << " passed, "
         << totals.failed << " failed (" << elapsed.count() << "s)" << endl;

    if (totals.failed != 0 || aborted || load_errors)
    {
        return EXIT_TEST_FAILURES;
    }

    return EXIT_ALL_PASSED;
}
