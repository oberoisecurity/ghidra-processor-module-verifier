//--------------------------------------------------------------------------------------
// File: json.cpp
//
// Parsing json unit tests (https://github.com/SingleStepTests/ProcessorTests)
//
// Copyright (c) Oberoi Security Solutions. All rights reserved.
// Licensed under the Apache 2.0 License.
//--------------------------------------------------------------------------------------

#include "json.h"
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <nlohmann/json.hpp>

using json = nlohmann::json;
using namespace std;

namespace
{

uint64_t to_u64(const json &value, const string &what)
{
    if (value.is_number_unsigned())
    {
        return value.get<uint64_t>();
    }
    if (value.is_number_integer() && value.get<int64_t>() >= 0)
    {
        return value.get<uint64_t>();
    }
    throw runtime_error(what + " is not a non-negative integer: " + value.dump());
}

// Registers are every integer field of the state object (other than "ram").
// Nested objects (e.g. {"regs": {...}} used by some test suites) are flattened.
void read_registers(const json &state, const map<string, string> &register_map,
                    map<string, uint64_t> &registers, set<string> &skipped_fields)
{
    for (const auto &[key, value] : state.items())
    {
        if (key == "ram")
        {
            continue;
        }

        if (value.is_object())
        {
            read_registers(value, register_map, registers, skipped_fields);
            continue;
        }

        if (!value.is_number_integer())
        {
            skipped_fields.insert(key);
            continue;
        }

        // use the register map to map test registers to Ghidra registers
        auto it = register_map.find(key);
        const string &reg_name = (it != register_map.end()) ? it->second : key;

        registers[reg_name] = to_u64(value, "register " + key);
    }
}

void read_memory(const json &ram, map<uint64_t, uint8_t> &memory)
{
    if (ram.is_null())
    {
        return;
    }
    if (!ram.is_array())
    {
        throw runtime_error("\"ram\" must be an array of [address, value] pairs");
    }

    for (const auto &entry : ram)
    {
        if (!entry.is_array() || entry.size() < 2)
        {
            throw runtime_error("bad ram entry: " + entry.dump());
        }

        uint64_t address = to_u64(entry[0], "ram address");
        uint64_t value = to_u64(entry[1], "ram value");
        if (value > 0xFF)
        {
            throw runtime_error("ram value does not fit in a byte: " + entry.dump());
        }
        memory[address] = (uint8_t)value;
    }
}

void read_state(const json &test, const char *which, const map<string, string> &register_map,
                TEST_STATE &state, set<string> &skipped_fields)
{
    if (!test.contains(which) || !test[which].is_object())
    {
        throw runtime_error(string("missing \"") + which + "\" object");
    }

    const json &obj = test[which];
    read_registers(obj, register_map, state.registers, skipped_fields);
    read_memory(obj.contains("ram") ? obj["ram"] : json(), state.memory);
}

}

// The json file format is defined here: https://github.com/SingleStepTests/ProcessorTests
int get_tests(const TEST_PARAMS &test_params, const string &json_filename,
              vector<TEST_CASE> &tests, set<string> &skipped_fields)
{
    ifstream f(json_filename);
    if (!f)
    {
        cout << "[-] Could not open " << json_filename << endl;
        return -1;
    }

    json data;
    try
    {
        data = json::parse(f);
    }
    catch (const json::exception &e)
    {
        cout << "[-] Failed to parse " << json_filename << ": " << e.what() << endl;
        return -1;
    }

    if (!data.is_array())
    {
        cout << "[-] " << json_filename << ": expected a top level array of tests" << endl;
        return -1;
    }

    tests.reserve(data.size());
    for (size_t i = 0; i < data.size(); i++)
    {
        const json &test = data[i];
        TEST_CASE test_case;

        try
        {
            if (!test.is_object())
            {
                throw runtime_error("test is not an object");
            }
            if (test.contains("name") && test["name"].is_string())
            {
                test_case.name = test["name"].get<string>();
            }

            read_state(test, "initial", test_params.register_map, test_case.initial, skipped_fields);
            read_state(test, "final", test_params.register_map, test_case.final, skipped_fields);
        }
        catch (const exception &e)
        {
            cout << "[-] " << json_filename << ": test " << i << ": " << e.what() << endl;
            return -1;
        }

        tests.push_back(std::move(test_case));
    }

    return 0;
}
