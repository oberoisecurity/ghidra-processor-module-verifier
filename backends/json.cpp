//--------------------------------------------------------------------------------------
// File: json.h
//
// Parsing json unit tests (https://github.com/TomHarte/ProcessorTests)
//
// Copyright (c) Oberoi Security Solutions. All rights reserved.
// Licensed under the Apache 2.0 License.
//--------------------------------------------------------------------------------------

#include "json.h"
#include <iostream>
#include <fstream>

int read_json_registers(json &state, map<std::string, unsigned int> &registers, map<std::string, std::string>& register_map);
int read_json_memory(json &state, map<unsigned long long, unsigned char> &memory);

// reads the json list of tests in json_filename. On success initial_states and final_states
// are vectors of unit tests
// The json file format is defined here: https://github.com/TomHarte/ProcessorTests
int get_tests(TEST_PARAMS& test_params, vector<TEST_STATE> &initial_states, vector<TEST_STATE> &final_states)
{
    try
    {
        std::ifstream f(test_params.json_filename);
        json data = json::parse(f);

        // loop through all of the tests
        for (unsigned int i = 0; i < data.size(); i++)
        {
            TEST_STATE initial_state;
            TEST_STATE final_state;

            json initial_registers = data[i]["initial"];
            json initial_memory = data[i]["initial"]["ram"];

            json final_registers = data[i]["final"];
            json final_memory = data[i]["final"]["ram"];

            read_json_registers(initial_registers, initial_state.registers, test_params.register_map);
            read_json_registers(final_registers, final_state.registers, test_params.register_map);

            read_json_memory(initial_memory, initial_state.memory);
            read_json_memory(final_memory, final_state.memory);

            initial_states.push_back(initial_state);
            final_states.push_back(final_state);
        }

    }
    catch(...)
    {
        cout << "[-] Failed to parse json file!" << endl;
        return -1;
    }



    return 0;
}

int read_json_registers(json &state, map<std::string, unsigned int> &registers, map<std::string, std::string>& register_map)
{
    string reg_name;

    for (auto& [key, value] : state.items())
    {
        if(key == "ram")
        {
            continue;
        }

        // use the register map to map test registers to Ghidra registers
        if(register_map.find(key) != register_map.end())
        {
            reg_name = register_map[key];
        }
        else
        {
            reg_name = key;
        }

        // TODO: validate registers against .sla?

        registers[reg_name] = value;
    }

    return 0;
}

int read_json_memory(json &state, map<unsigned long long, unsigned char> &memory)
{
    for (unsigned int i = 0; i < state.size(); i++)
    {
        memory[state[i][0]] = state[i][1];
    }

    return 0;
}
