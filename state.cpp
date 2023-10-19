//--------------------------------------------------------------------------------------
// File: state.cpp
//
//  Test parameters and state
//
// Copyright (c) Oberoi Security Solutions. All rights reserved.
// Licensed under the Apache 2.0 License.
//--------------------------------------------------------------------------------------

#include "state.h"
#include <iostream>

// print the state structure
int print_state(TEST_STATE &a)
{
    cout << "\tRegisters:" << endl;
    for (auto& [register_name, value] : a.registers)
    {
        cout << "\t\t" << register_name << ": " << value << endl;
    }

    cout << "\tRAM:" << endl;
    for (auto& [address, value] : a.memory)
    {
        cout << "\t\t" << address << ": " << (unsigned int)value << endl;
    }

    return 0;
}

// Compare states
// return 0 if a and b are equal
int compare_state(TEST_STATE &a, TEST_STATE &b)
{
    int result = 0;

    // TODO: check the opposite conditions as well.
    // It is not sufficient to check that all of a's registers are equal to b's
    // We need to check all of b's registers are equal to a's
    // Same for memory

    // validate registers
    for (auto& [register_name, value] : a.registers)
    {
        unsigned int reg_a = value;
        unsigned int reg_b = b.registers[register_name];

        if(reg_a != reg_b)
        {
            cout << "!! REGISTER ERROR: " << register_name << " " << reg_a << " " << reg_b << endl;
            result = -1;
        }
    }

    // validate memory
    for (auto& [address, value] : a.memory)
    {
        unsigned int mem_a = value;
        unsigned int mem_b = b.memory[address];

        if(mem_a != mem_b)
        {
            cout << "!! MEMORY ERROR: " << address << " " << mem_a << " " << mem_b << endl;
            result = -1;
        }
    }

    return result;
}
