//--------------------------------------------------------------------------------------
// File: state.cpp
//
//  Test parameters and state
//
// Copyright (c) Oberoi Security Solutions. All rights reserved.
// Licensed under the Apache 2.0 License.
//--------------------------------------------------------------------------------------

#include "state.h"
#include <sstream>

namespace
{
// "203 (0xcb)"
std::string fmt(uint64_t value)
{
    std::ostringstream s;
    s << value << " (0x" << std::hex << value << ")";
    return s.str();
}
}

// print the state structure
void print_state(const TEST_STATE &state, std::ostream &out)
{
    out << "\tRegisters:" << std::endl;
    for (const auto &[register_name, value] : state.registers)
    {
        out << "\t\t" << register_name << ": " << fmt(value) << std::endl;
    }

    out << "\tRAM:" << std::endl;
    for (const auto &[address, value] : state.memory)
    {
        out << "\t\t" << fmt(address) << ": " << fmt(value) << std::endl;
    }
}

bool compare_state(const TEST_STATE &expected, const EMU_RESULT &actual, std::ostream &out)
{
    bool match = true;

    if (!actual.error.empty())
    {
        out << "!! EMULATOR ERROR: " << actual.error << std::endl;
        match = false;
    }

    for (const auto &[register_name, value] : expected.registers)
    {
        auto it = actual.state.registers.find(register_name);
        if (it == actual.state.registers.end())
        {
            out << "!! REGISTER ERROR: " << register_name << " missing from emulator state" << std::endl;
            match = false;
        }
        else if (it->second != value)
        {
            out << "!! REGISTER ERROR: " << register_name << " expected " << fmt(value)
                << ", emulator " << fmt(it->second) << std::endl;
            match = false;
        }
    }

    for (const auto &[address, value] : expected.memory)
    {
        auto it = actual.state.memory.find(address);
        uint64_t emu = (it == actual.state.memory.end()) ? 0 : it->second;
        if (it == actual.state.memory.end() || emu != value)
        {
            out << "!! MEMORY ERROR: " << fmt(address) << " expected " << fmt(value)
                << ", emulator " << fmt(emu) << std::endl;
            match = false;
        }
    }

    for (const auto &[address, value] : actual.unlisted_writes)
    {
        out << "!! UNEXPECTED MEMORY WRITE: " << fmt(address) << " = " << fmt(value)
            << " (address not in expected final state)" << std::endl;
        match = false;
    }

    return match;
}
