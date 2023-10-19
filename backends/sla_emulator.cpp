//--------------------------------------------------------------------------------------
// File: sla_emulator.cpp
//
// libsla emulator
//
// Copyright (c) Oberoi Security Solutions. All rights reserved.
// Licensed under the Apache 2.0 License.
//--------------------------------------------------------------------------------------
#include "sla_emulator.h"
#include <iostream>

using namespace std;

// This is a tiny LoadImage class which feeds the executable bytes to the translator
class MyLoadImage : public LoadImage {
    map<unsigned long long, unsigned char>* address_space;

public:
    MyLoadImage(map<unsigned long long, unsigned char>* loader_address_space) : LoadImage("nofile") { address_space = loader_address_space; }
    virtual void loadFill(uint1 *ptr,int4 size,const Address &addr);
    virtual string getArchType(void) const { return "myload"; }
    virtual void adjustVma(long adjust) { }
};

// This is the only important method for the LoadImage. It returns bytes from the static array
// depending on the address range requested
void MyLoadImage::loadFill(uint1 *ptr, int4 size, const Address &addr)
{
    uintb start = addr.getOffset();

    for(int4 i = 0; i < size; i++)
    {
        uint1 value = 0;

        uintb cur_offset = start + i;

        // TODO: cur_offset really should be modulus the size of the address space

        // default to zero for addresses not in our map
        if(address_space->find(cur_offset) != address_space->end())
        {
            value = (*address_space)[cur_offset];
        }

        ptr[i] = value;
    }
}

int sla_emulate(TEST_PARAMS &test_params, TEST_STATE &initial_state, TEST_STATE &final_state)
{
    map<unsigned long long, unsigned char> address_space; // represents the emulators address space
    AttributeId::initialize();
    ElementId::initialize();
    int result = 0;

    // Set up the context object
    ContextInternal context;

    // set initial memory
    for (const auto & [address, value] : initial_state.memory)
    {
        address_space[address] = value;
    }

    MyLoadImage loader(&address_space);

    Sleigh trans(&loader, &context);

    // Read sleigh file into DOM
    DocumentStorage docstorage;
    Element *sleighroot = docstorage.openDocument(test_params.sla_filename)->getRoot();
    docstorage.registerTag(sleighroot);
    trans.initialize(docstorage); // Initialize the translator

    result = sla_emulate_internal(test_params, trans, loader, initial_state, final_state);

    return result;
}

int sla_emulate_internal(TEST_PARAMS &test_params, Translate &trans,LoadImage &loader, TEST_STATE &initial_state, TEST_STATE &final_state)
{
    // Set up memory state object
    // TODO: get page size dynamically
    MemoryImage loadmemory(trans.getDefaultCodeSpace(), test_params.word_size, 4096, &loader);
    MemoryPageOverlay ramstate(trans.getDefaultCodeSpace(), test_params.word_size, 4096, &loadmemory);
    MemoryHashOverlay registerstate(trans.getSpaceByName("register"), test_params.word_size, 4096, 4096, (MemoryBank *)0);
    MemoryHashOverlay tmpstate(trans.getUniqueSpace(), test_params.word_size, 4096, 4096, (MemoryBank *)0);

    // Instantiate the memory state object
    MemoryState memstate(&trans);
    memstate.setMemoryBank(&ramstate);
    memstate.setMemoryBank(&registerstate);
    memstate.setMemoryBank(&tmpstate);

    // set initial registers
    for (const auto & [register_name, value] : initial_state.registers)
    {
        try
        {
            memstate.setValue(register_name.c_str(), value);
        } catch(...)
        {
            cout << "[-] Failed to set emulator register " << register_name << "! Do you need to set a register map?" << endl;
            return -1;
        }
    }

    BreakTableCallBack breaktable(&trans); // Set up the callback object
    EmulatePcodeCache emulator(&trans, &memstate, &breaktable); // Set up the emulator

    try
    {
        emulator.setExecuteAddress(Address(trans.getDefaultCodeSpace(), memstate.getValue(test_params.program_counter.c_str())));

        unsigned int pc = emulator.getExecuteAddress().getOffset();
        emulator.setHalt(false);
        try
        {
            emulator.executeInstruction();
        }
        catch(...)
        {
            // TODO: document this exception
        }

        emulator.setHalt(true);

        pc = emulator.getExecuteAddress().getOffset();
        memstate.setValue(test_params.program_counter.c_str(), pc);
    }
    catch(...)
    {
        // TODO: document this exception
    }

    // record final register state
    for (const auto & [register_name, value] : initial_state.registers)
    {
        final_state.registers[register_name] = memstate.getValue(register_name);
    }

    // set initial memory
    for (const auto & [address, value] : final_state.memory)
    {
        final_state.memory[address] = memstate.getValue(trans.getDefaultCodeSpace(), address, 1);
    }

    /*
    // method to search entire address space
    for(unsigned int address = 0; address < 0x10000; address++)
    {
        unsigned val = 0;

        val = memstate.getValue(trans.getDefaultCodeSpace(), address, 1);

        //cout << "adddress " << address << val << endl;
        if(val != 0)
        {

        }
    }
    */

    return 0;
}
