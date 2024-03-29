//--------------------------------------------------------------------------------------
// File: sla_emulator.cpp
//
// libsla emulator
//
// Copyright (c) Oberoi Security Solutions. All rights reserved.
// Licensed under the Apache 2.0 License.
//--------------------------------------------------------------------------------------
#include "sla_emulator.h"
#include <boost/atomic.hpp>
#include <boost/timer/timer.hpp>
#include <boost/thread/mutex.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/thread_pool.hpp>
#include <boost/chrono.hpp>
#include <boost/thread/thread.hpp>
#include <boost/bind.hpp>
#include <iostream>
#include <boost/asio/execution.hpp>
#include "json.h"

using namespace std;

boost::atomic<unsigned int> failure_count = 0;
boost::atomic<unsigned int> completed_count = 0;

void incrementTestFailures(void)
{
    failure_count++;
}

unsigned int getTestFailures(void)
{
    return failure_count;
}

void incrementTestCompletions(void)
{
    completed_count++;
}

unsigned int getTestCompletions(void)
{
    return completed_count;
}

int execute_test(TEST_PARAMS& test_params, unsigned int test_id, TEST_STATE initial_state, TEST_STATE final_state, DocumentStorage docstorage);

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

int sla_emulate(TEST_PARAMS &test_params, TEST_STATE &initial_state, TEST_STATE &final_state, DocumentStorage docstorage)
{
    map<unsigned long long, unsigned char> address_space; // represents the emulators address space

    // Set up the context object
    ContextInternal context;

    // set initial memory
    for (const auto & [address, value] : initial_state.memory)
    {
        address_space[address] = value;
    }

    MyLoadImage loader(&address_space);
    Sleigh trans(&loader, &context);

    trans.initialize(docstorage); // Initialize the translator

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

int parallelize_test(TEST_PARAMS& test_params)
{
    boost::timer::auto_cpu_timer t;
    vector<TEST_STATE> initial_states;
    vector<TEST_STATE> final_states;
    unsigned int completed_count = 0;
    unsigned int fail_count = 0;
    boost::asio::thread_pool thread_pool(test_params.num_threads);
    unsigned int cases_submitted = 0;
    int result = 0;

    result = get_tests(test_params, initial_states, final_states);
    if(result != 0)
    {
        cout << "[-] Failed to load unit tests!" << endl;
        return -1;
    }

    cout << "[*] " << test_params.json_filename << ": Loaded " << initial_states.size() << " test cases" << endl;

    // can't have end test greater than the number of total tests
    if(test_params.end_test >= initial_states.size())
    {
        test_params.end_test = initial_states.size();
    }
    cout << "[*] Test Range: "  << test_params.start_test << "-" << test_params.end_test << endl;


    AttributeId::initialize();
    ElementId::initialize();

    // Read sleigh file into DOM
    DocumentStorage docstorage;
    Element *sleighroot = docstorage.openDocument(test_params.sla_filename)->getRoot();

    // TODO: improve performance of loop
    for(unsigned int i = test_params.start_test; i < test_params.end_test; i++)
    {
        // TODO: DocumentStorage needs to be copied or crashes will happen...
        DocumentStorage docstorage2;
        docstorage2.registerTag(sleighroot);

        boost::asio::post(thread_pool, boost::bind(execute_test, test_params, i, initial_states[i], final_states[i], docstorage2));
        cases_submitted++;
    }
    cout << "[*] Done posting tests" << endl;

    // TODO: improve poll logic
    while(1)
    {
        boost::this_thread::sleep(boost::posix_time::milliseconds(100));

        completed_count = getTestCompletions();
        fail_count = getTestFailures();

        cout << "Test cases: " << completed_count << "/" << cases_submitted  << " Fail cases: " << fail_count << endl;

        // check if we exceeded our max number of failures
        if(fail_count >= test_params.max_failures)
        {
            // abort the rest of the threads
            thread_pool.stop();
            break;
        }

        // check if we finished our submitted jobs
        if(completed_count >= cases_submitted)
        {
            // finished
            break;
        }
    }

    // wait for threads to finish
    // should be quick as we exited the polling loop
    thread_pool.join();

    cout << "Cases submitted " << cases_submitted  << endl;
    cout << "Completed cases " << getTestCompletions() << endl;
    cout << "Fail cases " << getTestFailures() << endl;

    return 0;
}

int execute_test(TEST_PARAMS& test_params, unsigned int test_id, TEST_STATE initial_state, TEST_STATE final_state, DocumentStorage docstorage)
{
    TEST_STATE emu_final_state;
    unsigned int fail_count = 0;
    int result = 0;

    // check if we hit the max number of test failures
    fail_count = getTestFailures();
    if(fail_count >= test_params.max_failures)
    {
        // hit max failures, just return
        return 0;
    }

    incrementTestCompletions();

    for (const auto & [address, value] : final_state.memory)
    {
        emu_final_state.memory[address] = 0;
    }

    try
    {
        result = sla_emulate(test_params, initial_state, emu_final_state,  docstorage);
        if(result != 0)
        {
            cout << "[-] Fatal emulation error!" << endl;
            return result;
        }
    }
    catch(BadDataError &e)
    {
        cout << "[-] BadDataError: " << e.explain << endl;
        return -1;
    }

    result = compare_state(final_state, emu_final_state);
    if(result != 0)
    {
        // TODO: output failure
        cout << "[-] " << test_id << ") FAIL" << endl;

        cout << "Initial State:" << endl;
        print_state(initial_state);
        cout << endl;

        cout << "Final (Expected) State:" << endl;
        print_state(final_state);
        cout << endl;

        cout << "Emulator:" << endl;
        print_state(emu_final_state);
        cout << endl;

        incrementTestFailures();
    }
    else
    {
        cout << "[+] " << test_id << ") SUCCESS" << endl;
    }

    return 0;
}
