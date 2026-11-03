//--------------------------------------------------------------------------------------
// File: sla_emulator.h
//
// libsla emulator
//
// Copyright (c) Oberoi Security Solutions. All rights reserved.
// Licensed under the Apache 2.0 License.
//--------------------------------------------------------------------------------------
#pragma once

#include <memory>
#include <string>
#include <vector>
#include "../state.h"

struct SLA_INFO
{
    std::string ram_space;   // name of the default code space
    unsigned int addr_size;  // size of an address in the default code space (bytes)
    unsigned int word_size;  // addressable unit size of the default code space (bytes)
    bool big_endian;
};

// Wraps one libsla translator + emulator. Not thread safe: create one per worker thread.
// The .sla is loaded once in the constructor and reused for every test.
class SlaEmulator
{
public:
    // Must be called once, before any SlaEmulator is constructed.
    static void global_init(void);

    // Throws std::runtime_error if the .sla, the program counter or a context variable is invalid.
    explicit SlaEmulator(const TEST_PARAMS &test_params);
    ~SlaEmulator();

    SlaEmulator(const SlaEmulator &) = delete;
    SlaEmulator &operator=(const SlaEmulator &) = delete;

    SLA_INFO info(void) const;
    bool has_register(const std::string &name) const;
    std::vector<std::string> register_names(void) const;

    // Execute a single instruction from test.initial and record the resulting state.
    // Emulator exceptions are reported through result.error rather than thrown.
    void run(const TEST_CASE &test, EMU_RESULT &result);

private:
    struct Impl;
    std::unique_ptr<Impl> impl;
};
