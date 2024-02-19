//--------------------------------------------------------------------------------------
// File: sla_emulator.h
//
// libsla emulator
//
// Copyright (c) Oberoi Security Solutions. All rights reserved.
// Licensed under the Apache 2.0 License.
//--------------------------------------------------------------------------------------
#include "../state.h"
#include "sleigh.hh"
#include "emulate.hh"

using namespace ghidra;

int sla_emulate(TEST_PARAMS &test_params, TEST_STATE &initial_state, TEST_STATE &final_state, DocumentStorage docstorage);
int sla_emulate_internal(TEST_PARAMS &test_params, TEST_STATE &initial_state, TEST_STATE &final_state, DocumentStorage docstorage);
