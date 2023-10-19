//--------------------------------------------------------------------------------------
// File: json.h
//
// Parsing json unit tests (https://github.com/TomHarte/ProcessorTests)
//
// Copyright (c) Oberoi Security Solutions. All rights reserved.
// Licensed under the Apache 2.0 License.
//--------------------------------------------------------------------------------------
#pragma once

#include <nlohmann/json.hpp>
using json = nlohmann::json;

#include "../state.h"

int get_tests(TEST_PARAMS& test_params, vector<TEST_STATE> &initial_states, vector<TEST_STATE> &final_states);
