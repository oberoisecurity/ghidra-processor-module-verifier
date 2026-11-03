//--------------------------------------------------------------------------------------
// File: json.h
//
// Parsing json unit tests (https://github.com/SingleStepTests/ProcessorTests)
//
// Copyright (c) Oberoi Security Solutions. All rights reserved.
// Licensed under the Apache 2.0 License.
//--------------------------------------------------------------------------------------
#pragma once

#include <set>
#include <string>
#include <vector>
#include "../state.h"

// Reads the json list of tests in json_filename into tests.
// Register names are translated through test_params.register_map.
// Non-numeric per-state fields (e.g. "queue", "prefetch") are skipped and their names
// added to skipped_fields.
// Returns 0 on success.
int get_tests(const TEST_PARAMS &test_params, const std::string &json_filename,
              std::vector<TEST_CASE> &tests, std::set<std::string> &skipped_fields);
