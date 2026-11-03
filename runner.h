//--------------------------------------------------------------------------------------
// File: runner.h
//
// Runs test cases across worker threads
//
// Copyright (c) Oberoi Security Solutions. All rights reserved.
// Licensed under the Apache 2.0 License.
//--------------------------------------------------------------------------------------
#pragma once

#include <atomic>
#include <memory>
#include <string>
#include <vector>
#include "state.h"
#include "backends/sla_emulator.h"

struct RUN_TOTALS
{
    size_t run = 0;
    size_t passed = 0;
    size_t failed = 0;
};

// Run tests[test_params.start_test, test_params.end_test) using one thread per worker.
// total_failures is shared across calls so --max-failures applies to the whole session.
// Returns false if the run was aborted because the maximum number of failures was reached.
bool run_tests(const TEST_PARAMS &test_params, const std::vector<TEST_CASE> &tests,
               std::vector<std::unique_ptr<SlaEmulator>> &workers,
               std::atomic<unsigned int> &total_failures, RUN_TOTALS &totals);
