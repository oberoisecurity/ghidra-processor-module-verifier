//--------------------------------------------------------------------------------------
// File: runner.cpp
//
// Runs test cases across worker threads
//
// Copyright (c) Oberoi Security Solutions. All rights reserved.
// Licensed under the Apache 2.0 License.
//--------------------------------------------------------------------------------------
#include "runner.h"

#include <algorithm>
#include <iostream>
#include <mutex>
#include <sstream>
#include <thread>

using namespace std;

namespace
{
string test_label(size_t index, const TEST_CASE &test)
{
    ostringstream s;
    s << index << ")";
    if (!test.name.empty())
    {
        s << " [" << test.name << "]";
    }
    return s.str();
}
}

bool run_tests(const TEST_PARAMS &test_params, const vector<TEST_CASE> &tests,
               vector<unique_ptr<SlaEmulator>> &workers,
               atomic<unsigned int> &total_failures, RUN_TOTALS &totals)
{
    const size_t end = min(test_params.end_test, tests.size());
    atomic<size_t> next(test_params.start_test);
    atomic<size_t> run_count(0);
    atomic<size_t> fail_count(0);
    atomic<bool> aborted(false);
    mutex output_lock;

    auto max_failures_hit = [&]()
    {
        return test_params.max_failures != 0 && total_failures >= test_params.max_failures;
    };

    auto worker_main = [&](SlaEmulator &emulator)
    {
        EMU_RESULT result;

        while (true)
        {
            if (max_failures_hit())
            {
                aborted = true;
                return;
            }

            size_t i = next++;
            if (i >= end)
            {
                return;
            }

            const TEST_CASE &test = tests[i];
            emulator.run(test, result);

            ostringstream report;
            bool passed = compare_state(test.final, result, report);
            run_count++;

            if (passed)
            {
                if (!test_params.quiet)
                {
                    lock_guard<mutex> guard(output_lock);
                    cout << "[+] " << test_label(i, test) << " SUCCESS" << endl;
                }
                continue;
            }

            fail_count++;
            total_failures++;

            report << "[-] " << test_label(i, test) << " FAIL" << endl;
            report << "Initial State:" << endl;
            print_state(test.initial, report);
            report << endl << "Final (Expected) State:" << endl;
            print_state(test.final, report);
            report << endl << "Emulator:" << endl;
            print_state(result.state, report);
            report << endl;

            lock_guard<mutex> guard(output_lock);
            cout << report.str() << flush;
        }
    };

    if (workers.size() == 1)
    {
        worker_main(*workers[0]);
    }
    else
    {
        vector<thread> threads;
        for (auto &worker : workers)
        {
            threads.emplace_back(worker_main, ref(*worker));
        }
        for (auto &t : threads)
        {
            t.join();
        }
    }

    totals.run += run_count;
    totals.failed += fail_count;
    totals.passed += run_count - fail_count;

    return !(aborted || (next < end && max_failures_hit()));
}
