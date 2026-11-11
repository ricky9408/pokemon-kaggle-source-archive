#ifndef EVALUATION_V6_3_1_M0_DIAGNOSTIC_RELAXED_FIXTURE_EXECUTION_ORIGIN_RELAXED_H
#define EVALUATION_V6_3_1_M0_DIAGNOSTIC_RELAXED_FIXTURE_EXECUTION_ORIGIN_RELAXED_H

#include <cstdint>
#include <vector>

namespace evaluation_v6_3_1::m0_diagnostic_relaxed {

// Runs only the explicitly nonconforming FD-emulation fixture.  Success
// returns the canonical six-field relaxed wrapper, never bare census bytes.
bool run_relaxed_fixture(const char* raw_collector_path, std::vector<std::uint8_t>* wrapper);

}  // namespace evaluation_v6_3_1::m0_diagnostic_relaxed

#endif  // EVALUATION_V6_3_1_M0_DIAGNOSTIC_RELAXED_FIXTURE_EXECUTION_ORIGIN_RELAXED_H
