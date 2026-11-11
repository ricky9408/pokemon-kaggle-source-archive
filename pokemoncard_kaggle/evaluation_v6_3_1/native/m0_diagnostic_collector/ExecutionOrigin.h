#ifndef EVALUATION_V6_3_1_M0_DIAGNOSTIC_COLLECTOR_EXECUTION_ORIGIN_H
#define EVALUATION_V6_3_1_M0_DIAGNOSTIC_COLLECTOR_EXECUTION_ORIGIN_H

namespace evaluation_v6_3_1::m0_diagnostic {

// Executes only the build-enabled test bootstrap.  This is an isolated
// Amendment-2 substrate, not the pending DIAGNOSTIC_CENSUS_V1 worker.  It has
// no final canonicalizer, diagnostic artifact, root, or campaign authority.
bool run_fresh_worker_substrate_test();

// Builds and retains Amendment-4's profile/dataflow substrate for a test-only
// bootstrap.  It is not wired to the closed extractor or production worker and
// cannot emit a campaign artifact, permit, or authority decision.
bool run_prelaunch_profile_dataflow_test(const char* tamper_field);

}  // namespace evaluation_v6_3_1::m0_diagnostic

#endif  // EVALUATION_V6_3_1_M0_DIAGNOSTIC_COLLECTOR_EXECUTION_ORIGIN_H
