#include "ExecutionOrigin.h"

#include <cstring>

int main(int argc, char** argv) {
    if (argc == 2 && std::strcmp(argv[1], "--test-bootstrap") == 0) {
        return evaluation_v6_3_1::m0_diagnostic::run_fresh_worker_substrate_test() ? 0 : 66;
    }
    constexpr char kTamperPrefix[] = "--test-prelaunch-profile=";
    if (argc != 2 || std::strncmp(argv[1], kTamperPrefix,
                                  sizeof(kTamperPrefix) - 1u) != 0) {
        return 66;
    }
    return evaluation_v6_3_1::m0_diagnostic::run_prelaunch_profile_dataflow_test(
               argv[1] + sizeof(kTamperPrefix) - 1u)
               ? 0
               : 66;
}
