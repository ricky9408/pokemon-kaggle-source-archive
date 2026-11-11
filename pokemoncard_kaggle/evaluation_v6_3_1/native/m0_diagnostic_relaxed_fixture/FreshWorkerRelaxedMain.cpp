#include "ExecutionOriginRelaxed.h"

#include <cstring>
#include <iostream>
#include <vector>

int main(int argc, char** argv) {
    constexpr char kRawCollectorPrefix[] = "--raw-collector-cbor=";
    if (argc != 2 || std::strncmp(argv[1], kRawCollectorPrefix,
                                  sizeof(kRawCollectorPrefix) - 1u) != 0 ||
        argv[1][sizeof(kRawCollectorPrefix) - 1u] == '\0') {
        return 66;
    }
    std::vector<std::uint8_t> wrapper;
    if (!evaluation_v6_3_1::m0_diagnostic_relaxed::run_relaxed_fixture(
            argv[1] + sizeof(kRawCollectorPrefix) - 1u, &wrapper)) {
        return 66;
    }
    std::cout.write(reinterpret_cast<const char*>(wrapper.data()),
                    static_cast<std::streamsize>(wrapper.size()));
    return std::cout ? 0 : 66;
}
