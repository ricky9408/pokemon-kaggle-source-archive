#include "Stage1SeccompFilterV1.h"

#include <array>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <string_view>

namespace {

using pokemon::evaluation_v631302::SeccompPolicyV1;
using pokemon::evaluation_v631302::kStage1SeccompFilterV1;
using pokemon::evaluation_v631302::kStage1SeccompRawBpfV1;
using pokemon::evaluation_v631302::initialize_stage1_seccomp_program_v1;
using pokemon::evaluation_v631302::validate_stage1_seccomp_filter_v1;
using pokemon::evaluation_v631302::validate_stage1_seccomp_program_mapping_v1;
using pokemon::evaluation_v631302::validate_stage1_seccomp_program_v1;

std::string read_proc_self_maps() {
    std::ifstream input("/proc/self/maps", std::ios::binary);
    std::ostringstream bytes;
    bytes << input.rdbuf();
    return input.good() || input.eof() ? bytes.str() : std::string{};
}

std::string mapping_row(
    const std::uintptr_t start,
    const std::uintptr_t end,
    const std::string_view permissions) {
    std::ostringstream row;
    row << std::hex << start << '-' << end << ' ' << permissions
        << " 00000000 00:00 0\n";
    return row.str();
}

int run_mapping(const std::string_view mutation) {
    sock_fprog program;
    if (!initialize_stage1_seccomp_program_v1(&program)) {
        return 65;
    }
    const auto start = reinterpret_cast<std::uintptr_t>(program.filter);
    const auto end = start + SeccompPolicyV1::raw_byte_count;
    if (mutation == "actual") {
        const std::string maps = read_proc_self_maps();
        return validate_stage1_seccomp_program_mapping_v1(&program, maps) ? 0 : 1;
    }

    std::string maps;
    if (mutation == "exact") {
        maps = mapping_row(start, end, "r--p");
    } else if (mutation == "padded-hex") {
        std::ostringstream row;
        row << '0' << std::hex << start << "-0" << end
            << " r--p 00000000 00:00 0\n";
        maps = row.str();
    } else if (mutation == "writable") {
        maps = mapping_row(start, end, "rw-p");
    } else if (mutation == "unreadable") {
        maps = mapping_row(start, end, "---p");
    } else if (mutation == "duplicate") {
        maps = mapping_row(start, end, "r--p") + mapping_row(start, end, "r-xp");
    } else if (mutation == "split") {
        const auto midpoint = start + (SeccompPolicyV1::raw_byte_count / 2u);
        maps = mapping_row(start, midpoint, "r--p") + mapping_row(midpoint, end, "r--p");
    } else if (mutation == "missing") {
        maps = mapping_row(end + 4096u, end + 8192u, "r--p");
    } else if (mutation == "malformed") {
        maps = "not-a-mapping\n";
    } else if (mutation == "unterminated") {
        maps = mapping_row(start, end, "r--p");
        maps.pop_back();
    } else {
        return 64;
    }
    const bool accepted = validate_stage1_seccomp_program_mapping_v1(&program, maps);
    const bool should_accept = mutation == "exact" || mutation == "padded-hex";
    return should_accept ? (accepted ? 0 : 1) : (accepted ? 1 : 0);
}

int run_summary() {
    sock_fprog program;
    if (!initialize_stage1_seccomp_program_v1(&program)) {
        return 65;
    }
    std::cout << "instructions=" << SeccompPolicyV1::instruction_count
              << " bytes=" << SeccompPolicyV1::raw_byte_count
              << " descriptor_valid=" << (validate_stage1_seccomp_program_v1(&program) ? 1 : 0)
              << " raw_first=" << static_cast<unsigned>(kStage1SeccompRawBpfV1[0])
              << " raw_last=" << static_cast<unsigned>(kStage1SeccompRawBpfV1[343])
              << " zero_authority=1\n";
    return 0;
}

int run_mutation(const std::string_view mutation) {
    std::array<sock_filter, SeccompPolicyV1::instruction_count> copy{};
    std::memcpy(copy.data(), kStage1SeccompFilterV1, sizeof(copy));
    if (mutation == "code") {
        copy[0].code ^= 1u;
    } else if (mutation == "jt") {
        copy[1].jt ^= 1u;
    } else if (mutation == "jf") {
        copy[4].jf ^= 1u;
    } else if (mutation == "constant") {
        copy[6].k ^= 1u;
    } else if (mutation == "architecture") {
        copy[1].k ^= 1u;
    } else if (mutation == "architecture-reversed") {
        copy[1].jt = 0u;
        copy[1].jf = 1u;
    } else if (mutation == "x32-constant") {
        copy[4].k ^= 1u;
    } else if (mutation == "x32-jump") {
        copy[4].jf = 0u;
    } else if (mutation == "denied-order") {
        const sock_filter temporary = copy[6];
        copy[6] = copy[8];
        copy[8] = temporary;
    } else if (mutation == "denied-duplicate") {
        copy[6].k = copy[8].k;
    } else if (mutation == "kill-action") {
        copy[7].k = 0u;
    } else if (mutation == "jump-offset-above-one") {
        copy[6].jf = 2u;
    } else if (mutation == "backward-style-jump") {
        copy[6].jt = 255u;
    } else if (mutation == "final-action") {
        copy.back().k ^= 1u;
    } else if (mutation == "count") {
        return validate_stage1_seccomp_filter_v1(copy.data(), 42u) ? 1 : 0;
    } else if (mutation == "pointer") {
        sock_fprog program{};
        program.len = static_cast<unsigned short>(SeccompPolicyV1::instruction_count);
        program.filter = copy.data();
        return validate_stage1_seccomp_program_v1(&program) ? 1 : 0;
    } else if (mutation == "padding") {
        sock_fprog program;
        if (!initialize_stage1_seccomp_program_v1(&program)) {
            return 65;
        }
        auto* const bytes = reinterpret_cast<std::uint8_t*>(&program);
        bytes[2] = 1u;
        return validate_stage1_seccomp_program_v1(&program) ? 1 : 0;
    } else {
        return 64;
    }
    return validate_stage1_seccomp_filter_v1(copy.data(), copy.size()) ? 1 : 0;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc == 1) {
        return run_summary();
    }
    if (argc == 2 && std::string_view(argv[1]) == "validate") {
        sock_fprog program;
        if (!initialize_stage1_seccomp_program_v1(&program)) {
            return 65;
        }
        return validate_stage1_seccomp_program_v1(&program) ? 0 : 1;
    }
    if (argc == 3 && std::string_view(argv[1]) == "mapping") {
        return run_mapping(argv[2]);
    }
    if (argc == 2 && std::string_view(argv[1]) == "mutate") {
        return 64;
    }
    if (argc == 3 && std::string_view(argv[1]) == "mutate") {
        return run_mutation(argv[2]);
    }
    return 64;
}
