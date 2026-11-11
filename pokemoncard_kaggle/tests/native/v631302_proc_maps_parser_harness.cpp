#include "ProcMapsParser.h"

#include <cstddef>
#include <cstdint>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

namespace capture = evaluation_v6_3_1::capture_v2;

namespace {

int run(std::string_view mode) {
    std::string input;
    if (mode == "valid") {
        input =
            "00400000-00401000 r--p 00000000 08:01 42 /sealed/collector\n"
            "00401000-00403000 r-xp 00001000 08:01 42 /sealed/collector\n"
            "7f000000-7f002000 r-xp 00000000 08:01 43 /lib/libclang\\055cpp.so.16\n"
            "7fff0000-7fff1000 r-xp 00000000 00:00 0 [vdso]\n";
    } else if (mode == "deleted") {
        input = "00400000-00401000 r-xp 00000000 08:01 42 /sealed/collector (deleted)\n";
    } else if (mode == "nonabsolute") {
        input = "00400000-00401000 r-xp 00000000 08:01 42 relative\n";
    } else if (mode == "escape") {
        input = "00400000-00401000 r-xp 00000000 08:01 42 /bad\\999\n";
    } else if (mode == "order") {
        input =
            "00500000-00501000 r-xp 00000000 08:01 42 /second\n"
            "00400000-00401000 r-xp 00000000 08:01 43 /first\n";
    } else if (mode == "duplicate-start") {
        input =
            "00400000-00401000 r-xp 00000000 08:01 42 /first\n"
            "00400000-00402000 r-xp 00000000 08:01 43 /second\n";
    } else if (mode == "overlap") {
        input =
            "00400000-00403000 r-xp 00000000 08:01 42 /first\n"
            "00402000-00404000 r-xp 00000000 08:01 43 /second\n";
    } else if (mode == "unterminated") {
        input = "00400000-00401000 r-xp 00000000 08:01 42 /sealed/collector";
    } else {
        return 10;
    }

    try {
        const std::vector<std::uint8_t> bytes(input.begin(), input.end());
        const auto rows = capture::ProcMapsParser::parse_executable_file_mappings(
            bytes, 32u, 4096u);
        if (mode != "valid" || rows.size() != 2u ||
            rows[0].diagnostic_absolute_path != "/sealed/collector" ||
            rows[0].mapping_length() != 8192u || rows[0].protection_flags != 5u ||
            rows[1].diagnostic_absolute_path != "/lib/libclang-cpp.so.16") {
            return 20;
        }
        std::cout << "proc_maps_ok rows=2 first_offset=" << rows[0].file_offset
                  << " second_path=" << rows[1].diagnostic_absolute_path
                  << " zero_authority=1\n";
        return 0;
    } catch (const capture::SupervisorError& error) {
        if (mode == "valid") {
            return 21;
        }
        std::cout << "proc_maps_rejected " << mode << " failure="
                  << static_cast<std::uint32_t>(error.failure())
                  << " zero_authority=1\n";
        return 0;
    }
}

}  // namespace

int main(int argc, char** argv) {
    return argc == 2 ? run(argv[1]) : 11;
}
