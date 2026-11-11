#include "ElfMetadata.h"

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <fcntl.h>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <unistd.h>
#include <vector>

namespace capture = evaluation_v6_3_1::capture_v2;

namespace {

class Fd final {
public:
    explicit Fd(int descriptor) : descriptor_(descriptor) {
        if (descriptor_ < 0) {
            throw std::runtime_error("open ELF fixture failed");
        }
    }
    ~Fd() {
        if (descriptor_ >= 0) {
            static_cast<void>(::close(descriptor_));
        }
    }
    Fd(const Fd&) = delete;
    Fd& operator=(const Fd&) = delete;
    [[nodiscard]] int get() const noexcept { return descriptor_; }

private:
    int descriptor_ = -1;
};

std::string hex(const std::vector<std::uint8_t>& bytes) {
    constexpr char digits[] = "0123456789abcdef";
    std::string output;
    output.reserve(bytes.size() * 2u);
    for (const std::uint8_t byte : bytes) {
        output.push_back(digits[byte >> 4u]);
        output.push_back(digits[byte & 0x0fu]);
    }
    return output;
}

int run(std::string_view mode, const char* path) {
    Fd descriptor(::open(path, O_RDONLY | O_CLOEXEC | O_NOCTTY | O_NOFOLLOW));
    const std::uint64_t timeout = mode == "timeout" ? 1u : 10'000u;
    capture::MonotonicDeadline deadline(timeout);
    if (mode == "timeout") {
        std::this_thread::sleep_for(std::chrono::milliseconds(3));
    }
    try {
        capture::ElfMetadataLimits limits{};
        if (mode == "relaxed-limit") {
            limits.maximum_soname_bytes = 65'536u;
        }
        const capture::ElfMetadataObservation observation =
            capture::ElfMetadata::inspect_linux_amd64(
                descriptor.get(), 128u * 1024u * 1024u, deadline, limits);
        if (mode != "inspect") {
            return 20;
        }
        std::cout << "elf_metadata_ok interp=" << hex(observation.interpreter)
                  << " soname=" << hex(observation.soname)
                  << " build_id=" << hex(observation.build_id)
                  << " zero_authority=1\n";
        return 0;
    } catch (const capture::SupervisorError& error) {
        if (mode == "inspect") {
            std::cerr << error.what() << '\n';
            return 21;
        }
        std::cout << "elf_metadata_rejected " << mode << " failure="
                  << static_cast<std::uint32_t>(error.failure())
                  << " zero_authority=1\n";
        return 0;
    }
}

}  // namespace

int main(int argc, char** argv) {
    if (argc != 3) {
        return 10;
    }
    try {
        return run(argv[1], argv[2]);
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 11;
    }
}
