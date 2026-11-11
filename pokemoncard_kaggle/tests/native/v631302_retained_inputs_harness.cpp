#include "RetainedInputs.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdint>
#include <fcntl.h>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

namespace capture = evaluation_v6_3_1::capture_v2;

namespace {

class TempTree final {
public:
    TempTree() {
        std::array<char, 64> pattern{};
        const std::string value = "/tmp/v631302-retained-XXXXXX";
        std::copy(value.begin(), value.end(), pattern.begin());
        if (::mkdtemp(pattern.data()) == nullptr) {
            throw std::runtime_error("mkdtemp failed");
        }
        path_ = pattern.data();
        std::filesystem::create_directory(path_ / "original");
        std::filesystem::create_directory(path_ / "destination");
    }

    ~TempTree() { std::filesystem::remove_all(path_); }

    const std::filesystem::path& path() const noexcept { return path_; }

private:
    std::filesystem::path path_;
};

void write_file(const std::filesystem::path& path, const std::string& bytes, mode_t mode) {
    const int descriptor = ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (descriptor < 0) {
        throw std::runtime_error("file create failed");
    }
    std::size_t offset = 0;
    while (offset < bytes.size()) {
        const ssize_t count = ::write(descriptor, bytes.data() + offset, bytes.size() - offset);
        if (count <= 0) {
            ::close(descriptor);
            throw std::runtime_error("file write failed");
        }
        offset += static_cast<std::size_t>(count);
    }
    if (::fchmod(descriptor, mode) != 0 || ::fsync(descriptor) != 0 || ::close(descriptor) != 0) {
        throw std::runtime_error("file finalize failed");
    }
}

std::string hex(const capture::Sha256Digest& digest) {
    constexpr char digits[] = "0123456789abcdef";
    std::string output;
    output.reserve(64);
    for (const std::uint8_t byte : digest) {
        output.push_back(digits[byte >> 4u]);
        output.push_back(digits[byte & 0x0fu]);
    }
    return output;
}

std::vector<capture::RetainedInputSpec> valid_specs(int root) {
    return {
        {root, "collector", "bin/collector", {1}, 0555},
        {root, "fixture.cc", "src/fixture.cc", {2, 3}, 0444},
    };
}

int expect_error(const std::string& mode) {
    TempTree tree;
    const auto original = tree.path() / "original";
    write_file(original / "collector", "collector-bytes", 0555);
    write_file(original / "fixture.cc", mode == "alias-destination" ? "" : "int value = 7;\n", 0444);
    const int root = ::open(original.c_str(), O_PATH | O_DIRECTORY | O_CLOEXEC);
    if (root < 0) {
        return 20;
    }
    try {
        auto specs = valid_specs(root);
        if (mode == "symlink") {
            std::filesystem::create_symlink("fixture.cc", original / "alias.cc");
            specs[1].original_relative_path = "alias.cc";
        } else if (mode == "hardlink") {
            std::filesystem::create_hard_link(original / "fixture.cc", original / "second.cc");
        } else if (mode == "writable") {
            if (::chmod((original / "fixture.cc").c_str(), 0644) != 0) return 21;
        } else if (mode == "duplicate-namespace") {
            specs[1].namespace_relative_path = specs[0].namespace_relative_path;
        } else if (mode == "unsafe-path") {
            specs[1].original_relative_path = "../fixture.cc";
        } else if (mode == "wrong-mode") {
            specs[1].normalized_mode = 0555;
        } else if (mode == "missing-primary") {
            specs[1].role_codes = {3};
        } else if (mode == "unsorted") {
            std::swap(specs[0], specs[1]);
        }
        auto retained = capture::RetainedInputSet::acquire(std::move(specs));
        if (mode == "alias-destination") {
            retained.inputs()[1].materialize_to(retained.inputs()[1].descriptor());
        } else if (mode == "mutate") {
            if (::chmod((original / "fixture.cc").c_str(), 0644) != 0) return 22;
            write_file(tree.path() / "replacement", "int value = 8;\n", 0444);
            std::filesystem::rename(tree.path() / "replacement", original / "fixture.cc");
            const int destination = ::open(
                (tree.path() / "destination/out").c_str(),
                O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC,
                0600);
            retained.inputs()[1].materialize_to(destination);
            ::close(destination);
        } else {
            ::close(root);
            return 1;
        }
    } catch (const capture::SupervisorError& error) {
        std::cout << static_cast<std::uint32_t>(error.failure()) << ':' << error.what() << '\n';
        ::close(root);
        return 0;
    }
    ::close(root);
    return 2;
}

int valid() {
    TempTree tree;
    const auto original = tree.path() / "original";
    const auto destination = tree.path() / "destination";
    write_file(original / "collector", "collector-bytes", 0555);
    write_file(original / "fixture.cc", "int value = 7;\n", 0444);
    const int root = ::open(original.c_str(), O_PATH | O_DIRECTORY | O_CLOEXEC);
    if (root < 0) return 30;
    auto retained = capture::RetainedInputSet::acquire(valid_specs(root));
    std::vector<capture::MaterializedInput> rows;
    for (std::size_t index = 0; index < retained.inputs().size(); ++index) {
        const auto path = destination / (index == 0 ? "collector" : "fixture.cc");
        const int output = ::open(path.c_str(), O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        if (output < 0) return 31;
        rows.push_back(retained.inputs()[index].materialize_to(output));
        ::close(output);
    }
    ::close(root);
    std::cout << rows[0].namespace_relative_path << ' ' << rows[0].byte_length << ' '
              << hex(rows[0].sha256) << '\n';
    std::cout << rows[1].namespace_relative_path << ' ' << rows[1].byte_length << ' '
              << hex(rows[1].sha256) << '\n';
    struct stat collector_status {};
    struct stat source_status {};
    if (::stat((destination / "collector").c_str(), &collector_status) != 0 ||
        ::stat((destination / "fixture.cc").c_str(), &source_status) != 0) {
        return 32;
    }
    if ((collector_status.st_mode & 07777) != 0555 || (source_status.st_mode & 07777) != 0444) {
        return 33;
    }
    try {
        const int output = ::open((destination / "again").c_str(), O_RDWR | O_CREAT | O_EXCL, 0600);
        retained.inputs()[0].materialize_to(output);
        ::close(output);
        return 34;
    } catch (const capture::SupervisorError&) {
        std::cout << "single-materialization-enforced\n";
    }
    return 0;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc != 2) return 10;
    const std::string mode = argv[1];
    if (mode == "valid") return valid();
    return expect_error(mode);
}
