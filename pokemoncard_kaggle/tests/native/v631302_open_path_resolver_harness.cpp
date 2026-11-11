#include "OpenPathResolver.h"
#include "SupervisorTypes.h"

#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>

namespace capture = evaluation_v6_3_1::capture_v2;
using Family = capture::OpenPathResolver::SyscallFamily;

namespace {

void require(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

std::string resolve(
    const std::string& path,
    Family family = Family::OpenAt,
    std::int64_t dirfd = capture::OpenPathResolver::kAtFdcwd,
    const std::string& cwd = "workspace/src") {
    return capture::OpenPathResolver::resolve(path, family, dirfd, cwd);
}

void require_rejected(
    const std::string& path,
    Family family = Family::OpenAt,
    std::int64_t dirfd = capture::OpenPathResolver::kAtFdcwd,
    const std::string& cwd = "workspace/src") {
    bool rejected = false;
    try {
        static_cast<void>(resolve(path, family, dirfd, cwd));
    } catch (const capture::SupervisorError&) {
        rejected = true;
    }
    require(rejected, "unsafe input was accepted");
}

void test_valid_family_matrix() {
    require(resolve("file.cc") == "workspace/src/file.cc", "relative openat join");
    require(resolve("file.cc", Family::OpenAt2) == "workspace/src/file.cc", "relative openat2 join");
    require(resolve("file.cc", Family::Open) == "workspace/src/file.cc", "relative open join");
    require(resolve("/file.cc") == "file.cc", "absolute openat root stripping");
    require(resolve("/file.cc", Family::OpenAt2, 77) == "file.cc", "absolute openat2 ignores dirfd");
    require(resolve("/file.cc", Family::Open, capture::OpenPathResolver::kAtFdcwd) == "file.cc",
            "absolute open root stripping");
    require(resolve("caf\xC3\xA9.cc") == "workspace/src/caf\xC3\xA9.cc", "valid UTF-8 preserved");
}

void test_reject_path_forms() {
    require_rejected("");
    require_rejected(std::string("a\0b", 3u));
    require_rejected("a\\b");
    require_rejected("a//b");
    require_rejected("/a//b");
    require_rejected("/a/");
    require_rejected("//a");
    require_rejected("/");
    require_rejected(".");
    require_rejected("..");
    require_rejected("a/./b");
    require_rejected("a/../b");
    require_rejected(std::string("a\xC0\xAF") + "b");
    require_rejected(std::string("a\xE2\x28\xA1") + "b");
    require_rejected("a", Family::OpenAt, capture::OpenPathResolver::kAtFdcwd, "bad//cwd");
    require_rejected("a", Family::OpenAt, capture::OpenPathResolver::kAtFdcwd, ".");
}

void test_reject_family_dirfd_and_size() {
    require_rejected("a", Family::Open, 9);
    require_rejected("a", Family::OpenAt, 9);
    require_rejected("a", Family::OpenAt2, 9);
    require_rejected("/a", static_cast<Family>(99));
    require_rejected("a", static_cast<Family>(99));

    const std::string path(capture::OpenPathResolver::kPathMaxBytes, 'a');
    require_rejected(path);
    const std::string absolute_path = "/" + std::string(capture::OpenPathResolver::kPathMaxBytes - 1u, 'a');
    require_rejected(absolute_path);
    const std::string cwd(capture::OpenPathResolver::kPathMaxBytes - 2u, 'c');
    require_rejected("d", Family::OpenAt, capture::OpenPathResolver::kAtFdcwd, cwd);
}

}  // namespace

int main() {
    try {
        test_valid_family_matrix();
        test_reject_path_forms();
        test_reject_family_dirfd_and_size();
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return EXIT_FAILURE;
    }
    std::cout << "open_path_resolver_harness_ok zero_authority=1\n";
    return EXIT_SUCCESS;
}
