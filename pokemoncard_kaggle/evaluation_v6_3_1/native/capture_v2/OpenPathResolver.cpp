#include "OpenPathResolver.h"

#include "SupervisorTypes.h"

#include <cstddef>
#include <cstdint>
#include <limits>
#include <new>
#include <string_view>

namespace evaluation_v6_3_1::capture_v2 {
namespace {

[[noreturn]] void fail(SupervisorFailure failure, const char* message) {
    throw SupervisorError(failure, message);
}

bool valid_utf8(std::string_view value) noexcept {
    const auto* bytes = reinterpret_cast<const std::uint8_t*>(value.data());
    std::size_t index = 0u;
    while (index < value.size()) {
        const std::uint8_t first = bytes[index++];
        const auto continuation = [](std::uint8_t byte) noexcept {
            return (byte & 0xc0u) == 0x80u;
        };
        if (first <= 0x7fu) {
            continue;
        }
        if (first >= 0xc2u && first <= 0xdfu) {
            if (index >= value.size() || !continuation(bytes[index++])) {
                return false;
            }
            continue;
        }
        if (first >= 0xe0u && first <= 0xefu) {
            if (index + 1u >= value.size()) {
                return false;
            }
            const std::uint8_t second = bytes[index++];
            const std::uint8_t third = bytes[index++];
            const bool second_valid =
                first == 0xe0u   ? second >= 0xa0u && second <= 0xbfu
                : first == 0xedu ? second >= 0x80u && second <= 0x9fu
                                 : continuation(second);
            if (!second_valid || !continuation(third)) {
                return false;
            }
            continue;
        }
        if (first >= 0xf0u && first <= 0xf4u) {
            if (index + 2u >= value.size()) {
                return false;
            }
            const std::uint8_t second = bytes[index++];
            const std::uint8_t third = bytes[index++];
            const std::uint8_t fourth = bytes[index++];
            const bool second_valid =
                first == 0xf0u   ? second >= 0x90u && second <= 0xbfu
                : first == 0xf4u ? second >= 0x80u && second <= 0x8fu
                                 : continuation(second);
            if (!second_valid || !continuation(third) || !continuation(fourth)) {
                return false;
            }
            continue;
        }
        return false;
    }
    return true;
}

bool normalized_relative(std::string_view path) noexcept {
    if (path.empty() || path.size() >= OpenPathResolver::kPathMaxBytes ||
        path.front() == '/' || path.back() == '/' || path.find('\\') != std::string_view::npos ||
        path.find('\0') != std::string_view::npos || !valid_utf8(path)) {
        return false;
    }

    std::size_t start = 0u;
    for (;;) {
        const std::size_t separator = path.find('/', start);
        const std::size_t end = separator == std::string_view::npos ? path.size() : separator;
        const std::string_view component = path.substr(start, end - start);
        if (component.empty() || component == "." || component == "..") {
            return false;
        }
        if (separator == std::string_view::npos) {
            return true;
        }
        start = separator + 1u;
    }
}

void require_normalized_relative(std::string_view path, const char* message) {
    if (!normalized_relative(path)) {
        fail(SupervisorFailure::UnsafePath, message);
    }
}

void require_family_and_dirfd(
    OpenPathResolver::SyscallFamily family,
    std::int64_t dirfd,
    bool absolute) {
    switch (family) {
    case OpenPathResolver::SyscallFamily::Open:
        if (dirfd != OpenPathResolver::kAtFdcwd) {
            fail(SupervisorFailure::InvalidRequest, "open family requires AT_FDCWD");
        }
        return;
    case OpenPathResolver::SyscallFamily::OpenAt:
    case OpenPathResolver::SyscallFamily::OpenAt2:
        if (!absolute && dirfd != OpenPathResolver::kAtFdcwd) {
            fail(SupervisorFailure::InvalidRequest, "relative openat family requires AT_FDCWD");
        }
        return;
    default:
        fail(SupervisorFailure::InvalidRequest, "unknown open syscall family");
    }
}

}  // namespace

std::string OpenPathResolver::resolve(
    const std::string& raw_syscall_path,
    SyscallFamily family,
    std::int64_t dirfd,
    const std::string& frozen_cwd_relative_path) {
    require_normalized_relative(
        frozen_cwd_relative_path,
        "frozen working directory is not a normalized relative UTF-8 path");
    if (raw_syscall_path.size() >= kPathMaxBytes) {
        fail(SupervisorFailure::ResourceLimit, "syscall path exceeds PATH_MAX bound");
    }

    const bool absolute = !raw_syscall_path.empty() && raw_syscall_path.front() == '/';
    require_family_and_dirfd(family, dirfd, absolute);

    std::string_view normalized_path = raw_syscall_path;
    if (absolute) {
        // Exactly one root slash is removed. The remaining bytes must already
        // be normalized; no canonicalization or component repair is allowed.
        if (raw_syscall_path.size() < 2u || raw_syscall_path[1] == '/') {
            fail(SupervisorFailure::UnsafePath, "absolute path has no single normalized root");
        }
        normalized_path = std::string_view(raw_syscall_path).substr(1u);
    }
    require_normalized_relative(normalized_path, "syscall path is not normalized relative UTF-8");

    try {
        if (absolute) {
            return std::string(normalized_path);
        }
        if (frozen_cwd_relative_path.size() >
            std::numeric_limits<std::size_t>::max() - 1u - normalized_path.size()) {
            fail(SupervisorFailure::ResourceLimit, "joined path length arithmetic overflow");
        }
        const std::size_t joined_size =
            frozen_cwd_relative_path.size() + 1u + normalized_path.size();
        if (joined_size >= kPathMaxBytes) {
            fail(SupervisorFailure::ResourceLimit, "joined path exceeds PATH_MAX bound");
        }
        std::string result;
        result.reserve(joined_size);
        result.append(frozen_cwd_relative_path);
        result.push_back('/');
        result.append(normalized_path);
        return result;
    } catch (const std::bad_alloc&) {
        fail(SupervisorFailure::ResourceLimit, "path result allocation failed");
    }
}

}  // namespace evaluation_v6_3_1::capture_v2
