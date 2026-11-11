#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "TraceeMemory.h"

#include <cerrno>
#include <cstdint>
#include <limits>
#include <new>
#include <stdexcept>
#include <sys/uio.h>
#include <utility>

namespace evaluation_v6_3_1::capture_v2 {
namespace {

[[noreturn]] void fail(SupervisorFailure failure, std::string message, int error = 0) {
    throw SupervisorError(failure, std::move(message), error);
}

void validate_remote_span(
    std::uintptr_t remote_address,
    std::size_t length,
    std::size_t positive_maximum) {
    if (remote_address == 0u) {
        fail(SupervisorFailure::InvalidRequest, "tracee remote address must be nonzero");
    }
    if (length == 0u || positive_maximum == 0u) {
        fail(SupervisorFailure::InvalidRequest, "tracee memory lengths must be positive");
    }
    if (length > positive_maximum) {
        fail(SupervisorFailure::ResourceLimit, "tracee memory length exceeds configured maximum");
    }
    if (length - 1u > std::numeric_limits<std::uintptr_t>::max() - remote_address) {
        fail(SupervisorFailure::InvalidRequest, "tracee memory address arithmetic overflow");
    }
}

void read_exact_remote(
    pid_t stopped_pid,
    std::uintptr_t remote_address,
    void* local_address,
    std::size_t length) {
    struct iovec local {
        local_address,
        length,
    };
    struct iovec remote {
        reinterpret_cast<void*>(remote_address),
        length,
    };
    const ssize_t count = ::process_vm_readv(
        stopped_pid,
        &local,
        1UL,
        &remote,
        1UL,
        0UL);
    if (count < 0) {
        const int error = errno;
        fail(SupervisorFailure::SystemFailure, "process_vm_readv failed", error);
    }
    if (count == 0) {
        fail(SupervisorFailure::ProtocolViolation, "process_vm_readv returned zero bytes");
    }
    if (static_cast<std::size_t>(count) != length) {
        fail(SupervisorFailure::ProtocolViolation, "process_vm_readv returned a partial read");
    }
}

}  // namespace

TraceeMemory::TraceeMemory(pid_t stopped_pid) : stopped_pid_(stopped_pid) {
    if (stopped_pid <= 0) {
        fail(SupervisorFailure::InvalidRequest, "stopped process pid must be positive");
    }
}

void TraceeMemory::require_ready() const {
    if (state_ != State::Ready) {
        fail(SupervisorFailure::ProtocolViolation, "tracee memory reader is permanently failed");
    }
}

std::vector<std::uint8_t> TraceeMemory::exact_bytes(
    std::uintptr_t remote_address,
    std::size_t exact_length,
    std::size_t positive_maximum) {
    require_ready();
    try {
        validate_remote_span(remote_address, exact_length, positive_maximum);
        std::vector<std::uint8_t> result;
        result.resize(exact_length);
        read_exact_remote(
            stopped_pid_,
            remote_address,
            result.data(),
            exact_length);
        return result;
    } catch (const std::bad_alloc&) {
        fail_terminal();
        fail(SupervisorFailure::ResourceLimit, "tracee memory allocation exceeded available resources");
    } catch (const std::length_error&) {
        fail_terminal();
        fail(SupervisorFailure::ResourceLimit, "tracee memory allocation exceeded implementation limit");
    } catch (...) {
        fail_terminal();
        throw;
    }
}

std::string TraceeMemory::nul_terminated_string(
    std::uintptr_t remote_address,
    std::size_t positive_maximum) {
    require_ready();
    try {
        if (remote_address == 0u) {
            fail(SupervisorFailure::InvalidRequest, "tracee remote address must be nonzero");
        }
        if (positive_maximum == 0u) {
            fail(SupervisorFailure::InvalidRequest, "tracee string maximum must be positive");
        }

        std::string result;
        if (positive_maximum > result.max_size()) {
            fail(SupervisorFailure::ResourceLimit, "tracee string maximum exceeds implementation limit");
        }
        result.reserve(positive_maximum);
        for (std::size_t index = 0u; index < positive_maximum; ++index) {
            if (index > std::numeric_limits<std::uintptr_t>::max() - remote_address) {
                fail(SupervisorFailure::InvalidRequest, "tracee string address arithmetic overflow");
            }
            std::uint8_t byte = 0u;
            read_exact_remote(
                stopped_pid_,
                remote_address + static_cast<std::uintptr_t>(index),
                &byte,
                1u);
            if (byte == 0u) {
                return result;
            }
            result.push_back(static_cast<char>(byte));
        }
        fail(SupervisorFailure::ProtocolViolation, "tracee string is missing its NUL terminator");
    } catch (const std::bad_alloc&) {
        fail_terminal();
        fail(SupervisorFailure::ResourceLimit, "tracee string allocation exceeded available resources");
    } catch (const std::length_error&) {
        fail_terminal();
        fail(SupervisorFailure::ResourceLimit, "tracee string allocation exceeded implementation limit");
    } catch (...) {
        fail_terminal();
        throw;
    }
}

}  // namespace evaluation_v6_3_1::capture_v2
