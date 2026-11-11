#include "PrivateBridgeResult.h"

#include <atomic>
#include <cstddef>
#include <cstdlib>
#include <iostream>
#include <new>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

namespace bridge = evaluation_v6_3_1::capture_v2::private_bridge_v3;

namespace {

std::atomic<std::size_t> allocation_count{0u};

[[noreturn]] void fail(std::string_view message) {
    std::cerr << "private_bridge_result_failure: " << message << '\n';
    std::exit(1);
}

void require(bool condition, std::string_view message) {
    if (!condition) {
        fail(message);
    }
}

void normal_path() {
    bridge::Bytes bytes = {1u, 2u, 3u};
    const std::size_t before_success = allocation_count.load();
    bridge::EncodeResult success = bridge::EncodeResult::success(std::move(bytes));
    require(allocation_count.load() == before_success,
            "success result allocated after receiving the output vector");
    require(success.has_value(), "success result does not hold a value");

    const std::size_t before_move = allocation_count.load();
    bridge::EncodeResult moved(std::move(success));
    require(allocation_count.load() == before_move, "result move allocated");
    require(moved.has_value(), "moved result lost its value");
    bridge::Bytes returned = std::move(moved).take_value();
    require(returned == bridge::Bytes({1u, 2u, 3u}),
            "take_value changed the output bytes");

    const std::size_t before_failure = allocation_count.load();
    bridge::EncodeResult failure = bridge::EncodeResult::failure(
        bridge::EncodeFailure{
            bridge::EncodeFailureCode::kInternalEncodingFailure});
    require(allocation_count.load() == before_failure, "failure result allocated");
    require(!failure.has_value(), "failure result reports a value");
    require(
        failure.error().code == bridge::EncodeFailureCode::kInternalEncodingFailure,
        "failure result changed its code");
    const bridge::EncodeFailure returned_error = std::move(failure).take_error();
    require(
        returned_error.code == bridge::EncodeFailureCode::kInternalEncodingFailure,
        "take_error changed its code");
}

[[noreturn]] void invalid_access(std::string_view mode) {
    std::set_terminate([]() noexcept { std::_Exit(86); });
    if (mode == "error-on-value") {
        bridge::Bytes bytes = {1u};
        bridge::EncodeResult result = bridge::EncodeResult::success(std::move(bytes));
        static_cast<void>(result.error());
    }
    if (mode == "value-on-error") {
        bridge::EncodeResult result = bridge::EncodeResult::failure(
            bridge::EncodeFailure{bridge::EncodeFailureCode::kProfileLabelInvalid});
        static_cast<void>(std::move(result).take_value());
    }
    if (mode == "source-after-move") {
        bridge::EncodeResult source = bridge::EncodeResult::failure(
            bridge::EncodeFailure{bridge::EncodeFailureCode::kStdoutLengthInvalid});
        bridge::EncodeResult destination(std::move(source));
        require(
            destination.error().code == bridge::EncodeFailureCode::kStdoutLengthInvalid,
            "move destination changed the error");
        static_cast<void>(source.error());
    }
    if (mode == "value-after-take") {
        bridge::Bytes bytes = {1u};
        bridge::EncodeResult result = bridge::EncodeResult::success(std::move(bytes));
        static_cast<void>(std::move(result).take_value());
        static_cast<void>(std::move(result).take_value());
    }
    fail("unknown invalid-access mode");
}

}  // namespace

void* operator new(std::size_t size) {
    allocation_count.fetch_add(1u);
    if (void* memory = std::malloc(size); memory != nullptr) {
        return memory;
    }
    throw std::bad_alloc();
}

void operator delete(void* memory) noexcept {
    std::free(memory);
}

void operator delete(void* memory, std::size_t) noexcept {
    std::free(memory);
}

static_assert(!std::is_copy_constructible_v<bridge::EncodeResult>);
static_assert(!std::is_copy_assignable_v<bridge::EncodeResult>);
static_assert(std::is_nothrow_move_constructible_v<bridge::EncodeResult>);
static_assert(!std::is_move_assignable_v<bridge::EncodeResult>);
static_assert(noexcept(bridge::EncodeResult::failure(
    bridge::EncodeFailure{bridge::EncodeFailureCode::kInternalEncodingFailure})));

int main(int argc, char** argv) {
    if (argc == 1) {
        normal_path();
        std::cout << "private_bridge_result_ok zero_authority=1\n";
        return 0;
    }
    if (argc == 2) {
        invalid_access(argv[1]);
    }
    fail("usage: harness [invalid-access-mode]");
}
