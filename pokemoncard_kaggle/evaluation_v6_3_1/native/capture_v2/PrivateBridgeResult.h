#ifndef EVALUATION_V6_3_1_CAPTURE_V2_PRIVATE_BRIDGE_RESULT_H
#define EVALUATION_V6_3_1_CAPTURE_V2_PRIVATE_BRIDGE_RESULT_H

#include <cstddef>
#include <cstdint>
#include <exception>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

namespace evaluation_v6_3_1::capture_v2::private_bridge_v3 {

enum class EncodeFailureCode : std::uint8_t {
    kInvalidSuccessInvariant = 1u,
    kProfileLabelInvalid = 2u,
    kStdoutLengthInvalid = 3u,
    kEncodedSizeOverflow = 4u,
    kAllocationFailure = 5u,
    kInternalEncodingFailure = 6u,
};

struct EncodeFailure final {
    EncodeFailureCode code;
};

using Bytes = std::vector<std::uint8_t>;

template <class T, class E>
class Result final {
public:
    Result() = delete;

    Result(const Result&) = delete;
    Result& operator=(const Result&) = delete;

    Result(Result&& other) noexcept : storage_(std::monostate{}) {
        static_assert(std::is_nothrow_move_constructible_v<T>);
        static_assert(std::is_nothrow_move_constructible_v<E>);
        if (other.storage_.index() == kValueIndex) {
            storage_.template emplace<kValueIndex>(
                std::move(std::get<kValueIndex>(other.storage_)));
        } else if (other.storage_.index() == kErrorIndex) {
            storage_.template emplace<kErrorIndex>(
                std::move(std::get<kErrorIndex>(other.storage_)));
        }
        other.storage_.template emplace<kConsumedIndex>();
    }

    Result& operator=(Result&&) = delete;

    ~Result() noexcept = default;

    [[nodiscard]] static Result success(T&& value) noexcept {
        return Result(SuccessTag{}, std::move(value));
    }

    [[nodiscard]] static Result failure(E error) noexcept {
        return Result(FailureTag{}, std::move(error));
    }

    [[nodiscard]] bool has_value() const noexcept {
        return storage_.index() == kValueIndex;
    }

    [[nodiscard]] const E& error() const& noexcept {
        if (storage_.index() != kErrorIndex) {
            std::terminate();
        }
        return std::get<kErrorIndex>(storage_);
    }

    [[nodiscard]] T take_value() && noexcept {
        if (storage_.index() != kValueIndex) {
            std::terminate();
        }
        T value(std::move(std::get<kValueIndex>(storage_)));
        storage_.template emplace<kConsumedIndex>();
        return value;
    }

    [[nodiscard]] E take_error() && noexcept {
        if (storage_.index() != kErrorIndex) {
            std::terminate();
        }
        E error(std::move(std::get<kErrorIndex>(storage_)));
        storage_.template emplace<kConsumedIndex>();
        return error;
    }

private:
    struct SuccessTag final {};
    struct FailureTag final {};

    static constexpr std::size_t kConsumedIndex = 0u;
    static constexpr std::size_t kValueIndex = 1u;
    static constexpr std::size_t kErrorIndex = 2u;

    explicit Result(SuccessTag, T&& value) noexcept
        : storage_(std::in_place_index<kValueIndex>, std::move(value)) {
        static_assert(std::is_nothrow_move_constructible_v<T>);
    }

    explicit Result(FailureTag, E error) noexcept
        : storage_(std::in_place_index<kErrorIndex>, std::move(error)) {
        static_assert(std::is_nothrow_move_constructible_v<E>);
    }

    std::variant<std::monostate, T, E> storage_;
};

using EncodeResult = Result<Bytes, EncodeFailure>;

static_assert(std::is_nothrow_move_constructible_v<Bytes>);
static_assert(std::is_nothrow_destructible_v<Bytes>);
static_assert(std::is_trivially_copyable_v<EncodeFailure>);
static_assert(std::is_nothrow_move_constructible_v<EncodeFailure>);
static_assert(std::is_nothrow_destructible_v<EncodeFailure>);
static_assert(!std::is_copy_constructible_v<EncodeResult>);
static_assert(!std::is_copy_assignable_v<EncodeResult>);
static_assert(std::is_nothrow_move_constructible_v<EncodeResult>);
static_assert(!std::is_move_assignable_v<EncodeResult>);

}  // namespace evaluation_v6_3_1::capture_v2::private_bridge_v3

#endif  // EVALUATION_V6_3_1_CAPTURE_V2_PRIVATE_BRIDGE_RESULT_H
