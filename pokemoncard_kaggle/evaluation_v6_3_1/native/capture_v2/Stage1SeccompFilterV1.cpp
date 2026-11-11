#include "Stage1SeccompFilterV1.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <string_view>

#if !defined(__linux__) || !defined(__x86_64__)
#error "Stage1SeccompFilterV1 is pinned to Linux ELF64 x86_64"
#endif

namespace pokemon::evaluation_v631302 {
namespace {

static_assert(sizeof(std::uint16_t) == 2u);
static_assert(sizeof(std::uint32_t) == 4u);
static_assert(sizeof(std::uint8_t) == 1u);

constexpr std::uint16_t kLoadWordAbsolute = 0x0020u;
constexpr std::uint16_t kJumpEqual = 0x0015u;
constexpr std::uint16_t kJumpSet = 0x0045u;
constexpr std::uint16_t kReturn = 0x0006u;

constexpr std::uint32_t kDeniedSyscalls[18] = {
    56u, 57u, 58u, 80u, 81u, 155u, 165u, 166u, 272u,
    308u, 428u, 429u, 430u, 431u, 432u, 433u, 435u, 442u,
};

constexpr std::uint32_t rotate_right(const std::uint32_t value, const unsigned shift) {
    return (value >> shift) | (value << (32u - shift));
}

constexpr std::uint32_t sha_ch(const std::uint32_t x, const std::uint32_t y,
                               const std::uint32_t z) {
    return (x & y) ^ ((~x) & z);
}

constexpr std::uint32_t sha_maj(const std::uint32_t x, const std::uint32_t y,
                                const std::uint32_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

constexpr std::uint32_t sha_big_sigma0(const std::uint32_t x) {
    return rotate_right(x, 2u) ^ rotate_right(x, 13u) ^ rotate_right(x, 22u);
}

constexpr std::uint32_t sha_big_sigma1(const std::uint32_t x) {
    return rotate_right(x, 6u) ^ rotate_right(x, 11u) ^ rotate_right(x, 25u);
}

constexpr std::uint32_t sha_small_sigma0(const std::uint32_t x) {
    return rotate_right(x, 7u) ^ rotate_right(x, 18u) ^ (x >> 3u);
}

constexpr std::uint32_t sha_small_sigma1(const std::uint32_t x) {
    return rotate_right(x, 17u) ^ rotate_right(x, 19u) ^ (x >> 10u);
}

constexpr std::uint32_t kSha256RoundConstants[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
    0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
    0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
    0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
};

std::uint32_t load_be32(const std::uint8_t* const bytes) noexcept {
    return (static_cast<std::uint32_t>(bytes[0]) << 24u) |
           (static_cast<std::uint32_t>(bytes[1]) << 16u) |
           (static_cast<std::uint32_t>(bytes[2]) << 8u) |
           static_cast<std::uint32_t>(bytes[3]);
}

void store_be32(const std::uint32_t value, std::uint8_t* const bytes) noexcept {
    bytes[0] = static_cast<std::uint8_t>(value >> 24u);
    bytes[1] = static_cast<std::uint8_t>(value >> 16u);
    bytes[2] = static_cast<std::uint8_t>(value >> 8u);
    bytes[3] = static_cast<std::uint8_t>(value);
}

void sha256_block(std::uint32_t state[8], const std::uint8_t block[64]) noexcept {
    std::uint32_t schedule[64]{};
    for (unsigned index = 0u; index < 16u; ++index) {
        schedule[index] = load_be32(block + (index * 4u));
    }
    for (unsigned index = 16u; index < 64u; ++index) {
        schedule[index] = sha_small_sigma1(schedule[index - 2u]) +
                           schedule[index - 7u] +
                           sha_small_sigma0(schedule[index - 15u]) +
                           schedule[index - 16u];
    }

    std::uint32_t a = state[0];
    std::uint32_t b = state[1];
    std::uint32_t c = state[2];
    std::uint32_t d = state[3];
    std::uint32_t e = state[4];
    std::uint32_t f = state[5];
    std::uint32_t g = state[6];
    std::uint32_t h = state[7];
    for (unsigned index = 0u; index < 64u; ++index) {
        const std::uint32_t temp1 = h + sha_big_sigma1(e) + sha_ch(e, f, g) +
                                    kSha256RoundConstants[index] + schedule[index];
        const std::uint32_t temp2 = sha_big_sigma0(a) + sha_maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

void sha256_v1(const std::uint8_t* const bytes, const std::size_t length,
               std::uint8_t digest[32]) noexcept {
    std::uint32_t state[8] = {
        0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
        0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u,
    };
    std::size_t offset = 0u;
    while (offset + 64u <= length) {
        sha256_block(state, bytes + offset);
        offset += 64u;
    }

    std::uint8_t tail[128]{};
    const std::size_t remaining = length - offset;
    for (std::size_t index = 0u; index < remaining; ++index) {
        tail[index] = bytes[offset + index];
    }
    tail[remaining] = 0x80u;
    const std::uint64_t bit_length = static_cast<std::uint64_t>(length) * 8u;
    const std::size_t tail_length = remaining < 56u ? 64u : 128u;
    for (unsigned index = 0u; index < 8u; ++index) {
        tail[tail_length - 1u - index] = static_cast<std::uint8_t>(bit_length >> (index * 8u));
    }
    sha256_block(state, tail);
    if (tail_length == 128u) {
        sha256_block(state, tail + 64u);
    }
    for (unsigned index = 0u; index < 8u; ++index) {
        store_be32(state[index], digest + (index * 4u));
    }
}

void serialize_filter_v1(const sock_filter* const filter, std::uint8_t* const bytes) noexcept {
    for (std::size_t index = 0u; index < SeccompPolicyV1::instruction_count; ++index) {
        const std::size_t offset = index * 8u;
        const auto code = static_cast<std::uint16_t>(filter[index].code);
        const auto jump_true = static_cast<std::uint8_t>(filter[index].jt);
        const auto jump_false = static_cast<std::uint8_t>(filter[index].jf);
        const auto constant = static_cast<std::uint32_t>(filter[index].k);
        bytes[offset] = static_cast<std::uint8_t>(code);
        bytes[offset + 1u] = static_cast<std::uint8_t>(code >> 8u);
        bytes[offset + 2u] = jump_true;
        bytes[offset + 3u] = jump_false;
        bytes[offset + 4u] = static_cast<std::uint8_t>(constant);
        bytes[offset + 5u] = static_cast<std::uint8_t>(constant >> 8u);
        bytes[offset + 6u] = static_cast<std::uint8_t>(constant >> 16u);
        bytes[offset + 7u] = static_cast<std::uint8_t>(constant >> 24u);
    }
}

bool equal_bytes(const std::uint8_t* const left, const std::uint8_t* const right,
                 const std::size_t count) noexcept {
    return std::memcmp(left, right, count) == 0;
}

bool parse_hex_uintptr(const std::string_view value, std::uintptr_t* const output) noexcept {
    if (value.empty() || output == nullptr) {
        return false;
    }
    std::uintptr_t result = 0u;
    for (const char byte : value) {
        std::uintptr_t digit = 0u;
        if (byte >= '0' && byte <= '9') {
            digit = static_cast<std::uintptr_t>(byte - '0');
        } else if (byte >= 'a' && byte <= 'f') {
            digit = static_cast<std::uintptr_t>(byte - 'a' + 10);
        } else {
            return false;
        }
        if (result > (std::numeric_limits<std::uintptr_t>::max() - digit) / 16u) {
            return false;
        }
        result = result * 16u + digit;
    }
    *output = result;
    return true;
}

}  // namespace

const sock_filter kStage1SeccompFilterV1[SeccompPolicyV1::instruction_count] = {
    {kLoadWordAbsolute, 0u, 0u, 4u},
    {kJumpEqual, 1u, 0u, SeccompPolicyV1::audit_arch_x86_64},
    {kReturn, 0u, 0u, SeccompPolicyV1::kill_process},
    {kLoadWordAbsolute, 0u, 0u, 0u},
    {kJumpSet, 0u, 1u, SeccompPolicyV1::x32_syscall_bit},
    {kReturn, 0u, 0u, SeccompPolicyV1::kill_process},
    {kJumpEqual, 0u, 1u, kDeniedSyscalls[0]},
    {kReturn, 0u, 0u, SeccompPolicyV1::kill_process},
    {kJumpEqual, 0u, 1u, kDeniedSyscalls[1]},
    {kReturn, 0u, 0u, SeccompPolicyV1::kill_process},
    {kJumpEqual, 0u, 1u, kDeniedSyscalls[2]},
    {kReturn, 0u, 0u, SeccompPolicyV1::kill_process},
    {kJumpEqual, 0u, 1u, kDeniedSyscalls[3]},
    {kReturn, 0u, 0u, SeccompPolicyV1::kill_process},
    {kJumpEqual, 0u, 1u, kDeniedSyscalls[4]},
    {kReturn, 0u, 0u, SeccompPolicyV1::kill_process},
    {kJumpEqual, 0u, 1u, kDeniedSyscalls[5]},
    {kReturn, 0u, 0u, SeccompPolicyV1::kill_process},
    {kJumpEqual, 0u, 1u, kDeniedSyscalls[6]},
    {kReturn, 0u, 0u, SeccompPolicyV1::kill_process},
    {kJumpEqual, 0u, 1u, kDeniedSyscalls[7]},
    {kReturn, 0u, 0u, SeccompPolicyV1::kill_process},
    {kJumpEqual, 0u, 1u, kDeniedSyscalls[8]},
    {kReturn, 0u, 0u, SeccompPolicyV1::kill_process},
    {kJumpEqual, 0u, 1u, kDeniedSyscalls[9]},
    {kReturn, 0u, 0u, SeccompPolicyV1::kill_process},
    {kJumpEqual, 0u, 1u, kDeniedSyscalls[10]},
    {kReturn, 0u, 0u, SeccompPolicyV1::kill_process},
    {kJumpEqual, 0u, 1u, kDeniedSyscalls[11]},
    {kReturn, 0u, 0u, SeccompPolicyV1::kill_process},
    {kJumpEqual, 0u, 1u, kDeniedSyscalls[12]},
    {kReturn, 0u, 0u, SeccompPolicyV1::kill_process},
    {kJumpEqual, 0u, 1u, kDeniedSyscalls[13]},
    {kReturn, 0u, 0u, SeccompPolicyV1::kill_process},
    {kJumpEqual, 0u, 1u, kDeniedSyscalls[14]},
    {kReturn, 0u, 0u, SeccompPolicyV1::kill_process},
    {kJumpEqual, 0u, 1u, kDeniedSyscalls[15]},
    {kReturn, 0u, 0u, SeccompPolicyV1::kill_process},
    {kJumpEqual, 0u, 1u, kDeniedSyscalls[16]},
    {kReturn, 0u, 0u, SeccompPolicyV1::kill_process},
    {kJumpEqual, 0u, 1u, kDeniedSyscalls[17]},
    {kReturn, 0u, 0u, SeccompPolicyV1::kill_process},
    {kReturn, 0u, 0u, SeccompPolicyV1::allow},
};

const std::uint8_t kStage1SeccompRawBpfV1[SeccompPolicyV1::raw_byte_count] = {
    0x20u, 0x00u, 0x00u, 0x00u, 0x04u, 0x00u, 0x00u, 0x00u,
    0x15u, 0x00u, 0x01u, 0x00u, 0x3eu, 0x00u, 0x00u, 0xc0u,
    0x06u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x80u,
    0x20u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
    0x45u, 0x00u, 0x00u, 0x01u, 0x00u, 0x00u, 0x00u, 0x40u,
    0x06u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x80u,
    0x15u, 0x00u, 0x00u, 0x01u, 0x38u, 0x00u, 0x00u, 0x00u,
    0x06u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x80u,
    0x15u, 0x00u, 0x00u, 0x01u, 0x39u, 0x00u, 0x00u, 0x00u,
    0x06u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x80u,
    0x15u, 0x00u, 0x00u, 0x01u, 0x3au, 0x00u, 0x00u, 0x00u,
    0x06u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x80u,
    0x15u, 0x00u, 0x00u, 0x01u, 0x50u, 0x00u, 0x00u, 0x00u,
    0x06u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x80u,
    0x15u, 0x00u, 0x00u, 0x01u, 0x51u, 0x00u, 0x00u, 0x00u,
    0x06u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x80u,
    0x15u, 0x00u, 0x00u, 0x01u, 0x9bu, 0x00u, 0x00u, 0x00u,
    0x06u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x80u,
    0x15u, 0x00u, 0x00u, 0x01u, 0xa5u, 0x00u, 0x00u, 0x00u,
    0x06u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x80u,
    0x15u, 0x00u, 0x00u, 0x01u, 0xa6u, 0x00u, 0x00u, 0x00u,
    0x06u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x80u,
    0x15u, 0x00u, 0x00u, 0x01u, 0x10u, 0x01u, 0x00u, 0x00u,
    0x06u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x80u,
    0x15u, 0x00u, 0x00u, 0x01u, 0x34u, 0x01u, 0x00u, 0x00u,
    0x06u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x80u,
    0x15u, 0x00u, 0x00u, 0x01u, 0xacu, 0x01u, 0x00u, 0x00u,
    0x06u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x80u,
    0x15u, 0x00u, 0x00u, 0x01u, 0xadu, 0x01u, 0x00u, 0x00u,
    0x06u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x80u,
    0x15u, 0x00u, 0x00u, 0x01u, 0xaeu, 0x01u, 0x00u, 0x00u,
    0x06u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x80u,
    0x15u, 0x00u, 0x00u, 0x01u, 0xafu, 0x01u, 0x00u, 0x00u,
    0x06u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x80u,
    0x15u, 0x00u, 0x00u, 0x01u, 0xb0u, 0x01u, 0x00u, 0x00u,
    0x06u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x80u,
    0x15u, 0x00u, 0x00u, 0x01u, 0xb1u, 0x01u, 0x00u, 0x00u,
    0x06u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x80u,
    0x15u, 0x00u, 0x00u, 0x01u, 0xb3u, 0x01u, 0x00u, 0x00u,
    0x06u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x80u,
    0x15u, 0x00u, 0x00u, 0x01u, 0xbau, 0x01u, 0x00u, 0x00u,
    0x06u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x80u,
    0x06u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0xffu, 0x7fu,
};

bool initialize_stage1_seccomp_program_v1(sock_fprog* const output) noexcept {
    if (output == nullptr) {
        return false;
    }
    std::memset(output, 0, sizeof(*output));
    output->len = static_cast<unsigned short>(SeccompPolicyV1::instruction_count);
    // sock_fprog follows the kernel ABI and exposes a non-const pointer.  The
    // pointed-to object itself remains the immutable const array above.
    output->filter = const_cast<sock_filter*>(kStage1SeccompFilterV1);
    return validate_stage1_seccomp_program_v1(output);
}

bool validate_stage1_seccomp_filter_v1(
    const sock_filter* const actual_filter,
    const std::size_t instruction_count) noexcept {
    if (actual_filter == nullptr || instruction_count != SeccompPolicyV1::instruction_count) {
        return false;
    }
    std::uint8_t serialized[SeccompPolicyV1::raw_byte_count]{};
    serialize_filter_v1(actual_filter, serialized);
    if (!equal_bytes(serialized, kStage1SeccompRawBpfV1, SeccompPolicyV1::raw_byte_count)) {
        return false;
    }
    std::uint8_t digest[32]{};
    sha256_v1(serialized, SeccompPolicyV1::raw_byte_count, digest);
    return equal_bytes(digest, SeccompPolicyV1::raw_bpf_sha256, sizeof(digest));
}

bool validate_stage1_seccomp_program_v1(const sock_fprog* const actual_program) noexcept {
    if (actual_program == nullptr ||
        actual_program->len != SeccompPolicyV1::instruction_count ||
        actual_program->filter != kStage1SeccompFilterV1) {
        return false;
    }
    const auto* const descriptor_bytes = reinterpret_cast<const std::uint8_t*>(actual_program);
    for (std::size_t index = 2u; index < 8u; ++index) {
        if (descriptor_bytes[index] != 0u) {
            return false;
        }
    }
    return validate_stage1_seccomp_filter_v1(
        actual_program->filter,
        static_cast<std::size_t>(actual_program->len));
}

bool validate_stage1_seccomp_program_mapping_v1(
    const sock_fprog* const actual_program,
    const std::string_view proc_self_maps) noexcept {
    if (!validate_stage1_seccomp_program_v1(actual_program) || proc_self_maps.empty() ||
        proc_self_maps.find('\0') != std::string_view::npos || proc_self_maps.back() != '\n') {
        return false;
    }
    const std::uintptr_t target_start =
        reinterpret_cast<std::uintptr_t>(actual_program->filter);
    constexpr std::size_t kTargetBytes = SeccompPolicyV1::raw_byte_count;
    if (target_start > std::numeric_limits<std::uintptr_t>::max() - kTargetBytes) {
        return false;
    }
    const std::uintptr_t target_end = target_start + kTargetBytes;
    std::size_t matches = 0u;
    std::size_t line_start = 0u;
    while (line_start < proc_self_maps.size()) {
        const std::size_t newline = proc_self_maps.find('\n', line_start);
        if (newline == std::string_view::npos || newline == line_start) {
            return false;
        }
        const std::string_view line = proc_self_maps.substr(line_start, newline - line_start);
        const std::size_t hyphen = line.find('-');
        const std::size_t first_space = line.find(' ');
        if (hyphen == std::string_view::npos || first_space == std::string_view::npos ||
            hyphen == 0u || hyphen + 1u >= first_space || first_space + 5u >= line.size() ||
            line[first_space + 5u] != ' ') {
            return false;
        }
        std::uintptr_t mapping_start = 0u;
        std::uintptr_t mapping_end = 0u;
        if (!parse_hex_uintptr(line.substr(0u, hyphen), &mapping_start) ||
            !parse_hex_uintptr(
                line.substr(hyphen + 1u, first_space - hyphen - 1u),
                &mapping_end) ||
            mapping_start >= mapping_end) {
            return false;
        }
        const std::string_view permissions = line.substr(first_space + 1u, 4u);
        if ((permissions[0] != 'r' && permissions[0] != '-') ||
            (permissions[1] != '-' && permissions[1] != 'w') ||
            (permissions[2] != '-' && permissions[2] != 'x') ||
            (permissions[3] != 'p' && permissions[3] != 's')) {
            return false;
        }
        if (mapping_start <= target_start && target_end <= mapping_end) {
            ++matches;
            if (permissions[0] != 'r' || permissions[1] != '-') {
                return false;
            }
        }
        line_start = newline + 1u;
    }
    return matches == 1u;
}

}  // namespace pokemon::evaluation_v631302
