// Stage-1-only independent restricted x86-64 decoder for LaunchGateV1.
//
// This program is intentionally standalone.  It has no decoder-library
// dependency, no rendered-instruction path, and no shared executable schema
// logic.  It derives the closed wire
// manifest directly from the gate page bytes and always has zero authority.

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>
#include <unistd.h>

namespace {

constexpr std::size_t kPageSize = 4096u;
constexpr std::uint64_t kCodeSize = 874u;
constexpr std::uint64_t kProtocolId = 631302u;
constexpr std::uint64_t kWireVersion = 1u;
constexpr int kExitUsage = 64;
constexpr int kExitDecode = 65;
constexpr int kExitIo = 74;
constexpr bool kZeroAuthority = true;
static_assert(kZeroAuthority);

constexpr std::uint64_t kAttrRex = 1u << 0u;
constexpr std::uint64_t kAttrRexW = 1u << 1u;
constexpr std::uint64_t kAttrRexR = 1u << 2u;
constexpr std::uint64_t kAttrRexX = 1u << 3u;
constexpr std::uint64_t kAttrRexB = 1u << 4u;
constexpr std::uint64_t kAttrF3Endbr = 1u << 5u;
constexpr std::uint64_t kAttrModrm = 1u << 6u;
constexpr std::uint64_t kAttrSib = 1u << 7u;
constexpr std::uint64_t kAttrDisp8 = 1u << 8u;
constexpr std::uint64_t kAttrDisp32 = 1u << 9u;
constexpr std::uint64_t kAttrImm8 = 1u << 10u;
constexpr std::uint64_t kAttrImm16 = 1u << 11u;
constexpr std::uint64_t kAttrImm32 = 1u << 12u;
constexpr std::uint64_t kAttrImm64 = 1u << 13u;
constexpr std::uint64_t kAttrImmSignExtend = 1u << 14u;
[[maybe_unused]] constexpr std::uint64_t kAttrImmZeroExtend = 1u << 15u;
constexpr std::uint64_t kAttrDest32ZeroExtend = 1u << 16u;
constexpr std::uint64_t kAttrRipRelative = 1u << 17u;
constexpr std::uint64_t kAttrBranch8 = 1u << 18u;
constexpr std::uint64_t kAttrBranch32 = 1u << 19u;
constexpr std::uint64_t kAttrOpcodeMap0f = 1u << 20u;

enum class Opcode : std::uint8_t {
    Endbr64 = 1,
    Mov = 2,
    Lea = 3,
    XorZero = 4,
    Test = 5,
    Cmp = 6,
    Jcc = 7,
    Jmp = 8,
    Syscall = 9,
    Ret = 10,
};

enum class OperandTag : std::uint8_t { Register = 0, Immediate = 1, Branch = 2, Memory = 3, Address = 4 };
enum class Access : std::uint8_t { Read = 1, Write = 2, ReadWrite = 3, Clobber = 4 };
enum class Provenance : std::uint8_t { Unknown = 0, Input = 1, Result = 2, CloneArgs = 3 };

struct PointerValue final {
    Provenance provenance = Provenance::Unknown;
    std::int64_t offset = 0;

    [[nodiscard]] bool operator==(const PointerValue& other) const noexcept {
        return provenance == other.provenance && offset == other.offset;
    }
};

struct RegisterState final {
    std::array<PointerValue, 17u> values{};

    [[nodiscard]] bool operator==(const RegisterState& other) const noexcept {
        return values == other.values;
    }
};

struct Prefix final {
    bool rex = false;
    bool w = false;
    bool r = false;
    bool x = false;
    bool b = false;
    std::uint64_t attributes = 0u;
};

struct RexUse final {
    bool r = false;
    bool x = false;
    bool b = false;
    bool low8 = false;
};

struct Address final {
    std::uint64_t base = 0u;
    std::uint64_t index = 0u;
    std::uint64_t scale = 1u;
    std::uint64_t displacement_width = 0u;
    std::int64_t displacement = 0;
    std::int64_t rip_target = -1;
    bool has_sib = false;
};

struct Operand final {
    OperandTag tag = OperandTag::Register;
    Access access = Access::Read;
    std::uint64_t reg = 0u;
    std::uint64_t encoded_width = 0u;
    std::uint64_t semantic_width = 0u;
    std::uint64_t signedness = 0u;
    std::uint64_t extension = 0u;
    std::vector<std::uint8_t> encoded;
    std::vector<std::uint8_t> semantic;
    std::int64_t signed_value = 0;
    std::uint64_t branch_target = 0u;
    Address address{};
    std::uint64_t provenance = 0u;
    std::uint64_t provenance_offset = 0u;
};

struct Instruction final {
    std::uint64_t offset = 0u;
    std::uint64_t length = 0u;
    Opcode opcode = Opcode::Mov;
    std::uint64_t condition = 0u;
    std::vector<Operand> explicit_operands;
    std::vector<Operand> implicit_reads;
    std::vector<Operand> implicit_writes;
    std::uint64_t flags_read = 0u;
    std::uint64_t flags_write = 0u;
    std::uint64_t flags_undefined = 0u;
    std::uint64_t attributes = 0u;
    std::vector<std::uint8_t> raw;
    std::vector<std::uint64_t> successors;
    RegisterState after{};
};

struct ParsedRm final {
    bool register_form = false;
    std::uint64_t reg = 0u;
    Address address{};
    std::uint8_t reg_field = 0u;
};

[[noreturn]] void fail(const char* message, const int code = kExitDecode) {
    std::fputs(message, stderr);
    std::fputc('\n', stderr);
    std::exit(code);
}

[[nodiscard]] bool parse_code_size(const char* text, std::uint64_t* output) {
    if (text == nullptr || *text == '\0' || output == nullptr) {
        return false;
    }
    std::uint64_t value = 0u;
    for (const char* cursor = text; *cursor != '\0'; ++cursor) {
        if (*cursor < '0' || *cursor > '9' || value > (UINT64_MAX - 9u) / 10u) {
            return false;
        }
        value = value * 10u + static_cast<std::uint64_t>(*cursor - '0');
    }
    *output = value;
    return true;
}

[[nodiscard]] std::vector<std::uint8_t> read_exact_page(const char* path) {
    const int fd = ::open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        fail("LAUNCH_GATE_RESTRICTED_X86_INPUT_OPEN_FAILED", kExitIo);
    }
    std::vector<std::uint8_t> page(kPageSize);
    std::size_t used = 0u;
    while (used != page.size()) {
        const ssize_t count = ::read(fd, page.data() + used, page.size() - used);
        if (count <= 0) {
            ::close(fd);
            fail("LAUNCH_GATE_RESTRICTED_X86_PAGE_SIZE_INVALID", kExitDecode);
        }
        used += static_cast<std::size_t>(count);
    }
    std::uint8_t extra = 0u;
    const ssize_t count = ::read(fd, &extra, 1u);
    const int saved = errno;
    ::close(fd);
    if (count != 0 || (count < 0 && saved != 0)) {
        fail("LAUNCH_GATE_RESTRICTED_X86_PAGE_SIZE_INVALID", kExitDecode);
    }
    return page;
}

// Small standalone SHA-256 implementation.  It deliberately shares no code
// with the other decoder or the profile tooling.
class Sha256 final {
public:
    Sha256() { reset(); }

    void update(const std::uint8_t* data, std::size_t length) {
        for (std::size_t index = 0u; index < length; ++index) {
            block_[used_++] = data[index];
            if (used_ == block_.size()) {
                transform();
                bits_ += 512u;
                used_ = 0u;
            }
        }
    }

    [[nodiscard]] std::array<std::uint8_t, 32u> finish() {
        const std::uint64_t final_bits = bits_ + static_cast<std::uint64_t>(used_) * 8u;
        block_[used_++] = 0x80u;
        if (used_ > 56u) {
            while (used_ < 64u) block_[used_++] = 0u;
            transform();
            used_ = 0u;
        }
        while (used_ < 56u) block_[used_++] = 0u;
        for (int shift = 56; shift >= 0; shift -= 8) block_[used_++] = static_cast<std::uint8_t>(final_bits >> shift);
        transform();
        std::array<std::uint8_t, 32u> result{};
        for (std::size_t index = 0u; index < state_.size(); ++index) {
            for (int shift = 24; shift >= 0; shift -= 8) result[index * 4u + static_cast<std::size_t>((24 - shift) / 8)] = static_cast<std::uint8_t>(state_[index] >> shift);
        }
        return result;
    }

private:
    static constexpr std::array<std::uint32_t, 64u> kRound = {
        0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
        0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
        0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
        0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
        0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
        0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
        0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
        0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u};

    std::array<std::uint32_t, 8u> state_{};
    std::array<std::uint8_t, 64u> block_{};
    std::uint64_t bits_ = 0u;
    std::size_t used_ = 0u;

    static std::uint32_t rotate(const std::uint32_t value, const unsigned shift) { return (value >> shift) | (value << (32u - shift)); }
    void reset() { state_ = {0x6a09e667u,0xbb67ae85u,0x3c6ef372u,0xa54ff53au,0x510e527fu,0x9b05688cu,0x1f83d9abu,0x5be0cd19u}; bits_ = 0u; used_ = 0u; }
    void transform() {
        std::array<std::uint32_t, 64u> words{};
        for (std::size_t index = 0u; index < 16u; ++index) words[index] = (static_cast<std::uint32_t>(block_[index * 4u]) << 24u) | (static_cast<std::uint32_t>(block_[index * 4u + 1u]) << 16u) | (static_cast<std::uint32_t>(block_[index * 4u + 2u]) << 8u) | block_[index * 4u + 3u];
        for (std::size_t index = 16u; index < words.size(); ++index) { const std::uint32_t a = rotate(words[index - 15u], 7u) ^ rotate(words[index - 15u], 18u) ^ (words[index - 15u] >> 3u); const std::uint32_t b = rotate(words[index - 2u], 17u) ^ rotate(words[index - 2u], 19u) ^ (words[index - 2u] >> 10u); words[index] = words[index - 16u] + a + words[index - 7u] + b; }
        std::uint32_t a = state_[0], b = state_[1], c = state_[2], d = state_[3], e = state_[4], f = state_[5], g = state_[6], h = state_[7];
        for (std::size_t index = 0u; index < words.size(); ++index) { const std::uint32_t s1 = rotate(e, 6u) ^ rotate(e, 11u) ^ rotate(e, 25u); const std::uint32_t choose = (e & f) ^ (~e & g); const std::uint32_t t1 = h + s1 + choose + kRound[index] + words[index]; const std::uint32_t s0 = rotate(a, 2u) ^ rotate(a, 13u) ^ rotate(a, 22u); const std::uint32_t majority = (a & b) ^ (a & c) ^ (b & c); const std::uint32_t t2 = s0 + majority; h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2; }
        state_[0] += a; state_[1] += b; state_[2] += c; state_[3] += d; state_[4] += e; state_[5] += f; state_[6] += g; state_[7] += h;
    }
};

class Reader final {
public:
    Reader(const std::vector<std::uint8_t>& bytes, const std::uint64_t start) : bytes_(bytes), start_(start), cursor_(start) {}
    [[nodiscard]] std::uint64_t start() const noexcept { return start_; }
    [[nodiscard]] std::uint64_t cursor() const noexcept { return cursor_; }
    [[nodiscard]] std::uint8_t take() { if (cursor_ >= kCodeSize) fail("LAUNCH_GATE_RESTRICTED_X86_TRUNCATED_INSTRUCTION"); return bytes_[static_cast<std::size_t>(cursor_++)]; }
    [[nodiscard]] std::vector<std::uint8_t> raw() const { return std::vector<std::uint8_t>(bytes_.begin() + static_cast<std::ptrdiff_t>(start_), bytes_.begin() + static_cast<std::ptrdiff_t>(cursor_)); }
private:
    const std::vector<std::uint8_t>& bytes_;
    std::uint64_t start_;
    std::uint64_t cursor_;
};

[[nodiscard]] std::int64_t sign_extend(const std::uint64_t value, const std::uint64_t width) {
    if (width == 64u) return static_cast<std::int64_t>(value);
    const std::uint64_t sign = 1ull << (width - 1u);
    const std::uint64_t mask = (1ull << width) - 1u;
    return static_cast<std::int64_t>((value & sign) ? (value | ~mask) : value);
}

[[nodiscard]] std::vector<std::uint8_t> little_bytes(const std::uint64_t value, const std::uint64_t width) {
    std::vector<std::uint8_t> result(static_cast<std::size_t>(width / 8u));
    for (std::size_t index = 0u; index < result.size(); ++index) result[index] = static_cast<std::uint8_t>(value >> (index * 8u));
    return result;
}

[[nodiscard]] std::uint64_t read_unsigned(Reader* reader, const std::uint64_t width) {
    std::uint64_t value = 0u;
    for (std::uint64_t index = 0u; index < width / 8u; ++index) value |= static_cast<std::uint64_t>(reader->take()) << (index * 8u);
    return value;
}

[[nodiscard]] std::uint64_t reg_id(const std::uint8_t raw, const std::uint64_t width, const bool rex_present, RexUse* use) {
    if (raw > 15u) fail("LAUNCH_GATE_RESTRICTED_X86_REGISTER_ENCODING_INVALID");
    if (width == 64u) return 1u + raw;
    if (width == 32u) return 18u + raw;
    if (width == 16u) return 34u + raw;
    if (width == 8u) {
        if (raw < 4u) return 50u + raw;
        if (raw < 8u) {
            if (!rex_present) fail("LAUNCH_GATE_RESTRICTED_X86_HIGH_BYTE_REGISTER_FORBIDDEN");
            if (use != nullptr) use->low8 = true;
            return 54u + (raw - 4u);
        }
        return 58u + (raw - 8u);
    }
    fail("LAUNCH_GATE_RESTRICTED_X86_OPERAND_WIDTH_INVALID");
}

[[nodiscard]] std::uint64_t parent64(const std::uint64_t reg) {
    if (reg >= 1u && reg <= 16u) return reg;
    if (reg >= 18u && reg <= 33u) return reg - 17u;
    if (reg >= 34u && reg <= 49u) return reg - 33u;
    if (reg >= 50u && reg <= 65u) return reg - 49u;
    fail("LAUNCH_GATE_RESTRICTED_X86_REGISTER_VIEW_INVALID");
}

struct PrefixAndOpcode final { Prefix prefix{}; std::uint8_t opcode = 0u; bool endbr = false; };

[[nodiscard]] PrefixAndOpcode decode_prefix(Reader* reader) {
    PrefixAndOpcode result;
    const std::uint8_t first = reader->take();
    if (first == 0xf3u) {
        if (reader->take() != 0x0fu || reader->take() != 0x1eu || reader->take() != 0xfau) fail("LAUNCH_GATE_RESTRICTED_X86_PREFIX_FORBIDDEN");
        result.prefix.attributes = kAttrF3Endbr | kAttrModrm | kAttrOpcodeMap0f;
        result.endbr = true;
        return result;
    }
    if (first == 0xf0u || first == 0xf2u || first == 0x66u || first == 0x67u || first == 0x2eu || first == 0x36u || first == 0x3eu || first == 0x26u || first == 0x64u || first == 0x65u) fail("LAUNCH_GATE_RESTRICTED_X86_PREFIX_FORBIDDEN");
    if (first >= 0x40u && first <= 0x4fu) {
        result.prefix.rex = true;
        result.prefix.w = (first & 8u) != 0u;
        result.prefix.r = (first & 4u) != 0u;
        result.prefix.x = (first & 2u) != 0u;
        result.prefix.b = (first & 1u) != 0u;
        result.prefix.attributes = kAttrRex | (result.prefix.w ? kAttrRexW : 0u) | (result.prefix.r ? kAttrRexR : 0u) | (result.prefix.x ? kAttrRexX : 0u) | (result.prefix.b ? kAttrRexB : 0u);
        const std::uint8_t opcode = reader->take();
        if (opcode >= 0x40u && opcode <= 0x4fu) fail("LAUNCH_GATE_RESTRICTED_X86_MULTIPLE_REX_FORBIDDEN");
        result.opcode = opcode;
        return result;
    }
    result.opcode = first;
    return result;
}

void validate_rex(const Prefix& prefix, const RexUse& use) {
    if (!prefix.rex) return;
    if (prefix.r != use.r || prefix.x != use.x || prefix.b != use.b) fail("LAUNCH_GATE_RESTRICTED_X86_REDUNDANT_REX");
    if (!prefix.w && !prefix.r && !prefix.x && !prefix.b && !use.low8) fail("LAUNCH_GATE_RESTRICTED_X86_REDUNDANT_REX");
}

[[nodiscard]] ParsedRm parse_modrm(Reader* reader, const Prefix& prefix, const std::uint64_t width, RexUse* use) {
    const std::uint8_t modrm = reader->take();
    ParsedRm result;
    result.reg_field = static_cast<std::uint8_t>(((modrm >> 3u) & 7u) + (prefix.r ? 8u : 0u));
    if (prefix.r) use->r = true;
    const std::uint8_t mod = modrm >> 6u;
    const std::uint8_t rm_low = modrm & 7u;
    if (mod == 3u) {
        result.register_form = true;
        if (prefix.b) use->b = true;
        result.reg = reg_id(static_cast<std::uint8_t>(rm_low + (prefix.b ? 8u : 0u)), width, prefix.rex, use);
        return result;
    }
    result.address.scale = 1u;
    if (rm_low == 4u) {
        const std::uint8_t sib = reader->take();
        result.address.has_sib = true;
        const std::uint8_t scale_bits = sib >> 6u;
        const std::uint8_t index_low = (sib >> 3u) & 7u;
        const std::uint8_t base_low = sib & 7u;
        result.address.scale = 1u << scale_bits;
        if (index_low == 4u && !prefix.x) {
            result.address.index = 0u;
            result.address.scale = 1u;
        } else {
            if (prefix.x) use->x = true;
            result.address.index = 1u + index_low + (prefix.x ? 8u : 0u);
            if (result.address.index == 5u) fail("LAUNCH_GATE_RESTRICTED_X86_RSP_INDEX_FORBIDDEN");
        }
        if (mod == 0u && base_low == 5u && !prefix.b) fail("LAUNCH_GATE_RESTRICTED_X86_ABSOLUTE_ADDRESS_FORBIDDEN");
        if (prefix.b) use->b = true;
        result.address.base = 1u + base_low + (prefix.b ? 8u : 0u);
    } else if (mod == 0u && rm_low == 5u && !prefix.b) {
        result.address.base = 17u;
        result.address.displacement_width = 32u;
        result.address.displacement = sign_extend(read_unsigned(reader, 32u), 32u);
        result.address.rip_target = static_cast<std::int64_t>(reader->cursor()) + result.address.displacement;
        if (result.address.rip_target < 0 || result.address.rip_target >= static_cast<std::int64_t>(kPageSize)) fail("LAUNCH_GATE_RESTRICTED_X86_RIP_TARGET_INVALID");
        return result;
    } else {
        if (prefix.b) use->b = true;
        result.address.base = 1u + rm_low + (prefix.b ? 8u : 0u);
    }
    if (mod == 1u) {
        result.address.displacement_width = 8u;
        result.address.displacement = sign_extend(read_unsigned(reader, 8u), 8u);
    } else if (mod == 2u) {
        result.address.displacement_width = 32u;
        result.address.displacement = sign_extend(read_unsigned(reader, 32u), 32u);
    }
    return result;
}

[[nodiscard]] Operand register_operand(const std::uint64_t reg, const Access access) { Operand value; value.tag = OperandTag::Register; value.reg = reg; value.access = access; return value; }

[[nodiscard]] Operand immediate_operand(Reader* reader, const std::uint64_t encoded_width, const std::uint64_t semantic_width, const bool sign_extended, std::uint64_t* attributes) {
    const std::uint64_t raw = read_unsigned(reader, encoded_width);
    Operand value;
    value.tag = OperandTag::Immediate;
    value.encoded_width = encoded_width;
    value.semantic_width = semantic_width;
    value.signedness = sign_extended ? 1u : 0u;
    value.extension = sign_extended && semantic_width > encoded_width ? 1u : 0u;
    value.encoded = little_bytes(raw, encoded_width);
    value.semantic = value.encoded;
    if (value.extension == 1u) {
        value.semantic.resize(static_cast<std::size_t>(semantic_width / 8u), (raw & (1ull << (encoded_width - 1u))) ? 0xffu : 0u);
    }
    value.signed_value = sign_extend(raw, encoded_width);
    if (encoded_width == 8u) *attributes |= kAttrImm8;
    if (encoded_width == 16u) *attributes |= kAttrImm16;
    if (encoded_width == 32u) *attributes |= kAttrImm32;
    if (encoded_width == 64u) *attributes |= kAttrImm64;
    if (value.extension == 1u) *attributes |= kAttrImmSignExtend;
    return value;
}

[[nodiscard]] PointerValue pointer_for(const RegisterState& state, const std::uint64_t parent) {
    if (parent < 1u || parent > 16u) fail("LAUNCH_GATE_RESTRICTED_X86_PROVENANCE_REGISTER_INVALID");
    return state.values[static_cast<std::size_t>(parent)];
}

[[nodiscard]] std::pair<std::uint64_t, std::uint64_t> provenance_for(const Address& address, const RegisterState& state, const bool allow_gate_page) {
    if (address.base == 17u) {
        if (!allow_gate_page || address.index != 0u || address.scale != 1u || address.rip_target != 4095) fail("LAUNCH_GATE_RESTRICTED_X86_GATE_PROVENANCE_INVALID");
        return {4u, 4095u};
    }
    if (address.index != 0u || address.scale != 1u) fail("LAUNCH_GATE_RESTRICTED_X86_PROVENANCE_INDEX_UNKNOWN");
    const PointerValue pointer = pointer_for(state, address.base);
    if (pointer.provenance == Provenance::Unknown) fail("LAUNCH_GATE_RESTRICTED_X86_PROVENANCE_UNKNOWN");
    const std::int64_t result = pointer.offset + address.displacement;
    if (result < 0) fail("LAUNCH_GATE_RESTRICTED_X86_PROVENANCE_NEGATIVE");
    return {static_cast<std::uint64_t>(pointer.provenance), static_cast<std::uint64_t>(result)};
}

[[nodiscard]] Operand address_operand(const Address& address, const RegisterState& state) {
    Operand value;
    value.tag = OperandTag::Address;
    value.address = address;
    const auto [provenance, offset] = provenance_for(address, state, true);
    value.provenance = provenance;
    value.provenance_offset = offset;
    if ((provenance == 1u && offset > 64u) || (provenance == 2u && offset > 48u) || (provenance == 3u && offset > 88u)) fail("LAUNCH_GATE_RESTRICTED_X86_ADDRESS_PROVENANCE_RANGE");
    return value;
}

[[nodiscard]] Operand memory_operand(const Address& address, const Access access, const std::uint64_t width, const RegisterState& state) {
    Operand value;
    value.tag = OperandTag::Memory;
    value.access = access;
    value.semantic_width = width;
    value.address = address;
    const auto [provenance, offset] = provenance_for(address, state, false);
    value.provenance = provenance;
    value.provenance_offset = offset;
    const std::uint64_t size = width / 8u;
    if ((provenance == 1u && offset + size > 64u) || (provenance == 2u && offset + size > 48u) || (provenance == 3u && offset + size > 88u)) fail("LAUNCH_GATE_RESTRICTED_X86_MEMORY_PROVENANCE_RANGE");
    return value;
}

[[nodiscard]] Operand rm_operand(const ParsedRm& rm, const Access access, const std::uint64_t width, const RegisterState& state) {
    return rm.register_form ? register_operand(rm.reg, access) : memory_operand(rm.address, access, width, state);
}

void add_address_attributes(const ParsedRm& rm, std::uint64_t* attributes) {
    *attributes |= kAttrModrm;
    if (rm.register_form) return;
    if (rm.address.has_sib) *attributes |= kAttrSib;
    if (rm.address.displacement_width == 8u) *attributes |= kAttrDisp8;
    if (rm.address.displacement_width == 32u) *attributes |= kAttrDisp32;
    if (rm.address.base == 17u) *attributes |= kAttrRipRelative;
}

void require_width_match(const Operand& left, const Operand& right) {
    const std::uint64_t a = left.tag == OperandTag::Memory ? left.semantic_width : (left.tag == OperandTag::Immediate ? left.semantic_width : (left.reg >= 50u ? 8u : left.reg >= 34u ? 16u : left.reg >= 18u ? 32u : 64u));
    const std::uint64_t b = right.tag == OperandTag::Memory ? right.semantic_width : (right.tag == OperandTag::Immediate ? right.semantic_width : (right.reg >= 50u ? 8u : right.reg >= 34u ? 16u : right.reg >= 18u ? 32u : 64u));
    if (a != b) fail("LAUNCH_GATE_RESTRICTED_X86_OPERAND_WIDTH_MISMATCH");
}

[[nodiscard]] std::uint64_t condition_flags(const std::uint64_t condition) {
    switch (condition) {
        case 2u: case 3u: return 1u;
        case 4u: case 5u: return 8u;
        case 6u: case 7u: return 9u;
        case 8u: case 9u: return 16u;
        case 12u: case 13u: return 48u;
        case 14u: case 15u: return 56u;
        default: fail("LAUNCH_GATE_RESTRICTED_X86_CONDITION_FORBIDDEN");
    }
}

void apply_destination_state(Instruction* instruction, const Operand& destination, const Operand* source, const RegisterState& before) {
    instruction->after = before;
    if (destination.tag != OperandTag::Register) return;
    const std::uint64_t parent = parent64(destination.reg);
    PointerValue value{};
    const std::uint64_t width = destination.reg >= 50u ? 8u : destination.reg >= 34u ? 16u : destination.reg >= 18u ? 32u : 64u;
    if (instruction->opcode == Opcode::Mov && source != nullptr && width == 64u) {
        if (source->tag == OperandTag::Register) value = pointer_for(before, parent64(source->reg));
        if (source->tag == OperandTag::Memory && source->semantic_width == 64u && source->provenance == 1u) {
            if (source->provenance_offset == 16u) value = {Provenance::Result, 0};
            if (source->provenance_offset == 24u) value = {Provenance::CloneArgs, 0};
        }
    }
    if (instruction->opcode == Opcode::Lea && source != nullptr && width == 64u && source->tag == OperandTag::Address && source->provenance >= 1u && source->provenance <= 3u) value = {static_cast<Provenance>(source->provenance), static_cast<std::int64_t>(source->provenance_offset)};
    instruction->after.values[static_cast<std::size_t>(parent)] = value;
}

void set_implicit_parent_write(Instruction* instruction, const Operand& destination) {
    if (destination.tag != OperandTag::Register || destination.reg < 18u || destination.reg > 33u) return;
    instruction->implicit_writes.push_back(register_operand(parent64(destination.reg), Access::Write));
    instruction->attributes |= kAttrDest32ZeroExtend;
}

[[nodiscard]] Instruction decode_one(const std::vector<std::uint8_t>& page, const std::uint64_t offset, const RegisterState& state) {
    Reader reader(page, offset);
    const PrefixAndOpcode decoded_prefix = decode_prefix(&reader);
    const Prefix prefix = decoded_prefix.prefix;
    Instruction instruction;
    instruction.offset = offset;
    instruction.attributes = prefix.attributes;
    instruction.after = state;
    RexUse use;
    if (decoded_prefix.endbr) {
        instruction.opcode = Opcode::Endbr64;
        instruction.raw = reader.raw();
        instruction.length = instruction.raw.size();
        if (instruction.length != 4u || instruction.attributes != 1048672u) fail("LAUNCH_GATE_RESTRICTED_X86_ENDBR_INVALID");
        instruction.successors = {offset + instruction.length};
        return instruction;
    }
    const std::uint8_t opcode = decoded_prefix.opcode;
    const std::uint64_t width = prefix.w ? 64u : 32u;
    auto add_rm_attributes = [&](const ParsedRm& rm) { add_address_attributes(rm, &instruction.attributes); };
    auto reg_field = [&](const ParsedRm& rm, const Access access) -> Operand { if (prefix.r) use.r = true; return register_operand(reg_id(rm.reg_field, width, prefix.rex, &use), access); };
    if (opcode == 0x0fu) {
        const std::uint8_t second = reader.take();
        instruction.attributes |= kAttrOpcodeMap0f;
        if (second == 0x05u) {
            if (prefix.rex) fail("LAUNCH_GATE_RESTRICTED_X86_REDUNDANT_REX");
            instruction.opcode = Opcode::Syscall;
            instruction.implicit_reads = {register_operand(1u, Access::Read), register_operand(8u, Access::Read), register_operand(7u, Access::Read), register_operand(3u, Access::Read), register_operand(11u, Access::Read), register_operand(9u, Access::Read), register_operand(10u, Access::Read)};
            instruction.implicit_writes = {register_operand(1u, Access::Write), register_operand(2u, Access::Clobber), register_operand(12u, Access::Clobber)};
            instruction.flags_undefined = 63u;
        } else if (second >= 0x80u && second <= 0x8fu) {
            if (prefix.rex) fail("LAUNCH_GATE_RESTRICTED_X86_REDUNDANT_REX");
            instruction.opcode = Opcode::Jcc;
            instruction.condition = second & 0x0fu;
            instruction.flags_read = condition_flags(instruction.condition);
            const std::int64_t displacement = sign_extend(read_unsigned(&reader, 32u), 32u);
            const std::int64_t target = static_cast<std::int64_t>(reader.cursor()) + displacement;
            if (target < 0 || target >= static_cast<std::int64_t>(kCodeSize)) fail("LAUNCH_GATE_RESTRICTED_X86_BRANCH_TARGET_INVALID");
            Operand branch; branch.tag = OperandTag::Branch; branch.encoded_width = 32u; branch.signed_value = displacement; branch.branch_target = static_cast<std::uint64_t>(target);
            instruction.explicit_operands = {branch};
            instruction.implicit_writes = {register_operand(17u, Access::Write)};
            instruction.attributes |= kAttrBranch32;
        } else {
            fail("LAUNCH_GATE_RESTRICTED_X86_0F_OPCODE_FORBIDDEN");
        }
    } else if (opcode == 0xc3u) {
        if (prefix.rex) fail("LAUNCH_GATE_RESTRICTED_X86_REDUNDANT_REX");
        instruction.opcode = Opcode::Ret;
        Operand stack; stack.tag = OperandTag::Memory; stack.access = Access::Read; stack.semantic_width = 64u; stack.address = {5u, 0u, 1u, 0u, 0, -1, false}; stack.provenance = 5u; stack.provenance_offset = 0u;
        instruction.implicit_reads = {register_operand(5u, Access::Read), stack};
        instruction.implicit_writes = {register_operand(5u, Access::Write), register_operand(17u, Access::Write)};
    } else if (opcode >= 0x70u && opcode <= 0x7fu) {
        if (prefix.rex) fail("LAUNCH_GATE_RESTRICTED_X86_REDUNDANT_REX");
        instruction.opcode = Opcode::Jcc;
        instruction.condition = opcode & 0x0fu;
        instruction.flags_read = condition_flags(instruction.condition);
        const std::int64_t displacement = sign_extend(read_unsigned(&reader, 8u), 8u);
        const std::int64_t target = static_cast<std::int64_t>(reader.cursor()) + displacement;
        if (target < 0 || target >= static_cast<std::int64_t>(kCodeSize)) fail("LAUNCH_GATE_RESTRICTED_X86_BRANCH_TARGET_INVALID");
        Operand branch; branch.tag = OperandTag::Branch; branch.encoded_width = 8u; branch.signed_value = displacement; branch.branch_target = static_cast<std::uint64_t>(target);
        instruction.explicit_operands = {branch}; instruction.implicit_writes = {register_operand(17u, Access::Write)}; instruction.attributes |= kAttrBranch8;
    } else if (opcode == 0xebu || opcode == 0xe9u) {
        if (prefix.rex) fail("LAUNCH_GATE_RESTRICTED_X86_REDUNDANT_REX");
        instruction.opcode = Opcode::Jmp;
        const std::uint64_t bits = opcode == 0xebu ? 8u : 32u;
        const std::int64_t displacement = sign_extend(read_unsigned(&reader, bits), bits);
        const std::int64_t target = static_cast<std::int64_t>(reader.cursor()) + displacement;
        if (target < 0 || target >= static_cast<std::int64_t>(kCodeSize)) fail("LAUNCH_GATE_RESTRICTED_X86_BRANCH_TARGET_INVALID");
        Operand branch; branch.tag = OperandTag::Branch; branch.encoded_width = bits; branch.signed_value = displacement; branch.branch_target = static_cast<std::uint64_t>(target);
        instruction.explicit_operands = {branch}; instruction.implicit_writes = {register_operand(17u, Access::Write)}; instruction.attributes |= bits == 8u ? kAttrBranch8 : kAttrBranch32;
    } else if (opcode == 0xa8u || opcode == 0xa9u) {
        if (opcode == 0xa8u && prefix.w) fail("LAUNCH_GATE_RESTRICTED_X86_REDUNDANT_REX");
        instruction.opcode = Opcode::Test;
        const std::uint64_t accumulator_width = opcode == 0xa8u ? 8u : width;
        Operand left = register_operand(reg_id(0u, accumulator_width, prefix.rex, &use), Access::Read);
        Operand right = immediate_operand(&reader, opcode == 0xa8u ? 8u : 32u, accumulator_width, accumulator_width == 64u, &instruction.attributes);
        instruction.explicit_operands = {left, right};
        require_width_match(left, right);
        instruction.flags_write = 59u;
        instruction.flags_undefined = 4u;
    } else if (opcode >= 0xb8u && opcode <= 0xbfu) {
        instruction.opcode = Opcode::Mov;
        const std::uint8_t raw = static_cast<std::uint8_t>((opcode - 0xb8u) + (prefix.b ? 8u : 0u));
        if (prefix.b) use.b = true;
        Operand destination = register_operand(reg_id(raw, width, prefix.rex, &use), Access::Write);
        Operand immediate = immediate_operand(&reader, width, width, false, &instruction.attributes);
        instruction.explicit_operands = {destination, immediate};
        set_implicit_parent_write(&instruction, destination);
        apply_destination_state(&instruction, destination, &immediate, state);
    } else if (opcode == 0x89u || opcode == 0x8bu || opcode == 0xc7u || opcode == 0x8du || opcode == 0x31u || opcode == 0x85u || opcode == 0xf7u || opcode == 0xf6u || opcode == 0x39u || opcode == 0x3bu || opcode == 0x83u || opcode == 0x81u) {
        const std::uint64_t operand_width = (opcode == 0xf6u) ? 8u : width;
        ParsedRm rm = parse_modrm(&reader, prefix, operand_width, &use);
        add_rm_attributes(rm);
        if (opcode == 0x89u) {
            instruction.opcode = Opcode::Mov;
            Operand destination = rm_operand(rm, Access::Write, width, state);
            Operand source = reg_field(rm, Access::Read);
            instruction.explicit_operands = {destination, source}; require_width_match(destination, source); set_implicit_parent_write(&instruction, destination); apply_destination_state(&instruction, destination, &source, state);
        } else if (opcode == 0x8bu) {
            instruction.opcode = Opcode::Mov;
            Operand destination = reg_field(rm, Access::Write);
            Operand source = rm_operand(rm, Access::Read, width, state);
            instruction.explicit_operands = {destination, source}; require_width_match(destination, source); set_implicit_parent_write(&instruction, destination); apply_destination_state(&instruction, destination, &source, state);
        } else if (opcode == 0xc7u) {
            if ((rm.reg_field & 7u) != 0u) fail("LAUNCH_GATE_RESTRICTED_X86_GROUP_OPCODE_FORBIDDEN");
            instruction.opcode = Opcode::Mov;
            Operand destination = rm_operand(rm, Access::Write, width, state);
            Operand immediate = immediate_operand(&reader, 32u, width, width == 64u, &instruction.attributes);
            instruction.explicit_operands = {destination, immediate}; require_width_match(destination, immediate); set_implicit_parent_write(&instruction, destination); apply_destination_state(&instruction, destination, &immediate, state);
        } else if (opcode == 0x8du) {
            if (rm.register_form) fail("LAUNCH_GATE_RESTRICTED_X86_LEA_REGISTER_FORM_FORBIDDEN");
            instruction.opcode = Opcode::Lea;
            Operand destination = reg_field(rm, Access::Write);
            Operand source = address_operand(rm.address, state);
            instruction.explicit_operands = {destination, source}; set_implicit_parent_write(&instruction, destination); apply_destination_state(&instruction, destination, &source, state);
        } else if (opcode == 0x31u) {
            if (!rm.register_form) fail("LAUNCH_GATE_RESTRICTED_X86_XOR_MEMORY_FORBIDDEN");
            instruction.opcode = Opcode::XorZero;
            Operand destination = rm_operand(rm, Access::ReadWrite, width, state);
            Operand source = reg_field(rm, Access::Read);
            if (destination.reg != source.reg) fail("LAUNCH_GATE_RESTRICTED_X86_GENERAL_XOR_FORBIDDEN");
            instruction.explicit_operands = {destination, source}; instruction.flags_write = 59u; instruction.flags_undefined = 4u; set_implicit_parent_write(&instruction, destination); apply_destination_state(&instruction, destination, nullptr, state);
        } else if (opcode == 0x85u) {
            instruction.opcode = Opcode::Test;
            Operand left = rm_operand(rm, Access::Read, width, state); Operand right = reg_field(rm, Access::Read);
            instruction.explicit_operands = {left, right}; require_width_match(left, right); instruction.flags_write = 59u; instruction.flags_undefined = 4u;
        } else if (opcode == 0xf7u || opcode == 0xf6u) {
            if ((rm.reg_field & 7u) != 0u) fail("LAUNCH_GATE_RESTRICTED_X86_GROUP_OPCODE_FORBIDDEN");
            instruction.opcode = Opcode::Test;
            Operand left = rm_operand(rm, Access::Read, operand_width, state); Operand right = immediate_operand(&reader, operand_width == 8u ? 8u : 32u, operand_width, operand_width == 64u, &instruction.attributes);
            instruction.explicit_operands = {left, right}; require_width_match(left, right); instruction.flags_write = 59u; instruction.flags_undefined = 4u;
        } else if (opcode == 0x39u) {
            instruction.opcode = Opcode::Cmp;
            Operand left = rm_operand(rm, Access::Read, width, state); Operand right = reg_field(rm, Access::Read);
            instruction.explicit_operands = {left, right}; require_width_match(left, right); instruction.flags_write = 63u;
        } else if (opcode == 0x3bu) {
            instruction.opcode = Opcode::Cmp;
            Operand left = reg_field(rm, Access::Read); Operand right = rm_operand(rm, Access::Read, width, state);
            instruction.explicit_operands = {left, right}; require_width_match(left, right); instruction.flags_write = 63u;
        } else {
            if ((rm.reg_field & 7u) != 7u) fail("LAUNCH_GATE_RESTRICTED_X86_GROUP_OPCODE_FORBIDDEN");
            instruction.opcode = Opcode::Cmp;
            const std::uint64_t immediate_width = opcode == 0x83u ? 8u : 32u;
            Operand left = rm_operand(rm, Access::Read, width, state); Operand right = immediate_operand(&reader, immediate_width, width, immediate_width < width, &instruction.attributes);
            instruction.explicit_operands = {left, right}; require_width_match(left, right); instruction.flags_write = 63u;
        }
    } else {
        fail("LAUNCH_GATE_RESTRICTED_X86_OPCODE_FORBIDDEN");
    }
    validate_rex(prefix, use);
    instruction.raw = reader.raw();
    instruction.length = instruction.raw.size();
    if (instruction.length == 0u || instruction.length > 15u || offset + instruction.length > kCodeSize) fail("LAUNCH_GATE_RESTRICTED_X86_INSTRUCTION_RANGE_INVALID");
    if (instruction.opcode == Opcode::Jcc) instruction.successors = {instruction.explicit_operands[0].branch_target, offset + instruction.length};
    else if (instruction.opcode == Opcode::Jmp) instruction.successors = {instruction.explicit_operands[0].branch_target};
    else if (instruction.opcode != Opcode::Ret) instruction.successors = {offset + instruction.length};
    for (const std::uint64_t successor : instruction.successors) if (successor >= kCodeSize) fail("LAUNCH_GATE_RESTRICTED_X86_SUCCESSOR_RANGE_INVALID");
    return instruction;
}

[[nodiscard]] std::map<std::uint64_t, Instruction> recursively_decode(const std::vector<std::uint8_t>& page) {
    std::set<std::uint64_t> pending{0u};
    std::map<std::uint64_t, RegisterState> expected;
    RegisterState initial;
    initial.values[8u] = {Provenance::Input, 0}; // SysV rdi is wire register ID 8.
    expected.emplace(0u, initial);
    std::map<std::uint64_t, Instruction> decoded;
    std::array<std::int64_t, kCodeSize> owner{};
    owner.fill(-1);
    const auto meet = [](const RegisterState& left, const RegisterState& right) {
        RegisterState result;
        for (std::size_t index = 1u; index < result.values.size(); ++index) {
            result.values[index] = left.values[index] == right.values[index] ? left.values[index] : PointerValue{};
        }
        return result;
    };
    while (!pending.empty()) {
        const std::uint64_t offset = *pending.begin();
        pending.erase(pending.begin());
        const RegisterState before = expected.at(offset);
        const auto found = decoded.find(offset);
        for (std::uint64_t index = 0u; index < kCodeSize; ++index) if (owner[index] >= 0 && offset > static_cast<std::uint64_t>(owner[index]) && offset < static_cast<std::uint64_t>(owner[index]) + decoded.at(static_cast<std::uint64_t>(owner[index])).length) fail("LAUNCH_GATE_RESTRICTED_X86_BRANCH_INSTRUCTION_INTERIOR");
        Instruction instruction = decode_one(page, offset, before);
        if (found != decoded.end() && found->second.length != instruction.length) fail("LAUNCH_GATE_RESTRICTED_X86_DECODE_LENGTH_INSTABILITY");
        for (std::uint64_t index = offset; index < offset + instruction.length; ++index) {
            if (owner[index] != -1 && owner[index] != static_cast<std::int64_t>(offset)) fail("LAUNCH_GATE_RESTRICTED_X86_DECODE_OVERLAP");
            owner[index] = static_cast<std::int64_t>(offset);
        }
        const RegisterState after = instruction.after;
        decoded.insert_or_assign(offset, instruction);
        for (const std::uint64_t successor : decoded.at(offset).successors) {
            const auto known = expected.find(successor);
            if (known == expected.end()) { expected.emplace(successor, after); pending.insert(successor); }
            else {
                const RegisterState merged = meet(known->second, after);
                if (!(merged == known->second)) {
                    known->second = merged;
                    pending.insert(successor);
                }
            }
        }
    }
    for (std::uint64_t index = 0u; index < kCodeSize; ++index) if (owner[index] < 0) fail("LAUNCH_GATE_RESTRICTED_X86_REACHABILITY_COVERAGE_INCOMPLETE");
    for (const auto& [offset, instruction] : decoded) {
        static_cast<void>(offset);
        for (const std::uint64_t successor : instruction.successors) if (!decoded.contains(successor)) fail("LAUNCH_GATE_RESTRICTED_X86_SUCCESSOR_BOUNDARY_INVALID");
    }
    return decoded;
}

struct CfgRow final { std::uint64_t start = 0u; std::uint64_t terminal = 0u; std::vector<std::uint64_t> successors; };

[[nodiscard]] std::vector<CfgRow> build_cfg(const std::map<std::uint64_t, Instruction>& decoded) {
    std::set<std::uint64_t> starts{0u};
    for (const auto& [offset, instruction] : decoded) {
        static_cast<void>(offset);
        if (instruction.opcode == Opcode::Jcc) { starts.insert(instruction.successors[0]); starts.insert(instruction.successors[1]); }
        if (instruction.opcode == Opcode::Jmp) starts.insert(instruction.successors[0]);
        if (instruction.opcode == Opcode::Syscall) starts.insert(instruction.successors[0]);
    }
    for (const std::uint64_t start : starts) if (!decoded.contains(start)) fail("LAUNCH_GATE_RESTRICTED_X86_CFG_START_INVALID");
    std::set<std::uint64_t> assigned;
    std::vector<CfgRow> rows;
    for (const std::uint64_t start : starts) {
        if (assigned.contains(start)) fail("LAUNCH_GATE_RESTRICTED_X86_CFG_OVERLAPPING_BLOCK");
        std::uint64_t current = start;
        for (;;) {
            const Instruction& instruction = decoded.at(current);
            if (!assigned.insert(current).second) fail("LAUNCH_GATE_RESTRICTED_X86_CFG_INSTRUCTION_DUPLICATE");
            const std::uint64_t next = current + instruction.length;
            CfgRow row; row.start = start;
            if (instruction.opcode == Opcode::Jcc) { row.terminal = 1u; row.successors = instruction.successors; rows.push_back(row); break; }
            if (instruction.opcode == Opcode::Jmp) { row.terminal = 2u; row.successors = instruction.successors; rows.push_back(row); break; }
            if (instruction.opcode == Opcode::Ret) { row.terminal = 3u; rows.push_back(row); break; }
            if (instruction.opcode == Opcode::Syscall) { row.terminal = 4u; row.successors = instruction.successors; rows.push_back(row); break; }
            if (next >= kCodeSize || !decoded.contains(next)) fail("LAUNCH_GATE_RESTRICTED_X86_CFG_FALLTHROUGH_INVALID");
            if (starts.contains(next)) { row.terminal = 0u; row.successors = {next}; rows.push_back(row); break; }
            current = next;
        }
    }
    if (assigned.size() != decoded.size()) fail("LAUNCH_GATE_RESTRICTED_X86_CFG_COVERAGE_INVALID");
    for (const CfgRow& row : rows) for (const std::uint64_t successor : row.successors) if (!starts.contains(successor)) fail("LAUNCH_GATE_RESTRICTED_X86_CFG_SUCCESSOR_INVALID");
    return rows;
}

class Cbor final {
public:
    void array(const std::uint64_t length) { head(4u, length); }
    void uint(const std::uint64_t value) { head(0u, value); }
    void sint(const std::int64_t value) { if (value >= 0) uint(static_cast<std::uint64_t>(value)); else head(1u, static_cast<std::uint64_t>(-(value + 1))); }
    void bytes(const std::uint8_t* data, const std::size_t length) { head(2u, length); value_.insert(value_.end(), data, data + length); }
    void bytes(const std::vector<std::uint8_t>& value) { bytes(value.data(), value.size()); }
    void bytes(const std::array<std::uint8_t, 32u>& value) { bytes(value.data(), value.size()); }
    void append(const std::vector<std::uint8_t>& value) { value_.insert(value_.end(), value.begin(), value.end()); }
    [[nodiscard]] const std::vector<std::uint8_t>& value() const noexcept { return value_; }
private:
    void head(const std::uint8_t major, const std::uint64_t argument) {
        if (argument < 24u) value_.push_back(static_cast<std::uint8_t>((major << 5u) | argument));
        else if (argument <= 0xffu) { value_.push_back(static_cast<std::uint8_t>((major << 5u) | 24u)); value_.push_back(static_cast<std::uint8_t>(argument)); }
        else if (argument <= 0xffffu) { value_.push_back(static_cast<std::uint8_t>((major << 5u) | 25u)); value_.push_back(static_cast<std::uint8_t>(argument >> 8u)); value_.push_back(static_cast<std::uint8_t>(argument)); }
        else if (argument <= 0xffffffffu) { value_.push_back(static_cast<std::uint8_t>((major << 5u) | 26u)); for (int shift = 24; shift >= 0; shift -= 8) value_.push_back(static_cast<std::uint8_t>(argument >> shift)); }
        else { value_.push_back(static_cast<std::uint8_t>((major << 5u) | 27u)); for (int shift = 56; shift >= 0; shift -= 8) value_.push_back(static_cast<std::uint8_t>(argument >> shift)); }
    }
    std::vector<std::uint8_t> value_;
};

void encode_operand(Cbor* cbor, const Operand& operand) {
    if (operand.tag == OperandTag::Register) { cbor->array(3u); cbor->uint(0u); cbor->uint(operand.reg); cbor->uint(static_cast<std::uint64_t>(operand.access)); return; }
    if (operand.tag == OperandTag::Immediate) { cbor->array(7u); cbor->uint(1u); cbor->uint(operand.encoded_width); cbor->uint(operand.semantic_width); cbor->uint(operand.signedness); cbor->uint(operand.extension); cbor->bytes(operand.encoded); cbor->bytes(operand.semantic); return; }
    if (operand.tag == OperandTag::Branch) { cbor->array(4u); cbor->uint(2u); cbor->uint(operand.encoded_width); cbor->sint(operand.signed_value); cbor->uint(operand.branch_target); return; }
    const Address& address = operand.address;
    if (operand.tag == OperandTag::Memory) { cbor->array(12u); cbor->uint(3u); cbor->uint(static_cast<std::uint64_t>(operand.access)); cbor->uint(operand.semantic_width); cbor->uint(64u); }
    else { cbor->array(10u); cbor->uint(4u); cbor->uint(64u); }
    cbor->uint(address.base); cbor->uint(address.index); cbor->uint(address.scale); cbor->uint(address.displacement_width); cbor->sint(address.displacement); cbor->sint(address.rip_target); cbor->uint(operand.provenance); cbor->uint(operand.provenance_offset);
}

void encode_operands(Cbor* cbor, const std::vector<Operand>& operands) { cbor->array(operands.size()); for (const Operand& operand : operands) encode_operand(cbor, operand); }

[[nodiscard]] std::vector<std::uint8_t> encode_instruction_manifest(const std::map<std::uint64_t, Instruction>& decoded) {
    Cbor cbor; cbor.array(decoded.size());
    for (const auto& [offset, instruction] : decoded) {
        cbor.array(4u); cbor.uint(offset); cbor.uint(instruction.length); cbor.uint(static_cast<std::uint64_t>(instruction.opcode)); cbor.array(9u);
        cbor.uint(instruction.condition); encode_operands(&cbor, instruction.explicit_operands); encode_operands(&cbor, instruction.implicit_reads); encode_operands(&cbor, instruction.implicit_writes); cbor.uint(instruction.flags_read); cbor.uint(instruction.flags_write); cbor.uint(instruction.flags_undefined); cbor.uint(instruction.attributes); cbor.bytes(instruction.raw);
    }
    return cbor.value();
}

[[nodiscard]] std::vector<std::uint8_t> encode_cfg_manifest(const std::vector<CfgRow>& rows) {
    Cbor cbor; cbor.array(rows.size());
    for (const CfgRow& row : rows) { cbor.array(3u); cbor.uint(row.start); cbor.uint(row.terminal); cbor.array(row.successors.size()); for (const std::uint64_t successor : row.successors) cbor.uint(successor); }
    return cbor.value();
}

[[nodiscard]] std::vector<std::uint8_t> encode_wrapper(const std::array<std::uint8_t, 32u>& page_hash, const std::vector<std::uint8_t>& instructions, const std::vector<std::uint8_t>& cfg) {
    Cbor cbor; cbor.array(6u); cbor.uint(kProtocolId); cbor.uint(kWireVersion); cbor.bytes(page_hash); cbor.uint(kCodeSize); cbor.append(instructions); cbor.append(cfg); return cbor.value();
}

void write_exact_output(const char* path, const std::vector<std::uint8_t>& output) {
    const int fd = ::open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) fail("LAUNCH_GATE_RESTRICTED_X86_OUTPUT_OPEN_FAILED", kExitIo);
    const auto discard_output = [&]() noexcept {
        (void)::close(fd);
        (void)::unlink(path);
    };
    std::size_t used = 0u;
    while (used < output.size()) {
        const ssize_t count = ::write(fd, output.data() + used, output.size() - used);
        if (count <= 0) {
            discard_output();
            fail("LAUNCH_GATE_RESTRICTED_X86_OUTPUT_WRITE_FAILED", kExitIo);
        }
        used += static_cast<std::size_t>(count);
    }
    if (::fsync(fd) != 0) {
        discard_output();
        fail("LAUNCH_GATE_RESTRICTED_X86_OUTPUT_SYNC_FAILED", kExitIo);
    }
    if (::close(fd) != 0) {
        (void)::unlink(path);
        fail("LAUNCH_GATE_RESTRICTED_X86_OUTPUT_CLOSE_FAILED", kExitIo);
    }
}

}  // namespace

int main(const int argc, char* const argv[]) {
    if (argc != 4) fail("usage: launch_gate_restricted_x86_decoder_v1 PAGE GATE_CODE_SIZE OUTPUT_CBOR", kExitUsage);
    std::uint64_t requested = 0u;
    if (!parse_code_size(argv[2], &requested) || requested != kCodeSize) fail("LAUNCH_GATE_RESTRICTED_X86_CODE_SIZE_INVALID", kExitUsage);
    const std::vector<std::uint8_t> page = read_exact_page(argv[1]);
    if (!std::all_of(page.begin() + static_cast<std::ptrdiff_t>(kCodeSize), page.end() - 1, [](const std::uint8_t byte) { return byte == 0xccu; }) || page.back() != 0u) fail("LAUNCH_GATE_RESTRICTED_X86_TRAILER_INVALID");
    Sha256 digest; digest.update(page.data(), page.size());
    const std::array<std::uint8_t, 32u> page_hash = digest.finish();
    const std::map<std::uint64_t, Instruction> decoded = recursively_decode(page);
    const std::vector<CfgRow> cfg = build_cfg(decoded);
    const std::vector<std::uint8_t> instructions = encode_instruction_manifest(decoded);
    const std::vector<std::uint8_t> cfg_bytes = encode_cfg_manifest(cfg);
    const std::vector<std::uint8_t> wrapper = encode_wrapper(page_hash, instructions, cfg_bytes);
    write_exact_output(argv[3], wrapper);
    return 0; // Zero-authority diagnostic output only.
}
