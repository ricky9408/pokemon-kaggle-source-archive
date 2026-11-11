// Stage-1-only independent LLVM 16 MC decoder for LaunchGateV1.
//
// This is a zero-authority diagnostic tool.  LLVM MC establishes x86 decode
// success and instruction boundaries; this file independently derives the
// frozen wire semantics from the machine bytes.  It never emits disassembly
// text, LLVM opcode IDs, LLVM register IDs, or LLVM operand order.

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/Triple.h"
#include "llvm/Config/llvm-config.h"
#include "llvm/MC/MCAsmInfo.h"
#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCDisassembler/MCDisassembler.h"
#include "llvm/MC/MCInst.h"
#include "llvm/MC/MCInstrInfo.h"
#include "llvm/MC/MCRegisterInfo.h"
#include "llvm/MC/MCSubtargetInfo.h"
#include "llvm/MC/MCTargetOptions.h"
#include "llvm/MC/TargetRegistry.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/SHA256.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm/Support/raw_ostream.h"

#if LLVM_VERSION_MAJOR != 16 || LLVM_VERSION_MINOR != 0 || LLVM_VERSION_PATCH != 6
#error unsupported LLVM header version
#endif

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include <limits>
#include <limits.h>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <utility>
#include <variant>
#include <vector>

#include <sys/stat.h>
#include <dlfcn.h>
#include <link.h>
#include <unistd.h>

namespace {

constexpr std::uint64_t kProtocolId = 631302u;
constexpr std::uint64_t kWireVersion = 1u;
constexpr std::uint64_t kCodeSize = 874u;
constexpr std::size_t kPageSize = 4096u;
constexpr std::uint64_t kFlagMaskAll = 63u;
constexpr std::uint64_t kAttrRex = 1u;
constexpr std::uint64_t kAttrRexW = 2u;
constexpr std::uint64_t kAttrRexR = 4u;
constexpr std::uint64_t kAttrRexX = 8u;
constexpr std::uint64_t kAttrRexB = 16u;
constexpr std::uint64_t kAttrF3Endbr = 32u;
constexpr std::uint64_t kAttrModrm = 64u;
constexpr std::uint64_t kAttrSib = 128u;
constexpr std::uint64_t kAttrDisp8 = 256u;
constexpr std::uint64_t kAttrDisp32 = 512u;
constexpr std::uint64_t kAttrImm8 = 1024u;
constexpr std::uint64_t kAttrImm16 = 2048u;
constexpr std::uint64_t kAttrImm32 = 4096u;
constexpr std::uint64_t kAttrImm64 = 8192u;
constexpr std::uint64_t kAttrImmSignExtend = 16384u;
constexpr std::uint64_t kAttrImmZeroExtend = 32768u;
constexpr std::uint64_t kAttrDest32ZeroExtend = 65536u;
constexpr std::uint64_t kAttrRipRelative = 131072u;
constexpr std::uint64_t kAttrBranch8 = 262144u;
constexpr std::uint64_t kAttrBranch32 = 524288u;
constexpr std::uint64_t kAttrMap0F = 1048576u;
constexpr int kExitUsage = 64;
constexpr int kExitDecode = 65;
constexpr int kExitIo = 74;
constexpr const char* kCanonicalLlvmPath = "/usr/lib/x86_64-linux-gnu/libLLVM-16.so.1";
constexpr std::array<std::uint8_t, 32u> kCanonicalLlvmSha256{
    0xf6u, 0x2du, 0x25u, 0x4bu, 0x7fu, 0x2bu, 0xf4u, 0x2du,
    0xf8u, 0xc8u, 0xb0u, 0x7du, 0x46u, 0xeeu, 0x3bu, 0xb4u,
    0xc2u, 0xcau, 0xfeu, 0xcau, 0x43u, 0x6bu, 0x2eu, 0x6bu,
    0xc6u, 0xccu, 0xbeu, 0x45u, 0x81u, 0xf5u, 0x8fu, 0x40u,
};

enum class Opcode : std::uint64_t {
    Endbr64 = 1u, Mov = 2u, Lea = 3u, XorZero = 4u, Test = 5u,
    Cmp = 6u, Jcc = 7u, Jmp = 8u, Syscall = 9u, Ret = 10u,
};
enum class Access : std::uint64_t { Read = 1u, Write = 2u, ReadWrite = 3u, Clobber = 4u };

struct Reg final { std::uint64_t id; Access access; };
struct Immediate final {
    std::uint64_t encoded_width;
    std::uint64_t semantic_width;
    std::uint64_t signedness;
    std::uint64_t extension;
    std::vector<std::uint8_t> encoded;
    std::vector<std::uint8_t> semantic;
};
struct Branch final { std::uint64_t width; std::int64_t displacement; std::uint64_t target; };
struct Address final {
    std::uint64_t base;
    std::uint64_t index;
    std::uint64_t scale;
    std::uint64_t displacement_width;
    std::int64_t displacement;
    std::int64_t rip_target;
    std::uint64_t provenance;
    std::uint64_t provenance_offset;
};
struct Memory final { Access access; std::uint64_t width; Address address; };
using Operand = std::variant<Reg, Immediate, Branch, Memory, Address>;

struct Instruction final {
    std::uint64_t offset;
    std::uint64_t length;
    Opcode opcode;
    std::uint64_t condition;
    std::vector<Operand> explicit_operands;
    std::vector<Operand> implicit_reads;
    std::vector<Operand> implicit_writes;
    std::uint64_t flags_read = 0u;
    std::uint64_t flags_write = 0u;
    std::uint64_t flags_undefined = 0u;
    std::uint64_t attributes = 0u;
    std::vector<std::uint8_t> raw;
};
struct Flow final { std::vector<std::uint64_t> successors; };
struct Block final { std::uint64_t start; std::uint64_t terminal; std::vector<std::uint64_t> successors; };

[[noreturn]] void fail(const char* message, int exit_code) {
    std::fputs(message, stderr);
    std::fputc('\n', stderr);
    std::exit(exit_code);
}

class IndependentSha256 final {
public:
    void update(const std::uint8_t* data, std::size_t size) {
        if (data == nullptr || size > (std::numeric_limits<std::uint64_t>::max() / 8u) - bytes_) {
            fail("LAUNCH_GATE_LLVM_MC_RUNTIME_LIBRARY_HASH_LENGTH_INVALID", kExitIo);
        }
        bytes_ += size;
        if (used_ != 0u) {
            const std::size_t fill = std::min(size, block_.size() - used_);
            std::memcpy(block_.data() + used_, data, fill);
            used_ += fill;
            data += fill;
            size -= fill;
            if (used_ == block_.size()) {
                compress(block_.data());
                used_ = 0u;
            }
        }
        while (size >= block_.size()) {
            compress(data);
            data += block_.size();
            size -= block_.size();
        }
        if (size != 0u) {
            std::memcpy(block_.data(), data, size);
            used_ = size;
        }
    }

    [[nodiscard]] std::array<std::uint8_t, 32u> final() {
        const std::uint64_t bit_length = bytes_ * 8u;
        block_[used_++] = 0x80u;
        if (used_ > 56u) {
            std::fill(block_.begin() + static_cast<std::ptrdiff_t>(used_), block_.end(), 0u);
            compress(block_.data());
            used_ = 0u;
        }
        std::fill(block_.begin() + static_cast<std::ptrdiff_t>(used_), block_.begin() + 56, 0u);
        for (unsigned byte = 0u; byte < 8u; ++byte) {
            block_[63u - byte] = static_cast<std::uint8_t>(bit_length >> (byte * 8u));
        }
        compress(block_.data());
        std::array<std::uint8_t, 32u> result{};
        for (unsigned word = 0u; word < state_.size(); ++word) {
            for (unsigned byte = 0u; byte < 4u; ++byte) {
                result[word * 4u + byte] = static_cast<std::uint8_t>(state_[word] >> ((3u - byte) * 8u));
            }
        }
        return result;
    }

private:
    [[nodiscard]] static std::uint32_t rotate_right(std::uint32_t value, unsigned amount) {
        return (value >> amount) | (value << (32u - amount));
    }

    void compress(const std::uint8_t* bytes) {
        static constexpr std::array<std::uint32_t, 64u> kRoundConstants{
            0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
            0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
            0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
            0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
            0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
            0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
            0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
            0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
        };
        std::array<std::uint32_t, 64u> words{};
        for (unsigned word = 0u; word < 16u; ++word) {
            words[word] = (static_cast<std::uint32_t>(bytes[word * 4u]) << 24u) |
                (static_cast<std::uint32_t>(bytes[word * 4u + 1u]) << 16u) |
                (static_cast<std::uint32_t>(bytes[word * 4u + 2u]) << 8u) |
                static_cast<std::uint32_t>(bytes[word * 4u + 3u]);
        }
        for (unsigned word = 16u; word < words.size(); ++word) {
            const std::uint32_t lower0 = rotate_right(words[word - 15u], 7u) ^ rotate_right(words[word - 15u], 18u) ^ (words[word - 15u] >> 3u);
            const std::uint32_t lower1 = rotate_right(words[word - 2u], 17u) ^ rotate_right(words[word - 2u], 19u) ^ (words[word - 2u] >> 10u);
            words[word] = words[word - 16u] + lower0 + words[word - 7u] + lower1;
        }
        std::uint32_t a = state_[0u], b = state_[1u], c = state_[2u], d = state_[3u];
        std::uint32_t e = state_[4u], f = state_[5u], g = state_[6u], h = state_[7u];
        for (unsigned round = 0u; round < words.size(); ++round) {
            const std::uint32_t upper1 = rotate_right(e, 6u) ^ rotate_right(e, 11u) ^ rotate_right(e, 25u);
            const std::uint32_t choose = (e & f) ^ ((~e) & g);
            const std::uint32_t temporary1 = h + upper1 + choose + kRoundConstants[round] + words[round];
            const std::uint32_t upper0 = rotate_right(a, 2u) ^ rotate_right(a, 13u) ^ rotate_right(a, 22u);
            const std::uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
            const std::uint32_t temporary2 = upper0 + majority;
            h = g; g = f; f = e; e = d + temporary1; d = c; c = b; b = a; a = temporary1 + temporary2;
        }
        state_[0u] += a; state_[1u] += b; state_[2u] += c; state_[3u] += d;
        state_[4u] += e; state_[5u] += f; state_[6u] += g; state_[7u] += h;
    }

    std::array<std::uint32_t, 8u> state_{
        0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
        0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u,
    };
    std::array<std::uint8_t, 64u> block_{};
    std::uint64_t bytes_ = 0u;
    std::size_t used_ = 0u;
};

struct LoadedLlvmObservation final {
    std::size_t implementations = 0u;
    std::size_t canonical_implementations = 0u;
    bool wrong_path = false;
};

[[nodiscard]] bool has_llvm_implementation_basename(const char* path) {
    if (path == nullptr || *path == '\0') return false;
    const char* basename = std::strrchr(path, '/');
    basename = basename == nullptr ? path : basename + 1;
    return std::strncmp(basename, "libLLVM", 7u) == 0 ||
        std::strncmp(basename, "libclang", 8u) == 0;
}

int observe_loaded_llvm(struct dl_phdr_info* info, std::size_t, void* opaque) {
    auto* observation = static_cast<LoadedLlvmObservation*>(opaque);
    if (info == nullptr || observation == nullptr || !has_llvm_implementation_basename(info->dlpi_name)) return 0;
    ++observation->implementations;
    std::array<char, PATH_MAX> canonical_path{};
    if (::realpath(info->dlpi_name, canonical_path.data()) == nullptr ||
        std::strcmp(canonical_path.data(), kCanonicalLlvmPath) != 0) {
        observation->wrong_path = true;
        return 0;
    }
    ++observation->canonical_implementations;
    return 0;
}

[[nodiscard]] std::array<std::uint8_t, 32u> sha256_regular_file(const char* path) {
    const int fd = ::open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) fail("LAUNCH_GATE_LLVM_MC_RUNTIME_LIBRARY_OPEN_FAILED", kExitIo);
    struct stat metadata {};
    if (::fstat(fd, &metadata) != 0 || !S_ISREG(metadata.st_mode) || metadata.st_size < 0) {
        ::close(fd);
        fail("LAUNCH_GATE_LLVM_MC_RUNTIME_LIBRARY_TYPE_INVALID", kExitIo);
    }
    IndependentSha256 hasher;
    std::array<std::uint8_t, 65536u> buffer{};
    for (;;) {
        const ssize_t count = ::read(fd, buffer.data(), buffer.size());
        if (count < 0) {
            if (errno == EINTR) continue;
            ::close(fd);
            fail("LAUNCH_GATE_LLVM_MC_RUNTIME_LIBRARY_READ_FAILED", kExitIo);
        }
        if (count == 0) break;
        hasher.update(buffer.data(), static_cast<std::size_t>(count));
    }
    if (::close(fd) != 0) fail("LAUNCH_GATE_LLVM_MC_RUNTIME_LIBRARY_CLOSE_FAILED", kExitIo);
    return hasher.final();
}

void verify_loaded_llvm_custody() {
    LoadedLlvmObservation observation;
    if (::dl_iterate_phdr(observe_loaded_llvm, &observation) < 0) fail("LAUNCH_GATE_LLVM_MC_RUNTIME_LIBRARY_ENUMERATION_FAILED", kExitDecode);
    if (observation.implementations == 0u) fail("LAUNCH_GATE_LLVM_MC_RUNTIME_LIBRARY_ABSENT", kExitDecode);
    if (observation.wrong_path) fail("LAUNCH_GATE_LLVM_MC_RUNTIME_LIBRARY_WRONG_PATH", kExitDecode);
    if (observation.implementations != 1u || observation.canonical_implementations != 1u) fail("LAUNCH_GATE_LLVM_MC_RUNTIME_LIBRARY_DUPLICATE", kExitDecode);
    if (sha256_regular_file(kCanonicalLlvmPath) != kCanonicalLlvmSha256) fail("LAUNCH_GATE_LLVM_MC_RUNTIME_LIBRARY_HASH_MISMATCH", kExitDecode);
    for (const char* symbol_name : {
             "LLVMInitializeX86TargetInfo",
             "LLVMInitializeX86TargetMC",
             "LLVMInitializeX86Disassembler",
         }) {
        ::dlerror();
        void* symbol = ::dlsym(RTLD_DEFAULT, symbol_name);
        const char* lookup_error = ::dlerror();
        Dl_info symbol_info{};
        std::array<char, PATH_MAX> symbol_path{};
        if (lookup_error != nullptr || symbol == nullptr || ::dladdr(symbol, &symbol_info) == 0 ||
            symbol_info.dli_fname == nullptr || ::realpath(symbol_info.dli_fname, symbol_path.data()) == nullptr ||
            std::strcmp(symbol_path.data(), kCanonicalLlvmPath) != 0) {
            fail("LAUNCH_GATE_LLVM_MC_RUNTIME_SYMBOL_ORIGIN_INVALID", kExitDecode);
        }
    }
}

[[nodiscard]] bool parse_code_size(const char* text, std::uint64_t* output) {
    if (text == nullptr || *text == '\0' || output == nullptr) return false;
    std::uint64_t value = 0u;
    for (const char* p = text; *p != '\0'; ++p) {
        if (*p < '0' || *p > '9') return false;
        const std::uint64_t digit = static_cast<std::uint64_t>(*p - '0');
        if (value > (std::numeric_limits<std::uint64_t>::max() - digit) / 10u) return false;
        value = value * 10u + digit;
    }
    *output = value;
    return true;
}

[[nodiscard]] std::vector<std::uint8_t> read_page(const char* path) {
    auto input = llvm::MemoryBuffer::getFile(path, false, false);
    if (!input) fail("LAUNCH_GATE_LLVM_MC_INPUT_OPEN_FAILED", kExitIo);
    const llvm::StringRef bytes = (*input)->getBuffer();
    if (bytes.size() != kPageSize) fail("LAUNCH_GATE_LLVM_MC_PAGE_SIZE_INVALID", kExitDecode);
    const auto* first = reinterpret_cast<const std::uint8_t*>(bytes.data());
    return {first, first + kPageSize};
}

class Cbor final {
public:
    void array(std::uint64_t n) { head(4u, n); }
    void uint(std::uint64_t n) { head(0u, n); }
    void sint(std::int64_t n) {
        if (n >= 0) { uint(static_cast<std::uint64_t>(n)); return; }
        head(1u, static_cast<std::uint64_t>(-(n + 1)));
    }
    void bytes(const std::vector<std::uint8_t>& value) { head(2u, value.size()); out_.insert(out_.end(), value.begin(), value.end()); }
    void bytes(const std::array<std::uint8_t, 32u>& value) { head(2u, value.size()); out_.insert(out_.end(), value.begin(), value.end()); }
    void append(const std::vector<std::uint8_t>& value) { out_.insert(out_.end(), value.begin(), value.end()); }
    [[nodiscard]] const std::vector<std::uint8_t>& value() const noexcept { return out_; }
private:
    void head(std::uint8_t major, std::uint64_t argument) {
        if (argument < 24u) { out_.push_back(static_cast<std::uint8_t>((major << 5u) | argument)); return; }
        if (argument <= 0xffu) { out_.push_back(static_cast<std::uint8_t>((major << 5u) | 24u)); out_.push_back(static_cast<std::uint8_t>(argument)); return; }
        if (argument <= 0xffffu) { out_.push_back(static_cast<std::uint8_t>((major << 5u) | 25u)); put_be(argument, 2u); return; }
        if (argument <= 0xffffffffu) { out_.push_back(static_cast<std::uint8_t>((major << 5u) | 26u)); put_be(argument, 4u); return; }
        out_.push_back(static_cast<std::uint8_t>((major << 5u) | 27u)); put_be(argument, 8u);
    }
    void put_be(std::uint64_t value, unsigned bytes) {
        for (unsigned i = bytes; i > 0u; --i) out_.push_back(static_cast<std::uint8_t>(value >> ((i - 1u) * 8u)));
    }
    std::vector<std::uint8_t> out_;
};

[[nodiscard]] std::uint64_t reg_id(unsigned raw, unsigned width) {
    if (raw > 15u) fail("LAUNCH_GATE_LLVM_MC_REGISTER_UNSUPPORTED", kExitDecode);
    if (width == 64u) return 1u + raw;
    if (width == 32u) return 18u + raw;
    if (width == 16u) return 34u + raw;
    if (width == 8u) return 50u + raw;
    fail("LAUNCH_GATE_LLVM_MC_REGISTER_WIDTH_UNSUPPORTED", kExitDecode);
}

[[nodiscard]] std::uint64_t parent64(std::uint64_t id) {
    if (id >= 18u && id <= 33u) return id - 17u;
    if (id >= 34u && id <= 49u) return id - 33u;
    if (id >= 50u && id <= 65u) return id - 49u;
    fail("LAUNCH_GATE_LLVM_MC_PARENT_REGISTER_INVALID", kExitDecode);
}

[[nodiscard]] std::int64_t sign_value(const std::vector<std::uint8_t>& raw) {
    if (raw.empty() || raw.size() > 8u) fail("LAUNCH_GATE_LLVM_MC_SIGN_WIDTH_INVALID", kExitDecode);
    std::uint64_t value = 0u;
    for (std::size_t i = 0u; i < raw.size(); ++i) value |= static_cast<std::uint64_t>(raw[i]) << (8u * i);
    const unsigned bits = static_cast<unsigned>(raw.size() * 8u);
    if (bits == 64u) return static_cast<std::int64_t>(value);
    const std::uint64_t sign = 1ull << (bits - 1u);
    return (value & sign) == 0u ? static_cast<std::int64_t>(value) : static_cast<std::int64_t>(value | (~0ull << bits));
}

[[nodiscard]] std::vector<std::uint8_t> slice(const std::vector<std::uint8_t>& raw, std::size_t offset, std::size_t size) {
    if (offset > raw.size() || size > raw.size() - offset) fail("LAUNCH_GATE_LLVM_MC_FIELD_RANGE_INVALID", kExitDecode);
    return {raw.begin() + static_cast<std::ptrdiff_t>(offset), raw.begin() + static_cast<std::ptrdiff_t>(offset + size)};
}

[[nodiscard]] Immediate immediate(const std::vector<std::uint8_t>& raw, std::size_t at, unsigned encoded_width, unsigned semantic_width, bool sign_extend) {
    const auto encoded = slice(raw, at, encoded_width / 8u);
    if (semantic_width < encoded_width || (semantic_width != encoded_width && !sign_extend)) fail("LAUNCH_GATE_LLVM_MC_IMMEDIATE_EXTENSION_INVALID", kExitDecode);
    std::vector<std::uint8_t> semantic = encoded;
    if (semantic_width > encoded_width) {
        semantic.resize(semantic_width / 8u, (encoded.back() & 0x80u) == 0u ? 0u : 0xffu);
    }
    return Immediate{encoded_width, semantic_width, sign_extend ? 1u : 0u, semantic_width == encoded_width ? 0u : 1u, encoded, semantic};
}

struct Prefix final { std::size_t cursor; std::uint8_t rex; std::uint64_t attributes; };

[[nodiscard]] Prefix prefixes(const std::vector<std::uint8_t>& raw) {
    if (raw.empty()) fail("LAUNCH_GATE_LLVM_MC_EMPTY_INSTRUCTION", kExitDecode);
    if (raw.size() == 4u && raw[0] == 0xf3u && raw[1] == 0x0fu && raw[2] == 0x1eu && raw[3] == 0xfau) return {4u, 0u, kAttrF3Endbr | kAttrModrm | kAttrMap0F};
    std::size_t p = 0u;
    const std::uint8_t first = raw[p];
    if (first == 0xf0u || first == 0xf2u || first == 0xf3u || first == 0x66u || first == 0x67u ||
        first == 0x26u || first == 0x2eu || first == 0x36u || first == 0x3eu || first == 0x64u || first == 0x65u) fail("LAUNCH_GATE_LLVM_MC_FORBIDDEN_PREFIX", kExitDecode);
    if (first >= 0x40u && first <= 0x4fu) {
        ++p;
        std::uint64_t attributes = kAttrRex;
        if ((first & 8u) != 0u) attributes |= kAttrRexW;
        if ((first & 4u) != 0u) attributes |= kAttrRexR;
        if ((first & 2u) != 0u) attributes |= kAttrRexX;
        if ((first & 1u) != 0u) attributes |= kAttrRexB;
        if ((first & 15u) == 0u) fail("LAUNCH_GATE_LLVM_MC_REDUNDANT_REX", kExitDecode);
        if (p == raw.size() || (raw[p] >= 0x40u && raw[p] <= 0x4fu)) fail("LAUNCH_GATE_LLVM_MC_PREFIX_SEQUENCE_INVALID", kExitDecode);
        return {p, first, attributes};
    }
    return {p, 0u, 0u};
}

struct ParsedRm final { Operand operand; std::size_t cursor; std::uint64_t attributes; };

[[nodiscard]] std::uint64_t record_provenance(std::uint64_t base, std::uint64_t* offset, std::int64_t displacement) {
    if (displacement < 0) fail("LAUNCH_GATE_LLVM_MC_PROVENANCE_OFFSET_NEGATIVE", kExitDecode);
    *offset = static_cast<std::uint64_t>(displacement);
    if (base == 8u || base == 10u) return 1u;  // RDI/R9 are the input record on their respective paths.
    if (base == 9u) return 2u;                 // R8 is the result record.
    if (base == 11u) return 3u;                // R10 is clone_args.
    fail("LAUNCH_GATE_LLVM_MC_PROVENANCE_UNRESOLVED", kExitDecode);
}

[[nodiscard]] ParsedRm parse_rm(const std::vector<std::uint8_t>& raw, std::size_t cursor, std::uint8_t rex, std::uint64_t offset, std::uint64_t length, unsigned width, Access access, bool address_only) {
    if (cursor >= raw.size()) fail("LAUNCH_GATE_LLVM_MC_MODRM_MISSING", kExitDecode);
    const std::uint8_t modrm = raw[cursor++];
    const unsigned mod = (modrm >> 6u) & 3u;
    const unsigned rm_low = modrm & 7u;
    const unsigned rm = rm_low | ((rex & 1u) != 0u ? 8u : 0u);
    std::uint64_t attributes = kAttrModrm;
    if (mod == 3u) return {Reg{reg_id(rm, width), access}, cursor, attributes};

    unsigned base_raw = rm;
    unsigned index_raw = 0u;
    bool absent_index = true;
    std::uint64_t scale = 1u;
    unsigned displacement_width = 0u;
    std::int64_t displacement = 0;
    bool rip = false;
    if (rm_low == 4u) {
        if (cursor >= raw.size()) fail("LAUNCH_GATE_LLVM_MC_SIB_MISSING", kExitDecode);
        const std::uint8_t sib = raw[cursor++];
        attributes |= kAttrSib;
        scale = 1u << ((sib >> 6u) & 3u);
        const unsigned index_low = (sib >> 3u) & 7u;
        // LLVM represents SIB index=4 without REX.X as MC NoRegister.  It is
        // legal solely as this absent-index address component and is wire ID 0.
        absent_index = index_low == 4u && (rex & 2u) == 0u;
        index_raw = absent_index ? 0u : index_low | ((rex & 2u) != 0u ? 8u : 0u);
        if (absent_index) scale = 1u;
        base_raw = (sib & 7u) | ((rex & 1u) != 0u ? 8u : 0u);
        if (mod == 0u && (sib & 7u) == 5u && (rex & 1u) == 0u) fail("LAUNCH_GATE_LLVM_MC_ABSOLUTE_ADDRESS_FORBIDDEN", kExitDecode);
    } else if (mod == 0u && rm_low == 5u && (rex & 1u) == 0u) {
        rip = true;
        base_raw = 16u;  // normalized RIP is 17.
        displacement_width = 32u;
    }
    if (mod == 1u) displacement_width = 8u;
    if (mod == 2u) displacement_width = 32u;
    if (displacement_width != 0u) {
        const auto field = slice(raw, cursor, displacement_width / 8u);
        displacement = sign_value(field);
        cursor += field.size();
        attributes |= displacement_width == 8u ? kAttrDisp8 : kAttrDisp32;
    }
    if (cursor > raw.size()) fail("LAUNCH_GATE_LLVM_MC_ADDRESS_RANGE_INVALID", kExitDecode);
    const std::uint64_t base = rip ? 17u : reg_id(base_raw, 64u);
    const std::uint64_t index = absent_index ? 0u : reg_id(index_raw, 64u);
    if (index == 5u) fail("LAUNCH_GATE_LLVM_MC_RSP_INDEX_FORBIDDEN", kExitDecode);
    const std::int64_t rip_target = rip ? static_cast<std::int64_t>(offset + length) + displacement : -1;
    if (rip && (rip_target < 0 || rip_target >= static_cast<std::int64_t>(kPageSize))) fail("LAUNCH_GATE_LLVM_MC_RIP_TARGET_INVALID", kExitDecode);
    std::uint64_t provenance = 0u;
    std::uint64_t provenance_offset = 0u;
    if (rip) {
        provenance = 4u;
        provenance_offset = static_cast<std::uint64_t>(rip_target);
        if (provenance_offset != 4095u) fail("LAUNCH_GATE_LLVM_MC_GATE_PROVENANCE_INVALID", kExitDecode);
        attributes |= kAttrRipRelative;
    } else {
        provenance = record_provenance(base, &provenance_offset, displacement);
        const std::uint64_t limit = provenance == 1u ? 64u : provenance == 2u ? 48u : 88u;
        if ((address_only && provenance_offset > limit) || (!address_only && provenance_offset + width / 8u > limit)) fail("LAUNCH_GATE_LLVM_MC_PROVENANCE_RANGE_INVALID", kExitDecode);
    }
    return {Memory{access, width, Address{base, index, scale, displacement_width, displacement, rip_target, provenance, provenance_offset}}, cursor, attributes};
}

[[nodiscard]] Reg modrm_reg(std::uint8_t modrm, std::uint8_t rex, unsigned width, Access access) {
    return Reg{reg_id(((modrm >> 3u) & 7u) | ((rex & 4u) != 0u ? 8u : 0u), width), access};
}

void add_parent_write(Instruction* instruction, const Operand& destination) {
    const auto* reg = std::get_if<Reg>(&destination);
    if (reg == nullptr || reg->access == Access::Read) return;
    if (reg->id >= 18u && reg->id <= 33u) {
        instruction->implicit_writes.push_back(Reg{parent64(reg->id), Access::Write});
        instruction->attributes |= kAttrDest32ZeroExtend;
    }
}

[[nodiscard]] std::uint64_t condition_flags(std::uint64_t condition) {
    switch (condition) {
        case 2u: case 3u: return 1u;
        case 4u: case 5u: return 8u;
        case 6u: case 7u: return 9u;
        case 8u: case 9u: return 16u;
        case 12u: case 13u: return 48u;
        case 14u: case 15u: return 56u;
        default: fail("LAUNCH_GATE_LLVM_MC_CONDITION_FORBIDDEN", kExitDecode);
    }
}

[[nodiscard]] Branch branch_operand(const std::vector<std::uint8_t>& raw, std::size_t at, unsigned width, std::uint64_t offset, std::uint64_t length) {
    const auto field = slice(raw, at, width / 8u);
    const std::int64_t displacement = sign_value(field);
    const std::int64_t target = static_cast<std::int64_t>(offset + length) + displacement;
    if (target < 0 || target >= static_cast<std::int64_t>(kCodeSize)) fail("LAUNCH_GATE_LLVM_MC_BRANCH_TARGET_INVALID", kExitDecode);
    return Branch{width, displacement, static_cast<std::uint64_t>(target)};
}

[[nodiscard]] Instruction normalize(const std::vector<std::uint8_t>& raw, std::uint64_t offset) {
    if (raw.empty() || raw.size() > 15u || offset + raw.size() > kCodeSize) fail("LAUNCH_GATE_LLVM_MC_INSTRUCTION_RANGE_INVALID", kExitDecode);
    Prefix prefix = prefixes(raw);
    if (prefix.cursor == 4u && raw.size() == 4u) return Instruction{offset, raw.size(), Opcode::Endbr64, 0u, {}, {}, {}, 0u, 0u, 0u, prefix.attributes, raw};
    std::size_t p = prefix.cursor;
    if (p >= raw.size()) fail("LAUNCH_GATE_LLVM_MC_OPCODE_MISSING", kExitDecode);
    const std::uint8_t opcode = raw[p++];
    const unsigned data_width = (prefix.rex & 8u) != 0u ? 64u : 32u;
    const auto finish = [&raw](std::size_t cursor) { if (cursor != raw.size()) fail("LAUNCH_GATE_LLVM_MC_ENCODING_TRAILING_BYTES", kExitDecode); };
    if (opcode == 0x0fu) {
        if (p >= raw.size()) fail("LAUNCH_GATE_LLVM_MC_0F_TRUNCATED", kExitDecode);
        const std::uint8_t second = raw[p++];
        if (second == 0x05u) { finish(p); return Instruction{offset, raw.size(), Opcode::Syscall, 0u, {}, {Reg{1u, Access::Read}, Reg{8u, Access::Read}, Reg{7u, Access::Read}, Reg{3u, Access::Read}, Reg{11u, Access::Read}, Reg{9u, Access::Read}, Reg{10u, Access::Read}}, {Reg{1u, Access::Write}, Reg{2u, Access::Clobber}, Reg{12u, Access::Clobber}}, 0u, 0u, kFlagMaskAll, kAttrMap0F, raw}; }
        if (second >= 0x80u && second <= 0x8fu) {
            const std::uint64_t condition = second & 15u;
            const Branch branch = branch_operand(raw, p, 32u, offset, raw.size()); finish(p + 4u);
            return Instruction{offset, raw.size(), Opcode::Jcc, condition, {branch}, {}, {Reg{17u, Access::Write}}, condition_flags(condition), 0u, 0u, prefix.attributes | kAttrMap0F | kAttrBranch32, raw};
        }
        fail("LAUNCH_GATE_LLVM_MC_0F_OPCODE_FORBIDDEN", kExitDecode);
    }
    if (opcode >= 0x70u && opcode <= 0x7fu) {
        const std::uint64_t condition = opcode & 15u;
        const Branch branch = branch_operand(raw, p, 8u, offset, raw.size()); finish(p + 1u);
        return Instruction{offset, raw.size(), Opcode::Jcc, condition, {branch}, {}, {Reg{17u, Access::Write}}, condition_flags(condition), 0u, 0u, prefix.attributes | kAttrBranch8, raw};
    }
    if (opcode == 0xebu || opcode == 0xe9u) {
        const unsigned width = opcode == 0xebu ? 8u : 32u;
        const Branch branch = branch_operand(raw, p, width, offset, raw.size()); finish(p + width / 8u);
        return Instruction{offset, raw.size(), Opcode::Jmp, 0u, {branch}, {}, {Reg{17u, Access::Write}}, 0u, 0u, 0u, prefix.attributes | (width == 8u ? kAttrBranch8 : kAttrBranch32), raw};
    }
    if (opcode == 0xc3u) {
        finish(p);
        const Memory stack{Access::Read, 64u, Address{5u, 0u, 1u, 0u, 0, -1, 5u, 0u}};
        return Instruction{offset, raw.size(), Opcode::Ret, 0u, {}, {Reg{5u, Access::Read}, stack}, {Reg{5u, Access::Write}, Reg{17u, Access::Write}}, 0u, 0u, 0u, 0u, raw};
    }
    if (opcode >= 0xb8u && opcode <= 0xbfu) {
        const unsigned raw_register = (opcode - 0xb8u) | ((prefix.rex & 1u) != 0u ? 8u : 0u);
        const unsigned imm_width = data_width == 64u ? 64u : 32u;
        const Immediate imm = immediate(raw, p, imm_width, data_width, false); finish(p + imm_width / 8u);
        Instruction result{offset, raw.size(), Opcode::Mov, 0u, {Reg{reg_id(raw_register, data_width), Access::Write}, imm}, {}, {}, 0u, 0u, 0u, prefix.attributes | (imm_width == 64u ? kAttrImm64 : kAttrImm32), raw};
        add_parent_write(&result, result.explicit_operands.front()); return result;
    }
    if (opcode == 0xa9u) {
        const Immediate imm = immediate(raw, p, 32u, data_width, data_width > 32u);
        finish(p + 4u);
        return Instruction{offset, raw.size(), Opcode::Test, 0u, {Reg{reg_id(0u, data_width), Access::Read}, imm}, {}, {}, 0u, 59u, 4u, prefix.attributes | kAttrImm32 | (data_width > 32u ? kAttrImmSignExtend : 0u), raw};
    }
    if (p >= raw.size()) fail("LAUNCH_GATE_LLVM_MC_MODRM_MISSING", kExitDecode);
    const std::uint8_t modrm = raw[p];
    const unsigned group = (modrm >> 3u) & 7u;
    if (opcode == 0x89u || opcode == 0x8bu || opcode == 0x8du || opcode == 0x31u || opcode == 0x85u || opcode == 0x39u || opcode == 0x3bu || opcode == 0x81u || opcode == 0x83u || opcode == 0xc7u || opcode == 0xf7u) {
        const bool rm_destination = opcode == 0x89u || opcode == 0x31u || opcode == 0xc7u;
        const bool is_lea = opcode == 0x8du;
        const bool is_group_imm = opcode == 0x81u || opcode == 0x83u || opcode == 0xc7u || opcode == 0xf7u;
        if ((opcode == 0x81u || opcode == 0x83u) && group != 7u) fail("LAUNCH_GATE_LLVM_MC_GROUP_OPCODE_FORBIDDEN", kExitDecode);
        if (opcode == 0xc7u && group != 0u) fail("LAUNCH_GATE_LLVM_MC_GROUP_OPCODE_FORBIDDEN", kExitDecode);
        if (opcode == 0xf7u && group != 0u) fail("LAUNCH_GATE_LLVM_MC_GROUP_OPCODE_FORBIDDEN", kExitDecode);
        const Access rm_access = rm_destination ? (opcode == 0x31u ? Access::ReadWrite : Access::Write) : Access::Read;
        ParsedRm parsed = parse_rm(raw, p, prefix.rex, offset, raw.size(), data_width, rm_access, is_lea);
        p = parsed.cursor;
        const Reg reg_read = modrm_reg(modrm, prefix.rex, data_width, Access::Read);
        const Reg reg_write = modrm_reg(modrm, prefix.rex, data_width, Access::Write);
        std::uint64_t attributes = prefix.attributes | parsed.attributes;
        if (is_lea) {
            const auto* memory = std::get_if<Memory>(&parsed.operand);
            if (memory == nullptr) fail("LAUNCH_GATE_LLVM_MC_LEA_REGISTER_SOURCE_FORBIDDEN", kExitDecode);
            Address address = memory->address;
            if (address.provenance == 4u && address.provenance_offset != 4095u) fail("LAUNCH_GATE_LLVM_MC_GATE_PROVENANCE_INVALID", kExitDecode);
            finish(p);
            Instruction result{offset, raw.size(), Opcode::Lea, 0u, {reg_write, address}, {}, {}, 0u, 0u, 0u, attributes, raw};
            add_parent_write(&result, result.explicit_operands.front()); return result;
        }
        if (opcode == 0x89u || opcode == 0x8bu) {
            const Operand destination = opcode == 0x89u ? parsed.operand : Operand{reg_write};
            const Operand source = opcode == 0x89u ? Operand{reg_read} : parsed.operand;
            finish(p);
            Instruction result{offset, raw.size(), Opcode::Mov, 0u, {destination, source}, {}, {}, 0u, 0u, 0u, attributes, raw};
            add_parent_write(&result, result.explicit_operands.front()); return result;
        }
        if (opcode == 0x31u) {
            const auto* destination = std::get_if<Reg>(&parsed.operand);
            if (destination == nullptr || destination->id != reg_read.id) fail("LAUNCH_GATE_LLVM_MC_XOR_NOT_ZERO", kExitDecode);
            finish(p);
            Instruction result{offset, raw.size(), Opcode::XorZero, 0u, {Reg{destination->id, Access::ReadWrite}, reg_read}, {}, {}, 0u, 59u, 4u, attributes, raw};
            add_parent_write(&result, result.explicit_operands.front()); return result;
        }
        if (opcode == 0x85u || opcode == 0xf7u) {
            std::vector<Operand> operands{parsed.operand};
            if (opcode == 0x85u) { operands.push_back(reg_read); }
            else { const Immediate imm = immediate(raw, p, 32u, data_width, data_width > 32u); p += 4u; attributes |= kAttrImm32 | (data_width > 32u ? kAttrImmSignExtend : 0u); operands.push_back(imm); }
            finish(p);
            return Instruction{offset, raw.size(), Opcode::Test, 0u, operands, {}, {}, 0u, 59u, 4u, attributes, raw};
        }
        if (opcode == 0x39u || opcode == 0x3bu || opcode == 0x81u || opcode == 0x83u) {
            std::vector<Operand> operands;
            if (opcode == 0x39u) { operands = {parsed.operand, reg_read}; }
            else if (opcode == 0x3bu) { operands = {reg_read, parsed.operand}; }
            else {
                const unsigned imm_width = opcode == 0x83u ? 8u : 32u;
                const Immediate imm = immediate(raw, p, imm_width, data_width, true); p += imm_width / 8u;
                attributes |= (imm_width == 8u ? kAttrImm8 : kAttrImm32) | kAttrImmSignExtend;
                operands = {parsed.operand, imm};
            }
            finish(p);
            return Instruction{offset, raw.size(), Opcode::Cmp, 0u, operands, {}, {}, 0u, 63u, 0u, attributes, raw};
        }
        if (opcode == 0xc7u) {
            const Immediate imm = immediate(raw, p, 32u, data_width, data_width > 32u); p += 4u; attributes |= kAttrImm32 | (data_width > 32u ? kAttrImmSignExtend : 0u); finish(p);
            Instruction result{offset, raw.size(), Opcode::Mov, 0u, {parsed.operand, imm}, {}, {}, 0u, 0u, 0u, attributes, raw};
            add_parent_write(&result, result.explicit_operands.front()); return result;
        }
    }
    fail("LAUNCH_GATE_LLVM_MC_OPCODE_FORBIDDEN", kExitDecode);
}

void encode_operand(Cbor* cbor, const Operand& operand) {
    if (const auto* reg = std::get_if<Reg>(&operand)) { cbor->array(3u); cbor->uint(0u); cbor->uint(reg->id); cbor->uint(static_cast<std::uint64_t>(reg->access)); return; }
    if (const auto* imm = std::get_if<Immediate>(&operand)) { cbor->array(7u); cbor->uint(1u); cbor->uint(imm->encoded_width); cbor->uint(imm->semantic_width); cbor->uint(imm->signedness); cbor->uint(imm->extension); cbor->bytes(imm->encoded); cbor->bytes(imm->semantic); return; }
    if (const auto* branch = std::get_if<Branch>(&operand)) { cbor->array(4u); cbor->uint(2u); cbor->uint(branch->width); cbor->sint(branch->displacement); cbor->uint(branch->target); return; }
    const auto encode_address = [cbor](const Address& address, bool memory, Access access, std::uint64_t width) {
        cbor->array(memory ? 12u : 10u); cbor->uint(memory ? 3u : 4u);
        if (memory) { cbor->uint(static_cast<std::uint64_t>(access)); cbor->uint(width); }
        cbor->uint(64u); cbor->uint(address.base); cbor->uint(address.index); cbor->uint(address.scale); cbor->uint(address.displacement_width); cbor->sint(address.displacement); cbor->sint(address.rip_target); cbor->uint(address.provenance); cbor->uint(address.provenance_offset);
    };
    if (const auto* memory = std::get_if<Memory>(&operand)) { encode_address(memory->address, true, memory->access, memory->width); return; }
    if (const auto* address = std::get_if<Address>(&operand)) { encode_address(*address, false, Access::Read, 0u); return; }
    fail("LAUNCH_GATE_LLVM_MC_OPERAND_VARIANT_INVALID", kExitDecode);
}

void encode_operands(Cbor* cbor, const std::vector<Operand>& operands) { cbor->array(operands.size()); for (const Operand& operand : operands) encode_operand(cbor, operand); }

[[nodiscard]] std::vector<std::uint8_t> encode_instruction_manifest(const std::map<std::uint64_t, Instruction>& instructions) {
    Cbor cbor; cbor.array(instructions.size());
    for (const auto& [offset, instruction] : instructions) {
        cbor.array(4u); cbor.uint(offset); cbor.uint(instruction.length); cbor.uint(static_cast<std::uint64_t>(instruction.opcode)); cbor.array(9u);
        cbor.uint(instruction.condition); encode_operands(&cbor, instruction.explicit_operands); encode_operands(&cbor, instruction.implicit_reads); encode_operands(&cbor, instruction.implicit_writes);
        cbor.uint(instruction.flags_read); cbor.uint(instruction.flags_write); cbor.uint(instruction.flags_undefined); cbor.uint(instruction.attributes); cbor.bytes(instruction.raw);
    }
    return cbor.value();
}

[[nodiscard]] std::vector<std::uint8_t> encode_cfg_manifest(const std::vector<Block>& blocks) {
    Cbor cbor; cbor.array(blocks.size());
    for (const Block& block : blocks) { cbor.array(3u); cbor.uint(block.start); cbor.uint(block.terminal); cbor.array(block.successors.size()); for (const std::uint64_t successor : block.successors) cbor.uint(successor); }
    return cbor.value();
}

void write_exact_output(const char* path, const std::vector<std::uint8_t>& value) {
    const int fd = ::open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) fail("LAUNCH_GATE_LLVM_MC_OUTPUT_CREATE_FAILED", kExitIo);
    std::size_t at = 0u;
    while (at < value.size()) {
        const ssize_t count = ::write(fd, value.data() + at, value.size() - at);
        if (count <= 0) { const int saved = errno; ::close(fd); ::unlink(path); errno = saved; fail("LAUNCH_GATE_LLVM_MC_OUTPUT_WRITE_FAILED", kExitIo); }
        at += static_cast<std::size_t>(count);
    }
    if (::fsync(fd) != 0) {
        (void)::close(fd);
        (void)::unlink(path);
        fail("LAUNCH_GATE_LLVM_MC_OUTPUT_SYNC_FAILED", kExitIo);
    }
    if (::close(fd) != 0) {
        (void)::unlink(path);
        fail("LAUNCH_GATE_LLVM_MC_OUTPUT_CLOSE_FAILED", kExitIo);
    }
}

[[nodiscard]] std::pair<std::map<std::uint64_t, Instruction>, std::map<std::uint64_t, Flow>> decode_all(llvm::MCDisassembler& decoder, const std::vector<std::uint8_t>& page) {
    std::set<std::uint64_t> pending{0u};
    std::map<std::uint64_t, Instruction> decoded;
    std::map<std::uint64_t, Flow> flows;
    std::array<std::int64_t, kCodeSize> owners{}; owners.fill(-1);
    while (!pending.empty()) {
        const std::uint64_t offset = *pending.begin(); pending.erase(pending.begin());
        if (decoded.contains(offset)) continue;
        llvm::MCInst raw_instance; std::uint64_t llvm_length = 0u;
        const auto status = decoder.getInstruction(raw_instance, llvm_length, llvm::ArrayRef<std::uint8_t>(page.data() + offset, kCodeSize - offset), offset, llvm::nulls());
        if (status != llvm::MCDisassembler::Success || llvm_length == 0u || llvm_length > 15u || llvm_length > kCodeSize - offset) fail("LAUNCH_GATE_LLVM_MC_DECODE_NOT_SUCCESS", kExitDecode);
        for (std::uint64_t byte = offset; byte < offset + llvm_length; ++byte) if (owners[byte] != -1 && owners[byte] != static_cast<std::int64_t>(offset)) fail("LAUNCH_GATE_LLVM_MC_DECODE_OVERLAP", kExitDecode);
        const Instruction instruction = normalize(slice(page, offset, llvm_length), offset);
        if (instruction.length != llvm_length) fail("LAUNCH_GATE_LLVM_MC_BOUNDARY_DISAGREEMENT", kExitDecode);
        for (std::uint64_t byte = offset; byte < offset + llvm_length; ++byte) owners[byte] = static_cast<std::int64_t>(offset);
        std::vector<std::uint64_t> successors;
        if (instruction.opcode == Opcode::Jcc || instruction.opcode == Opcode::Jmp) successors.push_back(std::get<Branch>(instruction.explicit_operands.front()).target);
        if (instruction.opcode != Opcode::Jmp && instruction.opcode != Opcode::Ret) successors.push_back(offset + instruction.length);
        for (const std::uint64_t successor : successors) {
            if (successor >= kCodeSize) fail("LAUNCH_GATE_LLVM_MC_SUCCESSOR_RANGE_INVALID", kExitDecode);
            for (const auto& [start, known] : decoded) if (successor > start && successor < start + known.length) fail("LAUNCH_GATE_LLVM_MC_SUCCESSOR_INTERIOR_INVALID", kExitDecode);
            pending.insert(successor);
        }
        decoded.emplace(offset, instruction); flows.emplace(offset, Flow{successors});
    }
    for (const std::int64_t owner : owners) if (owner < 0) fail("LAUNCH_GATE_LLVM_MC_REACHABILITY_COVERAGE_INCOMPLETE", kExitDecode);
    for (const auto& [offset, flow] : flows) for (const std::uint64_t successor : flow.successors) if (!decoded.contains(successor)) fail("LAUNCH_GATE_LLVM_MC_SUCCESSOR_NOT_DECODED", kExitDecode);
    return {std::move(decoded), std::move(flows)};
}

[[nodiscard]] std::vector<Block> build_cfg(const std::map<std::uint64_t, Instruction>& decoded, const std::map<std::uint64_t, Flow>& flows) {
    std::set<std::uint64_t> starts{0u};
    for (const auto& [offset, instruction] : decoded) {
        const Flow& flow = flows.at(offset);
        if (instruction.opcode == Opcode::Jcc || instruction.opcode == Opcode::Jmp) starts.insert(flow.successors.front());
        if (instruction.opcode == Opcode::Jcc || instruction.opcode == Opcode::Syscall) starts.insert(offset + instruction.length);
    }
    for (const std::uint64_t start : starts) if (!decoded.contains(start)) fail("LAUNCH_GATE_LLVM_MC_BLOCK_START_INVALID", kExitDecode);
    std::set<std::uint64_t> assigned; std::vector<Block> blocks;
    for (const std::uint64_t start : starts) {
        if (assigned.contains(start)) fail("LAUNCH_GATE_LLVM_MC_BLOCK_OVERLAP", kExitDecode);
        std::uint64_t current = start;
        for (;;) {
            const Instruction& instruction = decoded.at(current);
            if (!assigned.insert(current).second) fail("LAUNCH_GATE_LLVM_MC_BLOCK_OVERLAP", kExitDecode);
            const std::uint64_t next = current + instruction.length;
            if (instruction.opcode == Opcode::Jcc) { const auto& s = flows.at(current).successors; blocks.push_back({start, 1u, s}); break; }
            if (instruction.opcode == Opcode::Jmp) { blocks.push_back({start, 2u, flows.at(current).successors}); break; }
            if (instruction.opcode == Opcode::Ret) { blocks.push_back({start, 3u, {}}); break; }
            if (instruction.opcode == Opcode::Syscall) { blocks.push_back({start, 4u, flows.at(current).successors}); break; }
            if (next >= kCodeSize || !decoded.contains(next)) fail("LAUNCH_GATE_LLVM_MC_BLOCK_FALLTHROUGH_INVALID", kExitDecode);
            if (starts.contains(next)) { blocks.push_back({start, 0u, {next}}); break; }
            current = next;
        }
    }
    if (assigned.size() != decoded.size()) fail("LAUNCH_GATE_LLVM_MC_BLOCK_COVERAGE_INVALID", kExitDecode);
    for (const Block& block : blocks) {
        std::set<std::uint64_t> distinct;
        for (const std::uint64_t successor : block.successors) if (!starts.contains(successor) || !distinct.insert(successor).second) fail("LAUNCH_GATE_LLVM_MC_CFG_SUCCESSOR_INVALID", kExitDecode);
    }
    return blocks;
}

}  // namespace

int main(int argc, char* argv[]) {
    if (argc != 4) fail("usage: launch_gate_llvm_mc_decoder_v1 PAGE GATE_CODE_SIZE OUTPUT_CBOR", kExitUsage);
    std::uint64_t code_size = 0u;
    if (!parse_code_size(argv[2], &code_size) || code_size != kCodeSize) fail("LAUNCH_GATE_LLVM_MC_CODE_SIZE_INVALID", kExitUsage);
    verify_loaded_llvm_custody();
    const std::vector<std::uint8_t> page = read_page(argv[1]);
    if (!std::all_of(page.begin() + static_cast<std::ptrdiff_t>(kCodeSize), page.end() - 1, [](std::uint8_t value) { return value == 0xccu; }) || page.back() != 0u) fail("LAUNCH_GATE_LLVM_MC_TRAILER_INVALID", kExitDecode);
    LLVMInitializeX86TargetInfo(); LLVMInitializeX86TargetMC(); LLVMInitializeX86Disassembler();
    constexpr const char* triple = "x86_64-unknown-linux-gnu";
    std::string error; const llvm::Target* target = llvm::TargetRegistry::lookupTarget(triple, error);
    if (target == nullptr) fail("LAUNCH_GATE_LLVM_MC_TARGET_LOOKUP_FAILED", kExitDecode);
    auto registers = std::unique_ptr<llvm::MCRegisterInfo>(target->createMCRegInfo(triple));
    auto instructions = std::unique_ptr<llvm::MCInstrInfo>(target->createMCInstrInfo());
    auto subtarget = std::unique_ptr<llvm::MCSubtargetInfo>(target->createMCSubtargetInfo(triple, "x86-64", ""));
    if (!registers || !instructions || !subtarget) fail("LAUNCH_GATE_LLVM_MC_COMPONENT_CREATE_FAILED", kExitDecode);
    const llvm::MCTargetOptions options;
    auto assembly = std::unique_ptr<llvm::MCAsmInfo>(target->createMCAsmInfo(*registers, triple, options));
    if (!assembly) fail("LAUNCH_GATE_LLVM_MC_ASMINFO_CREATE_FAILED", kExitDecode);
    llvm::MCContext context(llvm::Triple(triple), assembly.get(), registers.get(), subtarget.get());
    auto decoder = std::unique_ptr<llvm::MCDisassembler>(target->createMCDisassembler(*subtarget, context));
    if (!decoder) fail("LAUNCH_GATE_LLVM_MC_DECODER_CREATE_FAILED", kExitDecode);
    auto [decoded, flows] = decode_all(*decoder, page);
    const std::vector<Block> blocks = build_cfg(decoded, flows);
    const auto page_hash = llvm::SHA256::hash(llvm::ArrayRef<std::uint8_t>(page.data(), page.size()));
    const std::vector<std::uint8_t> instruction_manifest = encode_instruction_manifest(decoded);
    const std::vector<std::uint8_t> cfg_manifest = encode_cfg_manifest(blocks);
    Cbor wrapper; wrapper.array(6u); wrapper.uint(kProtocolId); wrapper.uint(kWireVersion); wrapper.bytes(page_hash); wrapper.uint(kCodeSize); wrapper.append(instruction_manifest); wrapper.append(cfg_manifest);
    write_exact_output(argv[3], wrapper.value());
    return 0;
}
