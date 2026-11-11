#include "Stage1ExtractionCustodyReceiptV2EncoderCore.h"

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <limits>
#include <new>
#include <span>
#include <vector>

// The encoder must not allocate.  The test itself is allowed to own fixtures
// dynamically, so count allocations only around an encoder invocation.
namespace {
std::atomic<std::size_t> g_new_calls{0u};
}

void* operator new(const std::size_t size) {
  g_new_calls.fetch_add(1u, std::memory_order_relaxed);
  if (void* const result = std::malloc(size == 0u ? 1u : size); result != nullptr) {
    return result;
  }
  std::abort();
}

void* operator new[](const std::size_t size) {
  g_new_calls.fetch_add(1u, std::memory_order_relaxed);
  if (void* const result = std::malloc(size == 0u ? 1u : size); result != nullptr) {
    return result;
  }
  std::abort();
}

void operator delete(void* const pointer) noexcept { std::free(pointer); }
void operator delete[](void* const pointer) noexcept { std::free(pointer); }
void operator delete(void* const pointer, std::size_t) noexcept { std::free(pointer); }
void operator delete[](void* const pointer, std::size_t) noexcept { std::free(pointer); }

namespace {

using namespace evaluation_v6_3_1::stage1::receipt_v2::offline;

int g_failures = 0;

void check(const bool condition, const char* const message) {
  if (!condition) {
    std::fprintf(stderr, "FAIL: %s\n", message);
    ++g_failures;
  }
}

bool equal(const std::uint8_t* const left, const std::uint8_t* const right,
           const std::size_t count) {
  std::uint8_t difference = 0u;
  for (std::size_t index = 0u; index < count; ++index) {
    difference = static_cast<std::uint8_t>(difference | (left[index] ^ right[index]));
  }
  return difference == 0u;
}

template <std::size_t N>
bool all_zero(const std::array<std::uint8_t, N>& bytes) {
  std::uint8_t combined = 0u;
  for (const std::uint8_t byte : bytes) {
    combined = static_cast<std::uint8_t>(combined | byte);
  }
  return combined == 0u;
}

bool all_zero(const std::span<const std::uint8_t> bytes) {
  std::uint8_t combined = 0u;
  for (const std::uint8_t byte : bytes) {
    combined = static_cast<std::uint8_t>(combined | byte);
  }
  return combined == 0u;
}

constexpr std::uint32_t rotr(const std::uint32_t value, const unsigned shift) {
  return (value >> shift) | (value << (32u - shift));
}

class TestSha256 final {
 public:
  void update(const std::uint8_t* const data, const std::size_t size) {
    for (std::size_t offset = 0u; offset < size; ++offset) {
      block_[used_++] = data[offset];
      if (used_ == block_.size()) {
        compress();
        used_ = 0u;
      }
    }
    bytes_ += size;
  }

  Sha256Digest finish() {
    const std::uint64_t bit_count = bytes_ * 8u;
    block_[used_++] = 0x80u;
    if (used_ > 56u) {
      while (used_ < block_.size()) {
        block_[used_++] = 0u;
      }
      compress();
      used_ = 0u;
    }
    while (used_ < 56u) {
      block_[used_++] = 0u;
    }
    for (unsigned index = 0u; index < 8u; ++index) {
      block_[63u - index] = static_cast<std::uint8_t>(bit_count >> (index * 8u));
    }
    compress();
    Sha256Digest output{};
    for (unsigned index = 0u; index < 8u; ++index) {
      output[index * 4u] = static_cast<std::uint8_t>(state_[index] >> 24u);
      output[index * 4u + 1u] = static_cast<std::uint8_t>(state_[index] >> 16u);
      output[index * 4u + 2u] = static_cast<std::uint8_t>(state_[index] >> 8u);
      output[index * 4u + 3u] = static_cast<std::uint8_t>(state_[index]);
    }
    return output;
  }

 private:
  void compress() {
    static constexpr std::array<std::uint32_t, 64u> k = {
        0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u,
        0x923f82a4u, 0xab1c5ed5u, 0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
        0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u, 0xe49b69c1u, 0xefbe4786u,
        0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
        0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u,
        0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
        0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u, 0xa2bfe8a1u, 0xa81a664bu,
        0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
        0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au,
        0x5b9cca4fu, 0x682e6ff3u, 0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
        0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
    };
    std::array<std::uint32_t, 64u> words{};
    for (unsigned index = 0u; index < 16u; ++index) {
      const auto base = index * 4u;
      words[index] = (static_cast<std::uint32_t>(block_[base]) << 24u) |
                     (static_cast<std::uint32_t>(block_[base + 1u]) << 16u) |
                     (static_cast<std::uint32_t>(block_[base + 2u]) << 8u) |
                     static_cast<std::uint32_t>(block_[base + 3u]);
    }
    for (unsigned index = 16u; index < 64u; ++index) {
      const auto s0 = rotr(words[index - 15u], 7u) ^ rotr(words[index - 15u], 18u) ^
                      (words[index - 15u] >> 3u);
      const auto s1 = rotr(words[index - 2u], 17u) ^ rotr(words[index - 2u], 19u) ^
                      (words[index - 2u] >> 10u);
      words[index] = words[index - 16u] + s0 + words[index - 7u] + s1;
    }
    std::uint32_t a = state_[0], b = state_[1], c = state_[2], d = state_[3];
    std::uint32_t e = state_[4], f = state_[5], g = state_[6], h = state_[7];
    for (unsigned index = 0u; index < 64u; ++index) {
      const auto s1 = rotr(e, 6u) ^ rotr(e, 11u) ^ rotr(e, 25u);
      const auto choose = (e & f) ^ ((~e) & g);
      const auto t1 = h + s1 + choose + k[index] + words[index];
      const auto s0 = rotr(a, 2u) ^ rotr(a, 13u) ^ rotr(a, 22u);
      const auto majority = (a & b) ^ (a & c) ^ (b & c);
      const auto t2 = s0 + majority;
      h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    state_[0] += a; state_[1] += b; state_[2] += c; state_[3] += d;
    state_[4] += e; state_[5] += f; state_[6] += g; state_[7] += h;
  }

  std::array<std::uint32_t, 8u> state_ = {
      0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
      0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u,
  };
  std::array<std::uint8_t, 64u> block_{};
  std::size_t used_ = 0u;
  std::uint64_t bytes_ = 0u;
};

Sha256Digest digest(const std::uint8_t* const data, const std::size_t size) {
  TestSha256 sha;
  sha.update(data, size);
  return sha.finish();
}

Sha256Digest root_for(const std::uint8_t* const body, const std::size_t size,
                      const std::uint8_t* const domain,
                      const std::size_t domain_size) {
  TestSha256 sha;
  sha.update(domain, domain_size);
  sha.update(body, size);
  return sha.finish();
}

Sha256Digest tag_hash(const char tag, const unsigned index) {
  std::array<std::uint8_t, 16u> input{};
  std::size_t length = 0u;
  input[length++] = static_cast<std::uint8_t>(tag);
  input[length++] = static_cast<std::uint8_t>(':');
  unsigned digits[10]{};
  unsigned count = 0u;
  unsigned current = index;
  do {
    digits[count++] = current % 10u;
    current /= 10u;
  } while (current != 0u);
  while (count != 0u) {
    input[length++] = static_cast<std::uint8_t>('0' + digits[--count]);
  }
  return digest(input.data(), length);
}

Sha256Digest literal_hash(const char* const value) {
  std::size_t length = 0u;
  while (value[length] != '\0') {
    ++length;
  }
  return digest(reinterpret_cast<const std::uint8_t*>(value), length);
}

Sha256Digest hex_digest(const char* const hex) {
  Sha256Digest result{};
  auto hex_value = [](const char character) -> std::uint8_t {
    if (character >= '0' && character <= '9') return static_cast<std::uint8_t>(character - '0');
    if (character >= 'a' && character <= 'f') return static_cast<std::uint8_t>(character - 'a' + 10);
    return static_cast<std::uint8_t>(character - 'A' + 10);
  };
  for (std::size_t index = 0u; index < result.size(); ++index) {
    result[index] = static_cast<std::uint8_t>((hex_value(hex[index * 2u]) << 4u) |
                                              hex_value(hex[index * 2u + 1u]));
  }
  return result;
}

struct Fixture final {
  std::vector<std::vector<std::uint8_t>> bytes;
  std::vector<std::vector<ByteView>> byte_arrays;
  std::vector<std::vector<std::uint64_t>> uint_arrays;
  std::vector<std::vector<TaskCensusRowV1Wire>> tasks;
  std::vector<std::vector<ProcessCensusRowV1Wire>> processes;
  Stage1ExtractionCustodyBodyV2WireView body{};

  ByteView raw(std::vector<std::uint8_t> value) {
    bytes.emplace_back(std::move(value));
    const auto& stored = bytes.back();
    return ByteView{stored.empty() ? nullptr : stored.data(), stored.size()};
  }

  ByteView text(const char* const value) {
    std::vector<std::uint8_t> encoded{};
    for (std::size_t index = 0u; value[index] != '\0'; ++index) {
      encoded.push_back(static_cast<std::uint8_t>(value[index]));
    }
    return raw(std::move(encoded));
  }

  ByteView seeded_text(const char* const prefix, const std::uint64_t seed) {
    std::vector<std::uint8_t> encoded{};
    for (std::size_t index = 0u; prefix[index] != '\0'; ++index) {
      encoded.push_back(static_cast<std::uint8_t>(prefix[index]));
    }
    std::uint8_t digits[20]{};
    std::size_t count = 0u;
    std::uint64_t remaining = seed;
    do {
      digits[count++] = static_cast<std::uint8_t>(remaining % 10u);
      remaining /= 10u;
    } while (remaining != 0u);
    while (count != 0u) {
      encoded.push_back(static_cast<std::uint8_t>('0' + digits[--count]));
    }
    return raw(std::move(encoded));
  }

  ByteView repeated(const std::uint8_t value, const std::size_t count) {
    return raw(std::vector<std::uint8_t>(count, value));
  }

  ArrayView<ByteView> byte_array(std::vector<ByteView> values) {
    byte_arrays.emplace_back(std::move(values));
    const auto& stored = byte_arrays.back();
    return ArrayView<ByteView>{stored.empty() ? nullptr : stored.data(), stored.size()};
  }

  ArrayView<std::uint64_t> uint_array(std::vector<std::uint64_t> values) {
    uint_arrays.emplace_back(std::move(values));
    const auto& stored = uint_arrays.back();
    return ArrayView<std::uint64_t>{stored.empty() ? nullptr : stored.data(), stored.size()};
  }

  ObjectIdentityV1Wire object(const std::uint64_t seed, const std::uint32_t mode) const {
    return ObjectIdentityV1Wire{
        seed,
        static_cast<std::uint32_t>(seed + 1u),
        static_cast<std::uint32_t>(seed + 2u),
        1000u + seed,
        mode,
        static_cast<std::uint32_t>(2000u + seed),
        static_cast<std::uint32_t>(3000u + seed),
        4000u + seed,
        5000u + seed,
    };
  }

  FileIdentityV1Wire file(const std::uint64_t seed, const Sha256Digest& hash,
                          const std::uint32_t mode = 0100444u) const {
    return FileIdentityV1Wire{object(seed, mode), hash};
  }

  MountInfoRecordV1Wire mount(const std::uint64_t seed) {
    return MountInfoRecordV1Wire{
        1u,
        10u + seed,
        20u + seed,
        static_cast<std::uint32_t>(30u + seed),
        static_cast<std::uint32_t>(40u + seed),
        seeded_text("/root-", seed),
        seeded_text("/point-", seed),
        byte_array({seeded_text("mount-option-", seed)}),
        byte_array({seeded_text("optional-", seed)}),
        seeded_text("filesystem-", seed),
        seeded_text("source-", seed),
        byte_array({seeded_text("super-option-", seed)}),
        0x794c7630u,
        static_cast<std::uint32_t>(50u + seed),
        static_cast<std::uint32_t>(60u + seed),
        70u + seed,
        seeded_text("raw-mountinfo-", seed),
    };
  }

  ProcessCensusV1Wire census(const std::uint64_t seed) {
    tasks.emplace_back(std::vector<TaskCensusRowV1Wire>{
        TaskCensusRowV1Wire{1u, CwdIdentityV1Wire{1u, 8u, 0u, 100u}},
    });
    const auto first_tasks = ArrayView<TaskCensusRowV1Wire>{tasks.back().data(), tasks.back().size()};
    tasks.emplace_back(std::vector<TaskCensusRowV1Wire>{
        TaskCensusRowV1Wire{2u, CwdIdentityV1Wire{2u, 8u, 0u, 200u}},
    });
    const auto second_tasks = ArrayView<TaskCensusRowV1Wire>{tasks.back().data(), tasks.back().size()};
    processes.emplace_back(std::vector<ProcessCensusRowV1Wire>{
        ProcessCensusRowV1Wire{1u, 100u + seed, first_tasks},
        ProcessCensusRowV1Wire{2u, 200u + seed, second_tasks},
    });
    const auto& stored = processes.back();
    return ProcessCensusV1Wire{stored.data(), stored.size()};
  }

  ProcessCensusV1Wire vector_c_census() {
    tasks.emplace_back(std::vector<TaskCensusRowV1Wire>{
        TaskCensusRowV1Wire{1u, CwdIdentityV1Wire{1u, 8u, 0u, 100u}},
        TaskCensusRowV1Wire{3u, CwdIdentityV1Wire{3u, 9u, 1u, 101u}},
    });
    const auto first_tasks =
        ArrayView<TaskCensusRowV1Wire>{tasks.back().data(), tasks.back().size()};
    tasks.emplace_back(std::vector<TaskCensusRowV1Wire>{
        TaskCensusRowV1Wire{2u, CwdIdentityV1Wire{2u, 8u, 0u, 200u}},
    });
    const auto second_tasks =
        ArrayView<TaskCensusRowV1Wire>{tasks.back().data(), tasks.back().size()};
    tasks.emplace_back(std::vector<TaskCensusRowV1Wire>{
        TaskCensusRowV1Wire{4u, CwdIdentityV1Wire{4u, 10u, 2u, 400u}},
    });
    const auto third_tasks =
        ArrayView<TaskCensusRowV1Wire>{tasks.back().data(), tasks.back().size()};
    processes.emplace_back(std::vector<ProcessCensusRowV1Wire>{
        ProcessCensusRowV1Wire{1u, 101u, first_tasks},
        ProcessCensusRowV1Wire{2u, 202u, second_tasks},
        ProcessCensusRowV1Wire{4u, 404u, third_tasks},
    });
    const auto& stored = processes.back();
    return ProcessCensusV1Wire{stored.data(), stored.size()};
  }
};

constexpr std::uint32_t kExecutable = 0100755u;
constexpr std::uint32_t kDirectory = 0040755u;

Fixture make_fixture(const char tag) {
  Fixture fixture{};
  const auto code = static_cast<unsigned char>(tag);
  const auto hash = [tag](const unsigned index) { return tag_hash(tag, index); };
  const RootMountCustodyV2Wire root_pre{fixture.mount(code), fixture.object(500u + code, kDirectory)};
  const auto extraction_pre = DirectoryIdentityV1Wire{
      fixture.object(600u + code, 0040700u), 0x794c7630u, 1u, 2u, 0u};
  const auto raw_pre = fixture.file(700u + code, hash(7u));
  const auto page_pre = fixture.file(701u + code, hash(25u));
  fixture.body = Stage1ExtractionCustodyBodyV2WireView{
      Sha256Digest{},
      fixture.file(100u + code, hash(1u), kExecutable),
      NamespaceIdentityV1Wire{1u, 2u, 3u},
      NamespaceIdentityV1Wire{4u, 5u, 6u},
      root_pre,
      fixture.mount(code + 1u),
      extraction_pre,
      raw_pre,
      fixture.file(102u + code, hash(8u), kExecutable),
      fixture.file(103u + code, hash(9u), kExecutable),
      fixture.byte_array({fixture.text("/usr/bin/env"), fixture.text("-i"),
                          fixture.raw(std::vector<std::uint8_t>{static_cast<std::uint8_t>(tag), '-', 'a', 'r', 'g', 'v'})}),
      fixture.byte_array({fixture.text("PATH=/usr/bin:/bin"),
                          fixture.raw(std::vector<std::uint8_t>{static_cast<std::uint8_t>(tag), '-', 'e', 'n', 'v'})}),
      SeccompPolicyV1Wire{0xc000003eu, 0x40000000u, 0x80000000u, 0x7fff0000u,
                           fixture.uint_array({56u, 57u, 58u, 80u, 81u, 155u, 165u, 166u, 272u,
                                               308u, 428u, 429u, 430u, 431u, 432u, 433u, 435u, 442u}),
                           hash(12u)},
      fixture.census(1u), fixture.census(1u), 2u, 900u + code, UIntPairV1Wire{1u, 2u},
      fixture.census(2u), fixture.census(2u), UIntPairV1Wire{1u, 0u},
      RootMountCustodyV2Wire{fixture.mount(code), fixture.object(500u + code, kDirectory)},
      fixture.mount(code + 1u),
      extraction_pre,
      raw_pre,
      page_pre,
      FinalDirectoryListingV1Wire{{
          FinalDirectoryListingRowV1Wire{fixture.text("LaunchGateV1.o"), raw_pre},
          FinalDirectoryListingRowV1Wire{fixture.text("LaunchGateV1.page"), page_pre},
      }},
      BlobDigestV1Wire{0u, hash(27u)},
      BlobDigestV1Wire{0u, hash(28u)},
      PostCensusesV1Wire{fixture.census(3u), fixture.census(3u)},
      BuildPrincipalV1Wire{1000u, 1000u},
  };
  return fixture;
}

void apply_vector_variant(Fixture& fixture, const char vector) {
  if (vector == 'A') {
    fixture.body.pre_census_2 = fixture.census(11u);
    fixture.body.barrier_census_2 = fixture.census(22u);
    fixture.body.post_censuses.second = fixture.census(33u);
    fixture.body.build_principal = BuildPrincipalV1Wire{1000u, 1001u};
    return;
  }
  if (vector == 'B') {
    fixture.body.child_pid = 0u;
    fixture.body.child_starttime = 23u;
    fixture.body.child_security_state = UIntPairV1Wire{24u, 255u};
    fixture.body.child_wait_result = UIntPairV1Wire{256u, 65535u};
    fixture.body.build_principal = BuildPrincipalV1Wire{65536u, 0xffffffffu};
    fixture.body.pid_namespace_identity = NamespaceIdentityV1Wire{
        std::numeric_limits<std::uint64_t>::max(), 0u, 1u};
    fixture.body.mount_namespace_identity =
        NamespaceIdentityV1Wire{0xffffffffu, 0x100000000ull, 2u};
    fixture.body.root_custody_pre.root_object.statx_mnt_id = std::numeric_limits<std::uint64_t>::max();
    fixture.body.root_custody_post.root_object.statx_mnt_id = std::numeric_limits<std::uint64_t>::max();
    return;
  }
  if (vector == 'C') {
    fixture.body.extraction_argv = fixture.byte_array({fixture.raw({}), fixture.repeated('x', 23u),
                                                       fixture.repeated('y', 24u), fixture.repeated('z', 255u),
                                                       fixture.repeated('q', 256u)});
    fixture.body.extraction_envp = fixture.byte_array({fixture.raw({}), fixture.repeated('e', 23u),
                                                       fixture.repeated('f', 24u)});
    fixture.body.pre_census_1 = fixture.vector_c_census();
    fixture.body.objcopy_stdout = BlobDigestV1Wire{0u, Sha256Digest{}};
    fixture.body.objcopy_stderr = BlobDigestV1Wire{256u, literal_hash("C-stdout")};
    return;
  }
  if (vector == 'D') {
    fixture.body.root_custody_post.root_object.inode += 1u;
    fixture.body.build_principal = BuildPrincipalV1Wire{1234u, 1235u};
    fixture.body.post_censuses.second = ProcessCensusV1Wire{nullptr, 0u};
    // Corrected D: the listing does not silently duplicate top-level raw/page identities.
    auto listing_raw = fixture.body.raw_object_post;
    listing_raw.object.inode += 10u;
    listing_raw.sha256 = literal_hash("D-listing-raw");
    auto listing_page = fixture.body.committed_page_identity;
    listing_page.object.inode += 20u;
    listing_page.sha256 = literal_hash("D-listing-page");
    fixture.body.final_directory_listing.rows[0].identity = listing_raw;
    fixture.body.final_directory_listing.rows[1].identity = listing_page;
  }
}

struct Node final {
  enum class Kind : std::uint8_t { kUInt, kBytes, kArray };
  Kind kind;
  std::uint64_t value;
  std::size_t start;
  std::size_t end;
  std::vector<Node> children;
};

class Reader final {
 public:
  explicit Reader(const std::span<const std::uint8_t> input) : input_(input) {}

  bool item(Node& node, const unsigned depth = 0u) {
    if (depth > 128u || offset_ == input_.size()) return false;
    const std::size_t start = offset_;
    const std::uint8_t initial = input_[offset_++];
    const std::uint8_t major = initial >> 5u;
    const std::uint8_t additional = initial & 31u;
    std::uint64_t count = 0u;
    if (!argument(additional, count)) return false;
    if (major == 0u) { node = Node{Node::Kind::kUInt, count, start, offset_, {}}; return true; }
    if (major == 2u) {
      if (count > input_.size() - offset_) return false;
      offset_ += static_cast<std::size_t>(count);
      node = Node{Node::Kind::kBytes, count, start, offset_, {}};
      return true;
    }
    if (major != 4u || count > 100000u) return false;
    node = Node{Node::Kind::kArray, count, start, 0u, {}};
    node.children.reserve(static_cast<std::size_t>(count));
    for (std::uint64_t index = 0u; index < count; ++index) {
      Node child{};
      if (!item(child, depth + 1u)) return false;
      node.children.push_back(std::move(child));
    }
    node.end = offset_;
    return true;
  }

  std::size_t offset() const { return offset_; }

 private:
  bool argument(const std::uint8_t additional, std::uint64_t& output) {
    if (additional < 24u) { output = additional; return true; }
    unsigned width = 0u;
    if (additional == 24u) width = 1u;
    else if (additional == 25u) width = 2u;
    else if (additional == 26u) width = 4u;
    else if (additional == 27u) width = 8u;
    else return false;
    if (width > input_.size() - offset_) return false;
    output = 0u;
    for (unsigned index = 0u; index < width; ++index) {
      output = (output << 8u) | input_[offset_++];
    }
    const std::uint64_t minimum = width == 1u ? 24u : width == 2u ? 256u :
                                  width == 4u ? 65536u : (1ull << 32u);
    return output >= minimum;
  }

  std::span<const std::uint8_t> input_;
  std::size_t offset_ = 0u;
};

bool node_array_width(const Node& node, const std::size_t width) {
  return node.kind == Node::Kind::kArray && node.children.size() == width;
}

bool strict_wrapper(const std::span<const std::uint8_t> wrapper,
                    const std::span<const std::uint8_t> body,
                    const Sha256Digest& expected_root) {
  Reader reader(wrapper);
  Node top{};
  if (!reader.item(top) || reader.offset() != wrapper.size() || !node_array_width(top, 4u)) return false;
  if (top.children[0].kind != Node::Kind::kUInt || top.children[0].value != kProtocolId ||
      top.children[1].kind != Node::Kind::kUInt || top.children[1].value != kWireVersion ||
      !node_array_width(top.children[2], kBodyFieldCount) ||
      top.children[3].kind != Node::Kind::kBytes || top.children[3].value != 32u) return false;
  const Node& parsed_body = top.children[2];
  if (parsed_body.children[0].kind != Node::Kind::kBytes || parsed_body.children[0].value != 32u) return false;
  const std::size_t image_payload = parsed_body.children[0].end - parsed_body.children[0].value;
  if (image_payload + 32u > wrapper.size() || !all_zero(wrapper.subspan(image_payload, 32u))) return false;
  const auto custody_shape = [](const Node& node) {
    return node_array_width(node, 2u) && node_array_width(node.children[0], 17u) &&
           node_array_width(node.children[1], 9u);
  };
  if (!custody_shape(parsed_body.children[4]) || !custody_shape(parsed_body.children[21])) return false;
  if (!node_array_width(parsed_body.children[30], 2u) ||
      parsed_body.children[30].children[0].kind != Node::Kind::kUInt ||
      parsed_body.children[30].children[1].kind != Node::Kind::kUInt) return false;
  const auto body_slice = wrapper.subspan(parsed_body.start, parsed_body.end - parsed_body.start);
  if (body_slice.size() != body.size() || !equal(body_slice.data(), body.data(), body.size())) return false;
  static constexpr std::array<std::uint8_t, 45u> kDomain = {
      'V','6','3','1','3','0','2','_','S','T','A','G','E','1','_','E','X','T','R','A','C','T','I','O','N','_',
      'C','U','S','T','O','D','Y','_','R','E','C','E','I','P','T','_','V','2','\0'};
  const Sha256Digest computed = root_for(body.data(), body.size(), kDomain.data(), kDomain.size());
  const std::size_t root_payload = top.children[3].end - top.children[3].value;
  return equal(computed.data(), expected_root.data(), computed.size()) &&
         root_payload + computed.size() <= wrapper.size() &&
         equal(computed.data(), wrapper.data() + root_payload, computed.size());
}

struct CallResult final {
  EncodeStatus status;
  EncodeOutput output;
  std::vector<std::uint8_t> body;
  std::vector<std::uint8_t> wrapper;
  std::size_t allocations;
};

CallResult call(const Stage1ExtractionCustodyBodyV2WireView& body,
                const std::size_t body_capacity = 4096u,
                const std::size_t wrapper_capacity = 8192u) {
  CallResult result{EncodeStatus::kInternalInvariantFailure, EncodeOutput{99u, 99u, {}},
                    std::vector<std::uint8_t>(body_capacity, 0xa5u),
                    std::vector<std::uint8_t>(wrapper_capacity, 0x5au), 0u};
  result.output.root.fill(0x7eu);
  const std::size_t before = g_new_calls.load(std::memory_order_relaxed);
  result.status = encode_candidate_bytes(body, result.body, result.wrapper, result.output);
  result.allocations = g_new_calls.load(std::memory_order_relaxed) - before;
  return result;
}

bool failure_closed(const CallResult& result) {
  return result.status != EncodeStatus::kOk && result.allocations == 0u && result.output.body_size == 0u &&
         result.output.wrapper_size == 0u && all_zero(result.output.root) &&
         all_zero(std::span<const std::uint8_t>(result.body)) &&
         all_zero(std::span<const std::uint8_t>(result.wrapper));
}

struct Expected final {
  char vector;
  std::size_t body_size;
  std::size_t wrapper_size;
  const char* body_sha256;
  const char* wrapper_sha256;
  const char* root;
};

constexpr std::array<Expected, 4u> kExpected = {{
    {'A', 1623u, 1664u, "a6a6f730f412e42fc349c567846f7f426f63d0c36b58bd9b821d8c8e72286a45", "a4f62e4332bad7f27a930e18215ab211aecc1a5cface616942f0041a31904345", "84048ddd5cbd9a77a8bd578215f4c3ffd844ba9ad3ef4b25783ac324195b4cb2"},
    {'B', 1663u, 1704u, "a80c1b31d102db00b5985f21c83c7fbfa1a1c9d4efe842a526459539f47ad80c", "10acc36470cac78a337dcbccdb6becd7d16dd99da34e39ed0aa4872909c38c4f", "5a2dfa0ee3350a4972a22d17f77c8663da5390aed2fa9d73e49ecf4b8b664b8f"},
    {'C', 2218u, 2259u, "dbf3779c4368ae7304223034bfe71336997059e111d83eff10e441649034352a", "9a25359f638fd0676ab5fcc3eb64c52c0bb2ec0373068f893a2715745cf54a2d", "3895f7e5161c0bdd2c9279b1f1fe50d3cdbc970efafdac710eccb71a8adc7620"},
    {'D', 1597u, 1638u, "36b5ac8c9941619fd7ff459e90f2135b3d83aedba0fdb045e89cdcf01a490690", "f7a1be2deb072921e28d5cf052d1647ea977cf95d8ed10cb39bcc5eb2472c459", "7b1b2c8d403c99b1d36f75cb766d5ffadc39018dccc4d8a09f73c755ca71b272"},
}};

void test_vectors() {
  constexpr std::array<std::uint8_t, 3u> kShaSmoke = {'a', 'b', 'c'};
  const Sha256Digest smoke_digest = digest(kShaSmoke.data(), kShaSmoke.size());
  check(equal(smoke_digest.data(),
              hex_digest("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad").data(),
              smoke_digest.size()), "test SHA-256 implementation is incorrect");
  for (const Expected& expected : kExpected) {
    Fixture fixture = make_fixture(expected.vector);
    apply_vector_variant(fixture, expected.vector);
    const CallResult first = call(fixture.body);
    check(first.status == EncodeStatus::kOk, "success vector status");
    check(first.allocations == 0u, "encoder allocated heap memory");
    check(first.output.body_size == expected.body_size && first.output.wrapper_size == expected.wrapper_size,
          "success vector lengths differ from independent Python reference");
    const Sha256Digest body_digest = digest(first.body.data(), first.output.body_size);
    const Sha256Digest wrapper_digest = digest(first.wrapper.data(), first.output.wrapper_size);
    check(equal(body_digest.data(), hex_digest(expected.body_sha256).data(), body_digest.size()),
          "body digest differs from independent Python reference");
    check(equal(wrapper_digest.data(), hex_digest(expected.wrapper_sha256).data(), wrapper_digest.size()),
          "wrapper digest differs from independent Python reference");
    const Sha256Digest expected_root = hex_digest(expected.root);
    check(equal(first.output.root.data(), expected_root.data(), expected_root.size()),
          "root differs from independent Python reference");
    check(strict_wrapper(std::span<const std::uint8_t>(first.wrapper.data(), first.output.wrapper_size),
                         std::span<const std::uint8_t>(first.body.data(), first.output.body_size),
                         first.output.root), "strict parser rejected success vector");
    check(all_zero(std::span<const std::uint8_t>(first.body).subspan(first.output.body_size)),
          "body tail was not zero");
    check(all_zero(std::span<const std::uint8_t>(first.wrapper).subspan(first.output.wrapper_size)),
          "wrapper tail was not zero");

    const CallResult second = call(fixture.body);
    check(second.status == EncodeStatus::kOk && second.allocations == 0u,
          "second deterministic call failed or allocated");
    check(first.output.body_size == second.output.body_size &&
          first.output.wrapper_size == second.output.wrapper_size &&
          equal(first.body.data(), second.body.data(), first.output.body_size) &&
          equal(first.wrapper.data(), second.wrapper.data(), first.output.wrapper_size) &&
          equal(first.output.root.data(), second.output.root.data(), first.output.root.size()),
          "consecutive calls were not byte deterministic");

    Fixture moved = make_fixture(expected.vector);
    apply_vector_variant(moved, expected.vector);
    const CallResult relocated = call(moved.body);
    check(relocated.status == EncodeStatus::kOk && relocated.allocations == 0u &&
          equal(first.body.data(), relocated.body.data(), first.output.body_size) &&
          equal(first.wrapper.data(), relocated.wrapper.data(), first.output.wrapper_size),
          "different input addresses changed encoded bytes");
  }
}

bool all_artifacts_changed(const CallResult& baseline,
                           const CallResult& swapped) {
  if (baseline.status != EncodeStatus::kOk ||
      swapped.status != EncodeStatus::kOk || swapped.allocations != 0u) {
    return false;
  }
  const bool body_changed =
      baseline.output.body_size != swapped.output.body_size ||
      !equal(baseline.body.data(), swapped.body.data(),
             baseline.output.body_size);
  const Sha256Digest baseline_body_digest =
      digest(baseline.body.data(), baseline.output.body_size);
  const Sha256Digest swapped_body_digest =
      digest(swapped.body.data(), swapped.output.body_size);
  const bool wrapper_changed =
      baseline.output.wrapper_size != swapped.output.wrapper_size ||
      !equal(baseline.wrapper.data(), swapped.wrapper.data(),
             baseline.output.wrapper_size);
  const Sha256Digest baseline_wrapper_digest =
      digest(baseline.wrapper.data(), baseline.output.wrapper_size);
  const Sha256Digest swapped_wrapper_digest =
      digest(swapped.wrapper.data(), swapped.output.wrapper_size);
  return body_changed &&
         !equal(baseline_body_digest.data(), swapped_body_digest.data(),
                baseline_body_digest.size()) &&
         !equal(baseline.output.root.data(), swapped.output.root.data(),
                baseline.output.root.size()) &&
         wrapper_changed &&
         !equal(baseline_wrapper_digest.data(), swapped_wrapper_digest.data(),
                baseline_wrapper_digest.size());
}

void test_vector_a_adjacent_census_sentinels() {
  Fixture baseline_fixture = make_fixture('A');
  apply_vector_variant(baseline_fixture, 'A');
  const CallResult baseline = call(baseline_fixture.body);
  check(baseline.status == EncodeStatus::kOk && baseline.allocations == 0u,
        "Vector A adjacent-sentinel baseline failed");

  Fixture pre_swap = make_fixture('A');
  apply_vector_variant(pre_swap, 'A');
  const ProcessCensusV1Wire pre_temporary = pre_swap.body.pre_census_1;
  pre_swap.body.pre_census_1 = pre_swap.body.pre_census_2;
  pre_swap.body.pre_census_2 = pre_temporary;
  check(all_artifacts_changed(baseline, call(pre_swap.body)),
        "Vector A positions 13/14 swap did not change every artifact");

  Fixture barrier_swap = make_fixture('A');
  apply_vector_variant(barrier_swap, 'A');
  const ProcessCensusV1Wire barrier_temporary =
      barrier_swap.body.barrier_census_1;
  barrier_swap.body.barrier_census_1 = barrier_swap.body.barrier_census_2;
  barrier_swap.body.barrier_census_2 = barrier_temporary;
  check(all_artifacts_changed(baseline, call(barrier_swap.body)),
        "Vector A positions 18/19 swap did not change every artifact");

  Fixture post_swap = make_fixture('A');
  apply_vector_variant(post_swap, 'A');
  const ProcessCensusV1Wire post_temporary =
      post_swap.body.post_censuses.first;
  post_swap.body.post_censuses.first = post_swap.body.post_censuses.second;
  post_swap.body.post_censuses.second = post_temporary;
  check(all_artifacts_changed(baseline, call(post_swap.body)),
        "Vector A position 29 census swap did not change every artifact");
}

void test_failures() {
  Fixture fixture = make_fixture('A');
  const CallResult good = call(fixture.body);
  check(good.status == EncodeStatus::kOk, "failure setup success call");

  const CallResult body_short = call(fixture.body, good.output.body_size - 1u, 8192u);
  check(body_short.status == EncodeStatus::kBodyCapacityInsufficient && failure_closed(body_short),
        "one-byte-short body buffer was not fail closed");
  const CallResult wrapper_short = call(fixture.body, 4096u, good.output.wrapper_size - 1u);
  check(wrapper_short.status == EncodeStatus::kWrapperCapacityInsufficient && failure_closed(wrapper_short),
        "one-byte-short wrapper buffer was not fail closed after root computation");
  const CallResult zero_capacity = call(fixture.body, 0u, 0u);
  check(zero_capacity.status == EncodeStatus::kBodyCapacityInsufficient && failure_closed(zero_capacity),
        "zero capacities were not fail closed");

  Fixture null_view = make_fixture('A');
  null_view.body.extraction_argv = null_view.byte_array({ByteView{nullptr, 1u}});
  const CallResult null_result = call(null_view.body);
  check(null_result.status == EncodeStatus::kInvalidInput && failure_closed(null_result),
        "null nonempty input was not rejected");

  Fixture overflow = make_fixture('A');
  overflow.body.extraction_argv = overflow.byte_array({ByteView{
      reinterpret_cast<const std::uint8_t*>(std::numeric_limits<std::uintptr_t>::max() - 1u), 2u}});
  const CallResult overflow_result = call(overflow.body);
  check(overflow_result.status == EncodeStatus::kInvalidInput && failure_closed(overflow_result),
        "pointer-length overflow was not rejected");

  Fixture image = make_fixture('A');
  image.body.image_id_sha256[0] = 1u;
  const CallResult image_result = call(image.body);
  check(image_result.status == EncodeStatus::kInvalidInput && failure_closed(image_result),
        "nonzero offline image identity was not rejected");

  std::array<std::uint8_t, 8192u> shared{};
  EncodeOutput output{77u, 77u, {}};
  output.root.fill(0x77u);
  auto status = encode_candidate_bytes(fixture.body,
      std::span<std::uint8_t>(shared.data(), 4096u), std::span<std::uint8_t>(shared.data(), 4096u), output);
  check(status == EncodeStatus::kRangeOverlap && output.body_size == 0u && output.wrapper_size == 0u &&
        all_zero(output.root) && all_zero(std::span<const std::uint8_t>(shared.data(), 4096u)),
        "exact output overlap was not fail closed");

  shared.fill(0x61u); output = EncodeOutput{77u, 77u, {}}; output.root.fill(0x77u);
  status = encode_candidate_bytes(fixture.body,
      std::span<std::uint8_t>(shared.data(), 4096u), std::span<std::uint8_t>(shared.data() + 1u, 4096u), output);
  check(status == EncodeStatus::kRangeOverlap && output.body_size == 0u && output.wrapper_size == 0u &&
        all_zero(output.root) &&
        all_zero(std::span<const std::uint8_t>(shared.data(), 4096u)) &&
        all_zero(std::span<const std::uint8_t>(shared.data() + 1u, 4096u)),
        "partial output overlap was not fail closed");

  // Input views are immutable and may legitimately share backing storage. The
  // encoder needs only to prove that every declared input range is disjoint
  // from its output/result ranges; rejecting input/input aliasing would add an
  // unnecessary quadratic scan.
  Fixture exact_input_alias = make_fixture('A');
  const ByteView repeated_input = exact_input_alias.body.extraction_argv.data[0];
  exact_input_alias.body.extraction_envp = exact_input_alias.byte_array({repeated_input});
  const CallResult exact_input_alias_result = call(exact_input_alias.body);
  check(exact_input_alias_result.status == EncodeStatus::kOk &&
            exact_input_alias_result.allocations == 0u,
        "exact immutable input/input alias was rejected");

  Fixture partial_input_alias = make_fixture('A');
  const ByteView input_storage = partial_input_alias.raw({1u, 2u, 3u, 4u});
  partial_input_alias.body.extraction_argv = partial_input_alias.byte_array(
      {ByteView{input_storage.data, 3u}, ByteView{input_storage.data + 1u, 3u}});
  const CallResult partial_input_alias_result = call(partial_input_alias.body);
  check(partial_input_alias_result.status == EncodeStatus::kOk &&
            partial_input_alias_result.allocations == 0u,
        "partial immutable input/input alias was rejected");

  Fixture input_body_overlap = make_fixture('A');
  std::array<std::uint8_t, 8192u> body_buffer{};
  std::array<std::uint8_t, 8192u> wrapper_buffer{};
  input_body_overlap.body.extraction_argv =
      input_body_overlap.byte_array({ByteView{body_buffer.data(), 1u}});
  output = EncodeOutput{77u, 77u, {}}; output.root.fill(0x77u);
  status = encode_candidate_bytes(input_body_overlap.body, body_buffer, wrapper_buffer, output);
  check(status == EncodeStatus::kRangeOverlap && output.body_size == 0u && output.wrapper_size == 0u &&
        all_zero(output.root) && all_zero(std::span<const std::uint8_t>(body_buffer)) &&
        all_zero(std::span<const std::uint8_t>(wrapper_buffer)), "input/body overlap was not fail closed");

  Fixture input_wrapper_overlap = make_fixture('A');
  body_buffer.fill(0u); wrapper_buffer.fill(0u);
  input_wrapper_overlap.body.extraction_argv =
      input_wrapper_overlap.byte_array({ByteView{wrapper_buffer.data(), 1u}});
  output = EncodeOutput{77u, 77u, {}}; output.root.fill(0x77u);
  status = encode_candidate_bytes(input_wrapper_overlap.body, body_buffer, wrapper_buffer, output);
  check(status == EncodeStatus::kRangeOverlap && output.body_size == 0u && output.wrapper_size == 0u &&
        all_zero(output.root) && all_zero(std::span<const std::uint8_t>(body_buffer)) &&
        all_zero(std::span<const std::uint8_t>(wrapper_buffer)),
        "input/wrapper overlap was not fail closed");

  alignas(EncodeOutput) std::array<std::uint8_t, 8192u> output_alias{};
  auto* const overlapping_output = reinterpret_cast<EncodeOutput*>(output_alias.data());
  overlapping_output->body_size = 77u;
  overlapping_output->wrapper_size = 77u;
  overlapping_output->root.fill(0x77u);
  status = encode_candidate_bytes(fixture.body,
      std::span<std::uint8_t>(output_alias.data(), 4096u), wrapper_buffer, *overlapping_output);
  check(status == EncodeStatus::kRangeOverlap && overlapping_output->body_size == 0u &&
        overlapping_output->wrapper_size == 0u && all_zero(overlapping_output->root) &&
        all_zero(std::span<const std::uint8_t>(output_alias.data(), 4096u)) &&
        all_zero(std::span<const std::uint8_t>(wrapper_buffer)),
        "EncodeOutput/output overlap was not fail closed");
}

void test_undeclared_backing_bytes_do_not_change_output() {
  Fixture first = make_fixture('A');
  const ByteView first_backing = first.raw({'x', 'y', 'z', 0x11u, 0x22u});
  first.body.extraction_argv =
      first.byte_array({ByteView{first_backing.data, 3u}});
  const CallResult first_result = call(first.body);

  Fixture second = make_fixture('A');
  const ByteView second_backing = second.raw({'x', 'y', 'z', 0xaau, 0xbbu});
  second.body.extraction_argv =
      second.byte_array({ByteView{second_backing.data, 3u}});
  const CallResult second_result = call(second.body);

  check(first_result.status == EncodeStatus::kOk &&
            second_result.status == EncodeStatus::kOk &&
            first_result.output.body_size == second_result.output.body_size &&
            first_result.output.wrapper_size == second_result.output.wrapper_size &&
            equal(first_result.body.data(), second_result.body.data(),
                  first_result.output.body_size) &&
            equal(first_result.wrapper.data(), second_result.wrapper.data(),
                  first_result.output.wrapper_size) &&
            equal(first_result.output.root.data(), second_result.output.root.data(),
                  first_result.output.root.size()),
        "bytes outside declared input ranges changed encoded output");
}

void test_mutations() {
  // D deliberately makes the two root-custody records different, so a byte
  // preserving position swap cannot hide behind equal raw encodings.
  Fixture fixture = make_fixture('D');
  apply_vector_variant(fixture, 'D');
  const CallResult encoded = call(fixture.body);
  check(encoded.status == EncodeStatus::kOk, "mutation setup failed");
  const auto wrapper = std::span<const std::uint8_t>(encoded.wrapper.data(), encoded.output.wrapper_size);
  const auto body = std::span<const std::uint8_t>(encoded.body.data(), encoded.output.body_size);
  check(strict_wrapper(wrapper, body, encoded.output.root), "mutation setup parser failure");

  Reader reader(wrapper);
  Node top{};
  check(reader.item(top) && reader.offset() == wrapper.size(), "mutation setup parse tree failure");
  if (top.children.size() != 4u) return;
  const Node& parsed_body = top.children[2];
  auto rejected = [&](std::vector<std::uint8_t> candidate, const char* const message) {
    check(!strict_wrapper(candidate, body, encoded.output.root), message);
  };
  auto swapped_body_fields = [&](const std::size_t left, const std::size_t right) {
    std::vector<std::uint8_t> candidate{};
    candidate.insert(candidate.end(), encoded.wrapper.begin(),
                     encoded.wrapper.begin() + static_cast<std::ptrdiff_t>(parsed_body.children[0].start));
    for (std::size_t index = 0u; index < parsed_body.children.size(); ++index) {
      const std::size_t source = index == left ? right : index == right ? left : index;
      const Node& child = parsed_body.children[source];
      candidate.insert(candidate.end(), encoded.wrapper.begin() + static_cast<std::ptrdiff_t>(child.start),
                       encoded.wrapper.begin() + static_cast<std::ptrdiff_t>(child.end));
    }
    candidate.insert(candidate.end(), encoded.wrapper.begin() + static_cast<std::ptrdiff_t>(parsed_body.end),
                     encoded.wrapper.begin() + static_cast<std::ptrdiff_t>(encoded.output.wrapper_size));
    return candidate;
  };

  auto mutated = encoded.wrapper;
  mutated[0] = 0x83u; rejected(mutated, "wrapper count 3 accepted");
  mutated = encoded.wrapper; mutated[0] = 0x85u; rejected(mutated, "wrapper count 5 accepted");
  mutated = encoded.wrapper; mutated[top.children[1].start] = 0x03u; rejected(mutated, "wrapper version 3 accepted");
  mutated = encoded.wrapper; mutated[top.children[0].end - 1u] ^= 1u; rejected(mutated, "wrong protocol accepted");
  mutated = encoded.wrapper; mutated[parsed_body.start + 1u] = 30u; rejected(mutated, "body count 30 accepted");
  mutated = encoded.wrapper; mutated[parsed_body.start + 1u] = 32u; rejected(mutated, "body count 32 accepted");
  mutated = encoded.wrapper; mutated[parsed_body.start] = 0x58u; rejected(mutated, "body byte string accepted");
  mutated = encoded.wrapper; mutated[top.children[3].start] = 0x78u; rejected(mutated, "root text accepted");
  mutated = encoded.wrapper; mutated[0] = 0xa4u; rejected(mutated, "map accepted");
  mutated = encoded.wrapper; mutated[0] = 0xc0u; rejected(mutated, "tag accepted");
  mutated = encoded.wrapper; mutated[0] = 0x9fu; rejected(mutated, "indefinite array accepted");
  mutated = encoded.wrapper; mutated[0] = 0xf5u; rejected(mutated, "boolean accepted");
  mutated = encoded.wrapper; mutated[0] = 0xf9u; rejected(mutated, "floating point accepted");
  mutated = encoded.wrapper; mutated.insert(mutated.end(), 0u); rejected(mutated, "trailing byte accepted");
  mutated = encoded.wrapper; mutated[top.children[0].start] = 0x1bu;
  mutated.insert(mutated.begin() + static_cast<std::ptrdiff_t>(top.children[0].start + 1u), 4u, 0u);
  rejected(mutated, "nonshortest protocol integer accepted");
  mutated = encoded.wrapper; mutated[parsed_body.children[4].start] ^= 1u;
  rejected(mutated, "root custody mutation did not mismatch");
  mutated = encoded.wrapper; mutated[parsed_body.children[21].start] ^= 1u;
  rejected(mutated, "post root custody mutation did not mismatch");
  rejected(swapped_body_fields(4u, 21u), "root custody positions 4/21 swap accepted");
  rejected(swapped_body_fields(29u, 30u), "build principal move from position 30 accepted");
  mutated = encoded.wrapper; mutated[parsed_body.start + 2u] ^= 1u;
  rejected(mutated, "body mutation after root computation accepted");
  mutated = encoded.wrapper; mutated[top.children[3].end - 1u] ^= 1u;
  rejected(mutated, "root mutation accepted");

  // Domain, terminator, wrapper-hash, and byte-string-body variants all have a
  // nonmatching root, which the strict parser must reject.
  static constexpr std::array<std::uint8_t, 44u> kV1Domain = {
      'V','6','3','1','3','0','2','_','S','T','A','G','E','1','_','E','X','T','R','A','C','T','I','O','N','_',
      'C','U','S','T','O','D','Y','_','R','E','C','E','I','P','T','_','V','1'};
  const Sha256Digest wrong = root_for(body.data(), body.size(), kV1Domain.data(), kV1Domain.size());
  mutated = encoded.wrapper;
  const std::size_t root_start = top.children[3].start + 2u;
  for (std::size_t index = 0u; index < wrong.size(); ++index) mutated[root_start + index] = wrong[index];
  rejected(mutated, "wrong root domain accepted");
  static constexpr std::array<std::uint8_t, 44u> kNoNulDomain = {
      'V','6','3','1','3','0','2','_','S','T','A','G','E','1','_','E','X','T','R','A','C','T','I','O','N','_',
      'C','U','S','T','O','D','Y','_','R','E','C','E','I','P','T','_','V','2'};
  static constexpr std::array<std::uint8_t, 46u> kExtraNulDomain = {
      'V','6','3','1','3','0','2','_','S','T','A','G','E','1','_','E','X','T','R','A','C','T','I','O','N','_',
      'C','U','S','T','O','D','Y','_','R','E','C','E','I','P','T','_','V','2','\0','\0'};
  const std::array<std::pair<const std::uint8_t*, std::size_t>, 4u> wrong_inputs = {{
      {kNoNulDomain.data(), kNoNulDomain.size()},
      {kExtraNulDomain.data(), kExtraNulDomain.size()},
      {wrapper.data(), wrapper.size()},
      {body.data(), body.size()},
  }};
  for (std::size_t index = 0u; index < wrong_inputs.size(); ++index) {
    const Sha256Digest replacement = index < 2u
        ? root_for(body.data(), body.size(), wrong_inputs[index].first, wrong_inputs[index].second)
        : digest(wrong_inputs[index].first, wrong_inputs[index].second);
    mutated = encoded.wrapper;
    for (std::size_t byte = 0u; byte < replacement.size(); ++byte) {
      mutated[root_start + byte] = replacement[byte];
    }
    rejected(mutated, "noncanonical root scope accepted");
  }
}

void print_hex(FILE* const stream, const Sha256Digest& digest_value) {
  static constexpr char kHex[] = "0123456789abcdef";
  char encoded[(kSha256Size * 2u) + 1u]{};
  for (std::size_t index = 0u; index < digest_value.size(); ++index) {
    encoded[index * 2u] = kHex[digest_value[index] >> 4u];
    encoded[(index * 2u) + 1u] = kHex[digest_value[index] & 0x0fu];
  }
  std::fputs(encoded, stream);
}

void emit_vector_summaries() {
  for (const Expected& expected : kExpected) {
    Fixture fixture = make_fixture(expected.vector);
    apply_vector_variant(fixture, expected.vector);
    const CallResult result = call(fixture.body);
    if (result.status != EncodeStatus::kOk || result.allocations != 0u) {
      check(false, "summary vector failed");
      return;
    }
    const Sha256Digest body_digest =
        digest(result.body.data(), result.output.body_size);
    const Sha256Digest wrapper_digest =
        digest(result.wrapper.data(), result.output.wrapper_size);
    std::fprintf(stdout, "%c body_len=%zu wrapper_len=%zu body_sha256=",
                 expected.vector, result.output.body_size,
                 result.output.wrapper_size);
    print_hex(stdout, body_digest);
    std::fputs(" wrapper_sha256=", stdout);
    print_hex(stdout, wrapper_digest);
    std::fputs(" root=", stdout);
    print_hex(stdout, result.output.root);
    std::fputc('\n', stdout);
  }
}

}  // namespace

int main(const int argc, char** const argv) {
  const bool emit_summary =
      argc == 2 && argv[1] != nullptr &&
      std::strcmp(argv[1], "--emit-summary") == 0;
  test_vectors();
  test_vector_a_adjacent_census_sentinels();
  test_failures();
  test_undeclared_backing_bytes_do_not_change_output();
  test_mutations();
  if (g_failures == 0 && emit_summary) {
    emit_vector_summaries();
  }
  if (g_failures != 0) {
    std::fprintf(stderr, "%d offline receipt encoder checks failed\n", g_failures);
  }
  return g_failures == 0 ? 0 : 1;
}
