#include "Stage1ExtractionCustodyReceiptV2EncoderCore.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>

namespace evaluation_v6_3_1::stage1::receipt_v2::offline {
namespace {

static_assert(sizeof(std::uint8_t) == 1u);
static_assert(sizeof(std::uint32_t) == 4u);
static_assert(sizeof(std::uint64_t) == 8u);
static_assert(sizeof(std::size_t) <= sizeof(std::uint64_t));
static_assert(Stage1ExtractionCustodyBodyV2WireView::field_count == 31u);

constexpr std::uint8_t kRootDomain[] =
    "V631302_STAGE1_EXTRACTION_CUSTODY_RECEIPT_V2\0";
constexpr std::size_t kRootDomainSize = sizeof(kRootDomain) - 1u;

struct AddressRange final {
  std::uintptr_t begin;
  std::uintptr_t end;
};

[[nodiscard]] bool multiply_size(const std::size_t left,
                                 const std::size_t right,
                                 std::size_t& result) noexcept {
  if (left != 0u && right > std::numeric_limits<std::size_t>::max() / left) {
    return false;
  }
  result = left * right;
  return true;
}

[[nodiscard]] bool make_range(const void* const pointer,
                              const std::size_t byte_count,
                              AddressRange& result,
                              bool& present) noexcept {
  present = byte_count != 0u;
  result = AddressRange{0u, 0u};
  if (!present) {
    return true;
  }
  if (pointer == nullptr) {
    return false;
  }
  const auto begin = reinterpret_cast<std::uintptr_t>(pointer);
  if (byte_count > std::numeric_limits<std::uintptr_t>::max() - begin) {
    return false;
  }
  result = AddressRange{begin, begin + byte_count};
  return result.end > result.begin;
}

[[nodiscard]] bool overlaps(const AddressRange& left,
                            const AddressRange& right) noexcept {
  return left.begin < right.end && right.begin < left.end;
}

void zero_bytes(const std::span<std::uint8_t> bytes) noexcept {
  for (std::size_t index = 0u; index < bytes.size(); ++index) {
    bytes[index] = 0u;
  }
}

void reset_outputs(const std::span<std::uint8_t> body_output,
                   const std::span<std::uint8_t> wrapper_output,
                   EncodeOutput& output) noexcept {
  zero_bytes(body_output);
  zero_bytes(wrapper_output);
  output.body_size = 0u;
  output.wrapper_size = 0u;
  output.root.fill(0u);
}

class InputRangeWalk final {
 public:
  InputRangeWalk(const AddressRange* const forbidden,
                 const std::size_t forbidden_count) noexcept
      : forbidden_(forbidden),
        forbidden_count_(forbidden_count) {}

  [[nodiscard]] bool add(const void* const pointer,
                         const std::size_t byte_count) noexcept {
    AddressRange range{};
    bool present = false;
    if (!make_range(pointer, byte_count, range, present)) {
      valid_ = false;
      return false;
    }
    if (!present) {
      return true;
    }

    for (std::size_t index = 0u; index < forbidden_count_; ++index) {
      if (overlaps(range, forbidden_[index])) {
        overlap_ = true;
      }
    }

    return true;
  }

  template <typename T>
  [[nodiscard]] bool add_array(const ArrayView<T>& view) noexcept {
    std::size_t byte_count = 0u;
    if (!multiply_size(view.size, sizeof(T), byte_count)) {
      valid_ = false;
      return false;
    }
    return add(view.data, byte_count);
  }

  [[nodiscard]] bool valid() const noexcept { return valid_; }
  [[nodiscard]] bool overlap() const noexcept { return overlap_; }

 private:
  const AddressRange* forbidden_;
  std::size_t forbidden_count_;
  bool valid_ = true;
  bool overlap_ = false;
};

[[nodiscard]] bool walk_byte_view(const ByteView& value,
                                  InputRangeWalk& walk) noexcept {
  return walk.add(value.data, value.size);
}

[[nodiscard]] bool walk_byte_array(const ArrayView<ByteView>& values,
                                   InputRangeWalk& walk) noexcept {
  if (!walk.add_array(values)) {
    return false;
  }
  for (std::size_t index = 0u; index < values.size; ++index) {
    if (!walk_byte_view(values.data[index], walk)) {
      return false;
    }
  }
  return true;
}

[[nodiscard]] bool walk_mount_info(const MountInfoRecordV1Wire& value,
                                   InputRangeWalk& walk) noexcept {
  return walk_byte_view(value.decoded_root, walk) &&
         walk_byte_view(value.decoded_mount_point, walk) &&
         walk_byte_array(value.mount_options, walk) &&
         walk_byte_array(value.optional_fields, walk) &&
         walk_byte_view(value.filesystem, walk) &&
         walk_byte_view(value.source, walk) &&
         walk_byte_array(value.super_options, walk) &&
         walk_byte_view(value.raw_mountinfo_line, walk);
}

[[nodiscard]] bool walk_census(const ProcessCensusV1Wire& census,
                               InputRangeWalk& walk) noexcept {
  if (!walk.add_array(census)) {
    return false;
  }
  for (std::size_t process_index = 0u; process_index < census.size;
       ++process_index) {
    if (!walk.add_array(census.data[process_index].tasks)) {
      return false;
    }
  }
  return true;
}

[[nodiscard]] bool walk_body_inputs(
    const Stage1ExtractionCustodyBodyV2WireView& body,
    InputRangeWalk& walk) noexcept {
  if (!walk.add(&body, sizeof(body))) {
    return false;
  }
  if (!walk_mount_info(body.root_custody_pre.mount, walk) ||
      !walk_mount_info(body.proc_mount_pre, walk) ||
      !walk_byte_array(body.extraction_argv, walk) ||
      !walk_byte_array(body.extraction_envp, walk) ||
      !walk.add_array(body.seccomp_policy.denied_syscalls) ||
      !walk_census(body.pre_census_1, walk) ||
      !walk_census(body.pre_census_2, walk) ||
      !walk_census(body.barrier_census_1, walk) ||
      !walk_census(body.barrier_census_2, walk) ||
      !walk_mount_info(body.root_custody_post.mount, walk) ||
      !walk_mount_info(body.proc_mount_post, walk)) {
    return false;
  }
  for (const auto& row : body.final_directory_listing.rows) {
    if (!walk_byte_view(row.name, walk)) {
      return false;
    }
  }
  return walk_census(body.post_censuses.first, walk) &&
         walk_census(body.post_censuses.second, walk);
}

[[nodiscard]] bool all_zero(const Sha256Digest& digest) noexcept {
  std::uint8_t combined = 0u;
  for (const std::uint8_t byte : digest) {
    combined = static_cast<std::uint8_t>(combined | byte);
  }
  return combined == 0u;
}

class CborWriter final {
 public:
  CborWriter(std::uint8_t* const data, const std::size_t capacity) noexcept
      : data_(data), capacity_(capacity) {}

  [[nodiscard]] bool array(const std::size_t count) noexcept {
    return head(4u, static_cast<std::uint64_t>(count));
  }

  [[nodiscard]] bool uint(const std::uint64_t value) noexcept {
    return head(0u, value);
  }

  [[nodiscard]] bool bytes(const ByteView value) noexcept {
    return head(2u, static_cast<std::uint64_t>(value.size)) &&
           raw(value.data, value.size);
  }

  [[nodiscard]] bool bytes(const Sha256Digest& value) noexcept {
    return head(2u, static_cast<std::uint64_t>(value.size())) &&
           raw(value.data(), value.size());
  }

  [[nodiscard]] bool raw(const std::uint8_t* const source,
                         const std::size_t count) noexcept {
    if (count > capacity_ - position_) {
      failed_ = true;
      return false;
    }
    for (std::size_t index = 0u; index < count; ++index) {
      data_[position_ + index] = source[index];
    }
    position_ += count;
    return true;
  }

  [[nodiscard]] std::size_t position() const noexcept { return position_; }
  [[nodiscard]] bool failed() const noexcept { return failed_; }

 private:
  [[nodiscard]] bool byte(const std::uint8_t value) noexcept {
    if (position_ == capacity_) {
      failed_ = true;
      return false;
    }
    data_[position_++] = value;
    return true;
  }

  [[nodiscard]] bool head(const std::uint8_t major,
                          const std::uint64_t argument) noexcept {
    if (major != 0u && major != 2u && major != 4u) {
      failed_ = true;
      return false;
    }
    const auto prefix = static_cast<std::uint8_t>(major << 5u);
    if (argument < 24u) {
      return byte(static_cast<std::uint8_t>(prefix |
                                            static_cast<std::uint8_t>(argument)));
    }
    if (argument <= 0xffu) {
      return byte(static_cast<std::uint8_t>(prefix | 24u)) &&
             byte(static_cast<std::uint8_t>(argument));
    }
    if (argument <= 0xffffu) {
      return byte(static_cast<std::uint8_t>(prefix | 25u)) &&
             big_endian(argument, 2u);
    }
    if (argument <= 0xffffffffu) {
      return byte(static_cast<std::uint8_t>(prefix | 26u)) &&
             big_endian(argument, 4u);
    }
    return byte(static_cast<std::uint8_t>(prefix | 27u)) &&
           big_endian(argument, 8u);
  }

  [[nodiscard]] bool big_endian(const std::uint64_t value,
                                const unsigned width) noexcept {
    for (unsigned offset = 0u; offset < width; ++offset) {
      const unsigned shift = (width - 1u - offset) * 8u;
      if (!byte(static_cast<std::uint8_t>(value >> shift))) {
        return false;
      }
    }
    return true;
  }

  std::uint8_t* data_;
  std::size_t capacity_;
  std::size_t position_ = 0u;
  bool failed_ = false;
};

[[nodiscard]] bool encode_object_identity(CborWriter& writer,
                                          const ObjectIdentityV1Wire& value) noexcept {
  return writer.array(9u) && writer.uint(value.statx_mnt_id) &&
         writer.uint(value.device_major) && writer.uint(value.device_minor) &&
         writer.uint(value.inode) && writer.uint(value.full_mode) &&
         writer.uint(value.uid) && writer.uint(value.gid) &&
         writer.uint(value.link_count) && writer.uint(value.byte_size);
}

[[nodiscard]] bool encode_file_identity(CborWriter& writer,
                                        const FileIdentityV1Wire& value) noexcept {
  return writer.array(2u) && encode_object_identity(writer, value.object) &&
         writer.bytes(value.sha256);
}

[[nodiscard]] bool encode_namespace_identity(
    CborWriter& writer, const NamespaceIdentityV1Wire& value) noexcept {
  return writer.array(3u) && writer.uint(value.device) &&
         writer.uint(value.inode) && writer.uint(value.namespace_type);
}

[[nodiscard]] bool encode_byte_array(CborWriter& writer,
                                     const ArrayView<ByteView>& values) noexcept {
  if (!writer.array(values.size)) {
    return false;
  }
  for (std::size_t index = 0u; index < values.size; ++index) {
    if (!writer.bytes(values.data[index])) {
      return false;
    }
  }
  return true;
}

[[nodiscard]] bool encode_mount_info(CborWriter& writer,
                                     const MountInfoRecordV1Wire& value) noexcept {
  return writer.array(17u) && writer.uint(value.mount_class) &&
         writer.uint(value.mount_id) && writer.uint(value.parent_mount_id) &&
         writer.uint(value.device_major) && writer.uint(value.device_minor) &&
         writer.bytes(value.decoded_root) &&
         writer.bytes(value.decoded_mount_point) &&
         encode_byte_array(writer, value.mount_options) &&
         encode_byte_array(writer, value.optional_fields) &&
         writer.bytes(value.filesystem) && writer.bytes(value.source) &&
         encode_byte_array(writer, value.super_options) &&
         writer.uint(value.statfs_type) && writer.uint(value.fsid0) &&
         writer.uint(value.fsid1) && writer.uint(value.statfs_flags) &&
         writer.bytes(value.raw_mountinfo_line);
}

[[nodiscard]] bool encode_root_custody(CborWriter& writer,
                                       const RootMountCustodyV2Wire& value) noexcept {
  return writer.array(2u) && encode_mount_info(writer, value.mount) &&
         encode_object_identity(writer, value.root_object);
}

[[nodiscard]] bool encode_directory_identity(
    CborWriter& writer, const DirectoryIdentityV1Wire& value) noexcept {
  return writer.array(5u) && encode_object_identity(writer, value.object) &&
         writer.uint(value.statfs_type) && writer.uint(value.fsid0) &&
         writer.uint(value.fsid1) && writer.uint(value.statfs_flags);
}

[[nodiscard]] bool encode_cwd(CborWriter& writer,
                              const CwdIdentityV1Wire& value) noexcept {
  return writer.array(4u) && writer.uint(value.mount_id) &&
         writer.uint(value.device_major) && writer.uint(value.device_minor) &&
         writer.uint(value.inode);
}

[[nodiscard]] bool encode_census(CborWriter& writer,
                                 const ProcessCensusV1Wire& census) noexcept {
  if (!writer.array(census.size)) {
    return false;
  }
  for (std::size_t process_index = 0u; process_index < census.size;
       ++process_index) {
    const auto& process = census.data[process_index];
    if (!writer.array(3u) || !writer.uint(process.pid) ||
        !writer.uint(process.starttime) || !writer.array(process.tasks.size)) {
      return false;
    }
    for (std::size_t task_index = 0u; task_index < process.tasks.size;
         ++task_index) {
      const auto& task = process.tasks.data[task_index];
      if (!writer.array(2u) || !writer.uint(task.tid) ||
          !encode_cwd(writer, task.cwd)) {
        return false;
      }
    }
  }
  return true;
}

[[nodiscard]] bool encode_seccomp(CborWriter& writer,
                                  const SeccompPolicyV1Wire& value) noexcept {
  if (!writer.array(6u) || !writer.uint(value.audit_arch) ||
      !writer.uint(value.x32_syscall_bit) || !writer.uint(value.action_kill) ||
      !writer.uint(value.action_allow) ||
      !writer.array(value.denied_syscalls.size)) {
    return false;
  }
  for (std::size_t index = 0u; index < value.denied_syscalls.size; ++index) {
    if (!writer.uint(value.denied_syscalls.data[index])) {
      return false;
    }
  }
  return writer.bytes(value.raw_bpf_sha256);
}

[[nodiscard]] bool encode_uint_pair(CborWriter& writer,
                                    const UIntPairV1Wire& value) noexcept {
  return writer.array(2u) && writer.uint(value.first) &&
         writer.uint(value.second);
}

[[nodiscard]] bool encode_final_listing(
    CborWriter& writer, const FinalDirectoryListingV1Wire& value) noexcept {
  if (!writer.array(2u)) {
    return false;
  }
  for (const auto& row : value.rows) {
    if (!writer.array(2u) || !writer.bytes(row.name) ||
        !encode_file_identity(writer, row.identity)) {
      return false;
    }
  }
  return true;
}

[[nodiscard]] bool encode_blob_digest(CborWriter& writer,
                                      const BlobDigestV1Wire& value) noexcept {
  return writer.array(2u) && writer.uint(value.byte_count) &&
         writer.bytes(value.sha256);
}

[[nodiscard]] bool encode_body(
    CborWriter& writer,
    const Stage1ExtractionCustodyBodyV2WireView& body) noexcept {
  return writer.array(kBodyFieldCount) &&                    // 0..30
         writer.bytes(body.image_id_sha256) &&               // 0
         encode_file_identity(writer, body.custodian_file_identity) &&
         encode_namespace_identity(writer, body.pid_namespace_identity) &&
         encode_namespace_identity(writer, body.mount_namespace_identity) &&
         encode_root_custody(writer, body.root_custody_pre) &&
         encode_mount_info(writer, body.proc_mount_pre) &&
         encode_directory_identity(writer, body.extraction_directory_pre) &&
         encode_file_identity(writer, body.raw_object_pre) &&
         encode_file_identity(writer, body.env_executable_identity) &&
         encode_file_identity(writer, body.objcopy_executable_identity) &&
         encode_byte_array(writer, body.extraction_argv) &&
         encode_byte_array(writer, body.extraction_envp) &&
         encode_seccomp(writer, body.seccomp_policy) &&
         encode_census(writer, body.pre_census_1) &&
         encode_census(writer, body.pre_census_2) &&
         writer.uint(body.child_pid) && writer.uint(body.child_starttime) &&
         encode_uint_pair(writer, body.child_security_state) &&
         encode_census(writer, body.barrier_census_1) &&
         encode_census(writer, body.barrier_census_2) &&
         encode_uint_pair(writer, body.child_wait_result) &&
         encode_root_custody(writer, body.root_custody_post) &&
         encode_mount_info(writer, body.proc_mount_post) &&
         encode_directory_identity(writer, body.extraction_directory_post) &&
         encode_file_identity(writer, body.raw_object_post) &&
         encode_file_identity(writer, body.committed_page_identity) &&
         encode_final_listing(writer, body.final_directory_listing) &&
         encode_blob_digest(writer, body.objcopy_stdout) &&
         encode_blob_digest(writer, body.objcopy_stderr) &&
         writer.array(2u) && encode_census(writer, body.post_censuses.first) &&
         encode_census(writer, body.post_censuses.second) &&
         writer.array(2u) && writer.uint(body.build_principal.buid) &&
         writer.uint(body.build_principal.bgid);
}

constexpr std::uint32_t rotate_right(const std::uint32_t value,
                                     const unsigned shift) noexcept {
  return (value >> shift) | (value << (32u - shift));
}

constexpr std::uint32_t sha_ch(const std::uint32_t x, const std::uint32_t y,
                               const std::uint32_t z) noexcept {
  return (x & y) ^ ((~x) & z);
}

constexpr std::uint32_t sha_maj(const std::uint32_t x, const std::uint32_t y,
                                const std::uint32_t z) noexcept {
  return (x & y) ^ (x & z) ^ (y & z);
}

constexpr std::uint32_t sha_big_sigma0(const std::uint32_t x) noexcept {
  return rotate_right(x, 2u) ^ rotate_right(x, 13u) ^ rotate_right(x, 22u);
}

constexpr std::uint32_t sha_big_sigma1(const std::uint32_t x) noexcept {
  return rotate_right(x, 6u) ^ rotate_right(x, 11u) ^ rotate_right(x, 25u);
}

constexpr std::uint32_t sha_small_sigma0(const std::uint32_t x) noexcept {
  return rotate_right(x, 7u) ^ rotate_right(x, 18u) ^ (x >> 3u);
}

constexpr std::uint32_t sha_small_sigma1(const std::uint32_t x) noexcept {
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

[[nodiscard]] std::uint32_t load_be32(const std::uint8_t* const bytes) noexcept {
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

class Sha256 final {
 public:
  Sha256() noexcept = default;

  [[nodiscard]] bool update(const std::uint8_t* const bytes,
                            const std::size_t length) noexcept {
    if (length != 0u && bytes == nullptr) {
      return false;
    }
    constexpr std::uint64_t kMaximumBytes =
        std::numeric_limits<std::uint64_t>::max() / 8u;
    if (length > kMaximumBytes - total_bytes_) {
      return false;
    }
    total_bytes_ += static_cast<std::uint64_t>(length);
    std::size_t offset = 0u;
    while (offset < length) {
      const std::size_t available = 64u - block_size_;
      const std::size_t remaining = length - offset;
      const std::size_t take = remaining < available ? remaining : available;
      for (std::size_t index = 0u; index < take; ++index) {
        block_[block_size_ + index] = bytes[offset + index];
      }
      block_size_ += take;
      offset += take;
      if (block_size_ == 64u) {
        compress(block_.data());
        block_size_ = 0u;
      }
    }
    return true;
  }

  void finish(Sha256Digest& digest) noexcept {
    const std::uint64_t bit_length = total_bytes_ * 8u;
    block_[block_size_++] = 0x80u;
    if (block_size_ > 56u) {
      while (block_size_ < 64u) {
        block_[block_size_++] = 0u;
      }
      compress(block_.data());
      block_size_ = 0u;
    }
    while (block_size_ < 56u) {
      block_[block_size_++] = 0u;
    }
    for (unsigned index = 0u; index < 8u; ++index) {
      block_[63u - index] =
          static_cast<std::uint8_t>(bit_length >> (index * 8u));
    }
    compress(block_.data());
    for (unsigned index = 0u; index < 8u; ++index) {
      store_be32(state_[index], digest.data() + (index * 4u));
    }
  }

 private:
  void compress(const std::uint8_t* const block) noexcept {
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
    std::uint32_t a = state_[0];
    std::uint32_t b = state_[1];
    std::uint32_t c = state_[2];
    std::uint32_t d = state_[3];
    std::uint32_t e = state_[4];
    std::uint32_t f = state_[5];
    std::uint32_t g = state_[6];
    std::uint32_t h = state_[7];
    for (unsigned index = 0u; index < 64u; ++index) {
      const std::uint32_t temp1 =
          h + sha_big_sigma1(e) + sha_ch(e, f, g) +
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
    state_[0] += a;
    state_[1] += b;
    state_[2] += c;
    state_[3] += d;
    state_[4] += e;
    state_[5] += f;
    state_[6] += g;
    state_[7] += h;
  }

  std::uint32_t state_[8] = {
      0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
      0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u,
  };
  std::array<std::uint8_t, 64u> block_{};
  std::size_t block_size_ = 0u;
  std::uint64_t total_bytes_ = 0u;
};

[[nodiscard]] bool compute_root(const std::uint8_t* const body,
                                const std::size_t body_size,
                                Sha256Digest& root) noexcept {
  Sha256 sha;
  if (!sha.update(kRootDomain, kRootDomainSize) ||
      !sha.update(body, body_size)) {
    return false;
  }
  sha.finish(root);
  return true;
}

[[nodiscard]] bool equal_bytes(const std::uint8_t* const left,
                               const std::uint8_t* const right,
                               const std::size_t count) noexcept {
  std::uint8_t difference = 0u;
  for (std::size_t index = 0u; index < count; ++index) {
    difference = static_cast<std::uint8_t>(difference |
                                           (left[index] ^ right[index]));
  }
  return difference == 0u;
}

}  // namespace

EncodeStatus encode_candidate_bytes(
    const Stage1ExtractionCustodyBodyV2WireView& body,
    const std::span<std::uint8_t> body_output,
    const std::span<std::uint8_t> wrapper_output,
    EncodeOutput& output) noexcept {
  AddressRange body_output_range{};
  AddressRange wrapper_output_range{};
  AddressRange result_range{};
  bool body_output_present = false;
  bool wrapper_output_present = false;
  bool result_present = false;
  const bool body_output_valid =
      make_range(body_output.data(), body_output.size(), body_output_range,
                 body_output_present);
  const bool wrapper_output_valid =
      make_range(wrapper_output.data(), wrapper_output.size(),
                 wrapper_output_range, wrapper_output_present);
  const bool result_valid =
      make_range(&output, sizeof(output), result_range, result_present);
  if (!body_output_valid || !wrapper_output_valid || !result_valid) {
    output.body_size = 0u;
    output.wrapper_size = 0u;
    output.root.fill(0u);
    if (body_output_valid) {
      zero_bytes(body_output);
    }
    if (wrapper_output_valid) {
      zero_bytes(wrapper_output);
    }
    return EncodeStatus::kInvalidInput;
  }

  AddressRange forbidden[3]{};
  std::size_t forbidden_count = 0u;
  if (body_output_present) {
    forbidden[forbidden_count++] = body_output_range;
  }
  if (wrapper_output_present) {
    forbidden[forbidden_count++] = wrapper_output_range;
  }
  if (result_present) {
    forbidden[forbidden_count++] = result_range;
  }

  bool direct_overlap = false;
  for (std::size_t left = 0u; left < forbidden_count; ++left) {
    for (std::size_t right = left + 1u; right < forbidden_count; ++right) {
      if (overlaps(forbidden[left], forbidden[right])) {
        direct_overlap = true;
      }
    }
  }

  InputRangeWalk initial_walk(forbidden, forbidden_count);
  const bool initial_walk_completed = walk_body_inputs(body, initial_walk);
  if (!initial_walk_completed || !initial_walk.valid()) {
    reset_outputs(body_output, wrapper_output, output);
    return EncodeStatus::kInvalidInput;
  }
  if (direct_overlap || initial_walk.overlap()) {
    reset_outputs(body_output, wrapper_output, output);
    return EncodeStatus::kRangeOverlap;
  }

  reset_outputs(body_output, wrapper_output, output);
  if (!all_zero(body.image_id_sha256)) {
    return EncodeStatus::kInvalidInput;
  }

  CborWriter body_writer(body_output.data(), body_output.size());
  if (!encode_body(body_writer, body)) {
    reset_outputs(body_output, wrapper_output, output);
    return body_writer.failed() ? EncodeStatus::kBodyCapacityInsufficient
                                : EncodeStatus::kCborFailure;
  }
  const std::size_t body_size = body_writer.position();
  if (body_size == 0u || body_size > body_output.size()) {
    reset_outputs(body_output, wrapper_output, output);
    return EncodeStatus::kInternalInvariantFailure;
  }

  Sha256Digest root{};
  if (!compute_root(body_output.data(), body_size, root)) {
    reset_outputs(body_output, wrapper_output, output);
    return EncodeStatus::kSha256Failure;
  }

  CborWriter wrapper_writer(wrapper_output.data(), wrapper_output.size());
  if (!wrapper_writer.array(4u) || !wrapper_writer.uint(kProtocolId) ||
      !wrapper_writer.uint(kWireVersion)) {
    reset_outputs(body_output, wrapper_output, output);
    return EncodeStatus::kWrapperCapacityInsufficient;
  }
  const std::size_t wrapper_body_begin = wrapper_writer.position();
  if (!wrapper_writer.raw(body_output.data(), body_size) ||
      !wrapper_writer.bytes(root)) {
    reset_outputs(body_output, wrapper_output, output);
    return EncodeStatus::kWrapperCapacityInsufficient;
  }
  const std::size_t wrapper_size = wrapper_writer.position();
  if (wrapper_body_begin > wrapper_size ||
      body_size > wrapper_size - wrapper_body_begin ||
      !equal_bytes(body_output.data(),
                   wrapper_output.data() + wrapper_body_begin, body_size)) {
    reset_outputs(body_output, wrapper_output, output);
    return EncodeStatus::kInternalInvariantFailure;
  }

  output.body_size = body_size;
  output.wrapper_size = wrapper_size;
  output.root = root;
  return EncodeStatus::kOk;
}

}  // namespace evaluation_v6_3_1::stage1::receipt_v2::offline
