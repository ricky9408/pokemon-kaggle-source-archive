#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace evaluation_v6_3_1::stage1::receipt_v2::offline {

inline constexpr std::uint64_t kProtocolId = 631302u;
inline constexpr std::uint64_t kWireVersion = 2u;
inline constexpr std::size_t kBodyFieldCount = 31u;
inline constexpr std::size_t kSha256Size = 32u;

struct ByteView final {
  const std::uint8_t* data;
  std::size_t size;
};

template <typename T>
struct ArrayView final {
  const T* data;
  std::size_t size;
};

using Sha256Digest = std::array<std::uint8_t, kSha256Size>;

// ObjectIdentityV1: [mnt_id, dev_major, dev_minor, inode, mode, uid, gid,
//                     nlink, size].
struct ObjectIdentityV1Wire final {
  std::uint64_t statx_mnt_id;
  std::uint32_t device_major;
  std::uint32_t device_minor;
  std::uint64_t inode;
  std::uint32_t full_mode;
  std::uint32_t uid;
  std::uint32_t gid;
  std::uint64_t link_count;
  std::uint64_t byte_size;
};

struct FileIdentityV1Wire final {
  ObjectIdentityV1Wire object;
  Sha256Digest sha256;
};

struct NamespaceIdentityV1Wire final {
  std::uint64_t device;
  std::uint64_t inode;
  std::uint64_t namespace_type;
};

struct DirectoryIdentityV1Wire final {
  ObjectIdentityV1Wire object;
  std::uint64_t statfs_type;
  std::uint32_t fsid0;
  std::uint32_t fsid1;
  std::uint64_t statfs_flags;
};

// MountInfoRecordV1 is exactly a 17-element wire array.
struct MountInfoRecordV1Wire final {
  std::uint64_t mount_class;
  std::uint64_t mount_id;
  std::uint64_t parent_mount_id;
  std::uint32_t device_major;
  std::uint32_t device_minor;
  ByteView decoded_root;
  ByteView decoded_mount_point;
  ArrayView<ByteView> mount_options;
  ArrayView<ByteView> optional_fields;
  ByteView filesystem;
  ByteView source;
  ArrayView<ByteView> super_options;
  std::uint64_t statfs_type;
  std::uint32_t fsid0;
  std::uint32_t fsid1;
  std::uint64_t statfs_flags;
  ByteView raw_mountinfo_line;
};

struct RootMountCustodyV2Wire final {
  MountInfoRecordV1Wire mount;
  ObjectIdentityV1Wire root_object;
};

struct CwdIdentityV1Wire final {
  std::uint64_t mount_id;
  std::uint64_t device_major;
  std::uint64_t device_minor;
  std::uint64_t inode;
};

struct TaskCensusRowV1Wire final {
  std::uint64_t tid;
  CwdIdentityV1Wire cwd;
};

struct ProcessCensusRowV1Wire final {
  std::uint64_t pid;
  std::uint64_t starttime;
  ArrayView<TaskCensusRowV1Wire> tasks;
};

using ProcessCensusV1Wire = ArrayView<ProcessCensusRowV1Wire>;

struct BlobDigestV1Wire final {
  std::uint64_t byte_count;
  Sha256Digest sha256;
};

struct SeccompPolicyV1Wire final {
  std::uint64_t audit_arch;
  std::uint64_t x32_syscall_bit;
  std::uint64_t action_kill;
  std::uint64_t action_allow;
  ArrayView<std::uint64_t> denied_syscalls;
  Sha256Digest raw_bpf_sha256;
};

struct UIntPairV1Wire final {
  std::uint64_t first;
  std::uint64_t second;
};

struct FinalDirectoryListingRowV1Wire final {
  ByteView name;
  FileIdentityV1Wire identity;
};

struct FinalDirectoryListingV1Wire final {
  std::array<FinalDirectoryListingRowV1Wire, 2u> rows;
};

struct PostCensusesV1Wire final {
  ProcessCensusV1Wire first;
  ProcessCensusV1Wire second;
};

struct BuildPrincipalV1Wire final {
  std::uint32_t buid;
  std::uint32_t bgid;
};

// Immutable, non-owning, test-only typed view. The declaration order below is
// the frozen Stage1ExtractionCustodyBodyV2 position order 0..30.
struct Stage1ExtractionCustodyBodyV2WireView final {
  static constexpr std::size_t field_count = kBodyFieldCount;

  Sha256Digest image_id_sha256;                         // 0
  FileIdentityV1Wire custodian_file_identity;           // 1
  NamespaceIdentityV1Wire pid_namespace_identity;       // 2
  NamespaceIdentityV1Wire mount_namespace_identity;     // 3
  RootMountCustodyV2Wire root_custody_pre;              // 4
  MountInfoRecordV1Wire proc_mount_pre;                 // 5
  DirectoryIdentityV1Wire extraction_directory_pre;     // 6
  FileIdentityV1Wire raw_object_pre;                    // 7
  FileIdentityV1Wire env_executable_identity;           // 8
  FileIdentityV1Wire objcopy_executable_identity;       // 9
  ArrayView<ByteView> extraction_argv;                  // 10
  ArrayView<ByteView> extraction_envp;                  // 11
  SeccompPolicyV1Wire seccomp_policy;                   // 12
  ProcessCensusV1Wire pre_census_1;                     // 13
  ProcessCensusV1Wire pre_census_2;                     // 14
  std::uint64_t child_pid;                              // 15
  std::uint64_t child_starttime;                        // 16
  UIntPairV1Wire child_security_state;                  // 17
  ProcessCensusV1Wire barrier_census_1;                 // 18
  ProcessCensusV1Wire barrier_census_2;                 // 19
  UIntPairV1Wire child_wait_result;                     // 20
  RootMountCustodyV2Wire root_custody_post;             // 21
  MountInfoRecordV1Wire proc_mount_post;                // 22
  DirectoryIdentityV1Wire extraction_directory_post;    // 23
  FileIdentityV1Wire raw_object_post;                   // 24
  FileIdentityV1Wire committed_page_identity;           // 25
  FinalDirectoryListingV1Wire final_directory_listing;  // 26
  BlobDigestV1Wire objcopy_stdout;                      // 27
  BlobDigestV1Wire objcopy_stderr;                      // 28
  PostCensusesV1Wire post_censuses;                     // 29
  BuildPrincipalV1Wire build_principal;                 // 30
};

enum class EncodeStatus : std::uint32_t {
  kOk = 0,
  kInvalidInput = 1,
  kBodyCapacityInsufficient = 2,
  kWrapperCapacityInsufficient = 3,
  kRangeOverlap = 4,
  kCborFailure = 5,
  kSha256Failure = 6,
  kInternalInvariantFailure = 7,
};

struct EncodeOutput final {
  std::size_t body_size;
  std::size_t wrapper_size;
  Sha256Digest root;
};

[[gnu::visibility("hidden")]]
EncodeStatus encode_candidate_bytes(
    const Stage1ExtractionCustodyBodyV2WireView& body,
    std::span<std::uint8_t> body_output,
    std::span<std::uint8_t> wrapper_output,
    EncodeOutput& output) noexcept;

}  // namespace evaluation_v6_3_1::stage1::receipt_v2::offline
