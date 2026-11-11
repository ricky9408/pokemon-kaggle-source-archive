#include "Stage1ExtractionCustodianV1.h"
#include "Stage1ExtractionChildGateV1.h"
#include "Stage1PidfdChildLifecycleV1.h"
#include "Stage1SeccompFilterV1.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <string>
#include <string_view>
#include <vector>

#include <dirent.h>
#include <fcntl.h>
#include <linux/magic.h>
#include <linux/openat2.h>
#include <linux/sched.h>
#include <linux/stat.h>
#include <poll.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

namespace pokemon::evaluation_v631302 {
namespace {

constexpr char kExpectedArgv0[] = "/work/stage1/bin/Stage1ExtractionCustodianV1";
constexpr char kExtractionRelativePath[] = "work/stage1/gate-extract";
constexpr char kRawObjectName[] = "LaunchGateV1.o";
constexpr std::uint64_t kRawObjectSize = 8688u;
constexpr std::size_t kMaximumMountInfoBytes = 1u << 20u;
constexpr std::size_t kMaximumProcFileBytes = 1u << 16u;
constexpr std::size_t kMaximumProcMapsBytes = 1u << 20u;
constexpr std::size_t kMaximumCensusPids = 4096u;
constexpr std::size_t kMaximumCensusTidsPerPid = 4096u;
constexpr std::uint64_t kOverlayMagic = 0x794c7630u;
constexpr std::uint64_t kProcMagic = 0x9fa0u;
constexpr int kExitInvocation = 64;
constexpr int kExitTopology = 65;
constexpr int kExitNamespace = 66;
constexpr int kExitMountCustody = 67;
constexpr int kExitRawObject = 68;
constexpr int kExitChildGate = 69;
constexpr int kExitReadyBarrier = 70;
constexpr int kExitChildLifecycle = 71;
constexpr int kExitIncomplete = 78;
constexpr int kExitReadyBarrierComplete = 79;
constexpr std::uint64_t kReadyDeadlineMilliseconds = 5'000u;
constexpr std::uint64_t kKillReapDeadlineMilliseconds = 5'000u;
constexpr std::uint8_t kChildReleaseByte = 0x47u;
constexpr std::uint8_t kChildReadyByte = 0x52u;

constexpr std::array<std::uint8_t, 32u> kRawObjectSha256 = {
    0xc2u, 0x0eu, 0xa3u, 0xa1u, 0x83u, 0xf4u, 0x0cu, 0x61u,
    0xcau, 0x33u, 0x96u, 0x77u, 0x1fu, 0xb9u, 0x2cu, 0xb9u,
    0x48u, 0xccu, 0x60u, 0x3bu, 0x81u, 0xe9u, 0x66u, 0x48u,
    0x69u, 0x96u, 0xf4u, 0x8bu, 0xabu, 0x84u, 0xa5u, 0x30u,
};

constexpr char kEnvironmentRelativePath[] = "usr/bin/env";
constexpr char kEmptyPath[] = "";
constexpr char kExtractionArgv0[] = "/usr/bin/env";
constexpr char kExtractionArgv1[] = "-i";
constexpr char kEnvironmentPath[] = "PATH=/usr/bin:/bin";
constexpr char kEnvironmentLcAll[] = "LC_ALL=C";
constexpr char kEnvironmentLang[] = "LANG=C";
constexpr char kEnvironmentTimezone[] = "TZ=UTC";
constexpr char kEnvironmentEpoch[] = "SOURCE_DATE_EPOCH=0";
constexpr char kEnvironmentHome[] = "HOME=/nonexistent";
constexpr char kEnvironmentDebuginfod[] = "DEBUGINFOD_URLS=";
constexpr char kObjcopyPath[] = "/usr/bin/objcopy";
constexpr char kObjcopyInputTarget[] = "--input-target=elf64-x86-64";
constexpr char kObjcopyOutputTarget[] = "--output-target=elf64-x86-64";
constexpr char kObjcopyDumpSection[] = "--dump-section";
constexpr char kObjcopySectionAssignment[] =
    ".text.launch_gate_v1=LaunchGateV1.page.tmp";
constexpr char kObjcopyDiscardName[] = "LaunchGateV1.objcopy-discard.o";

static_assert(kStage1CustodianZeroAuthority);
static_assert(!kStage1CustodianUploadAuthority);
static_assert(!kStage1CustodianReceiptAvailable);
static_assert(kStage1CustodianChildLaunchAvailable);
static_assert(kStage1CustodianReadyBarrierCandidateAvailable);
static_assert(kStage1CustodianStopAfterReady);
static_assert(!kStage1CustodianAuthoritativeExtractionAvailable);
static_assert(sizeof(clone_args) == 88u);

class OwnedFd final {
public:
    explicit OwnedFd(const int fd = -1) noexcept : fd_(fd) {}
    ~OwnedFd() {
        if (fd_ >= 0) {
            (void)::close(fd_);
        }
    }
    OwnedFd(const OwnedFd&) = delete;
    OwnedFd& operator=(const OwnedFd&) = delete;
    OwnedFd(OwnedFd&& other) noexcept : fd_(other.release()) {}
    OwnedFd& operator=(OwnedFd&& other) noexcept {
        if (this != &other) {
            if (fd_ >= 0) {
                (void)::close(fd_);
            }
            fd_ = other.release();
        }
        return *this;
    }
    [[nodiscard]] int get() const noexcept { return fd_; }
    [[nodiscard]] bool valid() const noexcept { return fd_ >= 0; }
    [[nodiscard]] int release() noexcept {
        const int value = fd_;
        fd_ = -1;
        return value;
    }
    bool reset(const int replacement = -1) noexcept {
        bool closed = true;
        if (fd_ >= 0) {
            closed = ::close(fd_) == 0;
        }
        fd_ = replacement;
        return closed;
    }

private:
    int fd_;
};

struct PipePair final {
    OwnedFd read;
    OwnedFd write;
};

struct ObjectIdentity final {
    std::uint64_t mount_id = 0;
    std::uint64_t device_major = 0;
    std::uint64_t device_minor = 0;
    std::uint64_t inode = 0;
    std::uint32_t mode = 0;
    std::uint32_t uid = 0;
    std::uint32_t gid = 0;
    std::uint64_t link_count = 0;
    std::uint64_t size = 0;
};

struct FilesystemIdentity final {
    std::uint64_t type = 0;
    std::array<std::uint32_t, 2u> fsid{};
    std::uint64_t flags = 0;
};

using CwdIdentity = Stage1CwdIdentityV1;
using ProcessCensus = Stage1ProcessCensusV1;
using ProcessCensusRow = Stage1ProcessCensusRowV1;

struct ParsedMountLine final {
    std::uint64_t mount_id = 0;
    std::uint64_t parent_mount_id = 0;
    std::uint64_t device_major = 0;
    std::uint64_t device_minor = 0;
    std::string root;
    std::string mount_point;
    std::vector<std::string> mount_options;
    std::vector<std::string> optional_fields;
    std::string filesystem_type;
    std::string mount_source;
    std::vector<std::string> super_options;
};

void write_error(const char* value) noexcept {
    if (value == nullptr) {
        return;
    }
    const std::size_t length = std::strlen(value);
    std::size_t used = 0;
    while (used < length) {
        const ssize_t count = ::write(STDERR_FILENO, value + used, length - used);
        if (count <= 0) {
            return;
        }
        used += static_cast<std::size_t>(count);
    }
    (void)::write(STDERR_FILENO, "\n", 1u);
}

[[noreturn]] void immediate_pid1_exit() noexcept {
    ::_exit(kExitChildLifecycle);
}

[[nodiscard]] bool create_cloexec_pipe(PipePair* const output) noexcept {
    if (output == nullptr) {
        return false;
    }
    int descriptors[2] = {-1, -1};
    if (::pipe2(descriptors, O_CLOEXEC) != 0) {
        return false;
    }
    output->read = OwnedFd(descriptors[0]);
    output->write = OwnedFd(descriptors[1]);
    return true;
}

[[nodiscard]] bool valid_timespec(const timespec& value) noexcept {
    return value.tv_sec >= 0 && value.tv_nsec >= 0 && value.tv_nsec < 1'000'000'000L;
}

[[nodiscard]] int compare_timespec(
    const timespec& left,
    const timespec& right) noexcept {
    if (left.tv_sec != right.tv_sec) {
        return left.tv_sec < right.tv_sec ? -1 : 1;
    }
    if (left.tv_nsec != right.tv_nsec) {
        return left.tv_nsec < right.tv_nsec ? -1 : 1;
    }
    return 0;
}

[[nodiscard]] bool remaining_until_deadline(
    const timespec& deadline,
    timespec* const remaining) noexcept {
    if (remaining == nullptr || !valid_timespec(deadline)) {
        return false;
    }
    timespec now{};
    if (::clock_gettime(CLOCK_MONOTONIC, &now) != 0 || !valid_timespec(now) ||
        compare_timespec(now, deadline) >= 0) {
        return false;
    }
    remaining->tv_sec = deadline.tv_sec - now.tv_sec;
    remaining->tv_nsec = deadline.tv_nsec - now.tv_nsec;
    if (remaining->tv_nsec < 0) {
        --remaining->tv_sec;
        remaining->tv_nsec += 1'000'000'000L;
    }
    return valid_timespec(*remaining);
}

[[nodiscard]] bool wait_for_pipe_event(
    const int fd,
    const short requested,
    const timespec& deadline) noexcept {
    if (fd < 0 || (requested != POLLIN && requested != POLLOUT)) {
        return false;
    }
    for (;;) {
        timespec remaining{};
        if (!remaining_until_deadline(deadline, &remaining)) {
            return false;
        }
        pollfd descriptor{};
        descriptor.fd = fd;
        descriptor.events = requested;
        const int result = ::ppoll(&descriptor, 1u, &remaining, nullptr);
        if (result > 0) {
            return (descriptor.revents & requested) != 0 &&
                   (descriptor.revents & (POLLERR | POLLHUP | POLLNVAL)) == 0;
        }
        if (result == 0) {
            return false;
        }
        if (errno != EINTR) {
            return false;
        }
    }
}

[[nodiscard]] bool write_one_byte_until(
    const int fd,
    const std::uint8_t value,
    const timespec& deadline) noexcept {
    if (!wait_for_pipe_event(fd, POLLOUT, deadline)) {
        return false;
    }
    for (;;) {
        const ssize_t count = ::write(fd, &value, 1u);
        if (count == 1) {
            return true;
        }
        if (count < 0 && errno == EINTR) {
            continue;
        }
        return false;
    }
}

[[nodiscard]] bool read_exact_byte_until(
    const int fd,
    const std::uint8_t expected,
    const timespec& deadline) noexcept {
    if (!wait_for_pipe_event(fd, POLLIN, deadline)) {
        return false;
    }
    std::uint8_t value = 0u;
    for (;;) {
        const ssize_t count = ::read(fd, &value, 1u);
        if (count == 1) {
            return value == expected;
        }
        if (count < 0 && errno == EINTR) {
            continue;
        }
        return false;
    }
}

[[nodiscard]] bool pipe_is_empty_after_child_exit(const int fd) noexcept {
    if (fd < 0) {
        return false;
    }
    std::uint8_t byte = 0u;
    for (;;) {
        const ssize_t count = ::read(fd, &byte, 1u);
        if (count == 0) {
            return true;
        }
        if (count < 0 && errno == EINTR) {
            continue;
        }
        return false;
    }
}

[[nodiscard]] bool parse_decimal(
    const std::string_view value,
    std::uint64_t* output) noexcept {
    if (output == nullptr || value.empty()) {
        return false;
    }
    std::uint64_t result = 0;
    for (const char byte : value) {
        if (byte < '0' || byte > '9') {
            return false;
        }
        const auto digit = static_cast<std::uint64_t>(byte - '0');
        if (result > (std::numeric_limits<std::uint64_t>::max() - digit) / 10u) {
            return false;
        }
        result = result * 10u + digit;
    }
    *output = result;
    return true;
}

[[nodiscard]] bool parse_proc_integer_token(const std::string_view value) noexcept {
    if (value.empty()) {
        return false;
    }
    bool negative = false;
    std::string_view magnitude = value;
    if (magnitude.front() == '-') {
        negative = true;
        magnitude.remove_prefix(1u);
    }
    if (magnitude.empty() || (magnitude.size() > 1u && magnitude.front() == '0')) {
        return false;
    }
    std::uint64_t parsed = 0;
    if (!parse_decimal(magnitude, &parsed)) {
        return false;
    }
    return !negative || (parsed != 0u && parsed <= (std::uint64_t{1u} << 63u));
}

[[nodiscard]] bool split_single_spaces(
    const std::string_view value,
    std::vector<std::string_view>* output) {
    if (output == nullptr || value.empty() || value.front() == ' ' || value.back() == ' ') {
        return false;
    }
    output->clear();
    std::size_t start = 0;
    while (start < value.size()) {
        const std::size_t end = value.find(' ', start);
        const std::size_t stop = end == std::string_view::npos ? value.size() : end;
        if (stop == start) {
            return false;
        }
        output->push_back(value.substr(start, stop - start));
        if (end == std::string_view::npos) {
            break;
        }
        start = end + 1u;
    }
    return true;
}

[[nodiscard]] bool decode_mount_field(
    std::string_view input,
    std::string* output);

[[nodiscard]] bool split_options(
    const std::string_view value,
    std::vector<std::string>* output) {
    if (output == nullptr || value.empty()) {
        return false;
    }
    output->clear();
    std::size_t start = 0;
    for (;;) {
        const std::size_t comma = value.find(',', start);
        const std::size_t stop = comma == std::string_view::npos ? value.size() : comma;
        if (stop == start) {
            return false;
        }
        std::string decoded;
        if (!decode_mount_field(value.substr(start, stop - start), &decoded)) {
            return false;
        }
        output->push_back(std::move(decoded));
        if (comma == std::string_view::npos) {
            return true;
        }
        start = comma + 1u;
    }
}

[[nodiscard]] bool decode_mount_field(
    const std::string_view input,
    std::string* output) {
    if (output == nullptr) {
        return false;
    }
    output->clear();
    output->reserve(input.size());
    for (std::size_t index = 0; index < input.size();) {
        const char byte = input[index];
        if (byte == '\0') {
            return false;
        }
        if (byte != '\\') {
            output->push_back(byte);
            ++index;
            continue;
        }
        if (index + 3u >= input.size()) {
            return false;
        }
        const std::string_view escaped = input.substr(index, 4u);
        char decoded = '\0';
        if (escaped == "\\040") {
            decoded = ' ';
        } else if (escaped == "\\011") {
            decoded = '\t';
        } else if (escaped == "\\012") {
            decoded = '\n';
        } else if (escaped == "\\134") {
            decoded = '\\';
        } else {
            return false;
        }
        output->push_back(decoded);
        index += 4u;
    }
    return true;
}

[[nodiscard]] bool parse_device(
    const std::string_view value,
    std::uint64_t* major_value,
    std::uint64_t* minor_value) noexcept {
    const std::size_t colon = value.find(':');
    if (colon == std::string_view::npos || value.find(':', colon + 1u) != std::string_view::npos) {
        return false;
    }
    return parse_decimal(value.substr(0, colon), major_value) &&
           parse_decimal(value.substr(colon + 1u), minor_value);
}

[[nodiscard]] bool parse_mount_line(
    const std::string_view line,
    ParsedMountLine* output) {
    if (output == nullptr || line.empty() || line.find('\0') != std::string_view::npos) {
        return false;
    }
    const std::size_t separator = line.find(" - ");
    if (separator == std::string_view::npos ||
        line.find(" - ", separator + 3u) != std::string_view::npos) {
        return false;
    }
    std::vector<std::string_view> left;
    std::vector<std::string_view> right;
    if (!split_single_spaces(line.substr(0, separator), &left) || left.size() < 6u ||
        !split_single_spaces(line.substr(separator + 3u), &right) || right.size() != 3u) {
        return false;
    }
    ParsedMountLine parsed;
    if (!parse_decimal(left[0], &parsed.mount_id) ||
        !parse_decimal(left[1], &parsed.parent_mount_id) ||
        !parse_device(left[2], &parsed.device_major, &parsed.device_minor) ||
        !decode_mount_field(left[3], &parsed.root) ||
        !decode_mount_field(left[4], &parsed.mount_point) ||
        !split_options(left[5], &parsed.mount_options) ||
        !decode_mount_field(right[0], &parsed.filesystem_type) ||
        !decode_mount_field(right[1], &parsed.mount_source) ||
        !split_options(right[2], &parsed.super_options)) {
        return false;
    }
    for (std::size_t index = 6u; index < left.size(); ++index) {
        std::string decoded;
        if (!decode_mount_field(left[index], &decoded)) {
            return false;
        }
        parsed.optional_fields.push_back(std::move(decoded));
    }
    *output = std::move(parsed);
    return true;
}

[[nodiscard]] std::size_t option_count(
    const std::vector<std::string>& options,
    const std::string_view exact) noexcept {
    return static_cast<std::size_t>(std::count(options.begin(), options.end(), exact));
}

[[nodiscard]] bool extract_single_option_value(
    const std::vector<std::string>& options,
    const std::string_view prefix,
    std::string_view* output) noexcept {
    std::size_t count = 0;
    std::string_view value;
    for (const std::string& option : options) {
        if (option.starts_with(prefix)) {
            ++count;
            value = std::string_view(option).substr(prefix.size());
        }
    }
    if (count != 1u || value.empty() || output == nullptr) {
        return false;
    }
    *output = value;
    return true;
}

[[nodiscard]] bool root_mount_is_accepted(const ParsedMountLine& row) noexcept {
    if (row.root != "/" || row.mount_point != "/" || row.filesystem_type != "overlay" ||
        row.mount_source != "overlay" || !row.optional_fields.empty() ||
        option_count(row.mount_options, "rw") != 1u || option_count(row.mount_options, "ro") != 0u ||
        option_count(row.super_options, "rw") != 1u || option_count(row.super_options, "ro") != 0u) {
        return false;
    }
    std::string_view lower;
    std::string_view upper;
    std::string_view work;
    return extract_single_option_value(row.super_options, "lowerdir=", &lower) &&
           extract_single_option_value(row.super_options, "upperdir=", &upper) &&
           extract_single_option_value(row.super_options, "workdir=", &work) && upper != work;
}

[[nodiscard]] bool proc_mount_is_accepted(const ParsedMountLine& row) noexcept {
    return row.root == "/" && row.mount_point == "/proc" &&
           row.filesystem_type == "proc" && row.mount_source == "proc" &&
           row.optional_fields.empty();
}

[[nodiscard]] long raw_openat2(
    const int directory_fd,
    const char* path,
    const std::uint64_t flags,
    const std::uint64_t resolve) noexcept {
    struct open_how how {};
    how.flags = flags;
    how.mode = 0;
    how.resolve = resolve;
    return ::syscall(SYS_openat2, directory_fd, path, &how, sizeof(how));
}

[[nodiscard]] bool statx_identity(const int fd, ObjectIdentity* output) noexcept {
    if (output == nullptr) {
        return false;
    }
    struct statx value {};
    const unsigned int mask = STATX_BASIC_STATS | STATX_MNT_ID;
    if (::syscall(
            SYS_statx,
            fd,
            "",
            AT_EMPTY_PATH | AT_STATX_SYNC_AS_STAT,
            mask,
            &value) != 0 ||
        (value.stx_mask & STATX_MNT_ID) == 0u ||
        (value.stx_mask & STATX_BASIC_STATS) != STATX_BASIC_STATS) {
        return false;
    }
    output->mount_id = value.stx_mnt_id;
    output->device_major = value.stx_dev_major;
    output->device_minor = value.stx_dev_minor;
    output->inode = value.stx_ino;
    output->mode = value.stx_mode;
    output->uid = value.stx_uid;
    output->gid = value.stx_gid;
    output->link_count = value.stx_nlink;
    output->size = value.stx_size;
    return true;
}

[[nodiscard]] bool filesystem_identity(const int fd, FilesystemIdentity* output) noexcept {
    if (output == nullptr) {
        return false;
    }
    struct statfs value {};
    if (::fstatfs(fd, &value) != 0) {
        return false;
    }
    output->type = static_cast<std::uint64_t>(value.f_type);
    output->fsid[0] = static_cast<std::uint32_t>(value.f_fsid.__val[0]);
    output->fsid[1] = static_cast<std::uint32_t>(value.f_fsid.__val[1]);
    output->flags = static_cast<std::uint64_t>(value.f_flags);
    return true;
}

[[nodiscard]] bool same_object(const ObjectIdentity& first, const ObjectIdentity& second) noexcept {
    return first.mount_id == second.mount_id && first.device_major == second.device_major &&
           first.device_minor == second.device_minor && first.inode == second.inode;
}

[[nodiscard]] bool same_identity(const ObjectIdentity& first, const ObjectIdentity& second) noexcept {
    return same_object(first, second) && first.mode == second.mode && first.uid == second.uid &&
           first.gid == second.gid && first.link_count == second.link_count &&
           first.size == second.size;
}

[[nodiscard]] bool same_filesystem_identity(
    const FilesystemIdentity& first,
    const FilesystemIdentity& second) noexcept {
    return first.type == second.type && first.fsid == second.fsid &&
           first.flags == second.flags;
}

[[nodiscard]] bool read_bounded_file(
    const char* path,
    const std::size_t maximum,
    std::string* output) {
    if (path == nullptr || output == nullptr || maximum == 0u) {
        return false;
    }
    const OwnedFd fd(::open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW));
    if (!fd.valid()) {
        return false;
    }
    output->clear();
    std::array<char, 4096u> buffer{};
    for (;;) {
        const ssize_t count = ::read(fd.get(), buffer.data(), buffer.size());
        if (count < 0) {
            if (errno == EINTR) {
                continue;
            }
            return false;
        }
        if (count == 0) {
            return true;
        }
        const auto amount = static_cast<std::size_t>(count);
        if (amount > maximum - std::min(maximum, output->size())) {
            return false;
        }
        output->append(buffer.data(), amount);
    }
}

[[nodiscard]] bool read_bounded_file_at(
    const int directory_fd,
    const char* path,
    const std::size_t maximum,
    std::string* output) {
    if (directory_fd < 0 || path == nullptr || output == nullptr || maximum == 0u) {
        return false;
    }
    const OwnedFd fd(::openat(directory_fd, path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW));
    if (!fd.valid()) {
        return false;
    }
    output->clear();
    std::array<char, 4096u> buffer{};
    for (;;) {
        const ssize_t count = ::read(fd.get(), buffer.data(), buffer.size());
        if (count < 0) {
            if (errno == EINTR) {
                continue;
            }
            return false;
        }
        if (count == 0) {
            return true;
        }
        const auto amount = static_cast<std::size_t>(count);
        if (output->size() > maximum || amount > maximum - output->size()) {
            return false;
        }
        output->append(buffer.data(), amount);
    }
}

[[nodiscard]] bool parse_final_nspid_is_one(const std::string_view status) noexcept {
    if (status.empty() || status.find('\0') != std::string_view::npos || status.back() != '\n') {
        return false;
    }
    std::size_t matches = 0;
    std::size_t start = 0;
    while (start < status.size()) {
        const std::size_t newline = status.find('\n', start);
        if (newline == std::string_view::npos) {
            return false;
        }
        const std::string_view line = status.substr(start, newline - start);
        if (line.starts_with("NSpid:")) {
            ++matches;
            std::string_view values = line.substr(6u);
            while (!values.empty() && (values.front() == ' ' || values.front() == '\t')) {
                values.remove_prefix(1u);
            }
            std::uint64_t last = 0;
            bool found = false;
            while (!values.empty()) {
                std::size_t end = 0;
                while (end < values.size() && values[end] != ' ' && values[end] != '\t') {
                    ++end;
                }
                if (end == 0u || !parse_decimal(values.substr(0, end), &last)) {
                    return false;
                }
                found = true;
                values.remove_prefix(end);
                while (!values.empty() && (values.front() == ' ' || values.front() == '\t')) {
                    values.remove_prefix(1u);
                }
            }
            if (!found || last != 1u) {
                return false;
            }
        }
        start = newline + 1u;
    }
    return matches == 1u;
}

[[nodiscard]] bool parse_status_scalar(
    std::string_view value,
    std::uint64_t* const output) noexcept {
    if (output == nullptr) {
        return false;
    }
    while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) {
        value.remove_prefix(1u);
    }
    while (!value.empty() && (value.back() == ' ' || value.back() == '\t')) {
        value.remove_suffix(1u);
    }
    return !value.empty() && (value.size() == 1u || value.front() != '0') &&
           parse_decimal(value, output);
}

[[nodiscard]] bool parse_status_sequence_last(
    std::string_view value,
    std::uint64_t* const output) noexcept {
    if (output == nullptr) {
        return false;
    }
    while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) {
        value.remove_prefix(1u);
    }
    bool found = false;
    std::uint64_t last = 0u;
    while (!value.empty()) {
        std::size_t end = 0u;
        while (end < value.size() && value[end] != ' ' && value[end] != '\t') {
            ++end;
        }
        if (end == 0u || (end > 1u && value.front() == '0') ||
            !parse_decimal(value.substr(0u, end), &last)) {
            return false;
        }
        found = true;
        value.remove_prefix(end);
        while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) {
            value.remove_prefix(1u);
        }
    }
    if (!found) {
        return false;
    }
    *output = last;
    return true;
}

struct LinuxDirent64 final {
    std::uint64_t inode;
    std::int64_t offset;
    unsigned short record_length;
    unsigned char type;
    char name[1];
};

[[nodiscard]] bool enumerate_numeric_names(
    const int directory_fd,
    const std::size_t maximum_entries,
    std::vector<std::uint64_t>* output) {
    if (output == nullptr || maximum_entries == 0u) {
        return false;
    }
    const OwnedFd cursor(::openat(directory_fd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
    if (!cursor.valid()) {
        return false;
    }
    output->clear();
    alignas(std::uint64_t) std::array<char, 8192u> buffer{};
    for (;;) {
        const long count = ::syscall(SYS_getdents64, cursor.get(), buffer.data(), buffer.size());
        if (count < 0) {
            if (errno == EINTR) {
                continue;
            }
            return false;
        }
        if (count == 0) {
            break;
        }
        std::size_t offset = 0;
        const auto used = static_cast<std::size_t>(count);
        while (offset < used) {
            if (used - offset < offsetof(LinuxDirent64, name) + 1u) {
                return false;
            }
            const auto* entry = reinterpret_cast<const LinuxDirent64*>(buffer.data() + offset);
            const std::size_t record_length = entry->record_length;
            if (record_length < offsetof(LinuxDirent64, name) + 1u ||
                record_length > used - offset || record_length % alignof(std::uint64_t) != 0u) {
                return false;
            }
            const std::size_t name_capacity = record_length - offsetof(LinuxDirent64, name);
            const void* terminator = std::memchr(entry->name, '\0', name_capacity);
            if (terminator == nullptr) {
                return false;
            }
            const auto name_length = static_cast<std::size_t>(
                static_cast<const char*>(terminator) - entry->name);
            const std::string_view name(entry->name, name_length);
            if (!name.empty() && name != "." && name != "..") {
                bool numeric = true;
                for (const char byte : name) {
                    if (byte < '0' || byte > '9') {
                        numeric = false;
                        break;
                    }
                }
                if (numeric) {
                    if (name.size() > 1u && name.front() == '0') {
                        return false;
                    }
                    std::uint64_t value = 0;
                    if (!parse_decimal(name, &value)) {
                        return false;
                    }
                    if (output->size() == maximum_entries) {
                        return false;
                    }
                    output->push_back(value);
                }
            }
            offset += record_length;
        }
    }
    std::sort(output->begin(), output->end());
    return std::adjacent_find(output->begin(), output->end()) == output->end();
}

[[nodiscard]] CwdIdentity cwd_identity_from_object(const ObjectIdentity& identity) noexcept {
    return {
        identity.mount_id,
        identity.device_major,
        identity.device_minor,
        identity.inode,
    };
}

[[nodiscard]] bool capture_process_census(
    const int proc_fd,
    ProcessCensus* output) {
    if (proc_fd < 0 || output == nullptr) {
        return false;
    }
    std::vector<std::uint64_t> pids;
    if (!enumerate_numeric_names(proc_fd, kMaximumCensusPids, &pids) || pids.empty()) {
        return false;
    }
    ProcessCensus census;
    census.reserve(pids.size());
    for (const std::uint64_t pid : pids) {
        const std::string pid_text = std::to_string(pid);
        const std::string stat_path = pid_text + "/stat";
        std::string stat_bytes;
        std::uint64_t starttime = 0;
        const char* stat_error = nullptr;
        if (!read_bounded_file_at(proc_fd, stat_path.c_str(), kMaximumProcFileBytes, &stat_bytes) ||
            !parse_stage1_proc_stat_starttime_v1(
                stat_bytes,
                pid,
                &starttime,
                &stat_error)) {
            return false;
        }
        const std::string task_path = pid_text + "/task";
        const OwnedFd task_fd(
            ::openat(proc_fd, task_path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
        if (!task_fd.valid()) {
            return false;
        }
        std::vector<std::uint64_t> tids;
        if (!enumerate_numeric_names(
                task_fd.get(),
                kMaximumCensusTidsPerPid,
                &tids) ||
            tids.empty()) {
            return false;
        }
        ProcessCensusRow process;
        process.pid = pid;
        process.starttime = starttime;
        process.tasks.reserve(tids.size());
        for (const std::uint64_t tid : tids) {
            const std::string cwd_path =
                pid_text + "/task/" + std::to_string(tid) + "/cwd";
            // The final component is intentionally followed: procfs exposes
            // cwd as a magic link, and the frozen census records its target.
            const OwnedFd cwd_fd(
                ::openat(proc_fd, cwd_path.c_str(), O_PATH | O_DIRECTORY | O_CLOEXEC));
            ObjectIdentity cwd_object;
            if (!cwd_fd.valid() || !statx_identity(cwd_fd.get(), &cwd_object)) {
                return false;
            }
            process.tasks.push_back({tid, cwd_identity_from_object(cwd_object)});
        }
        census.push_back(std::move(process));
    }
    *output = std::move(census);
    return true;
}

[[nodiscard]] bool exact_prelaunch_census_shape(
    const ProcessCensus& census,
    const CwdIdentity& root,
    const CwdIdentity& extraction) noexcept {
    if (census.size() != 1u || census[0].pid != 1u || census[0].starttime == 0u ||
        census[0].tasks.size() != 1u || census[0].tasks[0].tid != 1u) {
        return false;
    }
    return census[0].tasks[0].cwd == root && census[0].tasks[0].cwd != extraction;
}

[[nodiscard]] bool exact_barrier_census_shape(
    const ProcessCensus& census,
    const CwdIdentity& root,
    const CwdIdentity& extraction,
    const std::uint64_t pid1_starttime,
    const std::uint64_t pid2_starttime) noexcept {
    return root != extraction && pid1_starttime != 0u && pid2_starttime != 0u &&
           census.size() == 2u && census[0].pid == 1u &&
           census[0].starttime == pid1_starttime && census[0].tasks.size() == 1u &&
           census[0].tasks[0].tid == 1u && census[0].tasks[0].cwd == root &&
           census[1].pid == 2u && census[1].starttime == pid2_starttime &&
           census[1].tasks.size() == 1u && census[1].tasks[0].tid == 2u &&
           census[1].tasks[0].cwd == extraction;
}

[[nodiscard]] bool exact_postexit_census_shape(
    const ProcessCensus& census,
    const CwdIdentity& root,
    const CwdIdentity& extraction,
    const std::uint64_t pid1_starttime) noexcept {
    return root != extraction && pid1_starttime != 0u && census.size() == 1u &&
           census[0].pid == 1u && census[0].starttime == pid1_starttime &&
           census[0].tasks.size() == 1u && census[0].tasks[0].tid == 1u &&
           census[0].tasks[0].cwd == root;
}

[[nodiscard]] bool bind_pid2_starttime_and_single_task(
    const int proc_fd,
    std::uint64_t* const starttime) {
    if (proc_fd < 0 || starttime == nullptr) {
        return false;
    }
    std::string stat_bytes;
    const char* stat_error = nullptr;
    if (!read_bounded_file_at(proc_fd, "2/stat", kMaximumProcFileBytes, &stat_bytes) ||
        !parse_stage1_proc_stat_starttime_v1(stat_bytes, 2u, starttime, &stat_error)) {
        return false;
    }
    const OwnedFd task_fd(
        ::openat(proc_fd, "2/task", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
    std::vector<std::uint64_t> tids;
    return task_fd.valid() &&
           enumerate_numeric_names(task_fd.get(), kMaximumCensusTidsPerPid, &tids) &&
           tids.size() == 1u && tids[0] == 2u;
}

[[nodiscard]] bool directory_contains_only_raw_object(const int directory_fd) {
    const OwnedFd cursor(::openat(directory_fd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
    if (!cursor.valid()) {
        return false;
    }
    std::vector<std::string> names;
    alignas(std::uint64_t) std::array<char, 4096u> buffer{};
    for (;;) {
        const long count = ::syscall(SYS_getdents64, cursor.get(), buffer.data(), buffer.size());
        if (count < 0) {
            if (errno == EINTR) {
                continue;
            }
            return false;
        }
        if (count == 0) {
            break;
        }
        std::size_t offset = 0;
        const auto used = static_cast<std::size_t>(count);
        while (offset < used) {
            if (used - offset < offsetof(LinuxDirent64, name) + 1u) {
                return false;
            }
            const auto* entry = reinterpret_cast<const LinuxDirent64*>(buffer.data() + offset);
            const std::size_t record_length = entry->record_length;
            if (record_length < offsetof(LinuxDirent64, name) + 1u ||
                record_length > used - offset || record_length % alignof(std::uint64_t) != 0u) {
                return false;
            }
            const std::size_t capacity = record_length - offsetof(LinuxDirent64, name);
            const void* terminator = std::memchr(entry->name, '\0', capacity);
            if (terminator == nullptr) {
                return false;
            }
            const auto length = static_cast<std::size_t>(
                static_cast<const char*>(terminator) - entry->name);
            const std::string_view name(entry->name, length);
            if (name != "." && name != "..") {
                names.emplace_back(name);
            }
            offset += record_length;
        }
    }
    return names.size() == 1u && names[0] == kRawObjectName;
}

[[nodiscard]] bool reset_and_block_signals() noexcept {
    struct sigaction action {};
    action.sa_handler = SIG_DFL;
    if (::sigemptyset(&action.sa_mask) != 0) {
        return false;
    }
    action.sa_flags = 0;
    for (int number = 1; number < NSIG; ++number) {
        if (number == SIGKILL || number == SIGSTOP) {
            continue;
        }
        if (::sigaction(number, &action, nullptr) != 0 && errno != EINVAL) {
            return false;
        }
    }
    sigset_t blocked {};
    if (::sigfillset(&blocked) != 0 || ::sigprocmask(SIG_SETMASK, &blocked, nullptr) != 0) {
        return false;
    }
    struct sigaction child_action {};
    return ::sigaction(SIGCHLD, nullptr, &child_action) == 0 &&
           (child_action.sa_flags & SA_NOCLDWAIT) == 0;
}

class Sha256 final {
public:
    Sha256() noexcept { reset(); }

    void update(const std::uint8_t* data, const std::size_t length) noexcept {
        for (std::size_t index = 0; index < length; ++index) {
            block_[used_++] = data[index];
            if (used_ == block_.size()) {
                transform();
                bits_ += 512u;
                used_ = 0;
            }
        }
    }

    [[nodiscard]] std::array<std::uint8_t, 32u> finish() noexcept {
        const std::uint64_t total_bits = bits_ + static_cast<std::uint64_t>(used_) * 8u;
        block_[used_++] = 0x80u;
        if (used_ > 56u) {
            while (used_ < block_.size()) {
                block_[used_++] = 0u;
            }
            transform();
            used_ = 0;
        }
        while (used_ < 56u) {
            block_[used_++] = 0u;
        }
        for (std::size_t index = 0; index < 8u; ++index) {
            block_[63u - index] = static_cast<std::uint8_t>(total_bits >> (index * 8u));
        }
        transform();
        std::array<std::uint8_t, 32u> output{};
        for (std::size_t index = 0; index < state_.size(); ++index) {
            const std::uint32_t word = state_[index];
            output[index * 4u] = static_cast<std::uint8_t>(word >> 24u);
            output[index * 4u + 1u] = static_cast<std::uint8_t>(word >> 16u);
            output[index * 4u + 2u] = static_cast<std::uint8_t>(word >> 8u);
            output[index * 4u + 3u] = static_cast<std::uint8_t>(word);
        }
        return output;
    }

private:
    static constexpr std::array<std::uint32_t, 64u> kRound = {
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

    static constexpr std::uint32_t rotate_right(const std::uint32_t value, const unsigned int bits) noexcept {
        return (value >> bits) | (value << (32u - bits));
    }

    void reset() noexcept {
        state_ = {0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
                  0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u};
        block_.fill(0u);
        used_ = 0;
        bits_ = 0;
    }

    void transform() noexcept {
        std::array<std::uint32_t, 64u> words{};
        for (std::size_t index = 0; index < 16u; ++index) {
            const std::size_t offset = index * 4u;
            words[index] = (static_cast<std::uint32_t>(block_[offset]) << 24u) |
                           (static_cast<std::uint32_t>(block_[offset + 1u]) << 16u) |
                           (static_cast<std::uint32_t>(block_[offset + 2u]) << 8u) |
                           static_cast<std::uint32_t>(block_[offset + 3u]);
        }
        for (std::size_t index = 16u; index < words.size(); ++index) {
            const std::uint32_t s0 = rotate_right(words[index - 15u], 7u) ^
                                     rotate_right(words[index - 15u], 18u) ^
                                     (words[index - 15u] >> 3u);
            const std::uint32_t s1 = rotate_right(words[index - 2u], 17u) ^
                                     rotate_right(words[index - 2u], 19u) ^
                                     (words[index - 2u] >> 10u);
            words[index] = words[index - 16u] + s0 + words[index - 7u] + s1;
        }
        std::uint32_t a = state_[0];
        std::uint32_t b = state_[1];
        std::uint32_t c = state_[2];
        std::uint32_t d = state_[3];
        std::uint32_t e = state_[4];
        std::uint32_t f = state_[5];
        std::uint32_t g = state_[6];
        std::uint32_t h = state_[7];
        for (std::size_t index = 0; index < words.size(); ++index) {
            const std::uint32_t sum1 = rotate_right(e, 6u) ^ rotate_right(e, 11u) ^ rotate_right(e, 25u);
            const std::uint32_t choice = (e & f) ^ ((~e) & g);
            const std::uint32_t temporary1 = h + sum1 + choice + kRound[index] + words[index];
            const std::uint32_t sum0 = rotate_right(a, 2u) ^ rotate_right(a, 13u) ^ rotate_right(a, 22u);
            const std::uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
            const std::uint32_t temporary2 = sum0 + majority;
            h = g;
            g = f;
            f = e;
            e = d + temporary1;
            d = c;
            c = b;
            b = a;
            a = temporary1 + temporary2;
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

    std::array<std::uint32_t, 8u> state_{};
    std::array<std::uint8_t, 64u> block_{};
    std::size_t used_ = 0;
    std::uint64_t bits_ = 0;
};

[[nodiscard]] bool hash_retained_file(
    const int fd,
    const ObjectIdentity& expected,
    std::array<std::uint8_t, 32u>* digest) noexcept {
    if (digest == nullptr || ::lseek(fd, 0, SEEK_SET) != 0) {
        return false;
    }
    Sha256 hasher;
    std::array<std::uint8_t, 4096u> buffer{};
    std::uint64_t total = 0;
    for (;;) {
        const ssize_t count = ::read(fd, buffer.data(), buffer.size());
        if (count < 0) {
            if (errno == EINTR) {
                continue;
            }
            return false;
        }
        if (count == 0) {
            break;
        }
        const auto amount = static_cast<std::size_t>(count);
        hasher.update(buffer.data(), amount);
        total += static_cast<std::uint64_t>(amount);
        if (total > kRawObjectSize) {
            return false;
        }
    }
    ObjectIdentity after;
    if (!statx_identity(fd, &after) || !same_object(expected, after) ||
        expected.mode != after.mode || expected.uid != after.uid || expected.gid != after.gid ||
        expected.link_count != after.link_count || expected.size != after.size || total != expected.size) {
        return false;
    }
    *digest = hasher.finish();
    return true;
}

[[nodiscard]] bool same_namespace_identity(const char* first_path, const char* second_path) noexcept {
    struct stat first {};
    struct stat second {};
    return ::stat(first_path, &first) == 0 && ::stat(second_path, &second) == 0 &&
           first.st_dev == second.st_dev && first.st_ino == second.st_ino;
}

[[nodiscard]] bool exact_singleton_topology(const int proc_fd) {
    std::vector<std::uint64_t> pids;
    if (!enumerate_numeric_names(proc_fd, kMaximumCensusPids, &pids) ||
        pids != std::vector<std::uint64_t>{1u}) {
        return false;
    }
    const OwnedFd task_fd(::openat(proc_fd, "1/task", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
    if (!task_fd.valid()) {
        return false;
    }
    std::vector<std::uint64_t> tids;
    return enumerate_numeric_names(task_fd.get(), kMaximumCensusTidsPerPid, &tids) &&
           tids == std::vector<std::uint64_t>{1u};
}

}  // namespace

bool validate_stage1_mountinfo_v1(
    const std::string_view bytes,
    const Stage1MountExpectationV1& expected,
    Stage1MountInfoV1* observed,
    const char** error_code) noexcept {
    const auto reject = [error_code](const char* code) noexcept {
        if (error_code != nullptr) {
            *error_code = code;
        }
        return false;
    };
    if (observed == nullptr || bytes.empty() || bytes.size() > kMaximumMountInfoBytes ||
        bytes.find('\0') != std::string_view::npos || bytes.back() != '\n') {
        return reject("STAGE1_MOUNTINFO_BYTES_INVALID");
    }
    std::size_t root_matches = 0;
    std::size_t proc_matches = 0;
    Stage1MountInfoV1 result;
    std::size_t start = 0;
    while (start < bytes.size()) {
        const std::size_t newline = bytes.find('\n', start);
        if (newline == std::string_view::npos || newline == start) {
            return reject("STAGE1_MOUNTINFO_LINE_INVALID");
        }
        ParsedMountLine row;
        if (!parse_mount_line(bytes.substr(start, newline - start), &row)) {
            return reject("STAGE1_MOUNTINFO_LINE_INVALID");
        }
        if (row.mount_id == expected.root_mount_id) {
            ++root_matches;
            if (row.device_major != expected.root_device_major ||
                row.device_minor != expected.root_device_minor ||
                (expected.root_parent_mount_id != 0u &&
                 row.parent_mount_id != expected.root_parent_mount_id) ||
                !root_mount_is_accepted(row)) {
                return reject("STAGE1_ROOT_MOUNT_REJECTED");
            }
            result.root_mount_id = row.mount_id;
            result.root_parent_mount_id = row.parent_mount_id;
        }
        if (row.mount_point == "/proc") {
            ++proc_matches;
            if (row.mount_id != expected.proc_mount_id ||
                row.device_major != expected.proc_device_major ||
                row.device_minor != expected.proc_device_minor ||
                !proc_mount_is_accepted(row)) {
                return reject("STAGE1_PROC_MOUNT_REJECTED");
            }
            result.proc_mount_id = row.mount_id;
        }
        start = newline + 1u;
    }
    if (root_matches != 1u) {
        return reject("STAGE1_ROOT_MOUNT_CARDINALITY_INVALID");
    }
    if (proc_matches != 1u) {
        return reject("STAGE1_PROC_MOUNT_CARDINALITY_INVALID");
    }
    *observed = result;
    if (error_code != nullptr) {
        *error_code = nullptr;
    }
    return true;
}

bool parse_stage1_proc_stat_starttime_v1(
    const std::string_view bytes,
    const std::uint64_t expected_pid,
    std::uint64_t* starttime,
    const char** error_code) noexcept {
    const auto reject = [error_code](const char* code) noexcept {
        if (error_code != nullptr) {
            *error_code = code;
        }
        return false;
    };
    if (expected_pid == 0u || starttime == nullptr || bytes.empty() ||
        bytes.size() > kMaximumProcFileBytes || bytes.find('\0') != std::string_view::npos ||
        bytes.back() != '\n' || bytes.substr(0u, bytes.size() - 1u).find('\n') != std::string_view::npos) {
        return reject("STAGE1_PROC_STAT_BYTES_INVALID");
    }
    std::string_view row = bytes.substr(0u, bytes.size() - 1u);
    const std::size_t first_space = row.find(' ');
    if (first_space == std::string_view::npos || first_space == 0u) {
        return reject("STAGE1_PROC_STAT_SYNTAX_INVALID");
    }
    std::uint64_t parsed_pid = 0;
    const std::string_view pid_token = row.substr(0u, first_space);
    if ((pid_token.size() > 1u && pid_token.front() == '0') ||
        !parse_decimal(pid_token, &parsed_pid) || parsed_pid != expected_pid ||
        row.size() <= first_space + 4u || row[first_space + 1u] != '(') {
        return reject("STAGE1_PROC_STAT_PID_INVALID");
    }
    const std::size_t close = row.rfind(") ");
    if (close == std::string_view::npos || close <= first_space + 1u ||
        close + 3u >= row.size()) {
        return reject("STAGE1_PROC_STAT_SYNTAX_INVALID");
    }
    const char state = row[close + 2u];
    if (state == ' ' || state == '\t' || state == '\r' || state == '\n' ||
        row[close + 3u] != ' ') {
        return reject("STAGE1_PROC_STAT_SYNTAX_INVALID");
    }
    std::string_view numeric_fields = row.substr(close + 4u);
    for (std::size_t index = 0u; index < 19u; ++index) {
        const std::size_t end = numeric_fields.find(' ');
        const std::string_view token =
            end == std::string_view::npos ? numeric_fields : numeric_fields.substr(0u, end);
        if (token.empty()) {
            return reject("STAGE1_PROC_STAT_SYNTAX_INVALID");
        }
        if (index == 18u) {
            std::uint64_t parsed_starttime = 0;
            if (!parse_decimal(token, &parsed_starttime) || parsed_starttime == 0u) {
                return reject("STAGE1_PROC_STAT_STARTTIME_INVALID");
            }
            *starttime = parsed_starttime;
            if (error_code != nullptr) {
                *error_code = nullptr;
            }
            return true;
        }
        if (!parse_proc_integer_token(token)) {
            return reject("STAGE1_PROC_STAT_FIELD_INVALID");
        }
        if (end == std::string_view::npos) {
            return reject("STAGE1_PROC_STAT_FIELD_COUNT_INVALID");
        }
        numeric_fields.remove_prefix(end + 1u);
    }
    return reject("STAGE1_PROC_STAT_FIELD_COUNT_INVALID");
}

bool validate_stage1_prelaunch_census_pair_v1(
    const Stage1ProcessCensusV1& first,
    const Stage1ProcessCensusV1& second,
    const Stage1CwdIdentityV1& root_cwd,
    const Stage1CwdIdentityV1& extraction_cwd,
    const char** error_code) noexcept {
    const auto reject = [error_code](const char* code) noexcept {
        if (error_code != nullptr) {
            *error_code = code;
        }
        return false;
    };
    if (root_cwd == extraction_cwd || !exact_prelaunch_census_shape(first, root_cwd, extraction_cwd) ||
        !exact_prelaunch_census_shape(second, root_cwd, extraction_cwd)) {
        return reject("STAGE1_PRELAUNCH_CENSUS_INVALID");
    }
    if (first != second) {
        return reject("STAGE1_PRELAUNCH_CENSUS_MISMATCH");
    }
    if (error_code != nullptr) {
        *error_code = nullptr;
    }
    return true;
}

bool validate_stage1_ready_status_v1(
    const std::string_view bytes,
    const std::uint64_t expected_final_nspid,
    const char** error_code) noexcept {
    const auto reject = [error_code](const char* code) noexcept {
        if (error_code != nullptr) {
            *error_code = code;
        }
        return false;
    };
    if (expected_final_nspid == 0u || bytes.empty() ||
        bytes.size() > kMaximumProcFileBytes || bytes.find('\0') != std::string_view::npos ||
        bytes.back() != '\n') {
        return reject("STAGE1_READY_STATUS_BYTES_INVALID");
    }
    std::size_t tgid_count = 0u;
    std::size_t pid_count = 0u;
    std::size_t nspid_count = 0u;
    std::size_t threads_count = 0u;
    std::size_t no_new_privs_count = 0u;
    std::size_t seccomp_count = 0u;
    std::size_t start = 0u;
    while (start < bytes.size()) {
        const std::size_t newline = bytes.find('\n', start);
        if (newline == std::string_view::npos || newline == start) {
            return reject("STAGE1_READY_STATUS_SYNTAX_INVALID");
        }
        const std::string_view line = bytes.substr(start, newline - start);
        std::uint64_t value = 0u;
        if (line.starts_with("Tgid:")) {
            ++tgid_count;
            if (!parse_status_scalar(line.substr(5u), &value) ||
                value != expected_final_nspid) {
                return reject("STAGE1_READY_STATUS_TGID_INVALID");
            }
        } else if (line.starts_with("Pid:")) {
            ++pid_count;
            if (!parse_status_scalar(line.substr(4u), &value) ||
                value != expected_final_nspid) {
                return reject("STAGE1_READY_STATUS_PID_INVALID");
            }
        } else if (line.starts_with("NSpid:")) {
            ++nspid_count;
            if (!parse_status_sequence_last(line.substr(6u), &value) ||
                value != expected_final_nspid) {
                return reject("STAGE1_READY_STATUS_NSPID_INVALID");
            }
        } else if (line.starts_with("Threads:")) {
            ++threads_count;
            if (!parse_status_scalar(line.substr(8u), &value) || value != 1u) {
                return reject("STAGE1_READY_STATUS_THREADS_INVALID");
            }
        } else if (line.starts_with("NoNewPrivs:")) {
            ++no_new_privs_count;
            if (!parse_status_scalar(line.substr(11u), &value) || value != 1u) {
                return reject("STAGE1_READY_STATUS_NO_NEW_PRIVS_INVALID");
            }
        } else if (line.starts_with("Seccomp:")) {
            ++seccomp_count;
            if (!parse_status_scalar(line.substr(8u), &value) || value != 2u) {
                return reject("STAGE1_READY_STATUS_SECCOMP_INVALID");
            }
        }
        start = newline + 1u;
    }
    if (tgid_count != 1u || pid_count != 1u || nspid_count != 1u ||
        threads_count != 1u || no_new_privs_count != 1u || seccomp_count != 1u) {
        return reject("STAGE1_READY_STATUS_FIELDS_INVALID");
    }
    if (error_code != nullptr) {
        *error_code = nullptr;
    }
    return true;
}

bool validate_stage1_barrier_census_pair_v1(
    const Stage1ProcessCensusV1& first,
    const Stage1ProcessCensusV1& second,
    const Stage1CwdIdentityV1& root_cwd,
    const Stage1CwdIdentityV1& extraction_cwd,
    const std::uint64_t expected_pid1_starttime,
    const std::uint64_t expected_pid2_starttime,
    const char** error_code) noexcept {
    const auto reject = [error_code](const char* code) noexcept {
        if (error_code != nullptr) {
            *error_code = code;
        }
        return false;
    };
    if (!exact_barrier_census_shape(
            first,
            root_cwd,
            extraction_cwd,
            expected_pid1_starttime,
            expected_pid2_starttime) ||
        !exact_barrier_census_shape(
            second,
            root_cwd,
            extraction_cwd,
            expected_pid1_starttime,
            expected_pid2_starttime)) {
        return reject("STAGE1_BARRIER_CENSUS_INVALID");
    }
    if (first != second) {
        return reject("STAGE1_BARRIER_CENSUS_MISMATCH");
    }
    if (error_code != nullptr) {
        *error_code = nullptr;
    }
    return true;
}

bool validate_stage1_postexit_census_pair_v1(
    const Stage1ProcessCensusV1& first,
    const Stage1ProcessCensusV1& second,
    const Stage1CwdIdentityV1& root_cwd,
    const Stage1CwdIdentityV1& extraction_cwd,
    const std::uint64_t expected_pid1_starttime,
    const char** error_code) noexcept {
    const auto reject = [error_code](const char* code) noexcept {
        if (error_code != nullptr) {
            *error_code = code;
        }
        return false;
    };
    if (!exact_postexit_census_shape(
            first, root_cwd, extraction_cwd, expected_pid1_starttime) ||
        !exact_postexit_census_shape(
            second, root_cwd, extraction_cwd, expected_pid1_starttime)) {
        return reject("STAGE1_POSTEXIT_CENSUS_INVALID");
    }
    if (first != second) {
        return reject("STAGE1_POSTEXIT_CENSUS_MISMATCH");
    }
    if (error_code != nullptr) {
        *error_code = nullptr;
    }
    return true;
}

int run_stage1_extraction_custodian_v1(
    const int argc,
    char** argv,
    char** envp) noexcept {
    if (argc != 1 || argv == nullptr || argv[0] == nullptr || argv[1] != nullptr ||
        std::strcmp(argv[0], kExpectedArgv0) != 0 || envp == nullptr || envp[0] != nullptr) {
        write_error("STAGE1_CUSTODIAN_INVOCATION_INVALID");
        return kExitInvocation;
    }
    if (::getpid() != 1 || ::syscall(SYS_gettid) != 1) {
        write_error("STAGE1_CUSTODIAN_PID1_REQUIRED");
        return kExitTopology;
    }

    const OwnedFd proc_fd(::open("/proc", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
    if (!proc_fd.valid() || !exact_singleton_topology(proc_fd.get())) {
        write_error("STAGE1_CUSTODIAN_INITIAL_TOPOLOGY_INVALID");
        return kExitTopology;
    }

    const auto build_uid_pre = static_cast<std::uint32_t>(::geteuid());
    const auto build_gid_pre = static_cast<std::uint32_t>(::getegid());

    const OwnedFd root_fd(::open("/", O_PATH | O_DIRECTORY | O_CLOEXEC));
    if (!root_fd.valid()) {
        write_error("STAGE1_ROOT_OPEN_FAILED");
        return kExitMountCustody;
    }
    constexpr std::uint64_t kResolve =
        RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV;
    const long extraction_raw = raw_openat2(
        root_fd.get(),
        kExtractionRelativePath,
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW,
        kResolve);
    if (extraction_raw < 0 || extraction_raw > INT_MAX) {
        const int open_error = errno;
        write_error(
            extraction_raw < 0 && (open_error == ENOSYS || open_error == EINVAL)
                ? "STAGE1_EXTRACTION_OPENAT2_KERNEL_UNAVAILABLE"
                : "STAGE1_EXTRACTION_OPENAT2_FAILED");
        return kExitMountCustody;
    }
    const OwnedFd extraction_fd(static_cast<int>(extraction_raw));
    ObjectIdentity root_identity;
    ObjectIdentity extraction_identity;
    ObjectIdentity proc_identity;
    ObjectIdentity cwd_identity;
    FilesystemIdentity root_filesystem;
    FilesystemIdentity extraction_filesystem;
    FilesystemIdentity proc_filesystem;
    if (!statx_identity(root_fd.get(), &root_identity) ||
        !statx_identity(extraction_fd.get(), &extraction_identity) ||
        !statx_identity(proc_fd.get(), &proc_identity) ||
        !statx_identity(AT_FDCWD, &cwd_identity) ||
        !filesystem_identity(root_fd.get(), &root_filesystem) ||
        !filesystem_identity(extraction_fd.get(), &extraction_filesystem) ||
        !filesystem_identity(proc_fd.get(), &proc_filesystem)) {
        write_error("STAGE1_STATX_OR_STATFS_FAILED");
        return kExitMountCustody;
    }
    if (!same_object(root_identity, cwd_identity) ||
        root_identity.mount_id != extraction_identity.mount_id ||
        root_identity.device_major != extraction_identity.device_major ||
        root_identity.device_minor != extraction_identity.device_minor ||
        root_filesystem.type != kOverlayMagic || extraction_filesystem.type != kOverlayMagic ||
        root_filesystem.fsid != extraction_filesystem.fsid ||
        (root_filesystem.flags & ST_RDONLY) != 0u ||
        (extraction_filesystem.flags & ST_RDONLY) != 0u ||
        proc_filesystem.type != kProcMagic ||
        extraction_identity.mode != (S_IFDIR | 0700u) ||
        extraction_identity.uid != build_uid_pre || extraction_identity.gid != build_gid_pre) {
        write_error("STAGE1_MOUNT_OR_DIRECTORY_PROFILE_INVALID");
        return kExitMountCustody;
    }

    std::string mountinfo;
    if (!read_bounded_file("/proc/self/mountinfo", kMaximumMountInfoBytes, &mountinfo)) {
        write_error("STAGE1_MOUNTINFO_READ_FAILED");
        return kExitMountCustody;
    }
    Stage1MountExpectationV1 mount_expectation;
    mount_expectation.root_mount_id = root_identity.mount_id;
    mount_expectation.root_device_major = root_identity.device_major;
    mount_expectation.root_device_minor = root_identity.device_minor;
    mount_expectation.proc_mount_id = proc_identity.mount_id;
    mount_expectation.proc_device_major = proc_identity.device_major;
    mount_expectation.proc_device_minor = proc_identity.device_minor;
    Stage1MountInfoV1 mount_observed;
    const char* mount_error = nullptr;
    if (!validate_stage1_mountinfo_v1(mountinfo, mount_expectation, &mount_observed, &mount_error)) {
        write_error(mount_error == nullptr ? "STAGE1_MOUNTINFO_REJECTED" : mount_error);
        return kExitMountCustody;
    }

    if (!same_namespace_identity("/proc/self/ns/pid", "/proc/1/ns/pid") ||
        !same_namespace_identity("/proc/self/ns/mnt", "/proc/1/ns/mnt")) {
        write_error("STAGE1_NAMESPACE_IDENTITY_INVALID");
        return kExitNamespace;
    }
    std::string status;
    if (!read_bounded_file("/proc/self/status", kMaximumProcFileBytes, &status) ||
        !parse_final_nspid_is_one(status)) {
        write_error("STAGE1_NSPID_INVALID");
        return kExitNamespace;
    }
    if (!reset_and_block_signals() || !exact_singleton_topology(proc_fd.get())) {
        write_error("STAGE1_SINGLETON_TOPOLOGY_INVALID");
        return kExitTopology;
    }

    if (!directory_contains_only_raw_object(extraction_fd.get())) {
        write_error("STAGE1_EXTRACTION_DIRECTORY_NOT_FRESH");
        return kExitRawObject;
    }
    const long raw_object_raw = raw_openat2(
        extraction_fd.get(),
        kRawObjectName,
        O_RDONLY | O_CLOEXEC | O_NOFOLLOW,
        kResolve);
    if (raw_object_raw < 0 || raw_object_raw > INT_MAX) {
        write_error("STAGE1_RAW_OBJECT_OPENAT2_FAILED");
        return kExitRawObject;
    }
    const OwnedFd raw_object_fd(static_cast<int>(raw_object_raw));
    ObjectIdentity raw_object_identity;
    if (!statx_identity(raw_object_fd.get(), &raw_object_identity) ||
        raw_object_identity.mode != (S_IFREG | 0444u) ||
        raw_object_identity.uid != build_uid_pre || raw_object_identity.gid != build_gid_pre ||
        raw_object_identity.link_count != 1u || raw_object_identity.size != kRawObjectSize) {
        write_error("STAGE1_RAW_OBJECT_PROFILE_INVALID");
        return kExitRawObject;
    }
    if (raw_object_identity.mount_id != extraction_identity.mount_id ||
        raw_object_identity.device_major != extraction_identity.device_major ||
        raw_object_identity.device_minor != extraction_identity.device_minor) {
        write_error("STAGE1_RAW_OBJECT_MOUNT_INVALID");
        return kExitRawObject;
    }
    std::array<std::uint8_t, 32u> raw_digest{};
    if (!hash_retained_file(raw_object_fd.get(), raw_object_identity, &raw_digest) ||
        raw_digest != kRawObjectSha256) {
        write_error("STAGE1_RAW_OBJECT_HASH_INVALID");
        return kExitRawObject;
    }

    ObjectIdentity root_census_identity;
    if (!statx_identity(root_fd.get(), &root_census_identity) ||
        !same_identity(root_identity, root_census_identity)) {
        write_error("STAGE1_ROOT_PRE_CENSUS_REAUTHENTICATION_FAILED");
        return kExitMountCustody;
    }
    ProcessCensus pre_census_1;
    ProcessCensus pre_census_2;
    const CwdIdentity root_cwd = cwd_identity_from_object(root_census_identity);
    const CwdIdentity extraction_cwd = cwd_identity_from_object(extraction_identity);
    if (!capture_process_census(proc_fd.get(), &pre_census_1) ||
        !capture_process_census(proc_fd.get(), &pre_census_2)) {
        write_error("STAGE1_PRELAUNCH_CENSUS_CAPTURE_FAILED");
        return kExitTopology;
    }
    const char* census_error = nullptr;
    if (!validate_stage1_prelaunch_census_pair_v1(
            pre_census_1,
            pre_census_2,
            root_cwd,
            extraction_cwd,
            &census_error)) {
        write_error(census_error == nullptr ? "STAGE1_PRELAUNCH_CENSUS_REJECTED" : census_error);
        return kExitTopology;
    }

    const long environment_raw = raw_openat2(
        root_fd.get(),
        kEnvironmentRelativePath,
        O_PATH | O_CLOEXEC | O_NOFOLLOW,
        kResolve);
    if (environment_raw < 0 || environment_raw > INT_MAX) {
        write_error("STAGE1_ENVIRONMENT_EXECUTABLE_OPEN_FAILED");
        return kExitChildGate;
    }
    const OwnedFd environment_fd(static_cast<int>(environment_raw));
    ObjectIdentity environment_identity;
    if (!statx_identity(environment_fd.get(), &environment_identity) ||
        (environment_identity.mode & S_IFMT) != S_IFREG ||
        (environment_identity.mode & 0111u) == 0u) {
        write_error("STAGE1_ENVIRONMENT_EXECUTABLE_PROFILE_INVALID");
        return kExitChildGate;
    }

    sock_fprog seccomp_program;
    std::string proc_maps;
    if (!initialize_stage1_seccomp_program_v1(&seccomp_program) ||
        !read_bounded_file("/proc/self/maps", kMaximumProcMapsBytes, &proc_maps) ||
        !validate_stage1_seccomp_program_mapping_v1(&seccomp_program, proc_maps)) {
        write_error("STAGE1_SECCOMP_PROGRAM_OR_MAPPING_INVALID");
        return kExitChildGate;
    }

    const char* const extraction_argv[] = {
        kExtractionArgv0,
        kExtractionArgv1,
        kEnvironmentPath,
        kEnvironmentLcAll,
        kEnvironmentLang,
        kEnvironmentTimezone,
        kEnvironmentEpoch,
        kEnvironmentHome,
        kEnvironmentDebuginfod,
        kObjcopyPath,
        kObjcopyInputTarget,
        kObjcopyOutputTarget,
        kObjcopyDumpSection,
        kObjcopySectionAssignment,
        kRawObjectName,
        kObjcopyDiscardName,
        nullptr,
    };
    const char* const extraction_envp[] = {
        kEnvironmentPath,
        kEnvironmentLcAll,
        kEnvironmentLang,
        kEnvironmentTimezone,
        kEnvironmentEpoch,
        kEnvironmentHome,
        kEnvironmentDebuginfod,
        nullptr,
    };
    static_assert(std::size(extraction_argv) == 17u);
    static_assert(std::size(extraction_envp) == 8u);

    PipePair control_pipe;
    PipePair ready_pipe;
    PipePair stdout_pipe;
    PipePair stderr_pipe;
    if (!create_cloexec_pipe(&control_pipe) || !create_cloexec_pipe(&ready_pipe) ||
        !create_cloexec_pipe(&stdout_pipe) || !create_cloexec_pipe(&stderr_pipe)) {
        write_error("STAGE1_CHILD_PIPE_CREATION_FAILED");
        return kExitChildGate;
    }
    const OwnedFd saved_stdout(::fcntl(STDOUT_FILENO, F_DUPFD_CLOEXEC, 3));
    const OwnedFd saved_stderr(::fcntl(STDERR_FILENO, F_DUPFD_CLOEXEC, 3));
    if (!saved_stdout.valid() || !saved_stderr.valid()) {
        write_error("STAGE1_STANDARD_DESCRIPTOR_DUPLICATION_FAILED");
        return kExitChildGate;
    }

    Stage1ExtractionChildGateResultV1 child_result{};
    clone_args child_clone_args{};
    child_clone_args.flags = CLONE_PIDFD;
    child_clone_args.pidfd = static_cast<std::uint64_t>(
        reinterpret_cast<std::uintptr_t>(&child_result.pidfd));
    child_clone_args.exit_signal = static_cast<std::uint64_t>(SIGCHLD);
    std::uint8_t child_byte = 0u;
    struct statx child_statx {};
    Stage1ExtractionChildGateInputV1 child_input{};
    child_input.clone_args = &child_clone_args;
    child_input.clone_args_size = sizeof(child_clone_args);
    child_input.control_read_fd = control_pipe.read.get();
    child_input.control_write_fd = control_pipe.write.get();
    child_input.ready_read_fd = ready_pipe.read.get();
    child_input.ready_write_fd = ready_pipe.write.get();
    child_input.stdout_read_fd = stdout_pipe.read.get();
    child_input.stderr_read_fd = stderr_pipe.read.get();
    child_input.parent_receipt_saved_fd = saved_stdout.get();
    child_input.parent_diagnostic_saved_fd = saved_stderr.get();
    child_input.extraction_directory_fd = extraction_fd.get();
    child_input.environment_executable_fd = environment_fd.get();
    child_input.one_byte_buffer = &child_byte;
    child_input.statx_buffer = &child_statx;
    child_input.empty_path = kEmptyPath;
    child_input.seccomp_program = &seccomp_program;
    child_input.extraction_argv = extraction_argv;
    child_input.extraction_envp = extraction_envp;
    child_input.expected_mount_id = extraction_identity.mount_id;
    child_input.expected_inode = extraction_identity.inode;
    child_input.expected_device_major =
        static_cast<std::uint32_t>(extraction_identity.device_major);
    child_input.expected_device_minor =
        static_cast<std::uint32_t>(extraction_identity.device_minor);

    if (::dup3(stdout_pipe.write.get(), STDOUT_FILENO, 0) != STDOUT_FILENO) {
        write_error("STAGE1_CHILD_STDOUT_REDIRECTION_FAILED");
        return kExitChildGate;
    }
    if (::dup3(stderr_pipe.write.get(), STDERR_FILENO, 0) != STDERR_FILENO) {
        (void)::dup3(saved_stdout.get(), STDOUT_FILENO, 0);
        write_error("STAGE1_CHILD_STDERR_REDIRECTION_FAILED");
        return kExitChildGate;
    }
    if (!stdout_pipe.write.reset() || !stderr_pipe.write.reset()) {
        (void)::dup3(saved_stderr.get(), STDERR_FILENO, 0);
        (void)::dup3(saved_stdout.get(), STDOUT_FILENO, 0);
        write_error("STAGE1_CHILD_OUTPUT_DUPLICATE_CLOSE_FAILED");
        return kExitChildGate;
    }

    const long gate_return =
        stage1_extraction_child_gate_v1(&child_input, &child_result);

    const bool stderr_restored =
        ::dup3(saved_stderr.get(), STDERR_FILENO, 0) == STDERR_FILENO;
    const bool stdout_restored =
        ::dup3(saved_stdout.get(), STDOUT_FILENO, 0) == STDOUT_FILENO;
    const bool control_child_end_closed = control_pipe.read.reset();
    const bool ready_child_end_closed = ready_pipe.write.reset();

    const auto terminate_and_reap = [&child_result]() noexcept {
        if (child_result.pidfd < 0 || child_result.child_pid <= 0) {
            immediate_pid1_exit();
        }
        timespec kill_deadline{};
        const char* deadline_error = nullptr;
        if (!make_stage1_pidfd_monotonic_deadline_v1(
                kKillReapDeadlineMilliseconds,
                &kill_deadline,
                &deadline_error)) {
            immediate_pid1_exit();
        }
        Stage1PidfdChildLifecycleRequestV1 request{};
        request.pidfd = child_result.pidfd;
        request.expected_pid = child_result.child_pid;
        request.absolute_deadline = kill_deadline;
        request.expectation = Stage1PidfdTerminalExpectationV1::KilledBySigkill;
        request.send_sigkill = true;
        Stage1PidfdChildLifecycleResultV1 lifecycle_result{};
        const char* lifecycle_error = nullptr;
        if (!run_stage1_pidfd_child_lifecycle_v1(
                request,
                &lifecycle_result,
                &lifecycle_error) ||
            lifecycle_result.requires_immediate_pid1_exit ||
            !lifecycle_result.inspected || !lifecycle_result.reaped ||
            !lifecycle_result.pidfd_closed) {
            immediate_pid1_exit();
        }
        child_result.pidfd = -1;
    };

    const bool positive_child = gate_return > 0;
    if (!stderr_restored || !stdout_restored || !control_child_end_closed ||
        !ready_child_end_closed) {
        if (positive_child) {
            terminate_and_reap();
        }
        immediate_pid1_exit();
    }
    if (gate_return != child_result.clone_return) {
        if (positive_child) {
            terminate_and_reap();
        }
        write_error("STAGE1_CHILD_GATE_RETURN_MISMATCH");
        return kExitChildGate;
    }
    if (gate_return < 0) {
        if (child_result.parent_outcome != 2u || child_result.child_pid != -1 ||
            child_result.pidfd != -1 || child_result.reserved != 0u) {
            write_error("STAGE1_CHILD_GATE_NO_CHILD_RESULT_INVALID");
            return kExitChildGate;
        }
        if (gate_return == -ENOSYS) {
            write_error("STAGE1_CHILD_GATE_CLONE3_UNSUPPORTED_ENOSYS");
            return kExitIncomplete;
        }
        if (gate_return == -EINVAL) {
            write_error("STAGE1_CHILD_GATE_CLONE_PIDFD_UNSUPPORTED_EINVAL");
            return kExitIncomplete;
        }
        write_error("STAGE1_CHILD_GATE_CLONE3_FAILED");
        return kExitChildGate;
    }
    if (!positive_child || child_result.parent_outcome != 1u ||
        child_result.reserved != 0u || child_result.child_pid != gate_return ||
        child_result.child_pid != 2 || child_result.pidfd < 0) {
        if (positive_child && child_result.pidfd >= 0 && child_result.child_pid > 0) {
            terminate_and_reap();
        }
        immediate_pid1_exit();
    }

    const auto fail_after_child = [&terminate_and_reap](
                                      const char* const error,
                                      const int exit_code) noexcept {
        terminate_and_reap();
        write_error(error);
        return exit_code;
    };

    std::uint64_t pid2_starttime = 0u;
    if (!bind_pid2_starttime_and_single_task(proc_fd.get(), &pid2_starttime)) {
        return fail_after_child("STAGE1_PID2_PRE_RELEASE_BINDING_FAILED", kExitReadyBarrier);
    }
    timespec ready_deadline{};
    const char* ready_deadline_error = nullptr;
    if (!make_stage1_pidfd_monotonic_deadline_v1(
            kReadyDeadlineMilliseconds,
            &ready_deadline,
            &ready_deadline_error) ||
        !write_one_byte_until(control_pipe.write.get(), kChildReleaseByte, ready_deadline) ||
        !read_exact_byte_until(ready_pipe.read.get(), kChildReadyByte, ready_deadline)) {
        return fail_after_child("STAGE1_CHILD_READY_HANDSHAKE_FAILED", kExitReadyBarrier);
    }

    std::string child_status;
    const char* child_status_error = nullptr;
    if (!read_bounded_file_at(
            proc_fd.get(), "2/status", kMaximumProcFileBytes, &child_status) ||
        !validate_stage1_ready_status_v1(
            child_status, 2u, &child_status_error)) {
        return fail_after_child(
            child_status_error == nullptr
                ? "STAGE1_CHILD_READY_STATUS_REJECTED"
                : child_status_error,
            kExitReadyBarrier);
    }
    std::uint64_t pid2_ready_starttime = 0u;
    if (!bind_pid2_starttime_and_single_task(proc_fd.get(), &pid2_ready_starttime) ||
        pid2_ready_starttime != pid2_starttime) {
        return fail_after_child("STAGE1_PID2_STARTTIME_CHANGED", kExitReadyBarrier);
    }

    const long extraction_barrier_path_raw = raw_openat2(
        root_fd.get(),
        kExtractionRelativePath,
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW,
        kResolve);
    if (extraction_barrier_path_raw < 0 || extraction_barrier_path_raw > INT_MAX) {
        return fail_after_child(
            "STAGE1_BARRIER_EXTRACTION_PATH_REOPEN_FAILED", kExitReadyBarrier);
    }
    const OwnedFd extraction_barrier_path_fd(
        static_cast<int>(extraction_barrier_path_raw));
    const long raw_object_barrier_path_raw = raw_openat2(
        extraction_barrier_path_fd.get(),
        kRawObjectName,
        O_RDONLY | O_CLOEXEC | O_NOFOLLOW,
        kResolve);
    if (raw_object_barrier_path_raw < 0 || raw_object_barrier_path_raw > INT_MAX) {
        return fail_after_child(
            "STAGE1_BARRIER_RAW_OBJECT_PATH_REOPEN_FAILED", kExitReadyBarrier);
    }
    const OwnedFd raw_object_barrier_path_fd(
        static_cast<int>(raw_object_barrier_path_raw));
    const OwnedFd pid2_cwd_fd(
        ::openat(proc_fd.get(), "2/task/2/cwd", O_PATH | O_DIRECTORY | O_CLOEXEC));
    ObjectIdentity pid2_cwd_identity;
    ObjectIdentity root_barrier_identity;
    ObjectIdentity extraction_barrier_identity;
    ObjectIdentity extraction_barrier_path_identity;
    ObjectIdentity raw_object_barrier_identity;
    FilesystemIdentity root_barrier_filesystem;
    FilesystemIdentity extraction_barrier_filesystem;
    std::array<std::uint8_t, 32u> raw_barrier_digest{};
    if (!pid2_cwd_fd.valid() ||
        !statx_identity(pid2_cwd_fd.get(), &pid2_cwd_identity) ||
        !statx_identity(root_fd.get(), &root_barrier_identity) ||
        !statx_identity(extraction_fd.get(), &extraction_barrier_identity) ||
        !statx_identity(
            extraction_barrier_path_fd.get(), &extraction_barrier_path_identity) ||
        !statx_identity(raw_object_barrier_path_fd.get(), &raw_object_barrier_identity) ||
        !filesystem_identity(root_fd.get(), &root_barrier_filesystem) ||
        !filesystem_identity(
            extraction_barrier_path_fd.get(), &extraction_barrier_filesystem) ||
        !hash_retained_file(
            raw_object_barrier_path_fd.get(),
            raw_object_barrier_identity,
            &raw_barrier_digest) ||
        !same_identity(pid2_cwd_identity, extraction_identity) ||
        !same_identity(root_barrier_identity, root_identity) ||
        !same_identity(extraction_barrier_identity, extraction_identity) ||
        !same_identity(extraction_barrier_path_identity, extraction_identity) ||
        !same_identity(raw_object_barrier_identity, raw_object_identity) ||
        !same_filesystem_identity(root_barrier_filesystem, root_filesystem) ||
        !same_filesystem_identity(
            extraction_barrier_filesystem, extraction_filesystem) ||
        raw_barrier_digest != kRawObjectSha256 ||
        !directory_contains_only_raw_object(extraction_barrier_path_fd.get())) {
        return fail_after_child("STAGE1_BARRIER_OBJECT_REAUTHENTICATION_FAILED", kExitReadyBarrier);
    }
    std::string barrier_mountinfo;
    Stage1MountInfoV1 barrier_mount_observed;
    const char* barrier_mount_error = nullptr;
    if (!read_bounded_file(
            "/proc/self/mountinfo", kMaximumMountInfoBytes, &barrier_mountinfo) ||
        !validate_stage1_mountinfo_v1(
            barrier_mountinfo,
            mount_expectation,
            &barrier_mount_observed,
            &barrier_mount_error) ||
        barrier_mount_observed.root_mount_id != mount_observed.root_mount_id ||
        barrier_mount_observed.root_parent_mount_id !=
            mount_observed.root_parent_mount_id ||
        barrier_mount_observed.proc_mount_id != mount_observed.proc_mount_id) {
        return fail_after_child(
            barrier_mount_error == nullptr
                ? "STAGE1_BARRIER_MOUNT_REAUTHENTICATION_FAILED"
                : barrier_mount_error,
            kExitReadyBarrier);
    }

    ProcessCensus barrier_census_1;
    ProcessCensus barrier_census_2;
    const char* barrier_census_error = nullptr;
    const std::uint64_t pid1_starttime = pre_census_1[0].starttime;
    if (!capture_process_census(proc_fd.get(), &barrier_census_1) ||
        !capture_process_census(proc_fd.get(), &barrier_census_2) ||
        !validate_stage1_barrier_census_pair_v1(
            barrier_census_1,
            barrier_census_2,
            root_cwd,
            extraction_cwd,
            pid1_starttime,
            pid2_starttime,
            &barrier_census_error)) {
        return fail_after_child(
            barrier_census_error == nullptr
                ? "STAGE1_BARRIER_CENSUS_REJECTED"
                : barrier_census_error,
            kExitReadyBarrier);
    }

    // Compile-time-fixed stop-after-ready boundary: byte 0x43 is never sent.
    terminate_and_reap();
    if (!control_pipe.write.reset() ||
        !pipe_is_empty_after_child_exit(ready_pipe.read.get()) ||
        !pipe_is_empty_after_child_exit(stdout_pipe.read.get()) ||
        !pipe_is_empty_after_child_exit(stderr_pipe.read.get())) {
        write_error("STAGE1_POST_REAP_PIPE_STATE_INVALID");
        return kExitReadyBarrier;
    }

    ObjectIdentity root_post_identity;
    ObjectIdentity extraction_post_identity;
    ObjectIdentity extraction_post_path_identity;
    ObjectIdentity raw_object_post_identity;
    ObjectIdentity raw_object_post_path_identity;
    FilesystemIdentity root_post_filesystem;
    FilesystemIdentity extraction_post_filesystem;
    std::array<std::uint8_t, 32u> raw_post_digest{};
    std::array<std::uint8_t, 32u> raw_post_path_digest{};
    const long extraction_post_path_raw = raw_openat2(
        root_fd.get(),
        kExtractionRelativePath,
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW,
        kResolve);
    if (extraction_post_path_raw < 0 || extraction_post_path_raw > INT_MAX) {
        write_error("STAGE1_POST_REAP_EXTRACTION_PATH_REOPEN_FAILED");
        return kExitReadyBarrier;
    }
    const OwnedFd extraction_post_path_fd(static_cast<int>(extraction_post_path_raw));
    const long raw_object_post_path_raw = raw_openat2(
        extraction_post_path_fd.get(),
        kRawObjectName,
        O_RDONLY | O_CLOEXEC | O_NOFOLLOW,
        kResolve);
    if (raw_object_post_path_raw < 0 || raw_object_post_path_raw > INT_MAX) {
        write_error("STAGE1_POST_REAP_RAW_OBJECT_PATH_REOPEN_FAILED");
        return kExitReadyBarrier;
    }
    const OwnedFd raw_object_post_path_fd(static_cast<int>(raw_object_post_path_raw));
    if (!statx_identity(root_fd.get(), &root_post_identity) ||
        !statx_identity(extraction_fd.get(), &extraction_post_identity) ||
        !statx_identity(extraction_post_path_fd.get(), &extraction_post_path_identity) ||
        !statx_identity(raw_object_fd.get(), &raw_object_post_identity) ||
        !statx_identity(raw_object_post_path_fd.get(), &raw_object_post_path_identity) ||
        !filesystem_identity(root_fd.get(), &root_post_filesystem) ||
        !filesystem_identity(extraction_post_path_fd.get(), &extraction_post_filesystem) ||
        !same_identity(root_post_identity, root_identity) ||
        !same_identity(extraction_post_identity, extraction_identity) ||
        !same_identity(extraction_post_path_identity, extraction_identity) ||
        !same_identity(raw_object_post_identity, raw_object_identity) ||
        !same_identity(raw_object_post_path_identity, raw_object_identity) ||
        !same_filesystem_identity(root_post_filesystem, root_filesystem) ||
        !same_filesystem_identity(extraction_post_filesystem, extraction_filesystem) ||
        !hash_retained_file(
            raw_object_fd.get(), raw_object_post_identity, &raw_post_digest) ||
        !hash_retained_file(
            raw_object_post_path_fd.get(),
            raw_object_post_path_identity,
            &raw_post_path_digest) ||
        raw_post_digest != kRawObjectSha256 ||
        raw_post_path_digest != kRawObjectSha256 ||
        !directory_contains_only_raw_object(extraction_post_path_fd.get())) {
        write_error("STAGE1_POST_REAP_OBJECT_REAUTHENTICATION_FAILED");
        return kExitReadyBarrier;
    }

    std::string post_mountinfo;
    Stage1MountInfoV1 post_mount_observed;
    const char* post_mount_error = nullptr;
    if (!read_bounded_file(
            "/proc/self/mountinfo", kMaximumMountInfoBytes, &post_mountinfo) ||
        !validate_stage1_mountinfo_v1(
            post_mountinfo,
            mount_expectation,
            &post_mount_observed,
            &post_mount_error) ||
        post_mount_observed.root_mount_id != mount_observed.root_mount_id ||
        post_mount_observed.root_parent_mount_id != mount_observed.root_parent_mount_id ||
        post_mount_observed.proc_mount_id != mount_observed.proc_mount_id) {
        write_error(
            post_mount_error == nullptr
                ? "STAGE1_POST_REAP_MOUNT_REAUTHENTICATION_FAILED"
                : post_mount_error);
        return kExitReadyBarrier;
    }

    ProcessCensus post_census_1;
    ProcessCensus post_census_2;
    const char* post_census_error = nullptr;
    if (!capture_process_census(proc_fd.get(), &post_census_1) ||
        !capture_process_census(proc_fd.get(), &post_census_2) ||
        !validate_stage1_postexit_census_pair_v1(
            post_census_1,
            post_census_2,
            root_cwd,
            extraction_cwd,
            pid1_starttime,
            &post_census_error)) {
        write_error(
            post_census_error == nullptr
                ? "STAGE1_POSTEXIT_CENSUS_REJECTED"
                : post_census_error);
        return kExitTopology;
    }

    write_error("STAGE1_EXTRACTION_READY_BARRIER_CANDIDATE_COMPLETE");
    return kExitReadyBarrierComplete;
}

}  // namespace pokemon::evaluation_v631302
