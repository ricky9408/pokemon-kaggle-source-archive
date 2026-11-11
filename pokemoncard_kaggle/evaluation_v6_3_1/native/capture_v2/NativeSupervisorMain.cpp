#include <cerrno>
#include <cstring>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace {

constexpr char kSupervisorArgv0[] = "v631302-native-supervisor";
constexpr int kUsageFailure = 64;
constexpr int kTopologyFailure = 65;
constexpr int kTransportUnavailable = 78;
constexpr int kRequiredGuardSeals =
    F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;

bool has_expected_descriptor_flags(int fd, int access_mode) noexcept {
    const int descriptor_flags = ::fcntl(fd, F_GETFD);
    const int status_flags = ::fcntl(fd, F_GETFL);
    return descriptor_flags >= 0 && (descriptor_flags & FD_CLOEXEC) == 0 &&
           status_flags >= 0 && (status_flags & O_ACCMODE) == access_mode;
}

bool has_expected_guard(int fd, const struct stat& reference) noexcept {
    struct stat observed {};
    const int seals = ::fcntl(fd, F_GET_SEALS);
    return has_expected_descriptor_flags(fd, O_RDWR) &&
           ::fstat(fd, &observed) == 0 && S_ISREG(observed.st_mode) &&
           observed.st_size == 0 && (observed.st_mode & 0777) == 0 &&
           observed.st_dev == reference.st_dev &&
           observed.st_ino == reference.st_ino && seals >= 0 &&
           (seals & kRequiredGuardSeals) == kRequiredGuardSeals;
}

bool has_expected_pipe(int fd, int access_mode) noexcept {
    struct stat observed {};
    return has_expected_descriptor_flags(fd, access_mode) &&
           ::fstat(fd, &observed) == 0 && S_ISFIFO(observed.st_mode);
}

bool descriptor_topology_is_exact() noexcept {
    struct stat guard {};
    return ::fstat(0, &guard) == 0 && S_ISREG(guard.st_mode) &&
           has_expected_guard(0, guard) && has_expected_guard(1, guard) &&
           has_expected_guard(2, guard) && has_expected_pipe(3, O_RDONLY) &&
           has_expected_pipe(4, O_WRONLY);
}

}  // namespace

int main(int argc, char** argv) noexcept {
    if (argc != 1 || argv == nullptr || argv[0] == nullptr ||
        std::strcmp(argv[0], kSupervisorArgv0) != 0) {
        return kUsageFailure;
    }
    if (!descriptor_topology_is_exact()) {
        return kTopologyFailure;
    }

    // Binding checkpoint 1 is intentionally non-operational. The executable
    // remains fail-closed until the later descriptor, exec, pidfd, handshake,
    // and single-use bridge checkpoints are implemented and verified.
    return kTransportUnavailable;
}
