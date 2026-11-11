#include "Stage1ExtractionCustodianV1.h"

#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <iterator>
#include <linux/openat2.h>
#include <limits>
#include <string>
#include <string_view>
#include <sys/syscall.h>
#include <unistd.h>
#include <utility>

namespace {

bool parse_unsigned(const char* text, std::uint64_t* output) {
    if (text == nullptr || output == nullptr || *text == '\0' || *text == '-') {
        return false;
    }
    errno = 0;
    char* end = nullptr;
    const unsigned long long value = std::strtoull(text, &end, 10);
    if (errno != 0 || end == nullptr || *end != '\0' ||
        value > std::numeric_limits<std::uint64_t>::max()) {
        return false;
    }
    *output = static_cast<std::uint64_t>(value);
    return true;
}

int run_openat2_probe(const char* root_path, const char* relative_path) {
    if (root_path == nullptr || relative_path == nullptr || *root_path == '\0' ||
        *relative_path == '\0' || *relative_path == '/') {
        return 64;
    }
    const int root_fd = ::open(root_path, O_PATH | O_DIRECTORY | O_CLOEXEC);
    if (root_fd < 0) {
        std::cerr << "OPENAT2_PROBE_ROOT_OPEN_FAILED\n";
        return 74;
    }
    open_how how{};
    how.flags = O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW;
    how.resolve = RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS |
                  RESOLVE_NO_XDEV;
    errno = 0;
    const long raw = ::syscall(SYS_openat2, root_fd, relative_path, &how, sizeof(how));
    const int open_error = errno;
    (void)::close(root_fd);
    if (raw >= 0) {
        (void)::close(static_cast<int>(raw));
        std::cout << "OPENAT2_AVAILABLE\n";
        return 0;
    }
    if (open_error == ENOSYS) {
        std::cerr << "OPENAT2_PROBE_ENOSYS\n";
        return 76;
    }
    if (open_error == EPERM) {
        std::cerr << "OPENAT2_PROBE_BLOCKED_EPERM\n";
        return 77;
    }
    if (open_error == EINVAL) {
        std::cerr << "OPENAT2_PROBE_UNSUPPORTED_EINVAL\n";
        return 78;
    }
    std::cerr << "OPENAT2_PROBE_FAILED_" << open_error << '\n';
    return 79;
}

int run_pre_census_scenario(const std::string_view scenario) {
    using pokemon::evaluation_v631302::Stage1CwdIdentityV1;
    using pokemon::evaluation_v631302::Stage1ProcessCensusRowV1;
    using pokemon::evaluation_v631302::Stage1ProcessCensusV1;
    using pokemon::evaluation_v631302::Stage1TaskCensusRowV1;

    const Stage1CwdIdentityV1 root{31u, 0u, 45u, 100u};
    Stage1CwdIdentityV1 extraction{31u, 0u, 45u, 101u};
    Stage1ProcessCensusV1 first{{1u, 424242u, {{1u, root}}}};
    Stage1ProcessCensusV1 second = first;

    if (scenario == "valid") {
        // Exact fixture above.
    } else if (scenario == "start-mismatch") {
        second[0].starttime += 1u;
    } else if (scenario == "cwd-mismatch") {
        second[0].tasks[0].cwd = extraction;
    } else if (scenario == "wrong-tid") {
        second[0].tasks[0].tid = 2u;
    } else if (scenario == "extra-pid") {
        second.push_back(Stage1ProcessCensusRowV1{2u, 515151u, {{2u, root}}});
    } else if (scenario == "task-order") {
        first[0].tasks.push_back(Stage1TaskCensusRowV1{2u, root});
        second[0].tasks.insert(second[0].tasks.begin(), Stage1TaskCensusRowV1{2u, root});
    } else if (scenario == "zero-start") {
        second[0].starttime = 0u;
    } else if (scenario == "same-root-extraction") {
        extraction = root;
    } else {
        return 64;
    }

    const char* error = nullptr;
    if (!pokemon::evaluation_v631302::validate_stage1_prelaunch_census_pair_v1(
            first,
            second,
            root,
            extraction,
            &error)) {
        std::cerr << (error == nullptr ? "STAGE1_PRELAUNCH_CENSUS_REJECTED" : error) << '\n';
        return 65;
    }
    std::cout << "STAGE1_PRELAUNCH_CENSUS_VALID\n";
    return 0;
}

int run_ready_status_scenario(const std::string_view scenario) {
    std::string status =
        "Name:\tStage1\n"
        "Tgid:\t2\n"
        "Pid:\t2\n"
        "NSpid:\t9002\t2\n"
        "Threads:\t1\n"
        "NoNewPrivs:\t1\n"
        "Seccomp:\t2\n";
    if (scenario == "valid") {
        // Exact fixture above.
    } else if (scenario == "pid") {
        status.replace(status.find("Pid:\t2"), 6u, "Pid:\t3");
    } else if (scenario == "tgid") {
        status.replace(status.find("Tgid:\t2"), 7u, "Tgid:\t3");
    } else if (scenario == "nspid") {
        status.replace(status.find("9002\t2"), 6u, "9002\t3");
    } else if (scenario == "threads") {
        status.replace(status.find("Threads:\t1"), 10u, "Threads:\t2");
    } else if (scenario == "no-new-privs") {
        status.replace(status.find("NoNewPrivs:\t1"), 13u, "NoNewPrivs:\t0");
    } else if (scenario == "seccomp") {
        status.replace(status.find("Seccomp:\t2"), 10u, "Seccomp:\t0");
    } else if (scenario == "duplicate") {
        status += "Seccomp:\t2\n";
    } else if (scenario == "missing") {
        status.erase(status.find("NoNewPrivs:"), std::string("NoNewPrivs:\t1\n").size());
    } else if (scenario == "leading-zero") {
        status.replace(status.find("Pid:\t2"), 6u, "Pid:\t02");
    } else if (scenario == "unterminated") {
        status.pop_back();
    } else {
        return 64;
    }
    const char* error = nullptr;
    if (!pokemon::evaluation_v631302::validate_stage1_ready_status_v1(
            status, 2u, &error)) {
        std::cerr << (error == nullptr ? "STAGE1_READY_STATUS_REJECTED" : error) << '\n';
        return 65;
    }
    std::cout << "STAGE1_READY_STATUS_VALID\n";
    return 0;
}

int run_barrier_census_scenario(const std::string_view scenario) {
    using pokemon::evaluation_v631302::Stage1CwdIdentityV1;
    using pokemon::evaluation_v631302::Stage1ProcessCensusRowV1;
    using pokemon::evaluation_v631302::Stage1ProcessCensusV1;
    using pokemon::evaluation_v631302::Stage1TaskCensusRowV1;

    const Stage1CwdIdentityV1 root{31u, 0u, 45u, 100u};
    Stage1CwdIdentityV1 extraction{31u, 0u, 45u, 101u};
    Stage1ProcessCensusV1 first{
        {1u, 424242u, {{1u, root}}},
        {2u, 515151u, {{2u, extraction}}},
    };
    Stage1ProcessCensusV1 second = first;
    if (scenario == "valid") {
        // Exact fixture above.
    } else if (scenario == "pid2-root") {
        second[1].tasks[0].cwd = root;
    } else if (scenario == "pid1-extraction") {
        second[0].tasks[0].cwd = extraction;
    } else if (scenario == "pid2-start") {
        second[1].starttime += 1u;
    } else if (scenario == "pid1-start") {
        second[0].starttime += 1u;
    } else if (scenario == "extra-task") {
        second[1].tasks.push_back(Stage1TaskCensusRowV1{3u, extraction});
    } else if (scenario == "missing-pid2") {
        second.pop_back();
    } else if (scenario == "wrong-order") {
        std::swap(second[0], second[1]);
    } else if (scenario == "same-root-extraction") {
        extraction = root;
    } else {
        return 64;
    }
    const char* error = nullptr;
    if (!pokemon::evaluation_v631302::validate_stage1_barrier_census_pair_v1(
            first, second, root, extraction, 424242u, 515151u, &error)) {
        std::cerr << (error == nullptr ? "STAGE1_BARRIER_CENSUS_REJECTED" : error) << '\n';
        return 65;
    }
    std::cout << "STAGE1_BARRIER_CENSUS_VALID\n";
    return 0;
}

int run_postexit_census_scenario(const std::string_view scenario) {
    using pokemon::evaluation_v631302::Stage1CwdIdentityV1;
    using pokemon::evaluation_v631302::Stage1ProcessCensusRowV1;
    using pokemon::evaluation_v631302::Stage1ProcessCensusV1;

    const Stage1CwdIdentityV1 root{31u, 0u, 45u, 100u};
    Stage1CwdIdentityV1 extraction{31u, 0u, 45u, 101u};
    Stage1ProcessCensusV1 first{{1u, 424242u, {{1u, root}}}};
    Stage1ProcessCensusV1 second = first;
    if (scenario == "valid") {
        // Exact fixture above.
    } else if (scenario == "pid2-remains") {
        second.push_back(Stage1ProcessCensusRowV1{2u, 515151u, {{2u, extraction}}});
    } else if (scenario == "pid1-start") {
        second[0].starttime += 1u;
    } else if (scenario == "pid1-cwd") {
        second[0].tasks[0].cwd = extraction;
    } else if (scenario == "same-root-extraction") {
        extraction = root;
    } else {
        return 64;
    }
    const char* error = nullptr;
    if (!pokemon::evaluation_v631302::validate_stage1_postexit_census_pair_v1(
            first, second, root, extraction, 424242u, &error)) {
        std::cerr << (error == nullptr ? "STAGE1_POSTEXIT_CENSUS_REJECTED" : error) << '\n';
        return 65;
    }
    std::cout << "STAGE1_POSTEXIT_CENSUS_VALID\n";
    return 0;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc == 4 && std::string_view(argv[1]) == "openat2-probe") {
        return run_openat2_probe(argv[2], argv[3]);
    }
    if (argc == 3 && std::string_view(argv[1]) == "pre-census") {
        return run_pre_census_scenario(argv[2]);
    }
    if (argc == 3 && std::string_view(argv[1]) == "ready-status") {
        return run_ready_status_scenario(argv[2]);
    }
    if (argc == 3 && std::string_view(argv[1]) == "barrier-census") {
        return run_barrier_census_scenario(argv[2]);
    }
    if (argc == 3 && std::string_view(argv[1]) == "postexit-census") {
        return run_postexit_census_scenario(argv[2]);
    }
    if (argc == 4 && std::string_view(argv[1]) == "proc-stat") {
        std::ifstream input(argv[2], std::ios::binary);
        if (!input.is_open()) {
            return 74;
        }
        const std::string bytes(
            (std::istreambuf_iterator<char>(input)),
            std::istreambuf_iterator<char>());
        if (input.bad()) {
            return 74;
        }
        std::uint64_t expected_pid = 0;
        if (!parse_unsigned(argv[3], &expected_pid)) {
            return 64;
        }
        std::uint64_t starttime = 0;
        const char* error = nullptr;
        if (!pokemon::evaluation_v631302::parse_stage1_proc_stat_starttime_v1(
                bytes,
                expected_pid,
                &starttime,
                &error)) {
            std::cerr << (error == nullptr ? "STAGE1_PROC_STAT_REJECTED" : error) << '\n';
            return 65;
        }
        std::cout << starttime << '\n';
        return 0;
    }
    if (argc != 9) {
        return 64;
    }
    std::ifstream input(argv[1], std::ios::binary);
    if (!input.is_open()) {
        return 74;
    }
    const std::string bytes(
        (std::istreambuf_iterator<char>(input)),
        std::istreambuf_iterator<char>());
    if (input.bad()) {
        return 74;
    }
    pokemon::evaluation_v631302::Stage1MountExpectationV1 expected;
    if (!parse_unsigned(argv[2], &expected.root_mount_id) ||
        !parse_unsigned(argv[3], &expected.root_parent_mount_id) ||
        !parse_unsigned(argv[4], &expected.root_device_major) ||
        !parse_unsigned(argv[5], &expected.root_device_minor) ||
        !parse_unsigned(argv[6], &expected.proc_mount_id) ||
        !parse_unsigned(argv[7], &expected.proc_device_major) ||
        !parse_unsigned(argv[8], &expected.proc_device_minor)) {
        return 64;
    }
    pokemon::evaluation_v631302::Stage1MountInfoV1 observed;
    const char* error = nullptr;
    if (!pokemon::evaluation_v631302::validate_stage1_mountinfo_v1(
            bytes,
            expected,
            &observed,
            &error)) {
        std::cerr << (error == nullptr ? "STAGE1_MOUNTINFO_REJECTED" : error) << '\n';
        return 65;
    }
    std::cout << observed.root_mount_id << ',' << observed.root_parent_mount_id << ','
              << observed.proc_mount_id << '\n';
    return 0;
}
