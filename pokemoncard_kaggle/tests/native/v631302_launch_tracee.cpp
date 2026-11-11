#include "CollectorReceipt.h"

#include <cerrno>
#include <array>
#include <fcntl.h>
#include <sys/eventfd.h>
#include <sys/types.h>
#include <string_view>
#include <unistd.h>
#include <vector>

namespace {

#if defined(V631302_RUNTIME_PRIMARY_FIXTURE)
extern "C" int v631302_runtime_primary_fixture();
#endif

#if !defined(V631302_TRACEE_MODE)
#define V631302_TRACEE_MODE 0
#endif

constexpr std::string_view kContextPrefix =
    "--capture-context-v1-cbor-hex=";

constexpr std::array<std::string_view, 15u> kExpectedArgv = {
    "/bin/collector",
    "--protocol=631302",
    "--level=2",
    "--primary-source=/src/Export.cpp",
    {},
    "--",
    "/bin/clang-tool",
    "-std=c++20",
    "-fsyntax-only",
    "-nostdinc",
    "-I",
    "/src",
    "/src/Export.cpp",
    "-resource-dir=/lib/clang/16",
    "--no-default-config",
};

std::string_view validate_and_extract_context(int argc, char** argv) {
    if (argc != static_cast<int>(kExpectedArgv.size())) {
        return {};
    }
    for (std::size_t index = 0u; index < kExpectedArgv.size(); ++index) {
        if (argv[index] == nullptr) {
            return {};
        }
        const std::string_view actual(argv[index]);
        if (index == 4u) {
            if (!actual.starts_with(kContextPrefix) ||
                actual.size() == kContextPrefix.size()) {
                return {};
            }
            continue;
        }
        if (actual != kExpectedArgv[index]) {
            return {};
        }
    }
    return std::string_view(argv[4]).substr(kContextPrefix.size());
}

bool consume_source() {
    const int descriptor = ::open("/src/Export.cpp", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) return false;
    char buffer[64]{};
    ssize_t count = -1;
    do {
        count = ::read(descriptor, buffer, sizeof(buffer));
    } while (count < 0 && errno == EINTR);
    return count > 0 && ::close(descriptor) == 0;
}

}  // namespace

int main(int argc, char** argv) {
    const std::string_view context = validate_and_extract_context(argc, argv);
    if (context.empty()) {
        return 20;
    }
    try {
#if defined(V631302_RUNTIME_PRIMARY_FIXTURE)
        if (v631302_runtime_primary_fixture() != 16) {
            return 19;
        }
#endif
        evaluation_v6_3_1::capture_v2::CollectorReceipt receipt(context);
        receipt.start();
#if V631302_TRACEE_MODE == 1
        for (;;) {
            static_cast<void>(::pause());
        }
#elif V631302_TRACEE_MODE == 2
        {
            const pid_t child = ::fork();
            if (child == 0) {
                ::_exit(0);
            }
            return 26;
        }
#elif V631302_TRACEE_MODE == 3
        {
            const int descriptor = ::eventfd(0u, EFD_CLOEXEC);
            if (descriptor >= 0) {
                static_cast<void>(::close(descriptor));
            }
            return 27;
        }
#elif V631302_TRACEE_MODE == 4
        static_cast<void>(::chdir("/"));
        return 29;
#elif V631302_TRACEE_MODE == 5
        {
            const int descriptor = ::dup(3);
            if (descriptor >= 0) {
                static_cast<void>(::close(descriptor));
            }
            return 30;
        }
#elif V631302_TRACEE_MODE == 6
        ::_exit(0);
#elif V631302_TRACEE_MODE != 0
#error "unsupported V631302_TRACEE_MODE"
#endif
        if (!consume_source()) return 21;
        receipt.driver_argv_frozen({
            "/bin/clang-tool",
            "-std=c++20",
            "-fsyntax-only",
            "-nostdinc",
            "-I",
            "/src",
            "/src/Export.cpp",
            "-resource-dir=/lib/clang/16",
            "--no-default-config",
        });
        receipt.driver_execution_begin();
        if (!consume_source()) return 22;
        receipt.cc1_argv_frozen({"clang", "-cc1", "/src/Export.cpp"});
        receipt.cc1_execution_begin();
        if (!consume_source()) return 23;
        receipt.cc1_execution_end();
        receipt.finalize();
        constexpr char output[] = "tracee-ok\n";
        return ::write(STDOUT_FILENO, output, sizeof(output) - 1u) ==
                       static_cast<ssize_t>(sizeof(output) - 1u)
                   ? 0
                   : 24;
    } catch (...) {
        return 25;
    }
}
