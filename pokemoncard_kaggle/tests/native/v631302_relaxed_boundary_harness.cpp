#include "../../evaluation_v6_3_1/native/m0_diagnostic_relaxed_fixture/ExecutionOriginRelaxed.cpp"

#include <cerrno>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <limits>
#include <string>
#include <sys/wait.h>
#include <vector>

namespace evaluation_v6_3_1::m0_diagnostic_relaxed {

std::optional<Bytes> harness_read(const char* path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) return std::nullopt;
    input.seekg(0, std::ios::end);
    const auto length = input.tellg();
    if (length < 0 || static_cast<std::uint64_t>(length) > kMaximumInputPayloadBytes) {
        return std::nullopt;
    }
    input.seekg(0, std::ios::beg);
    Bytes bytes(static_cast<std::size_t>(length));
    if (!bytes.empty()) {
        input.read(reinterpret_cast<char*>(bytes.data()), length);
    }
    return input || input.eof() ? std::optional<Bytes>(std::move(bytes)) : std::nullopt;
}

bool no_unreaped_children() {
    int status = 0;
    errno = 0;
    return waitpid(-1, &status, WNOHANG) == -1 && errno == ECHILD;
}

int candidate_mode(const char* candidate_path, const char* profile_path) {
    const auto candidate = harness_read(candidate_path);
    const auto profile = harness_read(profile_path);
    return candidate && profile && verify_candidate(*candidate, *profile) ? 0 : 66;
}

int frame_mode(const char* frame_path) {
    const auto frame = harness_read(frame_path);
    return frame && parse_frame(*frame, kOutputMagic, kMaximumCandidateBytes) ? 0 : 66;
}

int process_mode(const char* worker_path, const char* input_size_text, bool require_frame) {
    const auto worker = harness_read(worker_path);
    if (!worker) return 66;
    std::uint64_t input_size = 0;
    try {
        std::size_t consumed = 0;
        input_size = std::stoull(input_size_text, &consumed, 10);
        if (consumed != std::string(input_size_text).size() ||
            input_size > kMaximumInputPayloadBytes + kFrameHeaderBytes) {
            return 66;
        }
    } catch (...) {
        return 66;
    }
    const auto interpreter_digest = decode_hex_digest(V631302_RELAXED_INTERPRETER_SHA256);
    if (!interpreter_digest) return 66;
    auto interpreter = open_regular(
        V631302_RELAXED_PINNED_INTERPRETER_PATH,
        V631302_RELAXED_INTERPRETER_SIZE,
        *interpreter_digest,
        true);
    if (!interpreter) return 66;
    Bytes input(static_cast<std::size_t>(input_size), static_cast<std::uint8_t>('I'));
    auto process = launch_relaxed_worker(std::move(*interpreter), *worker, input);
    if (!process) return no_unreaped_children() ? 66 : 67;
    if (!no_unreaped_children() || !WIFEXITED(process->status) ||
        WEXITSTATUS(process->status) != 0 || !process->stderr_bytes.empty()) {
        return 67;
    }
    if (require_frame && !parse_frame(
            process->stdout_bytes, kOutputMagic, kMaximumCandidateBytes)) {
        return 66;
    }
    std::cout << "stdout_length=" << process->stdout_bytes.size() << '\n';
    std::cout << "stdout_sha256=";
    static constexpr char kHex[] = "0123456789abcdef";
    for (const auto byte : sha256(process->stdout_bytes)) {
        std::cout << kHex[byte >> 4u] << kHex[byte & 0x0fu];
    }
    std::cout << '\n';
    return std::cout ? 0 : 67;
}

int retained_worker_mode(const char* worker_path, const char* replacement_path) {
    const auto retained_worker = harness_read(worker_path);
    if (!retained_worker || rename(replacement_path, worker_path) != 0) return 66;
    const auto interpreter_digest = decode_hex_digest(V631302_RELAXED_INTERPRETER_SHA256);
    if (!interpreter_digest) return 66;
    auto interpreter = open_regular(
        V631302_RELAXED_PINNED_INTERPRETER_PATH,
        V631302_RELAXED_INTERPRETER_SIZE,
        *interpreter_digest,
        true);
    if (!interpreter) return 66;
    auto process = launch_relaxed_worker(
        std::move(*interpreter), *retained_worker, Bytes{static_cast<std::uint8_t>('I')});
    if (!process) return no_unreaped_children() ? 66 : 67;
    if (!no_unreaped_children() || !WIFEXITED(process->status) ||
        WEXITSTATUS(process->status) != 0 || !process->stderr_bytes.empty()) {
        return 67;
    }
    std::cout.write(reinterpret_cast<const char*>(process->stdout_bytes.data()),
                    static_cast<std::streamsize>(process->stdout_bytes.size()));
    return std::cout ? 0 : 67;
}

int timeout_mode(const char* worker_path) {
    const auto worker = harness_read(worker_path);
    const auto interpreter_digest = decode_hex_digest(V631302_RELAXED_INTERPRETER_SHA256);
    if (!worker || !interpreter_digest) return 67;
    auto interpreter = open_regular(
        V631302_RELAXED_PINNED_INTERPRETER_PATH,
        V631302_RELAXED_INTERPRETER_SIZE,
        *interpreter_digest,
        true);
    if (!interpreter) return 67;
    const auto started = std::chrono::steady_clock::now();
    auto process = launch_until(
        started + std::chrono::milliseconds(1000),
        std::move(*interpreter),
        *worker,
        Bytes{static_cast<std::uint8_t>('I')});
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - started);
    if (!process || !process->timed_out || !WIFSIGNALED(process->status) ||
        WTERMSIG(process->status) != SIGKILL || !no_unreaped_children() ||
        elapsed < std::chrono::milliseconds(1000) ||
        elapsed > std::chrono::milliseconds(5000)) {
        return 67;
    }
    std::cout << "deadline_clock=steady\n";
    std::cout << "elapsed_ms=" << elapsed.count() << '\n';
    std::cout << "signal=" << WTERMSIG(process->status) << '\n';
    std::cout << "reaped=1\n";
    std::cout << "wrapper_emitted=0\n";
    return std::cout ? 66 : 67;
}

}  // namespace evaluation_v6_3_1::m0_diagnostic_relaxed

int main(int argc, char** argv) {
    using namespace evaluation_v6_3_1::m0_diagnostic_relaxed;
    if (argc == 4 && std::string(argv[1]) == "candidate") {
        return candidate_mode(argv[2], argv[3]);
    }
    if (argc == 3 && std::string(argv[1]) == "frame") {
        return frame_mode(argv[2]);
    }
    if (argc == 4 && std::string(argv[1]) == "process") {
        return process_mode(argv[2], argv[3], false);
    }
    if (argc == 4 && std::string(argv[1]) == "process-frame") {
        return process_mode(argv[2], argv[3], true);
    }
    if (argc == 4 && std::string(argv[1]) == "retained-worker") {
        return retained_worker_mode(argv[2], argv[3]);
    }
    if (argc == 3 && std::string(argv[1]) == "timeout") {
        return timeout_mode(argv[2]);
    }
    return 66;
}
