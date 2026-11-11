#include "Stage1ExtractionChildGateV1.h"

#include <cstdint>
#include <linux/sched.h>

int main() {
    clone_args arguments{};
    pokemon::evaluation_v631302::Stage1ExtractionChildGateInputV1 input{};
    input.clone_args = &arguments;
    input.clone_args_size = 0u;
    pokemon::evaluation_v631302::Stage1ExtractionChildGateResultV1 result{};

    constexpr std::uint64_t kR12Sentinel = 0x123456789abcdef0u;
    constexpr std::uint64_t kR13Sentinel = 0x0fedcba987654321u;
    register std::uint64_t r12_value asm("r12") = kR12Sentinel;
    register std::uint64_t r13_value asm("r13") = kR13Sentinel;
    asm volatile("" : "+r"(r12_value), "+r"(r13_value) : : "memory");
    const long value = stage1_extraction_child_gate_v1(&input, &result);
    asm volatile("" : "+r"(r12_value), "+r"(r13_value) : : "memory");

    return value < 0 && result.clone_return == value && result.child_pid == -1 &&
                   result.pidfd == -1 && result.parent_outcome == 2u &&
                   result.reserved == 0u && r12_value == kR12Sentinel &&
                   r13_value == kR13Sentinel
               ? 0
               : 1;
}
