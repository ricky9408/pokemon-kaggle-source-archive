#ifndef EVALUATION_V6_3_1_CAPTURE_V2_NATIVE_PRELAUNCH_HANDOFF_H
#define EVALUATION_V6_3_1_CAPTURE_V2_NATIVE_PRELAUNCH_HANDOFF_H

#include "PrelaunchContext.h"

#include <cstddef>
#include <cstdint>
#include <span>

namespace evaluation_v6_3_1::capture_v2 {

// The sole production ingress for RawPrelaunchRequest. This decoder has no
// protocol, permit, holdout, upload, or campaign authority.
class NativePrelaunchHandoff final {
public:
    static constexpr std::uint64_t kProtocolId = 631302u;
    static constexpr std::uint64_t kVersionV1 = 1u;
    static constexpr std::size_t kRawPrelaunchRequestMaximumBytes =
        67u * 1024u * 1024u;

    [[nodiscard]] static RawPrelaunchRequest decode(
        std::span<const std::uint8_t> handoff_cbor);
};

}  // namespace evaluation_v6_3_1::capture_v2

#endif  // EVALUATION_V6_3_1_CAPTURE_V2_NATIVE_PRELAUNCH_HANDOFF_H
