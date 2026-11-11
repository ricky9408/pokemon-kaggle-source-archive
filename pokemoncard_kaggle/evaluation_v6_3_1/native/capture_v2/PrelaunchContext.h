#ifndef EVALUATION_V6_3_1_CAPTURE_V2_PRELAUNCH_CONTEXT_H
#define EVALUATION_V6_3_1_CAPTURE_V2_PRELAUNCH_CONTEXT_H

// Zero-authority native ingress types.  Expectations remain expectations until
// later native observations compare them.  Nothing here issues a permit,
// derives a protocol root, or creates campaign authority.

#include "HarnessObserver.h"
#include "SupervisorTypes.h"
#include "WorkDirectoryCustody.h"

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace evaluation_v6_3_1::capture_v2 {

inline constexpr std::size_t kValidatedCollectorProfileBuildLabelMaximumBytes =
    1u * 1024u * 1024u;

class ValidatedPrelaunchPlan;
class ValidatedPrelaunchContext;
class CompletedNativeCaptureSuccess;
class CaptureSession;
class PtraceOpenSupervisor;
class NativePrelaunchHandoff;
#if defined(EVALUATION_V631302_PRIVATE_BRIDGE_V3_TEST_ONLY)
class PrivateBridgeV3FixtureAccess;
#endif

class ValidatedCollectorProfileBuildLabelText final {
public:
    ValidatedCollectorProfileBuildLabelText(
        ValidatedCollectorProfileBuildLabelText&&) noexcept = default;
    ValidatedCollectorProfileBuildLabelText& operator=(
        ValidatedCollectorProfileBuildLabelText&&) = delete;
    ValidatedCollectorProfileBuildLabelText(
        const ValidatedCollectorProfileBuildLabelText&) = delete;
    ValidatedCollectorProfileBuildLabelText& operator=(
        const ValidatedCollectorProfileBuildLabelText&) = delete;

    [[nodiscard]] const std::string& value() const noexcept { return value_; }

private:
    friend class ValidatedPrelaunchPlan;

    explicit ValidatedCollectorProfileBuildLabelText(std::string value) noexcept
        : value_(std::move(value)) {}

    std::string value_;
};

class ExactGnuBuildIdDescriptorBytes final {
public:
    ExactGnuBuildIdDescriptorBytes(ExactGnuBuildIdDescriptorBytes&&) noexcept = default;
    ExactGnuBuildIdDescriptorBytes& operator=(ExactGnuBuildIdDescriptorBytes&&) = delete;
    ExactGnuBuildIdDescriptorBytes(const ExactGnuBuildIdDescriptorBytes&) = delete;
    ExactGnuBuildIdDescriptorBytes& operator=(const ExactGnuBuildIdDescriptorBytes&) = delete;

    [[nodiscard]] const std::vector<std::uint8_t>& value() const noexcept { return value_; }

private:
    friend class ValidatedPrelaunchPlan;

    explicit ExactGnuBuildIdDescriptorBytes(
        std::vector<std::uint8_t> value) noexcept
        : value_(std::move(value)) {}

    std::vector<std::uint8_t> value_;
};

// The only mutable ingress object. Production construction is private to the
// canonical handoff decoder; the retained root comes only from that outer
// handoff. It deliberately has no observed descriptor or custody field.
class RawPrelaunchRequest final {
public:
#if defined(EVALUATION_V631302_NATIVE_PRELAUNCH_HANDOFF_TEST_ONLY)
    // Fixture-only deep-copy constructor. Every translation unit in a fixture
    // target, including PrelaunchContext.cpp, must define this macro.
    static RawPrelaunchRequest copy_from(
        const std::string& collector_profile_build_label_text,
        const std::vector<std::uint8_t>&
            expected_collector_gnu_build_id_descriptor_bytes,
        const Sha256Digest32& validated_prelaunch_expectations_root,
        const std::vector<std::uint8_t>& collector_profile_cbor_bytes,
        std::uint64_t argv_grammar_version,
        const Sha256Digest& argv_grammar_sha256,
        const std::vector<std::uint8_t>& path_profile_cbor_bytes,
        const std::string& namespace_relative_cwd,
        const std::string& primary_source,
        const std::vector<std::uint8_t>& public_file_rows_cbor_bytes,
        const std::vector<std::string>& requested_argv,
        const HarnessExpectations& harness_expectations);

    // Source-compatibility overload for older fixture callers. The legacy
    // absolute value is intentionally discarded and never enters the request
    // or its binding digest; new callers must use the relative-only overload.
    static RawPrelaunchRequest copy_from(
        const std::string& collector_profile_build_label_text,
        const std::vector<std::uint8_t>&
            expected_collector_gnu_build_id_descriptor_bytes,
        const Sha256Digest32& validated_prelaunch_expectations_root,
        const std::vector<std::uint8_t>& collector_profile_cbor_bytes,
        std::uint64_t argv_grammar_version,
        const Sha256Digest& argv_grammar_sha256,
        const std::vector<std::uint8_t>& path_profile_cbor_bytes,
        const std::string& legacy_working_directory_absolute,
        const std::string& namespace_relative_cwd,
        const std::string& primary_source,
        const std::vector<std::uint8_t>& public_file_rows_cbor_bytes,
        const std::vector<std::string>& requested_argv,
        const HarnessExpectations& harness_expectations);
#endif

    RawPrelaunchRequest(RawPrelaunchRequest&&) noexcept = default;
    RawPrelaunchRequest& operator=(RawPrelaunchRequest&&) noexcept = default;
    RawPrelaunchRequest(const RawPrelaunchRequest&) = delete;
    RawPrelaunchRequest& operator=(const RawPrelaunchRequest&) = delete;

private:
    friend class ValidatedPrelaunchPlan;
    friend class NativePrelaunchHandoff;

    RawPrelaunchRequest(
        std::string collector_profile_build_label_text,
        std::vector<std::uint8_t> expected_collector_gnu_build_id_descriptor_bytes,
        Sha256Digest32 validated_prelaunch_expectations_root,
        std::vector<std::uint8_t> collector_profile_cbor_bytes,
        std::uint64_t argv_grammar_version,
        Sha256Digest argv_grammar_sha256,
        std::vector<std::uint8_t> path_profile_cbor_bytes,
        std::string namespace_relative_cwd,
        std::string primary_source,
        std::vector<std::uint8_t> public_file_rows_cbor_bytes,
        std::vector<std::string> requested_argv,
        HarnessExpectations harness_expectations);

    std::string collector_profile_build_label_text_;
    std::vector<std::uint8_t> expected_collector_gnu_build_id_descriptor_bytes_;
    Sha256Digest32 validated_prelaunch_expectations_root_{};
    std::vector<std::uint8_t> collector_profile_cbor_bytes_;
    std::uint64_t argv_grammar_version_ = 0u;
    Sha256Digest argv_grammar_sha256_{};
    std::vector<std::uint8_t> path_profile_cbor_bytes_;
    std::string namespace_relative_cwd_;
    std::string primary_source_;
    std::vector<std::uint8_t> public_file_rows_cbor_bytes_;
    std::vector<std::string> requested_argv_;
    HarnessExpectations harness_expectations_{};
};

struct DecodedPathProfileV2 final {
    std::uint64_t version = 0u;
    std::string source_absolute_prefix;
    std::string work_absolute_prefix;
    std::string command_absolute_prefix;
};

struct DecodedPublicFileRow final {
    std::string namespace_relative_path;
    std::vector<std::uint64_t> role_codes;
    std::uint64_t normalized_mode = 0u;
    std::uint64_t byte_length = 0u;
    Sha256Digest sha256{};
};

// An immutable, FD-free validation result. It is deliberately not usable as a
// context: only consuming it together with WorkDirectoryCustody makes the
// final context.
class ValidatedPrelaunchPlan final {
public:
    static constexpr std::uint64_t kFrozenArgvGrammarVersionV1 = 1u;
    static constexpr Sha256Digest kFrozenArgvGrammarSha256V1 = {
        0x08u, 0x50u, 0x29u, 0x05u, 0x87u, 0x92u, 0xfeu, 0xdau,
        0xdbu, 0x74u, 0x41u, 0xd7u, 0x33u, 0x32u, 0x1eu, 0x96u,
        0x12u, 0x55u, 0xbfu, 0x65u, 0x59u, 0x8bu, 0x2bu, 0x54u,
        0xa4u, 0x39u, 0xcbu, 0x42u, 0x6du, 0xb5u, 0x41u, 0x60u,
    };

    static ValidatedPrelaunchPlan validate(RawPrelaunchRequest&& raw);

    ValidatedPrelaunchPlan(ValidatedPrelaunchPlan&&) noexcept = default;
    ValidatedPrelaunchPlan& operator=(ValidatedPrelaunchPlan&&) = delete;
    ValidatedPrelaunchPlan(const ValidatedPrelaunchPlan&) = delete;
    ValidatedPrelaunchPlan& operator=(const ValidatedPrelaunchPlan&) = delete;

    [[nodiscard]] ValidatedPrelaunchContext bind_work_directory_custody(
        WorkDirectoryCustodyParentEndpoint&& parent_endpoint) &&;
    [[nodiscard]] const DecodedPathProfileV2& path_profile() const noexcept { return path_profile_; }
    [[nodiscard]] const std::string& working_directory_relative_path() const noexcept {
        return namespace_relative_cwd_;
    }
    // Compatibility name for the out-of-scope bridge encoder. It deliberately
    // returns the canonical relative value; no absolute CWD is retained.
    [[nodiscard]] const std::string& working_directory_absolute() const noexcept {
        return namespace_relative_cwd_;
    }
    [[nodiscard]] const std::string& namespace_relative_cwd() const noexcept {
        return namespace_relative_cwd_;
    }
    [[nodiscard]] const std::string& primary_source() const noexcept { return primary_source_; }
    [[nodiscard]] const std::vector<DecodedPublicFileRow>& public_file_rows() const noexcept {
        return public_file_rows_;
    }
    [[nodiscard]] const std::vector<std::string>& requested_argv() const noexcept {
        return requested_argv_;
    }
    // RAW_PRELAUNCH_REQUEST_V1 field 11 is the rooted logical Clang driver
    // argv. It remains unchanged after the collector wrapper separator.
    [[nodiscard]] const std::vector<std::string>& collector_launch_argv() const noexcept {
        return collector_launch_argv_;
    }
    [[nodiscard]] const std::string& absolute_primary_source() const noexcept {
        return absolute_primary_source_;
    }
    [[nodiscard]] const std::vector<std::uint8_t>&
    capture_context_cbor_bytes() const noexcept {
        return capture_context_cbor_bytes_;
    }
    [[nodiscard]] const HarnessExpectations& harness_expectations() const noexcept {
        return harness_expectations_;
    }
    [[nodiscard]] const std::vector<std::uint8_t>&
    path_profile_cbor_bytes() const noexcept {
        return path_profile_cbor_bytes_;
    }
    [[nodiscard]] const ValidatedCollectorProfileBuildLabelText&
    collector_profile_build_label_text() const noexcept {
        return collector_profile_build_label_text_;
    }
    [[nodiscard]] const ExactGnuBuildIdDescriptorBytes&
    expected_collector_gnu_build_id_descriptor_bytes() const noexcept {
        return expected_collector_gnu_build_id_descriptor_bytes_;
    }

private:
    friend class ValidatedPrelaunchContext;

    static Sha256Digest plan_binding_digest(const RawPrelaunchRequest& raw);
    static Sha256Digest context_binding_digest(
        const Sha256Digest& plan_digest,
        const Sha256Digest32& validated_prelaunch_expectations_root,
        WorkDirectoryIdentity identity);

    ValidatedPrelaunchPlan(
        RawPrelaunchRequest&& raw,
        DecodedPathProfileV2 path_profile,
        std::vector<DecodedPublicFileRow> public_file_rows,
        std::string absolute_primary_source,
        std::vector<std::uint8_t> capture_context_cbor_bytes,
        std::vector<std::string> collector_launch_argv,
        Sha256Digest private_plan_binding_digest) noexcept;

    ValidatedCollectorProfileBuildLabelText collector_profile_build_label_text_;
    ExactGnuBuildIdDescriptorBytes expected_collector_gnu_build_id_descriptor_bytes_;
    Sha256Digest32 validated_prelaunch_expectations_root_{};
    std::vector<std::uint8_t> collector_profile_cbor_bytes_;
    std::uint64_t argv_grammar_version_ = 0u;
    Sha256Digest argv_grammar_sha256_{};
    std::vector<std::uint8_t> path_profile_cbor_bytes_;
    std::string namespace_relative_cwd_;
    std::string primary_source_;
    std::vector<std::uint8_t> public_file_rows_cbor_bytes_;
    std::vector<std::string> requested_argv_;
    std::string absolute_primary_source_;
    std::vector<std::uint8_t> capture_context_cbor_bytes_;
    std::vector<std::string> collector_launch_argv_;
    HarnessExpectations harness_expectations_{};
    DecodedPathProfileV2 path_profile_;
    std::vector<DecodedPublicFileRow> public_file_rows_;
    Sha256Digest private_plan_binding_digest_{};
};

// The final immutable ownership boundary. Its constructor is private and can
// only consume a validated plan plus the dedicated custody input.
class ValidatedPrelaunchContext final {
public:
    ValidatedPrelaunchContext(ValidatedPrelaunchContext&&) noexcept = default;
    ValidatedPrelaunchContext& operator=(ValidatedPrelaunchContext&&) = delete;
    ValidatedPrelaunchContext(const ValidatedPrelaunchContext&) = delete;
    ValidatedPrelaunchContext& operator=(const ValidatedPrelaunchContext&) = delete;

    [[nodiscard]] const ValidatedCollectorProfileBuildLabelText&
    collector_profile_build_label_text() const noexcept {
        return collector_profile_build_label_text_;
    }
    [[nodiscard]] const ExactGnuBuildIdDescriptorBytes&
    expected_collector_gnu_build_id_descriptor_bytes() const noexcept {
        return expected_collector_gnu_build_id_descriptor_bytes_;
    }
    [[nodiscard]] const std::vector<std::uint8_t>& collector_profile_cbor_bytes() const noexcept {
        return collector_profile_cbor_bytes_;
    }
    [[nodiscard]] const std::vector<std::uint8_t>& path_profile_cbor_bytes() const noexcept {
        return path_profile_cbor_bytes_;
    }
    [[nodiscard]] const std::vector<std::uint8_t>& public_file_rows_cbor_bytes() const noexcept {
        return public_file_rows_cbor_bytes_;
    }
    [[nodiscard]] std::uint64_t argv_grammar_version() const noexcept { return argv_grammar_version_; }
    [[nodiscard]] const Sha256Digest& argv_grammar_sha256() const noexcept {
        return argv_grammar_sha256_;
    }
    [[nodiscard]] const DecodedPathProfileV2& path_profile() const noexcept { return path_profile_; }
    [[nodiscard]] const std::string& working_directory_relative_path() const noexcept {
        return namespace_relative_cwd_;
    }
    // See the corresponding plan accessor. This compatibility accessor is
    // relative by value and cannot expose an absolute CWD fact.
    [[nodiscard]] const std::string& working_directory_absolute() const noexcept {
        return namespace_relative_cwd_;
    }
    [[nodiscard]] const std::string& namespace_relative_cwd() const noexcept {
        return namespace_relative_cwd_;
    }
    [[nodiscard]] const std::string& primary_source() const noexcept { return primary_source_; }
    [[nodiscard]] const std::vector<DecodedPublicFileRow>& public_file_rows() const noexcept {
        return public_file_rows_;
    }
    [[nodiscard]] const std::vector<std::string>& requested_argv() const noexcept {
        return requested_argv_;
    }
    [[nodiscard]] const std::vector<std::string>& collector_launch_argv() const noexcept {
        return collector_launch_argv_;
    }
    [[nodiscard]] const std::string& absolute_primary_source() const noexcept {
        return absolute_primary_source_;
    }
    [[nodiscard]] const std::vector<std::uint8_t>&
    capture_context_cbor_bytes() const noexcept {
        return capture_context_cbor_bytes_;
    }
    [[nodiscard]] const HarnessExpectations& harness_expectations() const noexcept {
        return harness_expectations_;
    }
    [[nodiscard]] int retained_working_directory_fd() const noexcept {
        return retained_working_directory_fd_.get();
    }
    [[nodiscard]] const WorkDirectoryIdentity& retained_working_directory_identity() const noexcept {
        return retained_working_directory_identity_;
    }
    // The digest never crosses this native boundary. Equality is sufficient
    // for local consistency tests without exposing digest material.
    [[nodiscard]] bool has_same_private_binding(const ValidatedPrelaunchContext& other) const noexcept;

private:
    friend class ValidatedPrelaunchPlan;
    friend class CompletedNativeCaptureSuccess;
    friend class CaptureSession;
    friend class PtraceOpenSupervisor;
    friend class PrivateBridgeEncoder;
#if defined(EVALUATION_V631302_PRIVATE_BRIDGE_V3_TEST_ONLY)
    friend class PrivateBridgeV3FixtureAccess;
#endif

    [[nodiscard]] const Sha256Digest& private_context_binding_digest() const noexcept {
        return private_context_binding_digest_;
    }
    [[nodiscard]] const Sha256Digest32&
    validated_prelaunch_expectations_root() const noexcept {
        return validated_prelaunch_expectations_root_;
    }

    ValidatedPrelaunchContext(
        ValidatedPrelaunchPlan&& plan,
        OwnedFd retained_working_directory_fd,
        WorkDirectoryIdentity retained_working_directory_identity,
        Sha256Digest private_context_binding_digest) noexcept;

    ValidatedCollectorProfileBuildLabelText collector_profile_build_label_text_;
    ExactGnuBuildIdDescriptorBytes expected_collector_gnu_build_id_descriptor_bytes_;
    Sha256Digest32 validated_prelaunch_expectations_root_{};
    std::vector<std::uint8_t> collector_profile_cbor_bytes_;
    std::uint64_t argv_grammar_version_ = 0u;
    Sha256Digest argv_grammar_sha256_{};
    std::vector<std::uint8_t> path_profile_cbor_bytes_;
    std::string namespace_relative_cwd_;
    std::string primary_source_;
    std::vector<std::uint8_t> public_file_rows_cbor_bytes_;
    std::vector<std::string> requested_argv_;
    std::string absolute_primary_source_;
    std::vector<std::uint8_t> capture_context_cbor_bytes_;
    std::vector<std::string> collector_launch_argv_;
    HarnessExpectations harness_expectations_{};
    DecodedPathProfileV2 path_profile_;
    std::vector<DecodedPublicFileRow> public_file_rows_;
    OwnedFd retained_working_directory_fd_;
    WorkDirectoryIdentity retained_working_directory_identity_{};
    Sha256Digest private_context_binding_digest_{};
};

enum class ValidatedPrelaunchContextSlotState : std::uint8_t {
    Empty,
    Committed,
    Aborted,
    MovedFrom,
};

// One-shot local commit boundary used by the parent custody transaction. A
// context whose ACK send fails is destroyed by abort() and cannot escape.
class ValidatedPrelaunchContextSlot final {
public:
    ValidatedPrelaunchContextSlot() noexcept = default;
    ValidatedPrelaunchContextSlot(const ValidatedPrelaunchContextSlot&) = delete;
    ValidatedPrelaunchContextSlot& operator=(const ValidatedPrelaunchContextSlot&) = delete;
    ValidatedPrelaunchContextSlot(ValidatedPrelaunchContextSlot&&) = delete;
    ValidatedPrelaunchContextSlot& operator=(ValidatedPrelaunchContextSlot&&) = delete;

    [[nodiscard]] ValidatedPrelaunchContextSlotState state() const noexcept { return state_; }

private:
    friend class ValidatedPrelaunchPlan;

    void commit(ValidatedPrelaunchContext&& context);
    void abort() noexcept;
    [[nodiscard]] ValidatedPrelaunchContext take_committed() &&;

    std::optional<ValidatedPrelaunchContext> context_;
    ValidatedPrelaunchContextSlotState state_ = ValidatedPrelaunchContextSlotState::Empty;
};

}  // namespace evaluation_v6_3_1::capture_v2

#endif  // EVALUATION_V6_3_1_CAPTURE_V2_PRELAUNCH_CONTEXT_H
