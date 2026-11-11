#pragma once

#include "V631302TraceEmitter.h"

#include <algorithm>
#include <cstdint>
#include <mutex>
#include <stdexcept>

// Exact protocol-631302 run binding for the future native engine gateway.
// This is offline conformance code: sealed descriptor injection, durable trace
// persistence, and opened-engine integration are deliberately still absent.
namespace v631302 {

inline constexpr bool kEngineSessionBindingImplemented = true;
inline constexpr bool kEngineSessionTransactionSinkWiringImplemented = true;
inline constexpr bool kPrivateSeedCapabilitySynchronized = true;
inline constexpr bool kEngineSessionConnectedToOpenedEngine = false;
inline constexpr bool kSealedCapabilityDescriptorImplemented = false;
inline constexpr bool kDurableEngineJournalImplemented = false;
inline constexpr bool kEngineSessionCampaignAuthority = false;

struct PublicRunDescriptor {
	Root seed_commitment_root{};
	Root panel_schedule_root{};
	std::uint32_t common_seed_id = 0U;
	Root candidate_archive_sha256{};
	Root control_archive_sha256{};
	std::uint8_t candidate_seat = 0U;
	Root engine_binary_sha256{};
	Root ruleset_sha256{};
	Root card_catalog_sha256{};
	Root candidate_deck_root{};
	Root control_deck_root{};
	Root run_manifest_root{};
};

inline Root derive_match_id(const PublicRunDescriptor& descriptor) {
	if (descriptor.candidate_seat > 1U) {
		throw std::invalid_argument("631302 candidate seat must be zero or one");
	}
	static constexpr char domain[] = "V631/P3A/MATCH\0";
	Bytes preimage;
	preimage.reserve(
		(sizeof(domain) - 1U) + descriptor.panel_schedule_root.size()
		+ 4U + descriptor.candidate_archive_sha256.size()
		+ descriptor.control_archive_sha256.size() + 1U
	);
	detail::append_literal(preimage, domain);
	preimage.insert(
		preimage.end(),
		descriptor.panel_schedule_root.begin(),
		descriptor.panel_schedule_root.end()
	);
	detail::append_u32_be(preimage, descriptor.common_seed_id);
	preimage.insert(
		preimage.end(),
		descriptor.candidate_archive_sha256.begin(),
		descriptor.candidate_archive_sha256.end()
	);
	preimage.insert(
		preimage.end(),
		descriptor.control_archive_sha256.begin(),
		descriptor.control_archive_sha256.end()
	);
	preimage.push_back(descriptor.candidate_seat);
	return detail::sha256(preimage);
}

inline Bytes encode_run_binding(
	const PublicRunDescriptor& descriptor,
	const Root& match_id
) {
	if (descriptor.candidate_seat > 1U || match_id != derive_match_id(descriptor)) {
		throw std::invalid_argument("631302 run binding does not match its descriptor");
	}
	Bytes output;
	detail::cbor_array(output, 15U);
	detail::cbor_uint(output, kProtocolVersion);
	detail::cbor_uint(output, 2U);
	detail::cbor_bytes(output, descriptor.seed_commitment_root);
	detail::cbor_bytes(output, descriptor.panel_schedule_root);
	detail::cbor_bytes(output, match_id);
	detail::cbor_uint(output, descriptor.common_seed_id);
	detail::cbor_bytes(output, descriptor.candidate_archive_sha256);
	detail::cbor_bytes(output, descriptor.control_archive_sha256);
	detail::cbor_uint(output, descriptor.candidate_seat);
	detail::cbor_bytes(output, descriptor.engine_binary_sha256);
	detail::cbor_bytes(output, descriptor.ruleset_sha256);
	detail::cbor_bytes(output, descriptor.card_catalog_sha256);
	detail::cbor_bytes(output, descriptor.candidate_deck_root);
	detail::cbor_bytes(output, descriptor.control_deck_root);
	detail::cbor_bytes(output, descriptor.run_manifest_root);
	return output;
}

inline Root derive_run_binding_root(const Bytes& run_binding_bytes) {
	static constexpr char domain[] = "V631/P3A/RUN-BIND\0";
	return detail::hash_with_domain(
		domain, sizeof(domain) - 1U, run_binding_bytes
	);
}

inline Root derive_schedule_seed(
	const Root& evaluator_secret,
	const Root& panel_schedule_root,
	std::uint32_t common_seed_id
) {
	static constexpr char domain[] = "V631/P3A/SCHEDULE\0";
	Bytes message;
	message.reserve(
		(sizeof(domain) - 1U) + panel_schedule_root.size() + 4U
	);
	detail::append_literal(message, domain);
	message.insert(
		message.end(), panel_schedule_root.begin(), panel_schedule_root.end()
	);
	detail::append_u32_be(message, common_seed_id);
	return detail::hmac_sha256(evaluator_secret, message);
}

class PrivateSeedCapability {
public:
	explicit PrivateSeedCapability(const Root& evaluator_secret)
		: evaluator_secret_(evaluator_secret) {}

	PrivateSeedCapability(const PrivateSeedCapability&) = delete;
	PrivateSeedCapability& operator=(const PrivateSeedCapability&) = delete;
	PrivateSeedCapability(PrivateSeedCapability&&) = delete;
	PrivateSeedCapability& operator=(PrivateSeedCapability&&) = delete;

	~PrivateSeedCapability() noexcept { erase(); }

	bool consumed() const {
		std::lock_guard<std::mutex> lock(mutex_);
		return consumed_;
	}

private:
	friend class EngineSession;

	Root consume_schedule_seed(
		const Root& panel_schedule_root,
		std::uint32_t common_seed_id
	) {
		std::lock_guard<std::mutex> lock(mutex_);
		if (consumed_) {
			throw std::logic_error("631302 private seed capability was already consumed");
		}
		const Root result = derive_schedule_seed(
			evaluator_secret_, panel_schedule_root, common_seed_id
		);
		erase();
		consumed_ = true;
		return result;
	}

	void erase() noexcept {
		volatile std::uint8_t* output = evaluator_secret_.data();
		for (std::size_t index = 0U; index < evaluator_secret_.size(); ++index) {
			output[index] = 0U;
		}
	}

	Root evaluator_secret_{};
	mutable std::mutex mutex_;
	bool consumed_ = false;
};

class EngineSession {
public:
	EngineSession(
		const PublicRunDescriptor& descriptor,
		PrivateSeedCapability& capability,
		TraceTransactionSink* transaction_sink = nullptr
	) : EngineSession(
		build_material(descriptor, capability), transaction_sink
	) {}

	EngineSession(const EngineSession&) = delete;
	EngineSession& operator=(const EngineSession&) = delete;
	EngineSession(EngineSession&&) = delete;
	EngineSession& operator=(EngineSession&&) = delete;

	Root bind_stream(
		const Root& site_id,
		const Root& object_instance_id,
		std::uint16_t purpose_code,
		std::uint32_t stream_ordinal
	) {
		return emitter_.bind_stream(
			site_id, object_instance_id, purpose_code, stream_ordinal
		);
	}

	std::uint64_t raw_draw(const Root& stream_id) {
		return emitter_.raw_draw(stream_id);
	}

	BoundedResult bounded(
		const Root& stream_id,
		std::uint64_t upper_exclusive
	) {
		return emitter_.bounded(stream_id, upper_exclusive);
	}

	void close(
		const Root& canonical_trace_manifest_root,
		const Root& end_engine_state_root,
		std::uint16_t close_code = 0U
	) {
		emitter_.close(
			descriptor_.seed_commitment_root,
			run_binding_root_,
			canonical_trace_manifest_root,
			end_engine_state_root,
			close_code
		);
	}

	const Root& match_id() const noexcept { return match_id_; }
	const Root& run_binding_root() const noexcept { return run_binding_root_; }
	const Bytes& run_binding_bytes() const noexcept { return run_binding_bytes_; }
	const Bytes& trace_bytes() const { return emitter_.trace_bytes(); }
	const Root& trace_root() const { return emitter_.trace_root(); }
	std::uint64_t event_count() const { return emitter_.event_count(); }
	bool closed() const { return emitter_.closed(); }

private:
	struct Material {
		PublicRunDescriptor descriptor;
		Root match_id{};
		Bytes run_binding_bytes;
		Root run_binding_root{};
		Root schedule_seed{};
	};

	static Material build_material(
		const PublicRunDescriptor& descriptor,
		PrivateSeedCapability& capability
	) {
		if (descriptor.candidate_seat > 1U) {
			throw std::invalid_argument("631302 candidate seat must be zero or one");
		}
		Material output{};
		output.descriptor = descriptor;
		output.match_id = derive_match_id(descriptor);
		output.run_binding_bytes = encode_run_binding(descriptor, output.match_id);
		output.run_binding_root = derive_run_binding_root(output.run_binding_bytes);
		output.schedule_seed = capability.consume_schedule_seed(
			descriptor.panel_schedule_root, descriptor.common_seed_id
		);
		return output;
	}

	explicit EngineSession(
		Material material,
		TraceTransactionSink* transaction_sink
	)
		: descriptor_(material.descriptor),
		  match_id_(material.match_id),
		  run_binding_bytes_(std::move(material.run_binding_bytes)),
		  run_binding_root_(material.run_binding_root),
		  emitter_(run_binding_root_, material.schedule_seed, transaction_sink) {
		volatile std::uint8_t* schedule = material.schedule_seed.data();
		for (std::size_t index = 0U; index < material.schedule_seed.size(); ++index) {
			schedule[index] = 0U;
		}
	}

	PublicRunDescriptor descriptor_{};
	Root match_id_{};
	Bytes run_binding_bytes_;
	Root run_binding_root_{};
	TraceEmitter emitter_;
};

}  // namespace v631302
