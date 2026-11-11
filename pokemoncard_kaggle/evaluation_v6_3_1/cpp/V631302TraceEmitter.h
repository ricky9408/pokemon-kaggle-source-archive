#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <map>
#include <mutex>
#include <new>
#include <set>
#include <stdexcept>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

// This component is an offline native conformance probe. It is intentionally
// not connected to the engine and provides no persistence or campaign authority.
namespace v631302 {

using Root = std::array<std::uint8_t, 32>;
using Bytes = std::vector<std::uint8_t>;

inline constexpr std::uint64_t kProtocolVersion = 631302U;
inline constexpr bool kEngineIntegrated = false;
inline constexpr bool kDurablePersistenceImplemented = false;
inline constexpr bool kAtomicTransactionSinkImplemented = true;
inline constexpr bool kOwnerThreadEnforcementImplemented = true;
inline constexpr bool kSinkCallbackReentryRejected = true;
inline constexpr bool kProcessWideRegistryImplemented = false;
inline constexpr bool kTranslationUnitRegistryImplemented = true;
inline constexpr bool kDerivedKeyZeroizationImplemented = false;
inline constexpr bool kSensitiveHmacBufferWipeImplemented = true;
inline constexpr bool kCampaignAuthority = false;

inline constexpr std::uint8_t kStreamBind = 3U;
inline constexpr std::uint8_t kRawDraw = 4U;
inline constexpr std::uint8_t kBoundedSample = 5U;
inline constexpr std::uint8_t kSessionClose = 12U;

inline constexpr Root kZeroRoot{};

namespace detail {

template <typename Value>
inline void secure_zero(Value& value) noexcept {
	volatile std::uint8_t* output = reinterpret_cast<volatile std::uint8_t*>(
		value.data()
	);
	for (std::size_t index = 0U; index < value.size() * sizeof(value[0]); ++index) {
		output[index] = 0U;
	}
}

struct HmacScratch final {
	std::array<std::uint8_t, 64> inner_pad{};
	std::array<std::uint8_t, 64> outer_pad{};
	Bytes inner;
	Bytes outer;
	Root inner_hash{};

	~HmacScratch() noexcept {
		secure_zero(inner_pad);
		secure_zero(outer_pad);
		secure_zero(inner);
		secure_zero(outer);
		secure_zero(inner_hash);
	}
};

struct Sha256Scratch final {
	Bytes message;
	std::array<std::uint32_t, 8> hash{};
	std::array<std::uint32_t, 64> words{};
	std::array<std::uint32_t, 8> working{};

	~Sha256Scratch() noexcept {
		secure_zero(message);
		secure_zero(hash);
		secure_zero(words);
		secure_zero(working);
	}
};

inline std::uint32_t rotate_right(std::uint32_t value, unsigned int shift) {
	return (value >> shift) | (value << (32U - shift));
}

inline Root sha256(const std::uint8_t* data, std::size_t size) {
	static constexpr std::array<std::uint32_t, 64> constants = {
		0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U,
		0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
		0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
		0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
		0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
		0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
		0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
		0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
		0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
		0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
		0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U,
		0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
		0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U,
		0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
		0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
		0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U,
	};
	if (size > (std::numeric_limits<std::size_t>::max() - 72U)) {
		throw std::length_error("631302 SHA-256 input is too large");
	}
	if (size > std::numeric_limits<std::uint64_t>::max() / 8U) {
		throw std::length_error("631302 SHA-256 bit length overflows");
	}
	Sha256Scratch scratch;
	scratch.hash = {
		0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
		0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U,
	};
	const std::size_t padded_size = ((size + 72U) / 64U) * 64U;
	scratch.message.assign(padded_size, 0U);
	if (size != 0U) {
		std::copy(data, data + size, scratch.message.begin());
	}
	scratch.message[size] = 0x80U;
	const std::uint64_t bit_size = static_cast<std::uint64_t>(size) * 8U;
	for (int index = 0; index < 8; ++index) {
		scratch.message[padded_size - 1U - static_cast<std::size_t>(index)] =
			static_cast<std::uint8_t>(bit_size >> (index * 8));
	}
	for (std::size_t block = 0; block < padded_size; block += 64U) {
		for (int index = 0; index < 16; ++index) {
			const std::size_t offset = block + static_cast<std::size_t>(index) * 4U;
			scratch.words[index] =
				(static_cast<std::uint32_t>(scratch.message[offset]) << 24U)
				| (static_cast<std::uint32_t>(scratch.message[offset + 1U]) << 16U)
				| (static_cast<std::uint32_t>(scratch.message[offset + 2U]) << 8U)
				| static_cast<std::uint32_t>(scratch.message[offset + 3U]);
		}
		for (int index = 16; index < 64; ++index) {
			const std::uint32_t s0 = rotate_right(scratch.words[index - 15], 7U)
				^ rotate_right(scratch.words[index - 15], 18U)
				^ (scratch.words[index - 15] >> 3U);
			const std::uint32_t s1 = rotate_right(scratch.words[index - 2], 17U)
				^ rotate_right(scratch.words[index - 2], 19U)
				^ (scratch.words[index - 2] >> 10U);
			scratch.words[index] =
				scratch.words[index - 16] + s0 + scratch.words[index - 7] + s1;
		}
		scratch.working = scratch.hash;
		auto& a = scratch.working[0];
		auto& b = scratch.working[1];
		auto& c = scratch.working[2];
		auto& d = scratch.working[3];
		auto& e = scratch.working[4];
		auto& f = scratch.working[5];
		auto& g = scratch.working[6];
		auto& h = scratch.working[7];
		for (int index = 0; index < 64; ++index) {
			const std::uint32_t sum1 = rotate_right(e, 6U)
				^ rotate_right(e, 11U) ^ rotate_right(e, 25U);
			const std::uint32_t choose = (e & f) ^ ((~e) & g);
			const std::uint32_t temp1 =
				h + sum1 + choose + constants[index] + scratch.words[index];
			const std::uint32_t sum0 = rotate_right(a, 2U)
				^ rotate_right(a, 13U) ^ rotate_right(a, 22U);
			const std::uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
			const std::uint32_t temp2 = sum0 + majority;
			h = g;
			g = f;
			f = e;
			e = d + temp1;
			d = c;
			c = b;
			b = a;
			a = temp1 + temp2;
		}
		scratch.hash[0] += a;
		scratch.hash[1] += b;
		scratch.hash[2] += c;
		scratch.hash[3] += d;
		scratch.hash[4] += e;
		scratch.hash[5] += f;
		scratch.hash[6] += g;
		scratch.hash[7] += h;
	}
	Root output{};
	for (int index = 0; index < 8; ++index) {
		output[index * 4] = static_cast<std::uint8_t>(scratch.hash[index] >> 24U);
		output[index * 4 + 1] = static_cast<std::uint8_t>(scratch.hash[index] >> 16U);
		output[index * 4 + 2] = static_cast<std::uint8_t>(scratch.hash[index] >> 8U);
		output[index * 4 + 3] = static_cast<std::uint8_t>(scratch.hash[index]);
	}
	return output;
}

inline Root sha256(const Bytes& value) {
	return sha256(value.data(), value.size());
}

template <std::size_t Size>
inline void append_literal(Bytes& output, const char (&value)[Size]) {
	static_assert(Size >= 2U);
	output.insert(output.end(), value, value + Size - 1U);
}

inline Root hmac_sha256(const Root& key, const Bytes& message) {
	HmacScratch scratch;
	for (std::size_t index = 0; index < 64U; ++index) {
		const std::uint8_t key_byte = index < key.size() ? key[index] : 0U;
		scratch.inner_pad[index] = static_cast<std::uint8_t>(key_byte ^ 0x36U);
		scratch.outer_pad[index] = static_cast<std::uint8_t>(key_byte ^ 0x5cU);
	}
	scratch.inner.reserve(scratch.inner_pad.size() + message.size());
	scratch.inner.insert(
		scratch.inner.end(), scratch.inner_pad.begin(), scratch.inner_pad.end()
	);
	scratch.inner.insert(scratch.inner.end(), message.begin(), message.end());
	scratch.inner_hash = sha256(scratch.inner);
	scratch.outer.reserve(scratch.outer_pad.size() + scratch.inner_hash.size());
	scratch.outer.insert(
		scratch.outer.end(), scratch.outer_pad.begin(), scratch.outer_pad.end()
	);
	scratch.outer.insert(
		scratch.outer.end(), scratch.inner_hash.begin(), scratch.inner_hash.end()
	);
	return sha256(scratch.outer);
}

inline void cbor_length(Bytes& output, std::uint8_t major, std::uint64_t value) {
	const std::uint8_t prefix = static_cast<std::uint8_t>(major << 5U);
	if (value < 24U) {
		output.push_back(static_cast<std::uint8_t>(prefix | value));
	} else if (value <= 0xffU) {
		output.push_back(static_cast<std::uint8_t>(prefix | 24U));
		output.push_back(static_cast<std::uint8_t>(value));
	} else if (value <= 0xffffU) {
		output.push_back(static_cast<std::uint8_t>(prefix | 25U));
		output.push_back(static_cast<std::uint8_t>(value >> 8U));
		output.push_back(static_cast<std::uint8_t>(value));
	} else if (value <= 0xffffffffULL) {
		output.push_back(static_cast<std::uint8_t>(prefix | 26U));
		for (int shift = 24; shift >= 0; shift -= 8) {
			output.push_back(static_cast<std::uint8_t>(value >> shift));
		}
	} else {
		output.push_back(static_cast<std::uint8_t>(prefix | 27U));
		for (int shift = 56; shift >= 0; shift -= 8) {
			output.push_back(static_cast<std::uint8_t>(value >> shift));
		}
	}
}

inline void cbor_array(Bytes& output, std::uint64_t size) {
	cbor_length(output, 4U, size);
}

inline void cbor_bytes(Bytes& output, const Root& value) {
	cbor_length(output, 2U, value.size());
	output.insert(output.end(), value.begin(), value.end());
}

inline void cbor_uint(Bytes& output, std::uint64_t value) {
	cbor_length(output, 0U, value);
}

inline void append_u16_be(Bytes& output, std::uint16_t value) {
	output.push_back(static_cast<std::uint8_t>(value >> 8U));
	output.push_back(static_cast<std::uint8_t>(value));
}

inline void append_u32_be(Bytes& output, std::uint32_t value) {
	for (int shift = 24; shift >= 0; shift -= 8) {
		output.push_back(static_cast<std::uint8_t>(value >> shift));
	}
}

inline void append_u64_be(Bytes& output, std::uint64_t value) {
	for (int shift = 56; shift >= 0; shift -= 8) {
		output.push_back(static_cast<std::uint8_t>(value >> shift));
	}
}

inline Root hash_with_domain(const char* domain, std::size_t domain_size, const Bytes& value) {
	Bytes preimage;
	preimage.reserve(domain_size + value.size());
	preimage.insert(preimage.end(), domain, domain + domain_size);
	preimage.insert(preimage.end(), value.begin(), value.end());
	return sha256(preimage);
}

inline Root derive_stream_id(
	const Root& session_id,
	const Root& site_id,
	const Root& object_instance_id,
	std::uint16_t purpose_code,
	std::uint32_t stream_ordinal
) {
	Bytes semantic_path;
	cbor_array(semantic_path, 4U);
	cbor_bytes(semantic_path, site_id);
	cbor_bytes(semantic_path, object_instance_id);
	cbor_uint(semantic_path, purpose_code);
	cbor_uint(semantic_path, stream_ordinal);
	static constexpr char domain[] = "V631/P3A/STREAM-ID\0";
	Bytes preimage;
	preimage.reserve(sizeof(domain) - 1U + session_id.size() + semantic_path.size());
	append_literal(preimage, domain);
	preimage.insert(preimage.end(), session_id.begin(), session_id.end());
	preimage.insert(preimage.end(), semantic_path.begin(), semantic_path.end());
	return sha256(preimage);
}

inline Root derive_stream_key(
	const Root& schedule_seed,
	const Root& site_id,
	const Root& object_instance_id,
	std::uint16_t purpose_code,
	std::uint32_t stream_ordinal
) {
	static constexpr char domain[] = "V631/P3A/STREAM-KEY\0";
	Bytes message;
	message.reserve(sizeof(domain) - 1U + 32U + 32U + 2U + 4U);
	append_literal(message, domain);
	message.insert(message.end(), site_id.begin(), site_id.end());
	message.insert(message.end(), object_instance_id.begin(), object_instance_id.end());
	append_u16_be(message, purpose_code);
	append_u32_be(message, stream_ordinal);
	return hmac_sha256(schedule_seed, message);
}

inline std::uint64_t derive_raw_value(const Root& stream_key, std::uint64_t counter) {
	static constexpr char domain[] = "V631/P3A/RAW\0";
	Bytes message;
	message.reserve(sizeof(domain) - 1U + 8U);
	append_literal(message, domain);
	append_u64_be(message, counter);
	const Root digest = hmac_sha256(stream_key, message);
	std::uint64_t value = 0;
	for (std::size_t index = 0; index < 8U; ++index) {
		value = (value << 8U) | digest[index];
	}
	return value;
}

inline Root event_hash(const Bytes& event) {
	static constexpr char domain[] = "V631/P3A/EVENT/631302\0";
	return hash_with_domain(domain, sizeof(domain) - 1U, event);
}

}  // namespace detail

namespace registry_detail {

enum class SessionState : std::uint8_t {
	Open = 0U,
	Closed = 1U,
};

struct SessionEntry {
	std::uint64_t owner_nonce = 0U;
	std::uint64_t registry_generation = 0U;
	std::thread::id owning_thread{};
	SessionState state = SessionState::Open;
};

struct StreamEntry {
	std::uint64_t owner_nonce = 0U;
	std::uint64_t registry_generation = 0U;
	std::thread::id owning_thread{};
	std::uint64_t raw_counter = 0U;
	std::uint64_t next_shuffle_id = 0U;
	std::uint64_t next_branch_ordinal = 0U;
	std::set<Root> open_branch_ids;
	Root latest_checkpoint{};
	SessionState session_state = SessionState::Open;
};

struct ProcessRegistry {
	std::mutex mutex;
	std::map<Root, SessionEntry> sessions;
	std::map<std::pair<Root, Root>, StreamEntry> streams;
	std::uint64_t next_owner_nonce = 1U;
	std::uint64_t next_generation = 1U;
};

inline constexpr std::size_t kMaximumSessionTombstones = 65536U;
inline constexpr std::size_t kMaximumStreamsPerSession = 4096U;
inline constexpr std::size_t kMaximumRegistryStreams = 262144U;

inline ProcessRegistry& process_registry() {
	static ProcessRegistry registry;
	return registry;
}

#ifdef V631302_TRACE_TEST_HOOKS
inline std::size_t test_stream_count_for_session(const Root& session_id) {
	auto& registry = process_registry();
	std::lock_guard<std::mutex> lock(registry.mutex);
	std::size_t count = 0U;
	for (const auto& [key, value] : registry.streams) {
		(void)value;
		if (key.first == session_id) ++count;
	}
	return count;
}

inline std::size_t test_session_tombstone_count() {
	auto& registry = process_registry();
	std::lock_guard<std::mutex> lock(registry.mutex);
	return registry.sessions.size();
}
#endif

inline std::uint64_t take_counter(std::uint64_t& counter, const char* label) {
	if (counter == std::numeric_limits<std::uint64_t>::max()) {
		throw std::overflow_error(label);
	}
	const std::uint64_t value = counter;
	++counter;
	return value;
}

}  // namespace registry_detail

struct BoundedResult {
	std::uint64_t result = 0;
	std::uint64_t first_raw_counter = 0;
	std::uint32_t raw_draw_count = 0;
	std::uint64_t accepted_raw_counter = 0;
};

class TraceTransactionSink {
public:
	virtual ~TraceTransactionSink() = default;

	virtual void commit(
		const Bytes& transaction_bytes,
		std::uint64_t first_global_sequence,
		std::uint64_t event_count,
		const Root& previous_global_event_hash,
		const Root& final_global_event_hash
	) = 0;
};

class TraceEmitter {
public:
	TraceEmitter(
		const Root& session_id,
		const Root& schedule_seed,
		TraceTransactionSink* transaction_sink = nullptr
	)
		: session_id_(session_id), schedule_seed_(schedule_seed),
		  transaction_sink_(transaction_sink),
		  owner_thread_(std::this_thread::get_id()) {
		try {
				auto& registry = registry_detail::process_registry();
				std::lock_guard<std::mutex> lock(registry.mutex);
				if (registry.sessions.contains(session_id_)) {
					throw std::logic_error("631302 session is already registered in this module");
				}
				if (registry.sessions.size() >= registry_detail::kMaximumSessionTombstones) {
					throw std::overflow_error("631302 module registry session bound is exhausted");
				}
			const std::uint64_t owner_nonce = registry_detail::take_counter(
				registry.next_owner_nonce, "631302 owner nonce exhausted"
			);
			const std::uint64_t generation = registry_detail::take_counter(
				registry.next_generation, "631302 registry generation exhausted"
			);
			registry.sessions.emplace(
				session_id_,
				registry_detail::SessionEntry{
					owner_nonce, generation, owner_thread_, registry_detail::SessionState::Open
				}
			);
			owner_nonce_ = owner_nonce;
		} catch (...) {
			detail::secure_zero(schedule_seed_);
			throw;
		}
	}

	~TraceEmitter() noexcept {
		erase_derived_keys();
		try {
			auto& registry = registry_detail::process_registry();
			std::lock_guard<std::mutex> lock(registry.mutex);
			for (auto iterator = registry.streams.begin(); iterator != registry.streams.end();) {
				if (
					iterator->first.first == session_id_
					&& iterator->second.owner_nonce == owner_nonce_
				) {
					iterator = registry.streams.erase(iterator);
				} else {
					++iterator;
				}
			}
		} catch (...) {
			// Destruction cannot recover registry cleanup failures. The registry is
			// still bounded and this substrate remains zero-authority.
		}
	}

	TraceEmitter(const TraceEmitter&) = delete;
	TraceEmitter& operator=(const TraceEmitter&) = delete;
	TraceEmitter(TraceEmitter&&) = delete;
	TraceEmitter& operator=(TraceEmitter&&) = delete;

	Root bind_stream(
		const Root& site_id,
		const Root& object_instance_id,
		std::uint16_t purpose_code,
		std::uint32_t stream_ordinal
	) {
		check_owner_thread();
		check_sink_callback_reentry();
		ensure_open();
		auto& registry = registry_detail::process_registry();
		std::lock_guard<std::mutex> lock(registry.mutex);
		checked_registry_session(registry);
		if (streams_.size() >= registry_detail::kMaximumStreamsPerSession) {
			throw std::overflow_error("631302 per-session stream registry bound is exhausted");
		}
		if (registry.streams.size() >= registry_detail::kMaximumRegistryStreams) {
			throw std::overflow_error("631302 module registry stream bound is exhausted");
		}
		const Root stream_id = detail::derive_stream_id(
			session_id_, site_id, object_instance_id, purpose_code, stream_ordinal
		);
		if (stream_id == kZeroRoot || streams_.contains(stream_id)) {
			throw std::logic_error("631302 stream binding is zero or duplicated");
		}
		Bytes payload;
		detail::cbor_array(payload, 4U);
		detail::cbor_bytes(payload, site_id);
		detail::cbor_bytes(payload, object_instance_id);
		detail::cbor_uint(payload, purpose_code);
		detail::cbor_uint(payload, stream_ordinal);
		const Event event = prepare_event(
			kStreamBind, stream_id, kZeroRoot, kZeroRoot, kZeroRoot, payload
		);
		const auto inserted = streams_.try_emplace(stream_id);
		if (!inserted.second) {
			throw std::logic_error("631302 stream binding raced with a duplicate");
		}
		const auto registry_key = std::make_pair(session_id_, stream_id);
		auto registry_iterator = registry.streams.end();
		bool registry_owned = false;
		try {
			inserted.first->second.key = detail::derive_stream_key(
				schedule_seed_, site_id, object_instance_id, purpose_code, stream_ordinal
			);
			const std::uint64_t generation = registry_detail::take_counter(
				registry.next_generation, "631302 registry generation exhausted"
			);
			const auto registry_inserted = registry.streams.emplace(
				registry_key,
				registry_detail::StreamEntry{
					owner_nonce_, generation, owner_thread_, 0U, 0U, 0U, {},
					kZeroRoot, registry_detail::SessionState::Open
				}
			);
			if (!registry_inserted.second) {
					throw std::logic_error("631302 module-local stream binding is duplicated");
			}
			registry_iterator = registry_inserted.first;
			registry_owned = true;
			append_event(event);
			inserted.first->second.event_hash = event.hash;
		} catch (...) {
			if (registry_owned) registry.streams.erase(registry_iterator);
			detail::secure_zero(inserted.first->second.key);
			streams_.erase(inserted.first);
			throw;
		}
		return stream_id;
	}

	std::uint64_t raw_draw(const Root& stream_id) {
		check_owner_thread();
		check_sink_callback_reentry();
		ensure_open();
		auto& registry = registry_detail::process_registry();
		std::lock_guard<std::mutex> lock(registry.mutex);
		checked_registry_session(registry);
		auto& stream = checked_stream(stream_id);
		auto& registered_stream = checked_registry_stream(registry, stream_id, stream.raw_counter);
		const std::uint64_t generation = registry_detail::take_counter(
			registry.next_generation, "631302 registry generation exhausted"
		);
		if (stream.raw_counter == std::numeric_limits<std::uint64_t>::max()) {
			throw std::overflow_error("631302 raw counter exhausted");
		}
		const std::uint64_t counter = stream.raw_counter;
		const std::uint64_t value = detail::derive_raw_value(stream.key, counter);
		Bytes payload;
		detail::cbor_array(payload, 3U);
		detail::cbor_bytes(payload, kZeroRoot);
		detail::cbor_uint(payload, counter);
		detail::cbor_uint(payload, value);
		const Event event = prepare_event(
			kRawDraw, stream_id, stream.event_hash, kZeroRoot, kZeroRoot, payload
		);
		append_event(event);
		stream.event_hash = event.hash;
		++stream.raw_counter;
		registered_stream.raw_counter = stream.raw_counter;
		registered_stream.registry_generation = generation;
		return value;
	}

	BoundedResult bounded(const Root& stream_id, std::uint64_t upper_exclusive) {
		check_owner_thread();
		check_sink_callback_reentry();
		ensure_open();
		if (upper_exclusive == 0U) {
			throw std::invalid_argument("631302 bounded sample requires a positive upper bound");
		}
		auto& registry = registry_detail::process_registry();
		std::lock_guard<std::mutex> lock(registry.mutex);
		checked_registry_session(registry);
		auto& stream = checked_stream(stream_id);
		auto& registered_stream = checked_registry_stream(registry, stream_id, stream.raw_counter);
		const std::uint64_t generation = registry_detail::take_counter(
			registry.next_generation, "631302 registry generation exhausted"
		);
		Root staged_stream_hash = stream.event_hash;
		std::uint64_t staged_raw_counter = stream.raw_counter;
		Root staged_global_hash = previous_global_event_hash_;
		std::uint64_t staged_sequence = next_global_sequence_;
		std::vector<Event> events;
		const std::uint64_t first = staged_raw_counter;
		const std::uint64_t remainder =
			(std::numeric_limits<std::uint64_t>::max() % upper_exclusive
			 + (1U % upper_exclusive)) % upper_exclusive;
		std::uint32_t count = 0U;
		std::uint64_t accepted_value = 0U;
		while (true) {
			if (count == std::numeric_limits<std::uint32_t>::max()) {
				throw std::overflow_error("631302 bounded draw count exhausted");
			}
			if (staged_sequence == std::numeric_limits<std::uint64_t>::max()) {
				throw std::overflow_error("631302 global event sequence exhausted");
			}
			if (staged_raw_counter == std::numeric_limits<std::uint64_t>::max()) {
				throw std::overflow_error("631302 raw counter exhausted");
			}
			const std::uint64_t counter = staged_raw_counter;
			accepted_value = detail::derive_raw_value(stream.key, counter);
			Bytes raw_payload;
			detail::cbor_array(raw_payload, 3U);
			detail::cbor_bytes(raw_payload, kZeroRoot);
			detail::cbor_uint(raw_payload, counter);
			detail::cbor_uint(raw_payload, accepted_value);
			Event raw_event = prepare_event_at(
				kRawDraw,
				stream_id,
				staged_stream_hash,
				kZeroRoot,
				kZeroRoot,
				raw_payload,
				staged_sequence,
				staged_global_hash
			);
			events.push_back(raw_event);
			staged_stream_hash = raw_event.hash;
			staged_global_hash = raw_event.hash;
			++staged_raw_counter;
			++staged_sequence;
			++count;
			if (
				remainder == 0U
				|| accepted_value <= std::numeric_limits<std::uint64_t>::max() - remainder
			) {
				break;
			}
		}
		const std::uint64_t accepted_counter = first + count - 1U;
		const std::uint64_t result = accepted_value % upper_exclusive;
		if (staged_sequence == std::numeric_limits<std::uint64_t>::max()) {
			throw std::overflow_error("631302 global event sequence exhausted");
		}
		Bytes payload;
		detail::cbor_array(payload, 6U);
		detail::cbor_bytes(payload, kZeroRoot);
		detail::cbor_uint(payload, upper_exclusive);
		detail::cbor_uint(payload, first);
		detail::cbor_uint(payload, count);
		detail::cbor_uint(payload, accepted_counter);
		detail::cbor_uint(payload, result);
		Event bounded_event = prepare_event_at(
			kBoundedSample,
			stream_id,
			staged_stream_hash,
			kZeroRoot,
			kZeroRoot,
			payload,
			staged_sequence,
			staged_global_hash
		);
		events.push_back(bounded_event);
		staged_stream_hash = bounded_event.hash;

		append_events(events);
		stream.event_hash = staged_stream_hash;
		stream.raw_counter = staged_raw_counter;
		registered_stream.raw_counter = staged_raw_counter;
		registered_stream.registry_generation = generation;
		return {result, first, count, accepted_counter};
	}

	void close(
		const Root& seed_commitment_root,
		const Root& run_binding_root,
		const Root& canonical_trace_manifest_root,
		const Root& end_engine_state_root,
		std::uint16_t close_code = 0U
	) {
		check_owner_thread();
		check_sink_callback_reentry();
		ensure_open();
		auto& registry = registry_detail::process_registry();
		std::lock_guard<std::mutex> lock(registry.mutex);
		auto& registered_session = checked_registry_session(registry);
		std::vector<registry_detail::StreamEntry*> registered_streams;
		registered_streams.reserve(streams_.size());
		for (const auto& [stream_id, stream] : streams_) {
			registered_streams.push_back(&checked_registry_stream(
				registry, stream_id, stream.raw_counter
			));
		}
		const std::uint64_t session_generation = registry_detail::take_counter(
			registry.next_generation, "631302 registry generation exhausted"
		);
		std::vector<std::uint64_t> stream_generations;
		stream_generations.reserve(registered_streams.size());
		for (std::size_t index = 0U; index < registered_streams.size(); ++index) {
			stream_generations.push_back(registry_detail::take_counter(
				registry.next_generation, "631302 registry generation exhausted"
			));
		}
		if (run_binding_root != session_id_) {
			throw std::invalid_argument("631302 session ID must equal run binding root");
		}
		if (next_global_sequence_ == std::numeric_limits<std::uint64_t>::max()) {
			throw std::overflow_error("631302 global event sequence exhausted");
		}
		Bytes payload;
		detail::cbor_array(payload, 9U);
		detail::cbor_bytes(payload, seed_commitment_root);
		detail::cbor_bytes(payload, run_binding_root);
		detail::cbor_uint(payload, next_global_sequence_ + 1U);
		detail::cbor_array(payload, streams_.size());
		for (const auto& [stream_id, stream] : streams_) {
			detail::cbor_array(payload, 5U);
			detail::cbor_bytes(payload, stream_id);
			detail::cbor_uint(payload, stream.raw_counter);
			detail::cbor_uint(payload, 0U);
			detail::cbor_uint(payload, 0U);
			detail::cbor_bytes(payload, stream.event_hash);
		}
		detail::cbor_bytes(payload, kZeroRoot);
		detail::cbor_bytes(payload, canonical_trace_manifest_root);
		detail::cbor_bytes(payload, end_engine_state_root);
		detail::cbor_uint(payload, 0U);
		detail::cbor_uint(payload, close_code);
		const Event event = prepare_event(
			kSessionClose, kZeroRoot, kZeroRoot, kZeroRoot, kZeroRoot, payload
		);
		append_event(event);
		closed_ = true;
		registered_session.state = registry_detail::SessionState::Closed;
		registered_session.registry_generation = session_generation;
		for (std::size_t index = 0U; index < registered_streams.size(); ++index) {
			registered_streams[index]->session_state = registry_detail::SessionState::Closed;
			registered_streams[index]->registry_generation = stream_generations[index];
		}
		erase_derived_keys();
	}

	const Bytes& trace_bytes() const { check_owner_thread(); return trace_; }
	const Root& trace_root() const { check_owner_thread(); return previous_global_event_hash_; }
	std::uint64_t event_count() const { check_owner_thread(); return next_global_sequence_; }
	bool closed() const { check_owner_thread(); return closed_; }

#ifdef V631302_TRACE_TEST_HOOKS
	void test_fail_next_append() noexcept {
		fail_at_sequence_ = next_global_sequence_;
		has_fail_sequence_ = true;
	}

	void test_fail_append_at_sequence(std::uint64_t sequence) noexcept {
		fail_at_sequence_ = sequence;
		has_fail_sequence_ = true;
	}

	bool test_derived_keys_are_zero() const noexcept {
		if (schedule_seed_ != kZeroRoot) return false;
		return std::all_of(streams_.begin(), streams_.end(), [](const auto& item) {
			return item.second.key == kZeroRoot;
		});
	}
#endif

private:
	class SinkCallbackGuard final {
	public:
		explicit SinkCallbackGuard(bool& active) : active_(active) {
			if (active_) {
				throw std::logic_error("631302 trace sink callback reentered the emitter");
			}
			active_ = true;
		}

		~SinkCallbackGuard() noexcept { active_ = false; }

	private:
		bool& active_;
	};

	struct StreamState {
		Root key{};
		Root event_hash{};
		std::uint64_t raw_counter = 0U;
	};

	struct Event {
		Bytes bytes;
		Root hash{};
	};

	void ensure_open() const {
		if (closed_) {
			throw std::logic_error("631302 trace is already closed");
		}
	}

	void check_owner_thread() const {
		if (std::this_thread::get_id() != owner_thread_) {
			throw std::logic_error("631302 trace emitter crossed its registered OS thread");
		}
	}

	void check_sink_callback_reentry() const {
		if (sink_callback_active_) {
			throw std::logic_error("631302 trace sink callback reentered an emitter mutation");
		}
	}

	registry_detail::SessionEntry& checked_registry_session(
		registry_detail::ProcessRegistry& registry
	) const {
		const auto found = registry.sessions.find(session_id_);
		if (found == registry.sessions.end()
			|| found->second.owner_nonce != owner_nonce_
			|| found->second.owning_thread != owner_thread_
			|| found->second.state != registry_detail::SessionState::Open) {
			throw std::logic_error("631302 module-local session registry disagrees with the emitter");
		}
		return found->second;
	}

	registry_detail::StreamEntry& checked_registry_stream(
		registry_detail::ProcessRegistry& registry,
		const Root& stream_id,
		std::uint64_t expected_raw_counter
	) const {
		const auto found = registry.streams.find(std::make_pair(session_id_, stream_id));
		if (found == registry.streams.end()
			|| found->second.owner_nonce != owner_nonce_
			|| found->second.owning_thread != owner_thread_
			|| found->second.session_state != registry_detail::SessionState::Open
			|| found->second.raw_counter != expected_raw_counter) {
			throw std::logic_error("631302 module-local stream registry disagrees with the emitter");
		}
		return found->second;
	}

	void erase_derived_keys() noexcept {
		detail::secure_zero(schedule_seed_);
		for (auto& [stream_id, stream] : streams_) {
			(void)stream_id;
			detail::secure_zero(stream.key);
		}
	}

	StreamState& checked_stream(const Root& stream_id) {
		const auto found = streams_.find(stream_id);
		if (found == streams_.end()) {
			throw std::invalid_argument("631302 stream is not bound");
		}
		return found->second;
	}

	Event prepare_event(
		std::uint8_t event_type,
		const Root& stream_id,
		const Root& previous_stream_event_hash,
		const Root& branch_context_id,
		const Root& previous_branch_chain_hash,
		const Bytes& payload
	) const {
		return prepare_event_at(
			event_type,
			stream_id,
			previous_stream_event_hash,
			branch_context_id,
			previous_branch_chain_hash,
			payload,
			next_global_sequence_,
			previous_global_event_hash_
		);
	}

	Event prepare_event_at(
		std::uint8_t event_type,
		const Root& stream_id,
		const Root& previous_stream_event_hash,
		const Root& branch_context_id,
		const Root& previous_branch_chain_hash,
		const Bytes& payload,
		std::uint64_t global_sequence,
		const Root& previous_global_event_hash
	) const {
		Bytes event;
		detail::cbor_array(event, 10U);
		detail::cbor_uint(event, kProtocolVersion);
		detail::cbor_uint(event, event_type);
		detail::cbor_bytes(event, session_id_);
		detail::cbor_uint(event, global_sequence);
		detail::cbor_bytes(event, previous_global_event_hash);
		detail::cbor_bytes(event, stream_id);
		detail::cbor_bytes(event, previous_stream_event_hash);
		detail::cbor_bytes(event, branch_context_id);
		detail::cbor_bytes(event, previous_branch_chain_hash);
		event.insert(event.end(), payload.begin(), payload.end());
		return {event, detail::event_hash(event)};
	}

	void append_event(const Event& event) {
		append_events(std::vector<Event>{event});
	}

	void append_events(const std::vector<Event>& events) {
		if (events.empty()) {
			throw std::invalid_argument("631302 trace transaction cannot be empty");
		}
		if (
			events.size() > std::numeric_limits<std::uint64_t>::max() - next_global_sequence_
		) {
			throw std::overflow_error("631302 global event sequence exhausted");
		}
		std::size_t transaction_size = 0U;
		for (const auto& event : events) {
			if (event.bytes.size() > std::numeric_limits<std::size_t>::max() - transaction_size) {
				throw std::length_error("631302 trace transaction is too large");
			}
			transaction_size += event.bytes.size();
		}
		Bytes transaction;
		transaction.reserve(transaction_size);
		for (const auto& event : events) {
			transaction.insert(transaction.end(), event.bytes.begin(), event.bytes.end());
		}
		Bytes candidate = trace_;
		candidate.insert(candidate.end(), transaction.begin(), transaction.end());
#ifdef V631302_TRACE_TEST_HOOKS
		if (
			has_fail_sequence_
			&& fail_at_sequence_ >= next_global_sequence_
			&& fail_at_sequence_ < next_global_sequence_ + events.size()
		) {
			has_fail_sequence_ = false;
			throw std::bad_alloc();
		}
#endif
		if (transaction_sink_ != nullptr) {
			SinkCallbackGuard callback_guard(sink_callback_active_);
			transaction_sink_->commit(
				transaction,
				next_global_sequence_,
				static_cast<std::uint64_t>(events.size()),
				previous_global_event_hash_,
				events.back().hash
			);
		}
		trace_.swap(candidate);
		previous_global_event_hash_ = events.back().hash;
		next_global_sequence_ += static_cast<std::uint64_t>(events.size());
	}

	Root session_id_{};
	Root schedule_seed_{};
	Root previous_global_event_hash_{};
	std::uint64_t next_global_sequence_ = 0U;
	std::map<Root, StreamState> streams_;
	Bytes trace_;
	TraceTransactionSink* transaction_sink_ = nullptr;
	std::thread::id owner_thread_{};
	std::uint64_t owner_nonce_ = 0U;
	bool closed_ = false;
	bool sink_callback_active_ = false;
#ifdef V631302_TRACE_TEST_HOOKS
	std::uint64_t fail_at_sequence_ = 0U;
	bool has_fail_sequence_ = false;
#endif
};

}  // namespace v631302
