#pragma once

#if !defined(__unix__) && !defined(__APPLE__) && !defined(__linux__)
#error "V631302DurableJournal requires a POSIX platform"
#endif

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <limits>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <utility>
#include <vector>

#if !defined(O_CLOEXEC) || !defined(O_NOFOLLOW) || !defined(O_DIRECTORY)
#error "V631302DurableJournal requires O_CLOEXEC, O_NOFOLLOW, and O_DIRECTORY"
#endif

// This is a bounded, zero-authority storage substrate. It is not an engine
// integration, a campaign journal, or a production-ready custody component.
namespace v631302 {
namespace durable {

using Bytes = std::vector<std::uint8_t>;
using Digest = std::array<std::uint8_t, 32>;

inline constexpr std::uint64_t kProtocolVersion = 631302U;
inline constexpr bool kAuthority = false;
inline constexpr bool kCampaignAuthority = false;
inline constexpr bool kDurableProductionReady = false;
inline constexpr bool kEngineIntegrated = false;
inline constexpr bool kSemanticAuthenticationImplemented = false;
inline constexpr bool kExternalAnchorImplemented = false;
inline constexpr bool kPostPrepareFailurePoisoningImplemented = true;

inline constexpr std::string_view kTraceFile = "trace.cbor";
inline constexpr std::string_view kWalFile = "durable.wal";
inline constexpr std::string_view kLockFile = "session.lock";

inline constexpr std::string_view kCodePlatformUnsupported = "RNG_DURABLE_PLATFORM_UNSUPPORTED";
inline constexpr std::string_view kCodeLockUnavailable = "RNG_CONCURRENT_AUTHORITATIVE_ACCESS";
inline constexpr std::string_view kCodeIoFailed = "RNG_DURABLE_IO_FAILED";
inline constexpr std::string_view kCodeUnsafePath = "RNG_DURABLE_PATH_UNSAFE";
inline constexpr std::string_view kCodeJournalMalformed = "RNG_DURABLE_JOURNAL_MALFORMED";
inline constexpr std::string_view kCodeJournalCorrupt = "RNG_DURABLE_JOURNAL_INTERIOR_CORRUPTION";
inline constexpr std::string_view kCodeCommittedMismatch = "RNG_DURABLE_COMMITTED_MISMATCH";
inline constexpr std::string_view kCodePendingMismatch = "RNG_DURABLE_PENDING_MISMATCH";
inline constexpr std::string_view kCodePartialCommit = "RNG_TRANSACTION_PARTIAL_COMMIT";
inline constexpr std::string_view kCodeInvalidInput = "RNG_DURABLE_INPUT_INVALID";

class DurableJournalError final : public std::runtime_error {
public:
	DurableJournalError(std::string_view code, std::string message)
		: std::runtime_error(std::move(message)), code_(code) {}

	std::string_view code() const noexcept { return code_; }

private:
	std::string code_;
};

namespace durable_detail {

inline constexpr std::array<std::uint32_t, 64> kShaConstants = {
	0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U,
	0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
	0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
	0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
	0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
	0x2de92c6fU, 0x4d2c6dfcU, 0x53380d13U, 0x650a7354U,
	0x766a0abbU, 0x81c2c92eU, 0x92722c85U, 0xa2bfe8a1U,
	0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U, 0xd192e819U,
	0xd6990624U, 0xf40e3585U, 0x106aa070U, 0x19a4c116U,
	0x1e376c08U, 0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U,
	0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U, 0x748f82eeU,
	0x78a5636fU, 0x84c87814U, 0x8cc70208U, 0x90befffaU,
	0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U,
};

inline std::uint32_t rotate_right(std::uint32_t value, unsigned int shift) {
	return (value >> shift) | (value << (32U - shift));
}

inline Digest sha256(const std::uint8_t* data, std::size_t size) {
	if (size > std::numeric_limits<std::size_t>::max() - 72U) {
		throw DurableJournalError(std::string(kCodeInvalidInput), "SHA-256 input is too large");
	}
	if (size > std::numeric_limits<std::uint64_t>::max() / 8U) {
		throw DurableJournalError(std::string(kCodeInvalidInput), "SHA-256 bit length overflows");
	}
	const std::size_t padded_size = ((size + 72U) / 64U) * 64U;
	Bytes message(padded_size, 0U);
	if (size != 0U) {
		std::copy(data, data + size, message.begin());
	}
	message[size] = 0x80U;
	const std::uint64_t bit_size = static_cast<std::uint64_t>(size) * 8U;
	for (int index = 0; index < 8; ++index) {
		message[padded_size - 1U - static_cast<std::size_t>(index)] =
			static_cast<std::uint8_t>(bit_size >> (index * 8));
	}

	std::array<std::uint32_t, 8> state = {
		0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
		0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U,
	};
	for (std::size_t block = 0; block < padded_size; block += 64U) {
		std::array<std::uint32_t, 64> words{};
		for (int index = 0; index < 16; ++index) {
			const std::size_t offset = block + static_cast<std::size_t>(index) * 4U;
			words[index] = (static_cast<std::uint32_t>(message[offset]) << 24U)
				| (static_cast<std::uint32_t>(message[offset + 1U]) << 16U)
				| (static_cast<std::uint32_t>(message[offset + 2U]) << 8U)
				| static_cast<std::uint32_t>(message[offset + 3U]);
		}
		for (int index = 16; index < 64; ++index) {
			const std::uint32_t s0 = rotate_right(words[index - 15], 7U)
				^ rotate_right(words[index - 15], 18U) ^ (words[index - 15] >> 3U);
			const std::uint32_t s1 = rotate_right(words[index - 2], 17U)
				^ rotate_right(words[index - 2], 19U) ^ (words[index - 2] >> 10U);
			words[index] = words[index - 16] + s0 + words[index - 7] + s1;
		}
		std::uint32_t a = state[0];
		std::uint32_t b = state[1];
		std::uint32_t c = state[2];
		std::uint32_t d = state[3];
		std::uint32_t e = state[4];
		std::uint32_t f = state[5];
		std::uint32_t g = state[6];
		std::uint32_t h = state[7];
		for (int index = 0; index < 64; ++index) {
			const std::uint32_t sum1 = rotate_right(e, 6U)
				^ rotate_right(e, 11U) ^ rotate_right(e, 25U);
			const std::uint32_t choose = (e & f) ^ ((~e) & g);
			const std::uint32_t temp1 = h + sum1 + choose + kShaConstants[index] + words[index];
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
		state[0] += a;
		state[1] += b;
		state[2] += c;
		state[3] += d;
		state[4] += e;
		state[5] += f;
		state[6] += g;
		state[7] += h;
	}

	Digest output{};
	for (int index = 0; index < 8; ++index) {
		output[index * 4] = static_cast<std::uint8_t>(state[index] >> 24U);
		output[index * 4 + 1] = static_cast<std::uint8_t>(state[index] >> 16U);
		output[index * 4 + 2] = static_cast<std::uint8_t>(state[index] >> 8U);
		output[index * 4 + 3] = static_cast<std::uint8_t>(state[index]);
	}
	return output;
}

inline Digest sha256(const Bytes& value) { return sha256(value.data(), value.size()); }

inline void put_u32(Bytes& output, std::uint32_t value) {
	for (int shift = 24; shift >= 0; shift -= 8) {
		output.push_back(static_cast<std::uint8_t>(value >> shift));
	}
}

inline void put_u64(Bytes& output, std::uint64_t value) {
	for (int shift = 56; shift >= 0; shift -= 8) {
		output.push_back(static_cast<std::uint8_t>(value >> shift));
	}
}

inline std::uint32_t get_u32(const std::uint8_t* data) {
	return (static_cast<std::uint32_t>(data[0]) << 24U)
		| (static_cast<std::uint32_t>(data[1]) << 16U)
		| (static_cast<std::uint32_t>(data[2]) << 8U)
		| static_cast<std::uint32_t>(data[3]);
}

inline std::uint64_t get_u64(const std::uint8_t* data) {
	std::uint64_t value = 0U;
	for (int index = 0; index < 8; ++index) {
		value = (value << 8U) | data[index];
	}
	return value;
}

inline void put_digest(Bytes& output, const Digest& digest) {
	output.insert(output.end(), digest.begin(), digest.end());
}

inline Digest get_digest(const std::uint8_t* data) {
	Digest digest{};
	std::copy(data, data + digest.size(), digest.begin());
	return digest;
}

inline std::uint32_t crc32(const std::uint8_t* data, std::size_t size) {
	std::uint32_t crc = 0xffffffffU;
	for (std::size_t index = 0; index < size; ++index) {
		crc ^= data[index];
		for (int bit = 0; bit < 8; ++bit) {
			crc = (crc >> 1U) ^ (0xedb88320U & (0U - (crc & 1U)));
		}
	}
	return ~crc;
}

inline bool equal(const Digest& left, const Digest& right) {
	return std::equal(left.begin(), left.end(), right.begin(), right.end());
}

inline std::string code_message(std::string_view code, std::string_view message) {
	return std::string(code) + ": " + std::string(message);
}

inline void fail(std::string_view code, std::string_view message) {
	throw DurableJournalError(code, code_message(code, message));
}

inline off_t checked_offset(std::uint64_t value) {
	if (value > static_cast<std::uint64_t>(std::numeric_limits<off_t>::max())) {
		fail(kCodeIoFailed, "offset exceeds POSIX off_t");
	}
	return static_cast<off_t>(value);
}

}  // namespace durable_detail

enum class IoTarget : std::uint8_t { Wal = 1U, Trace = 2U };

enum class CrashPoint : std::uint8_t {
	None = 0U,
	AfterPrepareFsync = 1U,
	AfterTraceWrite = 2U,
	AfterTraceFsync = 3U,
	AfterCommitFsync = 4U,
};

struct AppendResult {
	std::uint64_t old_offset = 0U;
	std::uint64_t new_offset = 0U;
	// This is the committed transaction sequence. One transaction may carry
	// multiple canonical protocol events; it is not a global event sequence.
	std::uint64_t transaction_sequence = 0U;
	Digest trace_root{};
};

class DurableJournal final {
public:
	using Root = Digest;

	// These files are local recovery state only. They are not 631302 event
	// framing and must never be incorporated into an authoritative trace root.
	static constexpr std::uint8_t kPrepare = 1U;
	static constexpr std::uint8_t kCommit = 2U;

	explicit DurableJournal(const std::string& root_path) {
		try {
			open_store(root_path);
			recover();
		} catch (...) {
			close_fds();
			throw;
		}
	}

	DurableJournal(const DurableJournal&) = delete;
	DurableJournal& operator=(const DurableJournal&) = delete;
	DurableJournal(DurableJournal&&) = delete;
	DurableJournal& operator=(DurableJournal&&) = delete;

	~DurableJournal() { close_fds(); }

	// The opaque payload may contain multiple canonical events for one atomic
	// BOUNDED_SAMPLE operation. Its transaction sequence is not a global event
	// sequence.
	AppendResult append_transaction(const Bytes& transaction_payload) {
		std::lock_guard<std::mutex> lock(mutex_);
		if (poisoned_) {
			durable_detail::fail(
				kCodePartialCommit,
				"journal requires reopen after a failed append attempt"
			);
		}
		if (transaction_payload.empty()) {
			durable_detail::fail(kCodeInvalidInput, "an append transaction cannot be empty");
		}
		if (committed_transaction_sequence_ == std::numeric_limits<std::uint64_t>::max()) {
			durable_detail::fail(kCodePartialCommit, "transaction sequence exhausted");
		}
		if (wal_next_sequence_ > std::numeric_limits<std::uint64_t>::max() - 2U) {
			durable_detail::fail(kCodePartialCommit, "WAL sequence cannot fit PREPARE and COMMIT");
		}

		const Bytes current = read_file(trace_fd_);
		const std::uint64_t old_offset = checked_size(current.size());
		if (old_offset != committed_offset_ || durable_detail::sha256(current) != trace_root_) {
			durable_detail::fail(kCodeCommittedMismatch, "trace disagrees with committed WAL state");
		}
		if (transaction_payload.size() > std::numeric_limits<std::uint64_t>::max() - old_offset) {
			durable_detail::fail(kCodeInvalidInput, "transaction length overflows uint64");
		}

		const std::uint64_t new_offset = old_offset + static_cast<std::uint64_t>(transaction_payload.size());
		const std::uint64_t new_transaction_sequence = committed_transaction_sequence_ + 1U;
		const Digest event_digest = durable_detail::sha256(transaction_payload);
		Bytes combined = current;
		combined.insert(combined.end(), transaction_payload.begin(), transaction_payload.end());
		const Digest new_root = durable_detail::sha256(combined);
		const Digest transaction_id = transaction_digest(
			wal_next_sequence_, wal_head_, old_offset, event_digest
		);

		Prepare prepare{
			transaction_id,
			old_offset,
			static_cast<std::uint64_t>(transaction_payload.size()),
			committed_transaction_sequence_,
			new_transaction_sequence,
			trace_root_,
			event_digest,
			new_root,
		};
		poisoned_ = true;
		append_wal(kPrepare, encode_prepare(prepare));
		maybe_crash(CrashPoint::AfterPrepareFsync);

		write_exact(trace_fd_, old_offset, transaction_payload.data(), transaction_payload.size(), IoTarget::Trace);
		maybe_crash(CrashPoint::AfterTraceWrite);
		sync_fd(trace_fd_, IoTarget::Trace);
		maybe_crash(CrashPoint::AfterTraceFsync);

		Commit commit{
			transaction_id,
			old_offset,
			static_cast<std::uint64_t>(transaction_payload.size()),
			new_offset,
			new_transaction_sequence,
			event_digest,
			new_root,
		};
		append_wal(kCommit, encode_commit(commit));
		maybe_crash(CrashPoint::AfterCommitFsync);

		committed_offset_ = new_offset;
		committed_transaction_sequence_ = new_transaction_sequence;
		trace_root_ = new_root;
		poisoned_ = false;
		return {old_offset, new_offset, new_transaction_sequence, new_root};
	}

	std::uint64_t committed_offset() const {
		std::lock_guard<std::mutex> lock(mutex_);
		return committed_offset_;
	}
	// This is a transaction sequence, not the global 631302 event sequence.
	std::uint64_t committed_transaction_sequence() const {
		std::lock_guard<std::mutex> lock(mutex_);
		return committed_transaction_sequence_;
	}
	Digest trace_root() const {
		std::lock_guard<std::mutex> lock(mutex_);
		return trace_root_;
	}

#ifdef V631302_DURABLE_TEST_HOOKS
	void test_set_max_write_bytes(IoTarget target, std::size_t bytes) noexcept {
		test_hooks_.max_write_bytes[target_index(target)] = bytes;
	}

	void test_fail_write_call(IoTarget target, std::uint64_t call) noexcept {
		test_hooks_.fail_write_call[target_index(target)] = call;
	}

	void test_fail_fsync_call(IoTarget target, std::uint64_t call) noexcept {
		test_hooks_.fail_fsync_call[target_index(target)] = call;
	}

	void test_crash_at(CrashPoint point) noexcept { test_hooks_.crash_point = point; }

	void test_set_wal_next_sequence(std::uint64_t sequence) noexcept {
		wal_next_sequence_ = sequence;
	}

	void test_set_wal_end(std::uint64_t offset) noexcept { wal_end_ = offset; }
#endif

private:
	static constexpr std::size_t kMagicSize = 8U;
	static constexpr std::size_t kWalPrefixSize = 96U;
	static constexpr std::size_t kWalSuffixSize = 36U;
	static constexpr std::size_t kPreparePayloadSize = 160U;
	static constexpr std::size_t kCommitPayloadSize = 128U;
	static constexpr std::uint32_t kWalVersion = 1U;
	static constexpr std::array<std::uint8_t, kMagicSize> kMagic = {
		'V', '6', '3', '1', 'W', 'A', 'L', '1'
	};

	struct Prepare {
		Digest transaction_id{};
		std::uint64_t old_offset = 0U;
		std::uint64_t event_length = 0U;
		std::uint64_t old_transaction_sequence = 0U;
		std::uint64_t new_transaction_sequence = 0U;
		Digest old_root{};
		Digest event_digest{};
		Digest new_root{};
	};

	struct Commit {
		Digest transaction_id{};
		std::uint64_t old_offset = 0U;
		std::uint64_t event_length = 0U;
		std::uint64_t new_offset = 0U;
		std::uint64_t new_transaction_sequence = 0U;
		Digest event_digest{};
		Digest new_root{};
	};

	struct Pending {
		Prepare prepare{};
		std::uint64_t wal_start = 0U;
		Digest previous_wal_hash{};
	};

#ifdef V631302_DURABLE_TEST_HOOKS
	struct TestHooks {
		std::size_t max_write_bytes[2] = {0U, 0U};
		std::uint64_t write_calls[2] = {0U, 0U};
		std::int64_t fail_write_call[2] = {-1, -1};
		std::uint64_t fsync_calls[2] = {0U, 0U};
		std::int64_t fail_fsync_call[2] = {-1, -1};
		CrashPoint crash_point = CrashPoint::None;
	};
#endif

	static std::uint64_t checked_size(std::size_t value) {
		return static_cast<std::uint64_t>(value);
	}

	static std::size_t target_index(IoTarget target) {
		return target == IoTarget::Wal ? 0U : 1U;
	}

	static Digest transaction_digest(
		std::uint64_t wal_sequence,
		const Digest& previous_wal_hash,
		std::uint64_t old_offset,
		const Digest& event_digest
	) {
		Bytes input;
		static constexpr std::string_view domain = "V631/DURABLE/TX\0";
		input.insert(input.end(), domain.begin(), domain.end());
		durable_detail::put_u64(input, wal_sequence);
		durable_detail::put_u64(input, old_offset);
		durable_detail::put_digest(input, previous_wal_hash);
		durable_detail::put_digest(input, event_digest);
		return durable_detail::sha256(input);
	}

	static Bytes encode_prepare(const Prepare& value) {
		Bytes payload;
		payload.reserve(kPreparePayloadSize);
		durable_detail::put_digest(payload, value.transaction_id);
		durable_detail::put_u64(payload, value.old_offset);
		durable_detail::put_u64(payload, value.event_length);
		durable_detail::put_u64(payload, value.old_transaction_sequence);
		durable_detail::put_u64(payload, value.new_transaction_sequence);
		durable_detail::put_digest(payload, value.old_root);
		durable_detail::put_digest(payload, value.event_digest);
		durable_detail::put_digest(payload, value.new_root);
		return payload;
	}

	static Bytes encode_commit(const Commit& value) {
		Bytes payload;
		payload.reserve(kCommitPayloadSize);
		durable_detail::put_digest(payload, value.transaction_id);
		durable_detail::put_u64(payload, value.old_offset);
		durable_detail::put_u64(payload, value.event_length);
		durable_detail::put_u64(payload, value.new_offset);
		durable_detail::put_u64(payload, value.new_transaction_sequence);
		durable_detail::put_digest(payload, value.event_digest);
		durable_detail::put_digest(payload, value.new_root);
		return payload;
	}

	static Prepare decode_prepare(const Bytes& payload) {
		if (payload.size() != kPreparePayloadSize) {
			durable_detail::fail(kCodeJournalMalformed, "PREPARE payload size is invalid");
		}
		Prepare value{};
		const auto* data = payload.data();
		value.transaction_id = durable_detail::get_digest(data);
		value.old_offset = durable_detail::get_u64(data + 32U);
		value.event_length = durable_detail::get_u64(data + 40U);
		value.old_transaction_sequence = durable_detail::get_u64(data + 48U);
		value.new_transaction_sequence = durable_detail::get_u64(data + 56U);
		value.old_root = durable_detail::get_digest(data + 64U);
		value.event_digest = durable_detail::get_digest(data + 96U);
		value.new_root = durable_detail::get_digest(data + 128U);
		if (value.event_length == 0U || value.new_transaction_sequence != value.old_transaction_sequence + 1U) {
			durable_detail::fail(kCodeJournalMalformed, "PREPARE sequence or length is invalid");
		}
		if (value.old_offset > std::numeric_limits<std::uint64_t>::max() - value.event_length) {
			durable_detail::fail(kCodeJournalMalformed, "PREPARE offset overflows");
		}
		return value;
	}

	static Commit decode_commit(const Bytes& payload) {
		if (payload.size() != kCommitPayloadSize) {
			durable_detail::fail(kCodeJournalMalformed, "COMMIT payload size is invalid");
		}
		Commit value{};
		const auto* data = payload.data();
		value.transaction_id = durable_detail::get_digest(data);
		value.old_offset = durable_detail::get_u64(data + 32U);
		value.event_length = durable_detail::get_u64(data + 40U);
		value.new_offset = durable_detail::get_u64(data + 48U);
		value.new_transaction_sequence = durable_detail::get_u64(data + 56U);
		value.event_digest = durable_detail::get_digest(data + 64U);
		value.new_root = durable_detail::get_digest(data + 96U);
		if (value.event_length == 0U || value.old_offset > std::numeric_limits<std::uint64_t>::max() - value.event_length) {
			durable_detail::fail(kCodeJournalMalformed, "COMMIT offset or length is invalid");
		}
		if (value.new_offset != value.old_offset + value.event_length) {
			durable_detail::fail(kCodeJournalMalformed, "COMMIT new offset is invalid");
		}
		return value;
	}

	static Bytes make_frame(
		std::uint8_t type,
		std::uint64_t sequence,
		const Digest& previous_hash,
		const Bytes& payload,
		Digest& record_hash
	) {
		Bytes core;
		core.reserve(kWalPrefixSize + payload.size());
		core.insert(core.end(), kMagic.begin(), kMagic.end());
		durable_detail::put_u32(core, kWalVersion);
		core.push_back(type);
		core.insert(core.end(), 3U, 0U);
		durable_detail::put_u64(core, static_cast<std::uint64_t>(payload.size()));
		durable_detail::put_u64(core, sequence);
		durable_detail::put_digest(core, previous_hash);
		durable_detail::put_digest(core, durable_detail::sha256(payload));
		core.insert(core.end(), payload.begin(), payload.end());
		record_hash = durable_detail::sha256(core);
		Bytes frame = core;
		durable_detail::put_digest(frame, record_hash);
		durable_detail::put_u32(frame, durable_detail::crc32(frame.data(), frame.size()));
		return frame;
	}

	void open_store(const std::string& root_path) {
		if (root_path.empty()) {
			durable_detail::fail(kCodeInvalidInput, "store path is empty");
		}
		dir_fd_ = ::open(
			root_path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_DIRECTORY
		);
		if (dir_fd_ < 0) {
			if (errno == ELOOP) {
				durable_detail::fail(kCodeUnsafePath, "store directory cannot be a symlink");
			}
			durable_detail::fail(kCodeIoFailed, "cannot open store directory");
		}
		struct stat directory_stat{};
		if (::fstat(dir_fd_, &directory_stat) != 0 || !S_ISDIR(directory_stat.st_mode)) {
			durable_detail::fail(kCodePlatformUnsupported, "store root is not a directory");
		}
		if (
			directory_stat.st_uid != ::geteuid()
			|| (directory_stat.st_mode & static_cast<mode_t>(0022)) != 0U
		) {
			durable_detail::fail(
				kCodeUnsafePath,
				"store directory must be owned by the effective user and not group/world writable"
			);
		}
		lock_fd_ = open_private(kLockFile.data());
		if (::flock(lock_fd_, LOCK_EX | LOCK_NB) != 0) {
			if (errno == EWOULDBLOCK || errno == EAGAIN) {
				durable_detail::fail(kCodeLockUnavailable, "session lock is already held");
			}
			durable_detail::fail(kCodeIoFailed, "cannot acquire session lock");
		}
		trace_fd_ = open_private(kTraceFile.data());
		wal_fd_ = open_private(kWalFile.data());
		if (::fsync(dir_fd_) != 0) {
			durable_detail::fail(kCodeIoFailed, "cannot durably establish store files");
		}
	}

	int open_private(const char* name) {
		const int fd = ::openat(
			dir_fd_, name, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, static_cast<mode_t>(0600)
		);
		if (fd < 0) {
			if (errno == ELOOP) {
				durable_detail::fail(kCodeUnsafePath, "private store file cannot be a symlink");
			}
			durable_detail::fail(kCodeIoFailed, "cannot open private store file");
		}
		struct stat file_stat{};
		if (::fstat(fd, &file_stat) != 0 || !S_ISREG(file_stat.st_mode)) {
			::close(fd);
			durable_detail::fail(kCodePlatformUnsupported, "private store path is not a regular file");
		}
		if (file_stat.st_uid != ::geteuid() || file_stat.st_nlink != 1) {
			::close(fd);
			durable_detail::fail(
				kCodeUnsafePath,
				"private store file must be user-owned with exactly one hard link"
			);
		}
		if ((file_stat.st_mode & 0777U) != 0600U) {
			if (::fchmod(fd, static_cast<mode_t>(0600)) != 0 || ::fsync(fd) != 0) {
				::close(fd);
				durable_detail::fail(kCodeIoFailed, "cannot enforce mode 0600");
			}
		}
		return fd;
	}

	void close_fds() noexcept {
		if (wal_fd_ >= 0) (void)::close(wal_fd_);
		if (trace_fd_ >= 0) (void)::close(trace_fd_);
		if (lock_fd_ >= 0) {
			(void)::flock(lock_fd_, LOCK_UN);
		}
		if (lock_fd_ >= 0) (void)::close(lock_fd_);
		if (dir_fd_ >= 0) (void)::close(dir_fd_);
		wal_fd_ = -1;
		trace_fd_ = -1;
		lock_fd_ = -1;
		dir_fd_ = -1;
	}

	static std::uint64_t file_size(int fd) {
		struct stat file_stat{};
		if (::fstat(fd, &file_stat) != 0 || file_stat.st_size < 0) {
			durable_detail::fail(kCodeIoFailed, "cannot stat private store file");
		}
		return static_cast<std::uint64_t>(file_stat.st_size);
	}

	static Bytes read_file(int fd) {
		const std::uint64_t size = file_size(fd);
		if (size > std::numeric_limits<std::size_t>::max()) {
			durable_detail::fail(kCodeIoFailed, "private store file is too large");
		}
		Bytes result(static_cast<std::size_t>(size));
		std::size_t offset = 0U;
		while (offset < result.size()) {
			const ssize_t count = ::pread(
				fd, result.data() + offset, result.size() - offset,
				durable_detail::checked_offset(static_cast<std::uint64_t>(offset))
			);
			if (count <= 0) {
				durable_detail::fail(kCodeIoFailed, "cannot read private store file");
			}
			offset += static_cast<std::size_t>(count);
		}
		if (file_size(fd) != size) {
			durable_detail::fail(kCodeIoFailed, "private store file changed during read");
		}
		return result;
	}

#ifdef V631302_DURABLE_TEST_HOOKS
	static std::size_t hook_index(IoTarget target) { return target_index(target); }

	void before_write(IoTarget target) {
		const std::size_t index = hook_index(target);
		++test_hooks_.write_calls[index];
		if (test_hooks_.fail_write_call[index] >= 0
			&& test_hooks_.write_calls[index] == static_cast<std::uint64_t>(test_hooks_.fail_write_call[index])) {
			durable_detail::fail(kCodeIoFailed, "test-injected write failure");
		}
	}

	void before_fsync(IoTarget target) {
		const std::size_t index = hook_index(target);
		++test_hooks_.fsync_calls[index];
		if (test_hooks_.fail_fsync_call[index] >= 0
			&& test_hooks_.fsync_calls[index] == static_cast<std::uint64_t>(test_hooks_.fail_fsync_call[index])) {
			durable_detail::fail(kCodeIoFailed, "test-injected fsync failure");
		}
	}
#endif

	void write_exact(int fd, std::uint64_t offset, const std::uint8_t* data, std::size_t size, IoTarget target) {
		std::size_t written = 0U;
		while (written < size) {
#ifdef V631302_DURABLE_TEST_HOOKS
			before_write(target);
			std::size_t attempt = size - written;
			const std::size_t limit = test_hooks_.max_write_bytes[target_index(target)];
			if (limit != 0U) attempt = std::min(attempt, limit);
#else
			(void)target;
			const std::size_t attempt = size - written;
#endif
			if (written > std::numeric_limits<std::uint64_t>::max() - offset) {
				durable_detail::fail(kCodeInvalidInput, "private store write offset overflows");
			}
			const ssize_t count = ::pwrite(
				fd, data + written, attempt,
				durable_detail::checked_offset(offset + static_cast<std::uint64_t>(written))
			);
			if (count <= 0) {
				durable_detail::fail(kCodeIoFailed, "private store write failed");
			}
			written += static_cast<std::size_t>(count);
		}
	}

	void sync_fd(int fd, IoTarget target) {
#ifdef V631302_DURABLE_TEST_HOOKS
		before_fsync(target);
#else
		(void)target;
#endif
		if (::fsync(fd) != 0) {
			durable_detail::fail(kCodeIoFailed, "private store fsync failed");
		}
	}

	void append_wal(std::uint8_t type, const Bytes& payload) {
		if (wal_next_sequence_ == std::numeric_limits<std::uint64_t>::max()) {
			durable_detail::fail(kCodePartialCommit, "WAL sequence exhausted");
		}
		Digest record_hash{};
		const Bytes frame = make_frame(type, wal_next_sequence_, wal_head_, payload, record_hash);
		if (frame.size() > std::numeric_limits<std::uint64_t>::max() - wal_end_) {
			durable_detail::fail(kCodePartialCommit, "WAL offset exhausted");
		}
		write_exact(wal_fd_, wal_end_, frame.data(), frame.size(), IoTarget::Wal);
		sync_fd(wal_fd_, IoTarget::Wal);
		wal_end_ += static_cast<std::uint64_t>(frame.size());
		++wal_next_sequence_;
		wal_head_ = record_hash;
	}

#ifdef V631302_DURABLE_TEST_HOOKS
	void maybe_crash(CrashPoint point) {
		if (test_hooks_.crash_point == point) {
			::_exit(90 + static_cast<int>(point));
		}
	}
#else
	void maybe_crash(CrashPoint) {}
#endif

	static bool has_prefix(const Bytes& trace, std::uint64_t offset, std::uint64_t length) {
		return offset <= trace.size() && length <= trace.size() - static_cast<std::size_t>(offset);
	}

	void truncate_trace(std::uint64_t offset) {
		if (::ftruncate(trace_fd_, durable_detail::checked_offset(offset)) != 0) {
			durable_detail::fail(kCodeIoFailed, "cannot roll back trace suffix");
		}
		sync_fd(trace_fd_, IoTarget::Trace);
	}

	void truncate_wal(std::uint64_t offset, const Digest& head, std::uint64_t sequence) {
		if (::ftruncate(wal_fd_, durable_detail::checked_offset(offset)) != 0) {
			durable_detail::fail(kCodeIoFailed, "cannot truncate WAL tail");
		}
		sync_fd(wal_fd_, IoTarget::Wal);
		wal_end_ = offset;
		wal_head_ = head;
		wal_next_sequence_ = sequence;
	}

	void recover() {
		trace_root_ = durable_detail::sha256(Bytes{});
		committed_offset_ = 0U;
		committed_transaction_sequence_ = 0U;
		wal_end_ = 0U;
		wal_next_sequence_ = 0U;
		wal_head_ = Digest{};

		const Bytes wal = read_file(wal_fd_);
		std::size_t offset = 0U;
		Digest previous_hash{};
		std::uint64_t sequence = 0U;
		std::optional<Pending> pending;
		while (offset < wal.size()) {
			const std::size_t remaining = wal.size() - offset;
			if (remaining < kWalPrefixSize) {
				truncate_wal(offset, previous_hash, sequence);
				break;
			}
			const auto* prefix = wal.data() + offset;
			if (!std::equal(kMagic.begin(), kMagic.end(), prefix)) {
				durable_detail::fail(kCodeJournalCorrupt, "WAL magic is invalid");
			}
			if (durable_detail::get_u32(prefix + 8U) != kWalVersion) {
				durable_detail::fail(kCodeJournalCorrupt, "WAL version is invalid");
			}
			const std::uint8_t type = prefix[12];
			if (prefix[13] != 0U || prefix[14] != 0U || prefix[15] != 0U) {
				durable_detail::fail(kCodeJournalCorrupt, "WAL reserved bytes are nonzero");
			}
			const std::uint64_t payload_size = durable_detail::get_u64(prefix + 16U);
			if (payload_size > 4096U) {
				durable_detail::fail(kCodeJournalMalformed, "WAL payload is too large");
			}
			const std::uint64_t frame_size_u64 = kWalPrefixSize + payload_size + kWalSuffixSize;
			if (frame_size_u64 > remaining) {
				truncate_wal(offset, previous_hash, sequence);
				break;
			}
			const std::size_t frame_size = static_cast<std::size_t>(frame_size_u64);
			Bytes frame(wal.begin() + static_cast<std::ptrdiff_t>(offset), wal.begin() + static_cast<std::ptrdiff_t>(offset + frame_size));
			const std::uint64_t record_sequence = durable_detail::get_u64(frame.data() + 24U);
			if (record_sequence != sequence) {
				durable_detail::fail(kCodeJournalCorrupt, "WAL sequence is not contiguous");
			}
			const Digest recorded_previous = durable_detail::get_digest(frame.data() + 32U);
			if (recorded_previous != previous_hash) {
				durable_detail::fail(kCodeJournalCorrupt, "WAL hash chain predecessor is invalid");
			}
			const std::size_t payload_offset = kWalPrefixSize;
			const Bytes payload(frame.begin() + static_cast<std::ptrdiff_t>(payload_offset), frame.begin() + static_cast<std::ptrdiff_t>(payload_offset + payload_size));
			if (durable_detail::get_digest(frame.data() + 64U) != durable_detail::sha256(payload)) {
				durable_detail::fail(kCodeJournalCorrupt, "WAL payload hash is invalid");
			}
			const Digest recorded_hash = durable_detail::get_digest(frame.data() + kWalPrefixSize + payload_size);
			Bytes core(frame.begin(), frame.begin() + static_cast<std::ptrdiff_t>(kWalPrefixSize + payload_size));
			if (recorded_hash != durable_detail::sha256(core)) {
				durable_detail::fail(kCodeJournalCorrupt, "WAL record hash is invalid");
			}
			const std::uint32_t recorded_crc = durable_detail::get_u32(frame.data() + kWalPrefixSize + payload_size + 32U);
			if (recorded_crc != durable_detail::crc32(frame.data(), frame.size() - 4U)) {
				durable_detail::fail(kCodeJournalCorrupt, "WAL record CRC is invalid");
			}

			if (type == kPrepare) {
				if (pending.has_value()) {
					durable_detail::fail(kCodePartialCommit, "WAL contains two pending PREPARE records");
				}
				Prepare value = decode_prepare(payload);
				if (value.transaction_id != transaction_digest(
					record_sequence, recorded_previous, value.old_offset, value.event_digest
				)) {
					durable_detail::fail(kCodeJournalCorrupt, "PREPARE transaction ID is invalid");
				}
				if (value.old_offset != committed_offset_ || value.old_transaction_sequence != committed_transaction_sequence_ || value.old_root != trace_root_) {
					durable_detail::fail(kCodeJournalCorrupt, "PREPARE does not bind committed state");
				}
				pending = Pending{value, static_cast<std::uint64_t>(offset), previous_hash};
			} else if (type == kCommit) {
				if (!pending.has_value()) {
					durable_detail::fail(kCodePartialCommit, "COMMIT has no PREPARE");
				}
				const Commit value = decode_commit(payload);
				const Prepare& prepared = pending->prepare;
				if (value.transaction_id != prepared.transaction_id
					|| value.old_offset != prepared.old_offset
					|| value.event_length != prepared.event_length
					|| value.new_offset != prepared.old_offset + prepared.event_length
					|| value.new_transaction_sequence != prepared.new_transaction_sequence
					|| value.event_digest != prepared.event_digest
					|| value.new_root != prepared.new_root) {
					durable_detail::fail(kCodeJournalCorrupt, "COMMIT does not match PREPARE");
				}
				committed_offset_ = value.new_offset;
				committed_transaction_sequence_ = value.new_transaction_sequence;
				trace_root_ = value.new_root;
				pending.reset();
			} else {
				durable_detail::fail(kCodeJournalMalformed, "WAL record type is unsupported");
			}

			offset += frame_size;
			previous_hash = recorded_hash;
			if (sequence == std::numeric_limits<std::uint64_t>::max()) {
				durable_detail::fail(kCodeJournalCorrupt, "WAL sequence overflows");
			}
			++sequence;
			if (offset == wal.size()) {
				wal_end_ = static_cast<std::uint64_t>(offset);
				wal_head_ = previous_hash;
				wal_next_sequence_ = sequence;
			}
		}
		if (wal.size() == 0U) {
			wal_end_ = 0U;
			wal_head_ = Digest{};
			wal_next_sequence_ = 0U;
		}

		Bytes trace = read_file(trace_fd_);
		if (pending.has_value()) {
			const Prepare& value = pending->prepare;
			if (trace.size() < value.old_offset || trace.size() > value.old_offset + value.event_length) {
				durable_detail::fail(kCodePendingMismatch, "pending trace suffix is outside PREPARE range");
			}
			if (trace.size() > value.old_offset) {
				truncate_trace(value.old_offset);
			}
			truncate_wal(pending->wal_start, pending->previous_wal_hash, sequence - 1U);
			trace = read_file(trace_fd_);
		}
		if (trace.size() != committed_offset_ || durable_detail::sha256(trace) != trace_root_) {
			durable_detail::fail(kCodeCommittedMismatch, "trace does not match committed WAL state");
		}
	}

	int dir_fd_ = -1;
	int lock_fd_ = -1;
	int trace_fd_ = -1;
	int wal_fd_ = -1;
	std::uint64_t committed_offset_ = 0U;
	std::uint64_t committed_transaction_sequence_ = 0U;
	Digest trace_root_{};
	std::uint64_t wal_end_ = 0U;
	std::uint64_t wal_next_sequence_ = 0U;
	Digest wal_head_{};
	mutable std::mutex mutex_;
	bool poisoned_ = false;
#ifdef V631302_DURABLE_TEST_HOOKS
	TestHooks test_hooks_{};
#endif
};

}  // namespace durable
}  // namespace v631302
