#pragma once

#include "V631302DurableJournal.h"
#include "V631302TraceEmitter.h"

#include <cstdint>
#include <limits>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>

// This adapter closes the offline transaction boundary between the exact
// emitter and the POSIX journal. It supports fresh sessions only and provides
// no engine, restore, campaign, or upload authority.
namespace v631302 {
namespace durable {

inline constexpr bool kDurableTraceSinkImplemented = true;
inline constexpr bool kDurableTraceSinkOwnerThreadEnforced = true;
inline constexpr bool kDurableTraceSinkResumeImplemented = false;
inline constexpr bool kDurableTraceSinkEngineIntegrated = false;
inline constexpr bool kDurableTraceSinkCampaignAuthority = false;

inline constexpr std::string_view kCodeSinkNonempty =
	"RNG_DURABLE_SINK_NONEMPTY_SESSION_UNSUPPORTED";
inline constexpr std::string_view kCodeSinkMetadata =
	"RNG_DURABLE_SINK_TRANSACTION_METADATA_INVALID";
inline constexpr std::string_view kCodeSinkPostCommit =
	"RNG_DURABLE_SINK_POST_COMMIT_MISMATCH";

class DurableTraceSinkError final : public std::runtime_error {
public:
	DurableTraceSinkError(std::string_view code, std::string message)
		: std::runtime_error(std::move(message)), code_(code) {}

	std::string_view code() const noexcept { return code_; }

private:
	std::string code_;
};

class DurableTraceSink final : public ::v631302::TraceTransactionSink {
public:
	explicit DurableTraceSink(DurableJournal& journal)
		: journal_(journal), owner_thread_(std::this_thread::get_id()) {
		if (
			journal_.committed_offset() != 0U
			|| journal_.committed_transaction_sequence() != 0U
		) {
			fail(
				kCodeSinkNonempty,
				"fresh-session sink cannot attach to a nonempty journal"
			);
		}
	}

	DurableTraceSink(const DurableTraceSink&) = delete;
	DurableTraceSink& operator=(const DurableTraceSink&) = delete;
	DurableTraceSink(DurableTraceSink&&) = delete;
	DurableTraceSink& operator=(DurableTraceSink&&) = delete;

	void commit(
		const ::v631302::Bytes& transaction_bytes,
		std::uint64_t first_global_sequence,
		std::uint64_t event_count,
		const ::v631302::Root& previous_global_event_hash,
		const ::v631302::Root& final_global_event_hash
	) override {
		check_owner_thread();
		if (transaction_bytes.empty() || event_count == 0U) {
			fail(kCodeSinkMetadata, "trace transaction and event count must be nonzero");
		}
		if (
			first_global_sequence != committed_event_count_
			|| previous_global_event_hash != committed_event_hash_
		) {
			fail(kCodeSinkMetadata, "trace transaction does not extend committed event state");
		}
		if (
			event_count
			> std::numeric_limits<std::uint64_t>::max() - committed_event_count_
		) {
			fail(kCodeSinkMetadata, "global event count overflows uint64");
		}
		if (committed_transaction_count_ == std::numeric_limits<std::uint64_t>::max()) {
			fail(kCodeSinkMetadata, "transaction count overflows uint64");
		}
		if (
			transaction_bytes.size()
			> std::numeric_limits<std::uint64_t>::max() - committed_offset_
		) {
			fail(kCodeSinkMetadata, "durable trace offset overflows uint64");
		}

		const std::uint64_t expected_offset =
			committed_offset_ + static_cast<std::uint64_t>(transaction_bytes.size());
		const std::uint64_t expected_transaction_sequence =
			committed_transaction_count_ + 1U;
		const AppendResult result = journal_.append_transaction(transaction_bytes);
		if (
			result.old_offset != committed_offset_
			|| result.new_offset != expected_offset
			|| result.transaction_sequence != expected_transaction_sequence
		) {
			fail(kCodeSinkPostCommit, "journal returned an impossible committed transition");
		}

		committed_offset_ = result.new_offset;
		committed_transaction_count_ = result.transaction_sequence;
		committed_event_count_ += event_count;
		committed_event_hash_ = final_global_event_hash;
	}

	std::uint64_t committed_offset() const {
		check_owner_thread();
		return committed_offset_;
	}
	std::uint64_t committed_transaction_count() const {
		check_owner_thread();
		return committed_transaction_count_;
	}
	std::uint64_t committed_event_count() const {
		check_owner_thread();
		return committed_event_count_;
	}
	const ::v631302::Root& committed_event_hash() const {
		check_owner_thread();
		return committed_event_hash_;
	}

private:
	void check_owner_thread() const {
		if (std::this_thread::get_id() != owner_thread_) {
			fail(kCodeSinkMetadata, "durable trace sink crossed its owner thread");
		}
	}

	[[noreturn]] static void fail(std::string_view code, std::string_view message) {
		throw DurableTraceSinkError(
			code, std::string(code) + ": " + std::string(message)
		);
	}

	DurableJournal& journal_;
	std::thread::id owner_thread_{};
	std::uint64_t committed_offset_ = 0U;
	std::uint64_t committed_transaction_count_ = 0U;
	std::uint64_t committed_event_count_ = 0U;
	::v631302::Root committed_event_hash_{};
};

}  // namespace durable
}  // namespace v631302
