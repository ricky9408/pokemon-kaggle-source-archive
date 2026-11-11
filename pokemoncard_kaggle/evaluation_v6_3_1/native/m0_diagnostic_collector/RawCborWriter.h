#ifndef EVALUATION_V6_3_1_M0_DIAGNOSTIC_COLLECTOR_RAW_CBOR_WRITER_H
#define EVALUATION_V6_3_1_M0_DIAGNOSTIC_COLLECTOR_RAW_CBOR_WRITER_H

#include <cstdint>
#include <iosfwd>
#include <string_view>
#include <utility>
#include <vector>

namespace evaluation_v6_3_1::m0_diagnostic {

// The Level-2 collector uses arrays-only, definite-length CBOR.  This is an
// implementation-internal raw collector wire, not DIAGNOSTIC_CENSUS_V1: it
// intentionally has no ordered_blockers field and carries no authority.
class RawCborWriter {
public:
    using Byte = std::uint8_t;

    void array(std::uint64_t size);
    void uint(std::uint64_t value);
    void text(std::string_view value);
    void bytes(std::string_view value);
    std::vector<Byte> take_bytes() && noexcept { return std::move(bytes_); }
    void write_to(std::ostream& output) const;

private:
    void head(Byte major, std::uint64_t argument);
    void string(Byte major, std::string_view value);

    std::vector<Byte> bytes_;
};

}  // namespace evaluation_v6_3_1::m0_diagnostic

#endif  // EVALUATION_V6_3_1_M0_DIAGNOSTIC_COLLECTOR_RAW_CBOR_WRITER_H
