#ifndef EVALUATION_V6_3_1_NATIVE_STATE3_EXTRACTOR_CBOR_WRITER_H
#define EVALUATION_V6_3_1_NATIVE_STATE3_EXTRACTOR_CBOR_WRITER_H

#include <cstddef>
#include <cstdint>
#include <iosfwd>
#include <string_view>
#include <utility>
#include <vector>

namespace evaluation_v6_3_1::native {

// Arrays-only deterministic CBOR for the State-3 observation payload. This
// writer deliberately exposes no API for maps, tags, floats, or signed ints.
class CborWriter {
public:
    using Byte = std::uint8_t;

    void write_array(std::uint64_t length);
    void write_uint(std::uint64_t value);
    void write_bytes(std::string_view value);
    void write_text(std::string_view value);

    const std::vector<Byte>& bytes() const noexcept { return payload_; }
    std::vector<Byte> take_bytes() && noexcept { return std::move(payload_); }
    void write_to(std::ostream& output) const;

private:
    void write_head(Byte major_type, std::uint64_t argument);
    void write_string(Byte major_type, std::string_view value);

    std::vector<Byte> payload_;
};

}  // namespace evaluation_v6_3_1::native

#endif  // EVALUATION_V6_3_1_NATIVE_STATE3_EXTRACTOR_CBOR_WRITER_H
