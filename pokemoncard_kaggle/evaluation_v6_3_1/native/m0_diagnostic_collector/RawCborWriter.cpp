#include "RawCborWriter.h"

#include <ostream>
#include <stdexcept>

namespace evaluation_v6_3_1::m0_diagnostic {
namespace {

bool continuation(RawCborWriter::Byte value) {
    return (value & 0xC0u) == 0x80u;
}

bool valid_utf8(std::string_view value) {
    const auto* bytes = reinterpret_cast<const RawCborWriter::Byte*>(value.data());
    std::size_t index = 0;
    while (index < value.size()) {
        const auto first = bytes[index++];
        if (first <= 0x7Fu) {
            continue;
        }
        std::size_t tail = 0;
        if (first >= 0xC2u && first <= 0xDFu) {
            tail = 1;
        } else if (first >= 0xE0u && first <= 0xEFu) {
            tail = 2;
        } else if (first >= 0xF0u && first <= 0xF4u) {
            tail = 3;
        } else {
            return false;
        }
        if (index + tail > value.size()) {
            return false;
        }
        for (std::size_t offset = 0; offset < tail; ++offset) {
            if (!continuation(bytes[index + offset])) {
                return false;
            }
        }
        index += tail;
    }
    return true;
}

}  // namespace

void RawCborWriter::head(Byte major, std::uint64_t argument) {
    if (major != 0u && major != 2u && major != 3u && major != 4u) {
        throw std::logic_error("arrays-only raw CBOR profile rejected a major type");
    }
    if (argument < 24u) {
        bytes_.push_back(static_cast<Byte>((major << 5u) | static_cast<Byte>(argument)));
    } else if (argument <= 0xFFu) {
        bytes_.push_back(static_cast<Byte>((major << 5u) | 24u));
        bytes_.push_back(static_cast<Byte>(argument));
    } else if (argument <= 0xFFFFu) {
        bytes_.push_back(static_cast<Byte>((major << 5u) | 25u));
        bytes_.push_back(static_cast<Byte>(argument >> 8u));
        bytes_.push_back(static_cast<Byte>(argument));
    } else if (argument <= 0xFFFFFFFFu) {
        bytes_.push_back(static_cast<Byte>((major << 5u) | 26u));
        for (int shift = 24; shift >= 0; shift -= 8) {
            bytes_.push_back(static_cast<Byte>(argument >> shift));
        }
    } else {
        bytes_.push_back(static_cast<Byte>((major << 5u) | 27u));
        for (int shift = 56; shift >= 0; shift -= 8) {
            bytes_.push_back(static_cast<Byte>(argument >> shift));
        }
    }
}

void RawCborWriter::array(std::uint64_t size) {
    head(4u, size);
}

void RawCborWriter::uint(std::uint64_t value) {
    head(0u, value);
}

void RawCborWriter::string(Byte major, std::string_view value) {
    head(major, static_cast<std::uint64_t>(value.size()));
    const auto* begin = reinterpret_cast<const Byte*>(value.data());
    bytes_.insert(bytes_.end(), begin, begin + value.size());
}

void RawCborWriter::text(std::string_view value) {
    if (!valid_utf8(value)) {
        throw std::invalid_argument("raw CBOR text is not valid UTF-8");
    }
    string(3u, value);
}

void RawCborWriter::bytes(std::string_view value) {
    string(2u, value);
}

void RawCborWriter::write_to(std::ostream& output) const {
    output.write(reinterpret_cast<const char*>(bytes_.data()),
                 static_cast<std::streamsize>(bytes_.size()));
    if (!output) {
        throw std::ios_base::failure("unable to write raw collector CBOR");
    }
}

}  // namespace evaluation_v6_3_1::m0_diagnostic
