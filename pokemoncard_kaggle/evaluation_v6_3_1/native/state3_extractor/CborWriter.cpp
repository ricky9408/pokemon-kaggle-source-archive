#include "CborWriter.h"

#include <ostream>
#include <stdexcept>
#include <utility>

namespace evaluation_v6_3_1::native {
namespace {

using Byte = CborWriter::Byte;

bool is_continuation(Byte value) {
    return (value & 0xC0u) == 0x80u;
}

bool valid_utf8(std::string_view value) {
    const auto* bytes = reinterpret_cast<const Byte*>(value.data());
    std::size_t index = 0;
    while (index < value.size()) {
        const Byte first = bytes[index++];
        if (first <= 0x7Fu) {
            continue;
        }
        if (first >= 0xC2u && first <= 0xDFu) {
            if (index >= value.size() || !is_continuation(bytes[index])) {
                return false;
            }
            ++index;
            continue;
        }
        if (first == 0xE0u) {
            if (index + 1 >= value.size() || bytes[index] < 0xA0u || bytes[index] > 0xBFu ||
                !is_continuation(bytes[index + 1])) {
                return false;
            }
            index += 2;
            continue;
        }
        if ((first >= 0xE1u && first <= 0xECu) || (first >= 0xEEu && first <= 0xEFu)) {
            if (index + 1 >= value.size() || !is_continuation(bytes[index]) ||
                !is_continuation(bytes[index + 1])) {
                return false;
            }
            index += 2;
            continue;
        }
        if (first == 0xEDu) {
            if (index + 1 >= value.size() || bytes[index] < 0x80u || bytes[index] > 0x9Fu ||
                !is_continuation(bytes[index + 1])) {
                return false;
            }
            index += 2;
            continue;
        }
        if (first == 0xF0u) {
            if (index + 2 >= value.size() || bytes[index] < 0x90u || bytes[index] > 0xBFu ||
                !is_continuation(bytes[index + 1]) || !is_continuation(bytes[index + 2])) {
                return false;
            }
            index += 3;
            continue;
        }
        if (first >= 0xF1u && first <= 0xF3u) {
            if (index + 2 >= value.size() || !is_continuation(bytes[index]) ||
                !is_continuation(bytes[index + 1]) || !is_continuation(bytes[index + 2])) {
                return false;
            }
            index += 3;
            continue;
        }
        if (first == 0xF4u) {
            if (index + 2 >= value.size() || bytes[index] < 0x80u || bytes[index] > 0x8Fu ||
                !is_continuation(bytes[index + 1]) || !is_continuation(bytes[index + 2])) {
                return false;
            }
            index += 3;
            continue;
        }
        return false;
    }
    return true;
}

}  // namespace

void CborWriter::write_head(Byte major_type, std::uint64_t argument) {
    if (major_type != 0u && major_type != 2u && major_type != 3u && major_type != 4u) {
        throw std::logic_error("CBOR major type is forbidden by the arrays-only wire profile");
    }

    if (argument < 24u) {
        payload_.push_back(static_cast<Byte>((major_type << 5u) | static_cast<Byte>(argument)));
    } else if (argument <= 0xFFu) {
        payload_.push_back(static_cast<Byte>((major_type << 5u) | 24u));
        payload_.push_back(static_cast<Byte>(argument));
    } else if (argument <= 0xFFFFu) {
        payload_.push_back(static_cast<Byte>((major_type << 5u) | 25u));
        payload_.push_back(static_cast<Byte>(argument >> 8u));
        payload_.push_back(static_cast<Byte>(argument));
    } else if (argument <= 0xFFFFFFFFu) {
        payload_.push_back(static_cast<Byte>((major_type << 5u) | 26u));
        for (int shift = 24; shift >= 0; shift -= 8) {
            payload_.push_back(static_cast<Byte>(argument >> shift));
        }
    } else {
        payload_.push_back(static_cast<Byte>((major_type << 5u) | 27u));
        for (int shift = 56; shift >= 0; shift -= 8) {
            payload_.push_back(static_cast<Byte>(argument >> shift));
        }
    }
}

void CborWriter::write_array(std::uint64_t length) {
    write_head(4u, length);
}

void CborWriter::write_uint(std::uint64_t value) {
    write_head(0u, value);
}

void CborWriter::write_string(Byte major_type, std::string_view value) {
    static_assert(sizeof(std::size_t) <= sizeof(std::uint64_t));
    write_head(major_type, static_cast<std::uint64_t>(value.size()));
    if (!value.empty()) {
        const auto* begin = reinterpret_cast<const Byte*>(value.data());
        payload_.insert(payload_.end(), begin, begin + value.size());
    }
}

void CborWriter::write_bytes(std::string_view value) {
    write_string(2u, value);
}

void CborWriter::write_text(std::string_view value) {
    if (!valid_utf8(value)) {
        throw std::invalid_argument("CBOR text is not valid UTF-8");
    }
    write_string(3u, value);
}

void CborWriter::write_to(std::ostream& output) const {
    output.write(reinterpret_cast<const char*>(payload_.data()),
                 static_cast<std::streamsize>(payload_.size()));
    if (!output) {
        throw std::ios_base::failure("failed to write CBOR payload");
    }
}

}  // namespace evaluation_v6_3_1::native
