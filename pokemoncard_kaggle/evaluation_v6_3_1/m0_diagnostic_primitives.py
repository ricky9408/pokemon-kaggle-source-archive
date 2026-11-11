M0_DIAGNOSTIC_INVENTORY_INCOMPLETE = "M0_DIAGNOSTIC_INVENTORY_INCOMPLETE"
M0_TEMPLATE_EMISSION_STATUS_UNPROVEN = "M0_TEMPLATE_EMISSION_STATUS_UNPROVEN"

SOURCE_ROOT = "/v631302/src"
STRUCTURAL_PATH_VERSION_V2 = 2
DEFINITION_INSTANCE_KEY_VERSION_V2 = 2
CALLABLE_DECLARATION_KINDS = frozenset(
    (
        "FunctionDecl",
        "CXXMethodDecl",
        "CXXConstructorDecl",
        "CXXDestructorDecl",
        "CXXConversionDecl",
    )
)
TU_RUNTIME_DECLARATION_KINDS = frozenset(
    (
        "VarDecl",
        "VarTemplateSpecializationDecl",
        "VarTemplatePartialSpecializationDecl",
    )
)

MAX_DEPTH = 64
MAX_CONTAINER_ITEMS = 100000
MAX_NODES = 200000
MAX_TEXT_BYTES = 1048576
MAX_BYTE_STRING_BYTES = 16777216
MAX_ENCODED_BYTES = 33554432
UINT64_MAX = (1 << 64) - 1


M0PrimitiveError = type(
    "M0PrimitiveError",
    (ValueError,),
    {"code": M0_DIAGNOSTIC_INVENTORY_INCOMPLETE},
)


def fail(message, code=M0_DIAGNOSTIC_INVENTORY_INCOMPLETE):
    if code != M0_DIAGNOSTIC_INVENTORY_INCOMPLETE:
        return OverflowError(message)
    return M0PrimitiveError(message)


def uint(value, bits, label):
    if type(value) is not int or value < 0 or value >= 1 << bits:
        raise fail(label + " must fit uint" + str(bits))
    return value


def bit(value, label):
    if type(value) is not int or value not in (0, 1):
        raise fail(label + " must be 0 or 1")
    return value


def array(value, label):
    if type(value) not in (list, tuple):
        raise fail(label + " must be an array")
    return value


def text(value, label, allow_empty=False):
    if type(value) is not str or (not allow_empty and not value) or "\x00" in value:
        raise fail(label + " must be NUL-free text")
    try:
        encoded = value.encode("utf-8", "strict")
    except UnicodeError as exc:
        raise fail(label + " is not valid UTF-8") from exc
    # The diagnostic source, target registry, and type grammar are ASCII.  A
    # non-ASCII value fails closed instead of relying on installed Unicode data.
    if any([item >= 128 for item in encoded]):
        raise fail(label + " is outside the import-free ASCII text profile")
    if len(encoded) > MAX_TEXT_BYTES:
        raise fail(label + " exceeds the text limit")
    return value


def bstr32(value, label):
    if type(value) is not bytes or len(value) != 32:
        raise fail(label + " must be a 32-byte string")
    return value


def source_path(value, label):
    path = text(value, label)
    if not path.startswith(SOURCE_ROOT + "/") or path.endswith("/"):
        raise fail(label + " must be below " + SOURCE_ROOT)
    components = path.split("/")[1:]
    if any([component in ("", ".", "..") for component in components]):
        raise fail(label + " has a noncanonical component")
    return path


def ast_path(value, label):
    return [uint(item, 32, label + " component") for item in array(value, label)]


def structural_path_v2(value, label):
    row = array(value, label)
    if len(row) != 2:
        raise fail(label + " has the wrong width")
    version = uint(row[0], 16, label + " version")
    if version != STRUCTURAL_PATH_VERSION_V2:
        raise fail(label + " version is invalid")
    return [version, ast_path(row[1], label + " indices")]


def source_anchor(value, label="source_anchor"):
    row = array(value, label)
    if len(row) != 3:
        raise fail(label + " has the wrong width")
    path = source_path(row[0], label + " path")
    begin = uint(row[1], 64, label + " begin")
    end = uint(row[2], 64, label + " end")
    if end <= begin:
        raise fail(label + " span must be nonempty")
    return [path, begin, end]


def construct_key(value):
    row = array(value, "construct_key")
    if len(row) != 3:
        raise fail("construct_key has the wrong width")
    return [
        ast_path(row[0], "occurrence_ast_path"),
        text(row[1], "ast_node_kind"),
        source_anchor(row[2]),
    ]


_MULTI = ("->*", "...", "::", "&&", "->", ".*")
_SINGLE = frozenset("()[]<>,*&=+-/%!~?:.^|")
_ASCII_WHITESPACE = frozenset("\x09\x0a\x0b\x0c\x0d ")
_CV_QUALIFIERS = frozenset(("const", "volatile", "noexcept", "restrict"))


def _split_punctuator(raw, start):
    for punctuator in _MULTI:
        if raw[start] != punctuator[0]:
            continue
        cursor = start + 1
        for expected in punctuator[1:]:
            while cursor < len(raw) and raw[cursor] in _ASCII_WHITESPACE:
                cursor += 1
            if cursor >= len(raw) or raw[cursor] != expected:
                break
            cursor += 1
        else:
            if cursor != start + len(punctuator):
                return True
    return False


def _qtid_tokens(raw):
    text(raw, "raw_qual_type")
    tokens = []
    index = 0
    while index < len(raw):
        char = raw[index]
        code = ord(char)
        if (code < 32 and char not in _ASCII_WHITESPACE) or code == 127:
            raise fail("qualified type contains unsupported ASCII")
        if char in _ASCII_WHITESPACE:
            index += 1
            continue
        if _split_punctuator(raw, index):
            raise fail("whitespace splits a multi-byte punctuator")
        if ("a" <= char <= "z") or ("A" <= char <= "Z") or char == "_":
            end = index + 1
            while end < len(raw):
                item = raw[end]
                if not (
                    ("a" <= item <= "z")
                    or ("A" <= item <= "Z")
                    or ("0" <= item <= "9")
                    or item == "_"
                ):
                    break
                end += 1
            tokens.append(["word", raw[index:end]])
            index = end
            continue
        if "0" <= char <= "9":
            end = index + 1
            while end < len(raw):
                item = raw[end]
                if not (
                    ("a" <= item <= "z")
                    or ("A" <= item <= "Z")
                    or ("0" <= item <= "9")
                    or item in "_'"
                ):
                    break
                end += 1
            tokens.append(["number", raw[index:end]])
            index = end
            continue
        matched = None
        for punctuator in _MULTI:
            if raw.startswith(punctuator, index):
                matched = punctuator
                break
        if matched is not None:
            tokens.append(["punct", matched])
            index += len(matched)
            continue
        if char in _SINGLE:
            tokens.append(["punct", char])
            index += 1
            continue
        raise fail("qualified type contains an unsupported token")
    if not tokens:
        raise fail("qualified type contains no tokens")
    return tokens


def qtid_ascii_v1(raw_qual_type):
    tokens = _qtid_tokens(raw_qual_type)
    stack = []
    previous = None
    for kind, spelling in tokens:
        if spelling in ("(", "["):
            stack.append(spelling)
        elif spelling == "<":
            if previous is None or (
                previous[0] != "word" and previous[1] not in (")", "]", ">")
            ):
                raise fail("angle opener is not a template delimiter")
            stack.append(spelling)
        elif spelling in (")", "]", ">"):
            expected = {")": "(", "]": "[", ">": "<"}[spelling]
            if not stack or stack[-1] != expected:
                raise fail("qualified type delimiters are not nested")
            stack.pop()
        elif spelling == ",":
            if not stack or stack[-1] not in ("(", "<"):
                raise fail("qualified type comma is outside a delimiter")
        if stack and stack[-1] == "<" and spelling in (
            "=", "+", "-", "/", "%", "!", "~", "?", ":", ".", "^", "|"
        ):
            raise fail("angle contents are ambiguous")
        previous = [kind, spelling]
    if stack:
        raise fail("qualified type delimiters are unbalanced")
    for left, right in zip(tokens, tokens[1:]):
        if left[1] == ">" and right[0] in ("word", "number") and right[1] not in _CV_QUALIFIERS:
            raise fail("qualified type angle spelling is ambiguous")
    output = []
    for index, item in enumerate(tokens):
        kind, spelling = item
        if index and kind in ("word", "number") and tokens[index - 1][0] in ("word", "number"):
            output.append(" ")
        output.append(spelling)
    return "".join(output)


def definition_semantic_key_v1(value, descriptor_count=116):
    row = array(value, "definition semantic key")
    if len(row) != 8:
        raise fail("definition semantic key has the wrong width")
    kind = text(row[0], "definition ast_decl_kind")
    if kind not in CALLABLE_DECLARATION_KINDS:
        raise fail("definition kind is outside the frozen set")
    targets = [
        uint(item, 32, "definition target index")
        for item in array(row[4], "target_indices")
    ]
    if targets != sorted(set(targets)) or any(
        [item >= descriptor_count for item in targets]
    ):
        raise fail("definition target indices are not canonical")
    normalized = [
        kind,
        text(row[1], "definition qualified_name"),
        text(row[2], "definition raw_qual_type"),
        uint(row[3], 8, "definition linkage_code"),
        targets,
        source_path(row[5], "definition source path"),
        uint(row[6], 64, "definition begin"),
        uint(row[7], 64, "definition end"),
    ]
    if normalized[3] not in (1, 2) or normalized[7] <= normalized[6]:
        raise fail("definition semantic key is invalid")
    qtid_ascii_v1(normalized[2])
    return normalized


def definition_instance_key_v2(value, descriptor_count=116):
    row = array(value, "definition instance key")
    if len(row) != 3:
        raise fail("definition instance key has the wrong width")
    version = uint(row[0], 16, "definition instance key version")
    if version != DEFINITION_INSTANCE_KEY_VERSION_V2:
        raise fail("definition instance key version is invalid")
    source_subject = subject_key(1, row[1], descriptor_count)
    semantic_key = definition_semantic_key_v1(row[2], descriptor_count)
    if (
        source_subject[1] != semantic_key[0]
        or source_subject[2][0] != semantic_key[5]
        or source_subject[2][1] != semantic_key[6]
        or source_subject[2][2] != semantic_key[7]
    ):
        raise fail("definition instance key fields are not byte-identical")
    return [version, source_subject, semantic_key]


def subject_key(domain, value, descriptor_count=116):
    row = array(value, "subject_key")
    if domain == 1:
        if len(row) != 3:
            raise fail("source-definition subject key has the wrong width")
        kind = text(row[1], "source-definition ast_decl_kind")
        if kind not in CALLABLE_DECLARATION_KINDS:
            raise fail("source-definition kind is outside the frozen set")
        return [
            structural_path_v2(row[0], "source-definition structural path"),
            kind,
            source_anchor(row[2]),
        ]
    if domain == 2:
        if len(row) != 9:
            raise fail("TU-runtime subject key has the wrong width")
        targets = [uint(item, 32, "TU-runtime target index") for item in array(row[4], "target_indices")]
        if targets != sorted(set(targets)) or any([item >= descriptor_count for item in targets]):
            raise fail("TU-runtime target indices are not canonical")
        normalized = [
            text(row[0], "TU-runtime ast_decl_kind"),
            text(row[1], "TU-runtime qualified_name"),
            text(row[2], "TU-runtime raw_qual_type"),
            uint(row[3], 8, "TU-runtime linkage_code"),
            targets,
            source_path(row[5], "TU-runtime source path"),
            uint(row[6], 64, "TU-runtime begin"),
            uint(row[7], 64, "TU-runtime end"),
            structural_path_v2(row[8], "TU-runtime structural path"),
        ]
        if (
            normalized[0] not in TU_RUNTIME_DECLARATION_KINDS
            or normalized[3] not in (1, 2)
            or normalized[7] <= normalized[6]
        ):
            raise fail("TU-runtime subject key is invalid")
        qtid_ascii_v1(normalized[2])
        return normalized
    if domain == 3:
        return definition_instance_key_v2(row, descriptor_count)
    raise fail("subject domain code is invalid")


def _head(major, value):
    if type(value) is not int or value < 0:
        raise fail("CBOR argument is negative")
    if value < 24:
        return bytes(((major << 5) | value,))
    if value <= 255:
        return bytes(((major << 5) | 24, value))
    if value <= 65535:
        return bytes(((major << 5) | 25,)) + value.to_bytes(2, "big")
    if value <= 4294967295:
        return bytes(((major << 5) | 26,)) + value.to_bytes(4, "big")
    if value <= UINT64_MAX:
        return bytes(((major << 5) | 27,)) + value.to_bytes(8, "big")
    raise fail("CBOR argument exceeds uint64")


def canonical_cbor_encode(value):
    nodes = [0]
    active = []

    def encode(item, depth):
        if depth > MAX_DEPTH:
            raise fail("CBOR nesting exceeds the limit")
        nodes[0] += 1
        if nodes[0] > MAX_NODES:
            raise fail("CBOR node count exceeds the limit")
        if type(item) is int:
            if item < 0:
                raise fail("negative integers are forbidden")
            return _head(0, item)
        if type(item) is bytes:
            if len(item) > MAX_BYTE_STRING_BYTES:
                raise fail("CBOR byte string exceeds the limit")
            return _head(2, len(item)) + item
        if type(item) is str:
            text(item, "CBOR text", allow_empty=True)
            raw = item.encode("ascii")
            return _head(3, len(raw)) + raw
        if type(item) in (list, tuple):
            if len(item) > MAX_CONTAINER_ITEMS:
                raise fail("CBOR array exceeds the limit")
            for ancestor in active:
                if item is ancestor:
                    raise fail("cyclic arrays are forbidden")
            active.append(item)
            try:
                parts = [encode(child, depth + 1) for child in item]
                result = _head(4, len(parts)) + b"".join(parts)
            finally:
                active.pop()
            if len(result) > MAX_ENCODED_BYTES:
                raise fail("CBOR output exceeds the limit")
            return result
        raise fail("CBOR wire permits only uint, bytes, text, and arrays")

    result = encode(value, 0)
    if len(result) > MAX_ENCODED_BYTES:
        raise fail("CBOR output exceeds the limit")
    return result


def canonical_cbor_decode(raw):
    if type(raw) is not bytes or not raw or len(raw) > MAX_ENCODED_BYTES:
        raise fail("CBOR input is invalid or too large")
    offset = [0]
    nodes = [0]

    def take(count):
        end = offset[0] + count
        if count < 0 or end > len(raw):
            raise fail("CBOR input is truncated")
        value = raw[offset[0]:end]
        offset[0] = end
        return value

    def argument(additional):
        if additional < 24:
            return additional
        widths = {24: 1, 25: 2, 26: 4, 27: 8}
        width = widths.get(additional)
        if width is None:
            raise fail("CBOR argument is indefinite or reserved")
        encoded = take(width)
        value = int.from_bytes(encoded, "big")
        minimum = {1: 24, 2: 256, 4: 65536, 8: 1 << 32}[width]
        if value < minimum:
            raise fail("CBOR argument is not shortest-form")
        return value

    def decode(depth):
        if depth > MAX_DEPTH:
            raise fail("CBOR nesting exceeds the limit")
        nodes[0] += 1
        if nodes[0] > MAX_NODES:
            raise fail("CBOR node count exceeds the limit")
        initial = take(1)[0]
        major = initial >> 5
        additional = initial & 31
        if major == 0:
            return argument(additional)
        if major in (2, 3):
            length = argument(additional)
            limit = MAX_BYTE_STRING_BYTES if major == 2 else MAX_TEXT_BYTES
            if length > limit:
                raise fail("CBOR string exceeds the limit")
            payload = take(length)
            if major == 2:
                return payload
            if any([item >= 128 for item in payload]):
                raise fail("CBOR text is outside the ASCII profile")
            try:
                return payload.decode("ascii")
            except UnicodeError as exc:
                raise fail("CBOR text is invalid") from exc
        if major == 4:
            length = argument(additional)
            if length > MAX_CONTAINER_ITEMS:
                raise fail("CBOR array exceeds the limit")
            return [decode(depth + 1) for _ in range(length)]
        raise fail("CBOR type is forbidden by the arrays-only wire")

    value = decode(0)
    if offset[0] != len(raw):
        raise fail("CBOR input has trailing bytes")
    if canonical_cbor_encode(value) != raw:
        raise fail("CBOR input is not byte-canonical")
    return value


_SHA256_K = (
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
    0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
    0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
    0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
    0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
    0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
)


def _rotr(value, count):
    return ((value >> count) | ((value << (32 - count)) & 0xFFFFFFFF)) & 0xFFFFFFFF


def sha256_digest(data):
    if type(data) is not bytes:
        raise fail("SHA-256 input must be bytes")
    message = bytearray(data)
    bit_length = len(message) * 8
    message.append(0x80)
    while len(message) % 64 != 56:
        message.append(0)
    message.extend(bit_length.to_bytes(8, "big"))
    state = [
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
    ]
    for start in range(0, len(message), 64):
        chunk = message[start:start + 64]
        words = [int.from_bytes(chunk[index:index + 4], "big") for index in range(0, 64, 4)]
        for index in range(16, 64):
            left = words[index - 15]
            right = words[index - 2]
            s0 = _rotr(left, 7) ^ _rotr(left, 18) ^ (left >> 3)
            s1 = _rotr(right, 17) ^ _rotr(right, 19) ^ (right >> 10)
            words.append((words[index - 16] + s0 + words[index - 7] + s1) & 0xFFFFFFFF)
        a, b, c, d, e, f, g, h = state
        for index in range(64):
            s1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25)
            choice = (e & f) ^ ((~e) & g)
            temporary1 = (h + s1 + choice + _SHA256_K[index] + words[index]) & 0xFFFFFFFF
            s0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22)
            majority = (a & b) ^ (a & c) ^ (b & c)
            temporary2 = (s0 + majority) & 0xFFFFFFFF
            h, g, f, e, d, c, b, a = g, f, e, (d + temporary1) & 0xFFFFFFFF, c, b, a, (temporary1 + temporary2) & 0xFFFFFFFF
        state = [
            (state[0] + a) & 0xFFFFFFFF,
            (state[1] + b) & 0xFFFFFFFF,
            (state[2] + c) & 0xFFFFFFFF,
            (state[3] + d) & 0xFFFFFFFF,
            (state[4] + e) & 0xFFFFFFFF,
            (state[5] + f) & 0xFFFFFFFF,
            (state[6] + g) & 0xFFFFFFFF,
            (state[7] + h) & 0xFFFFFFFF,
        ]
    return b"".join([item.to_bytes(4, "big") for item in state])


def encoded(value):
    return canonical_cbor_encode(value)
