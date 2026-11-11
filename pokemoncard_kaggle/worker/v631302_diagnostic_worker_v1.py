import sys

_B = sys.modules["builtins"]
_ENTRY_PATH = "evaluation_v6_3_1/m0_diagnostic_census.py"
_ENTRY_NAME = "evaluation_v6_3_1.m0_diagnostic_census"
_WORKER_PATH = "worker/v631302_diagnostic_worker_v1.py"
_FUTURE_PREFIX = b"from __future__ import annotations\n"
_FUTURE_ANNOTATIONS = 0x01000000
_DOMAIN = b"V631302_CANONICALIZER_BUNDLE_V1"
_IN_MAGIC = b"V631DI01"
_OUT_MAGIC = b"V631DO01"
_FAIL = 80
_TEMPLATE = 81

_PROJECT_BUILTIN_NAMES = (
    "__import__",
    "abs",
    "all",
    "any",
    "bool",
    "bytearray",
    "bytes",
    "chr",
    "dict",
    "divmod",
    "enumerate",
    "Exception",
    "float",
    "frozenset",
    "IndexError",
    "int",
    "isinstance",
    "iter",
    "KeyError",
    "len",
    "list",
    "max",
    "memoryview",
    "min",
    "next",
    "ord",
    "OverflowError",
    "range",
    "reversed",
    "RuntimeError",
    "set",
    "slice",
    "sorted",
    "StopIteration",
    "str",
    "sum",
    "tuple",
    "type",
    "TypeError",
    "UnicodeDecodeError",
    "UnicodeEncodeError",
    "UnicodeError",
    "ValueError",
    "zip",
)

# CPython 3.11 wordcode opcodes admitted by Amendment 5.  CACHE and
# EXTENDED_ARG are parsed structurally rather than treated as instructions.
_PERMITTED_OPCODES = frozenset((
    1,    # POP_TOP
    2,    # PUSH_NULL
    9,    # NOP
    15,   # UNARY_INVERT
    25,   # BINARY_SUBSCR
    35,   # PUSH_EXC_INFO
    36,   # CHECK_EXC_MATCH
    60,   # STORE_SUBSCR
    68,   # GET_ITER
    83,   # RETURN_VALUE
    89,   # POP_EXCEPT
    90,   # STORE_NAME
    91,   # DELETE_NAME
    92,   # UNPACK_SEQUENCE
    93,   # FOR_ITER
    97,   # STORE_GLOBAL
    98,   # DELETE_GLOBAL
    99,   # SWAP
    100,  # LOAD_CONST
    101,  # LOAD_NAME
    102,  # BUILD_TUPLE
    103,  # BUILD_LIST
    104,  # BUILD_SET
    105,  # BUILD_MAP
    106,  # LOAD_ATTR
    107,  # COMPARE_OP
    108,  # IMPORT_NAME
    109,  # IMPORT_FROM
    110,  # JUMP_FORWARD
    111,  # JUMP_IF_FALSE_OR_POP
    112,  # JUMP_IF_TRUE_OR_POP
    114,  # POP_JUMP_FORWARD_IF_FALSE
    115,  # POP_JUMP_FORWARD_IF_TRUE
    116,  # LOAD_GLOBAL
    117,  # IS_OP
    118,  # CONTAINS_OP
    119,  # RERAISE
    120,  # COPY
    122,  # BINARY_OP
    124,  # LOAD_FAST
    125,  # STORE_FAST
    126,  # DELETE_FAST
    128,  # POP_JUMP_FORWARD_IF_NOT_NONE
    129,  # POP_JUMP_FORWARD_IF_NONE
    130,  # RAISE_VARARGS
    132,  # MAKE_FUNCTION
    133,  # BUILD_SLICE
    135,  # MAKE_CELL
    136,  # LOAD_CLOSURE
    137,  # LOAD_DEREF
    138,  # STORE_DEREF
    140,  # JUMP_BACKWARD
    145,  # LIST_APPEND
    146,  # SET_ADD
    147,  # MAP_ADD
    149,  # COPY_FREE_VARS
    151,  # RESUME
    156,  # BUILD_CONST_KEY_MAP
    160,  # LOAD_METHOD
    162,  # LIST_EXTEND
    166,  # PRECALL
    171,  # CALL
    172,  # KW_NAMES
    173,  # POP_JUMP_BACKWARD_IF_NOT_NONE
    174,  # POP_JUMP_BACKWARD_IF_NONE
    175,  # POP_JUMP_BACKWARD_IF_FALSE
    176,  # POP_JUMP_BACKWARD_IF_TRUE
))

_INLINE_CACHE_ENTRIES = {
    25: 4,   # BINARY_SUBSCR
    60: 1,   # STORE_SUBSCR
    92: 1,   # UNPACK_SEQUENCE
    95: 4,   # STORE_ATTR (prohibited executable opcode)
    106: 4,  # LOAD_ATTR
    107: 2,  # COMPARE_OP
    116: 5,  # LOAD_GLOBAL
    122: 1,  # BINARY_OP
    160: 10, # LOAD_METHOD
    166: 1,  # PRECALL
    171: 4,  # CALL
}

_NAME_OPCODES = frozenset((90, 91, 97, 98, 101, 108, 109, 116))
_WRITE_NAME_OPCODES = frozenset((90, 91, 97, 98))
_ATTRIBUTE_OPCODES = frozenset((106, 160))
_CO_NAMES_INDEX_RULES = {
    90: 0,   # STORE_NAME: DIRECT_OPARG
    91: 0,   # DELETE_NAME: DIRECT_OPARG
    95: 0,   # STORE_ATTR: DIRECT_OPARG (prohibited executable opcode)
    96: 0,   # DELETE_ATTR: DIRECT_OPARG (prohibited executable opcode)
    97: 0,   # STORE_GLOBAL: DIRECT_OPARG
    98: 0,   # DELETE_GLOBAL: DIRECT_OPARG
    101: 0,  # LOAD_NAME: DIRECT_OPARG
    106: 0,  # LOAD_ATTR: DIRECT_OPARG
    108: 0,  # IMPORT_NAME: DIRECT_OPARG
    109: 0,  # IMPORT_FROM: DIRECT_OPARG
    116: 1,  # LOAD_GLOBAL: OPARG_SHIFT_RIGHT_ONE
    160: 0,  # LOAD_METHOD: DIRECT_OPARG
}
_FORWARD_JUMPS = frozenset((93, 110, 111, 112, 114, 115, 128, 129))
_BACKWARD_JUMPS = frozenset((140, 173, 174, 175, 176))
_FAST_OPCODES = frozenset((124, 125, 126))
_LOCALSPLUS_OPCODES = frozenset((135, 136, 137, 138))
_FORBIDDEN_NAMES = frozenset((
    "__self__",
    "__globals__",
    "__subclasses__",
    "__getattribute__",
    "__dict__",
    "__builtins__",
    "__import__",
    "globals",
    "locals",
    "vars",
    "dir",
    "getattr",
    "setattr",
    "delattr",
    "hasattr",
    "eval",
    "exec",
    "compile",
    "open",
    "input",
    "breakpoint",
    "help",
))
_PERMITTED_ATTRIBUTES = frozenset((
    "add",
    "annotations",
    "append",
    "bit_length",
    "clear",
    "copy",
    "count",
    "decode",
    "discard",
    "encode",
    "endswith",
    "extend",
    "find",
    "from_bytes",
    "fromhex",
    "get",
    "hex",
    "index",
    "insert",
    "isascii",
    "items",
    "join",
    "keys",
    "pop",
    "remove",
    "replace",
    "reverse",
    "setdefault",
    "sort",
    "split",
    "splitlines",
    "startswith",
    "strip",
    "to_bytes",
    "update",
    "values",
))
_RESERVED_PROFILE_NAME = "V631302_BOUND_COLLECTOR_PROFILE_CBOR"


class _InventoryFailure(BaseException):
    pass


class _TemplateFailure(BaseException):
    pass


def _fail():
    raise _InventoryFailure()


def _exact(value, expected):
    if value != expected or type(value) is not type(expected):
        _fail()


def _uint(value, bits=64):
    if type(value) is not int or value < 0 or value >= (1 << bits):
        _fail()
    return value


def _bstr32(value):
    if type(value) is not bytes or len(value) != 32:
        _fail()
    return value


def _text(value):
    if type(value) is not str or not value or "\x00" in value:
        _fail()
    return value


def _sha256(raw):
    if type(raw) is not bytes:
        _fail()
    bits = len(raw) * 8
    data = raw + b"\x80"
    data += b"\x00" * ((56 - (len(data) % 64)) % 64)
    data += bits.to_bytes(8, "big")
    words = (
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
    )
    constants = (
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
    mask = 0xFFFFFFFF
    state = list(words)
    for start in range(0, len(data), 64):
        block = data[start:start + 64]
        schedule = [int.from_bytes(block[index:index + 4], "big") for index in range(0, 64, 4)]
        for index in range(16, 64):
            x = schedule[index - 15]
            y = schedule[index - 2]
            s0 = ((x >> 7) | ((x << 25) & mask)) ^ ((x >> 18) | ((x << 14) & mask)) ^ (x >> 3)
            s1 = ((y >> 17) | ((y << 15) & mask)) ^ ((y >> 19) | ((y << 13) & mask)) ^ (y >> 10)
            schedule.append((schedule[index - 16] + s0 + schedule[index - 7] + s1) & mask)
        a, b, c, d, e, f, g, h = state
        for index in range(64):
            s1 = ((e >> 6) | ((e << 26) & mask)) ^ ((e >> 11) | ((e << 21) & mask)) ^ ((e >> 25) | ((e << 7) & mask))
            choice = (e & f) ^ ((~e) & g)
            temp1 = (h + s1 + choice + constants[index] + schedule[index]) & mask
            s0 = ((a >> 2) | ((a << 30) & mask)) ^ ((a >> 13) | ((a << 19) & mask)) ^ ((a >> 22) | ((a << 10) & mask))
            majority = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (s0 + majority) & mask
            h, g, f, e, d, c, b, a = g, f, e, (d + temp1) & mask, c, b, a, (temp1 + temp2) & mask
        state = [
            (state[0] + a) & mask, (state[1] + b) & mask,
            (state[2] + c) & mask, (state[3] + d) & mask,
            (state[4] + e) & mask, (state[5] + f) & mask,
            (state[6] + g) & mask, (state[7] + h) & mask,
        ]
    return b"".join(value.to_bytes(4, "big") for value in state)


def _cbor_head(major, value):
    _uint(major, 3)
    _uint(value)
    if value < 24:
        return bytes(((major << 5) | value,))
    if value <= 0xFF:
        return bytes(((major << 5) | 24, value))
    if value <= 0xFFFF:
        return bytes(((major << 5) | 25,)) + value.to_bytes(2, "big")
    if value <= 0xFFFFFFFF:
        return bytes(((major << 5) | 26,)) + value.to_bytes(4, "big")
    return bytes(((major << 5) | 27,)) + value.to_bytes(8, "big")


def _cbor_encode(value):
    if type(value) is int:
        return _cbor_head(0, value)
    if type(value) is bytes:
        return _cbor_head(2, len(value)) + value
    if type(value) is str:
        raw = value.encode("utf-8", "strict")
        return _cbor_head(3, len(raw)) + raw
    if type(value) is list:
        return _cbor_head(4, len(value)) + b"".join(_cbor_encode(item) for item in value)
    _fail()


def _cbor_decode(raw):
    if type(raw) is not bytes:
        _fail()
    limit = len(raw)
    nodes = [0]

    def read(offset, count):
        if count < 0 or offset < 0 or offset + count > limit:
            _fail()
        return raw[offset:offset + count], offset + count

    def arg(offset, additional):
        if additional < 24:
            return additional, offset
        sizes = {24: 1, 25: 2, 26: 4, 27: 8}
        if additional not in sizes:
            _fail()
        chunk, offset = read(offset, sizes[additional])
        value = int.from_bytes(chunk, "big")
        minimum = {24: 24, 25: 256, 26: 65536, 27: 4294967296}[additional]
        if value < minimum:
            _fail()
        return value, offset

    def item(offset, depth):
        if depth > 64:
            _fail()
        nodes[0] += 1
        if nodes[0] > 200000:
            _fail()
        head, offset = read(offset, 1)
        major = head[0] >> 5
        additional = head[0] & 31
        value, offset = arg(offset, additional)
        if major == 0:
            return value, offset
        if major == 2:
            chunk, offset = read(offset, value)
            return chunk, offset
        if major == 3:
            chunk, offset = read(offset, value)
            try:
                return chunk.decode("utf-8", "strict"), offset
            except UnicodeError:
                _fail()
        if major == 4:
            if value > 200000:
                _fail()
            result = []
            for _ in range(value):
                child, offset = item(offset, depth + 1)
                result.append(child)
            return result, offset
        _fail()

    result, offset = item(0, 0)
    if offset != limit or _cbor_encode(result) != raw:
        _fail()
    return result


def _top_array_item_ranges(raw, expected_length):
    if type(raw) is not bytes or not raw:
        _fail()

    def argument(offset, additional):
        if additional < 24:
            return additional, offset
        sizes = {24: 1, 25: 2, 26: 4, 27: 8}
        if additional not in sizes or offset + sizes[additional] > len(raw):
            _fail()
        value = int.from_bytes(raw[offset:offset + sizes[additional]], "big")
        if value < {24: 24, 25: 256, 26: 65536, 27: 4294967296}[additional]:
            _fail()
        return value, offset + sizes[additional]

    def end(offset, depth):
        if depth > 64 or offset >= len(raw):
            _fail()
        head = raw[offset]
        value, next_offset = argument(offset + 1, head & 31)
        major = head >> 5
        if major == 0:
            return next_offset
        if major in (2, 3):
            if next_offset + value > len(raw):
                _fail()
            if major == 3:
                try:
                    raw[next_offset:next_offset + value].decode("utf-8", "strict")
                except UnicodeError:
                    _fail()
            return next_offset + value
        if major == 4:
            for _ in range(value):
                next_offset = end(next_offset, depth + 1)
            return next_offset
        _fail()

    head = raw[0]
    if head >> 5 != 4:
        _fail()
    length, offset = argument(1, head & 31)
    if length != expected_length:
        _fail()
    ranges = []
    for _ in range(length):
        start = offset
        offset = end(offset, 1)
        ranges.append((start, offset))
    if offset != len(raw):
        _fail()
    return ranges


def _read_exact(stream, size):
    _uint(size)
    pieces = []
    left = size
    while left:
        part = stream.read(left)
        if type(part) is not bytes or not part:
            _fail()
        pieces.append(part)
        left -= len(part)
    return b"".join(pieces)


def _read_input():
    stream = sys.stdin.buffer
    if _read_exact(stream, 8) != _IN_MAGIC:
        _fail()
    size = int.from_bytes(_read_exact(stream, 8), "big")
    payload = _read_exact(stream, size)
    if stream.read(1) != b"":
        _fail()
    return payload, _cbor_decode(payload)


def _bundle_path(value):
    path = _text(value)
    if path.startswith("/") or "\\" in path:
        _fail()
    parts = path.split("/")
    if any(part in ("", ".", "..") for part in parts):
        _fail()
    return path


def _module_name(path):
    if not path.startswith("evaluation_v6_3_1/") or not path.endswith(".py"):
        return None
    name = path[:-3].replace("/", ".")
    if name.endswith(".__init__"):
        name = name[:-9]
    if not name or name == "evaluation_v6_3_1.__init__":
        _fail()
    return name


def _parse_manifest(value):
    if type(value) is not list or len(value) != 3 or value[0] != 1 or type(value[0]) is not int:
        _fail()
    if _bundle_path(value[1]) != _ENTRY_PATH or type(value[2]) is not list or not value[2]:
        _fail()
    files = []
    seen = set()
    prior = None
    entry_count = 0
    names = {}
    packages = set()
    for row in value[2]:
        if type(row) is not list or len(row) != 3:
            _fail()
        path = _bundle_path(row[0])
        length = _uint(row[1])
        digest = _bstr32(row[2])
        encoded = path.encode("utf-8", "strict")
        if path in seen or (prior is not None and encoded <= prior):
            _fail()
        seen.add(path)
        prior = encoded
        if path == _ENTRY_PATH:
            entry_count += 1
        name = _module_name(path)
        if name is not None:
            if name in names:
                _fail()
            names[name] = path
            if path.endswith("/__init__.py"):
                packages.add(name)
        files.append([path, length, digest])
    if entry_count != 1 or _WORKER_PATH not in seen:
        _fail()
    for name in names:
        if "." in name:
            parent = name.rpartition(".")[0]
            if parent not in packages:
                _fail()
    return [1, _ENTRY_PATH, files], names, packages


def _parse_bytes(value, manifest):
    if type(value) is not list or len(value) != len(manifest[2]):
        _fail()
    result = {}
    for index, row in enumerate(value):
        expected = manifest[2][index]
        if type(row) is not list or len(row) != 2 or row[0] != expected[0] or type(row[0]) is not str:
            _fail()
        raw = row[1]
        if type(raw) is not bytes or len(raw) != expected[1] or _sha256(raw) != expected[2]:
            _fail()
        result[expected[0]] = raw
    return result


def _check_worker_source(raw, profile):
    if len(raw) > 65535 or not raw.endswith(b"\n") or b"\r" in raw or b"\x00" in raw:
        _fail()
    if any(byte > 127 for byte in raw) or raw.startswith(b"\xef\xbb\xbf"):
        _fail()
    if _sha256(raw) != profile[3]:
        _fail()


def _read_executable():
    handle = open("/proc/self/exe", "rb")
    try:
        pieces = []
        while True:
            piece = handle.read(1048576)
            if type(piece) is not bytes:
                _fail()
            if not piece:
                break
            pieces.append(piece)
        return b"".join(pieces)
    finally:
        handle.close()


def _parse_prelaunch_profile(value):
    if type(value) is not list or len(value) != 8:
        _fail()
    profile = [
        _bstr32(value[0]),
        _text(value[1]),
        _bstr32(value[2]),
        _uint(value[3], 16),
        value[4],
        value[5],
        value[6],
        value[7],
    ]
    if profile[4] != 1 or type(profile[4]) is not int:
        _fail()
    manifest, names, packages = _parse_manifest(profile[7])
    return profile, manifest, names, packages


def _check_execution_profile(profile, bytes_by_path):
    execution_profile = profile[5]
    if type(execution_profile) is not list or len(execution_profile) != 8 or execution_profile[0] != 1 or type(execution_profile[0]) is not int:
        _fail()
    pin = execution_profile[1]
    if type(pin) is not list or len(pin) != 7:
        _fail()
    if pin[0] != 1 or type(pin[0]) is not int or pin[1] != 1 or type(pin[1]) is not int:
        _fail()
    if type(pin[2]) is not int or pin[2] != sys.hexversion:
        _fail()
    if type(pin[3]) is not str or pin[3] != sys.implementation.cache_tag:
        _fail()
    if type(pin[4]) is not str or pin[4] != sys.abiflags:
        _fail()
    executable = _read_executable()
    if _uint(pin[5]) != len(executable) or _bstr32(pin[6]) != _sha256(executable):
        _fail()
    if execution_profile[2] != _WORKER_PATH or type(execution_profile[2]) is not str or _bstr32(execution_profile[3]) != _sha256(bytes_by_path[_WORKER_PATH]):
        _fail()
    for index in (4, 5, 6, 7):
        if execution_profile[index] != 1 or type(execution_profile[index]) is not int:
            _fail()
    if type(profile[6]) is not bytes or len(profile[6]) != 32:
        _fail()
    expected_root = _sha256(_cbor_encode([_DOMAIN, 631302, 1, 1, profile[7]]))
    if profile[6] != expected_root:
        _fail()
    _check_worker_source(bytes_by_path[_WORKER_PATH], execution_profile)


def _check_startup():
    if sys.argv != ["-c", "V631302_DIAGNOSTIC_WORKER_V1", _WORKER_PATH]:
        _fail()
    flags = sys.flags
    values = (
        flags.isolated, flags.no_site, flags.ignore_environment, flags.no_user_site,
        flags.safe_path, flags.dont_write_bytecode, flags.utf8_mode, flags.optimize,
    )
    if values != (1, 1, 1, 1, 1, 1, 1, 0):
        _fail()
    if getattr(sys.__spec__, "origin", None) != "built-in":
        _fail()
    builtins_module = sys.modules.get("builtins")
    if builtins_module is None or getattr(getattr(builtins_module, "__spec__", None), "origin", None) != "built-in":
        _fail()
    if sys.implementation.name != "cpython":
        _fail()


def _verify_code_units(raw, names, constants, varnames, cellvars, freevars):
    if type(raw) is not bytes or len(raw) == 0 or len(raw) % 2:
        _fail()
    namespaces = (names, constants, varnames, cellvars, freevars)
    if any(type(value) is not tuple for value in namespaces):
        _fail()
    if any(type(name) is not str for group in (names, varnames, cellvars, freevars) for name in group):
        _fail()
    localsplus_count = len(varnames) + len([name for name in cellvars if name not in varnames]) + len(freevars)

    instructions = []
    starts = set()
    offset = 0
    while offset < len(raw):
        start = offset
        extended = 0
        extended_count = 0
        while offset < len(raw) and raw[offset] == 144:
            if offset + 1 >= len(raw) or extended_count >= 3:
                _fail()
            extended = (extended << 8) | raw[offset + 1]
            extended_count += 1
            offset += 2
        if offset + 1 >= len(raw):
            _fail()
        opcode = raw[offset]
        if opcode == 0 or opcode == 144 or opcode not in _PERMITTED_OPCODES:
            _fail()
        if extended_count and opcode < 90:
            _fail()
        if opcode < 90 and raw[offset + 1] != 0:
            _fail()
        argument = (extended << 8) | raw[offset + 1]
        opcode_offset = offset
        starts.add(start)
        instructions.append((start, opcode_offset, opcode, argument))
        offset += 2
        cache_count = _INLINE_CACHE_ENTRIES.get(opcode, 0)
        for _ in range(cache_count):
            if offset + 1 >= len(raw) or raw[offset] != 0 or raw[offset + 1] != 0:
                _fail()
            offset += 2

    for start, opcode_offset, opcode, argument in instructions:
        if opcode in _NAME_OPCODES:
            name_index = argument >> 1 if opcode == 116 else argument
            if name_index >= len(names):
                _fail()
            name = names[name_index]
            if name in _FORBIDDEN_NAMES:
                _fail()
            if opcode in _WRITE_NAME_OPCODES and name == _RESERVED_PROFILE_NAME:
                _fail()
        if opcode in _ATTRIBUTE_OPCODES:
            if argument >= len(names):
                _fail()
            attribute = names[argument]
            if (
                attribute not in _PERMITTED_ATTRIBUTES
                or (attribute.startswith("__") and attribute.endswith("__"))
            ):
                _fail()
        if opcode in (100, 172):
            if argument >= len(constants):
                _fail()
            if opcode == 172:
                keywords = constants[argument]
                if type(keywords) is not tuple or any(type(item) is not str for item in keywords):
                    _fail()
        if opcode in _FAST_OPCODES and argument >= len(varnames):
            _fail()
        if opcode in _LOCALSPLUS_OPCODES and argument >= localsplus_count:
            _fail()
        if opcode == 149 and argument != len(freevars):
            _fail()
        if opcode == 107 and argument >= 6:
            _fail()
        if opcode == 122 and argument >= 26:
            _fail()
        if opcode in (117, 118) and argument >= 2:
            _fail()
        if opcode == 130 and argument >= 3:
            _fail()
        if opcode == 133 and argument not in (2, 3):
            _fail()
        if opcode == 132 and argument & ~15:
            _fail()
        if opcode in _FORWARD_JUMPS:
            target = opcode_offset + 2 + argument * 2
            if target not in starts:
                _fail()
        if opcode in _BACKWARD_JUMPS:
            target = opcode_offset + 2 - argument * 2
            if target not in starts:
                _fail()


def _verify_project_code(root, code_type):
    pending = [root]
    while pending:
        code = pending.pop()
        if type(code) is not code_type:
            _fail()
        _verify_code_units(
            code.co_code,
            code.co_names,
            code.co_consts,
            code.co_varnames,
            code.co_cellvars,
            code.co_freevars,
        )
        for value in code.co_consts:
            if type(value) is code_type:
                pending.append(value)


def _install_private_loader(names, packages, bytes_by_path):
    real_builtins = sys.modules["builtins"]
    real_dict = real_builtins.__dict__
    cache = {}
    function_type = type(_install_private_loader)
    code_type = type(compile(b"", "v631302-code-type", "exec", flags=0,
                             dont_inherit=True, optimize=0))
    module_type = type(sys)
    entry_namespace = [None]
    entry_code = [None]
    entry_body_active = [False]
    future_state = [0]
    nonfuture_entry_import = [False]

    def make_sys():
        facade = module_type("sys")
        facade.__dict__.update({
            "__name__": "sys",
            "byteorder": sys.byteorder,
            "maxsize": sys.maxsize,
            "hexversion": sys.hexversion,
            "version_info": tuple(sys.version_info[:5]),
        })
        return facade

    def make_builtins():
        facade = module_type("builtins")
        facade.__dict__.update(restricted())
        return facade

    def relative(name, globs, level):
        if type(level) is not int or level < 0 or type(name) is not str:
            _fail()
        if not level:
            return name
        if type(globs) is not dict or type(globs.get("__package__")) is not str:
            _fail()
        package = globs["__package__"]
        parts = package.split(".") if package else []
        trim = level - 1
        if trim > len(parts):
            _fail()
        base = ".".join(parts[:len(parts) - trim])
        if not base:
            _fail()
        return base + (("." + name) if name else "")

    def load(name, bound_profile=None, direct_entry=False):
        if name == _ENTRY_NAME and not direct_entry:
            _fail()
        if name in cache:
            return cache[name]
        if name not in names:
            _fail()
        path = names[name]
        source = bytes_by_path[path]
        code = compile(source, "v631302-bundle://" + path, "exec", flags=0, dont_inherit=True, optimize=0)
        _verify_project_code(code, code_type)
        if name == _ENTRY_NAME:
            if not source.startswith(_FUTURE_PREFIX) or (code.co_flags & _FUTURE_ANNOTATIONS) != _FUTURE_ANNOTATIONS:
                _fail()
            entry_code[0] = code
        module = module_type(name)
        package = name if name in packages else name.rpartition(".")[0]
        namespace = module.__dict__
        namespace.update({
            "__name__": name,
            "__package__": package,
            "__file__": "v631302-bundle://" + path,
            "__loader__": None,
            "__spec__": None,
            "__builtins__": restricted(),
        })
        if name == _ENTRY_NAME:
            if type(bound_profile) is not bytes:
                _fail()
            namespace["V631302_BOUND_COLLECTOR_PROFILE_CBOR"] = bound_profile
            if namespace.get("V631302_BOUND_COLLECTOR_PROFILE_CBOR") is not bound_profile:
                _fail()
            entry_namespace[0] = namespace
        if name in packages:
            namespace["__path__"] = []
        if name != _ENTRY_NAME:
            cache[name] = module
        if name != _ENTRY_NAME and "." in name:
            parent_name, _, child = name.rpartition(".")
            parent = load(parent_name)
            setattr(parent, child, module)
        if name == _ENTRY_NAME:
            entry_body_active[0] = True
            try:
                exec(code, namespace, namespace)
            finally:
                entry_body_active[0] = False
            if future_state[0] != 1:
                _fail()
        else:
            exec(code, namespace, namespace)
        return module

    def importer(name, globs=None, locs=None, fromlist=(), level=0):
        resolved = relative(name, globs, level)
        if resolved == "__future__":
            code = entry_code[0]
            if (
                name != "__future__"
                or level != 0
                or type(fromlist) is not tuple
                or fromlist != ("annotations",)
                or globs is not entry_namespace[0]
                or locs is not entry_namespace[0]
                or not entry_body_active[0]
                or future_state[0] != 0
                or nonfuture_entry_import[0]
                or code is None
                or (code.co_flags & _FUTURE_ANNOTATIONS) != _FUTURE_ANNOTATIONS
                or not bytes_by_path[_ENTRY_PATH].startswith(_FUTURE_PREFIX)
            ):
                _fail()
            future_state[0] = 1
            facade = module_type("__future__")
            facade.annotations = None
            return facade
        if globs is entry_namespace[0] and entry_body_active[0]:
            if future_state[0] != 1:
                _fail()
            nonfuture_entry_import[0] = True
        if resolved == "sys":
            return make_sys()
        if resolved == "builtins":
            return make_builtins()
        if resolved not in names:
            _fail()
        module = load(resolved)
        if type(fromlist) not in (tuple, list):
            _fail()
        if fromlist:
            for item in fromlist:
                if type(item) is not str:
                    _fail()
                if item != "*":
                    child = resolved + "." + item
                    if child in names:
                        load(child)
            return module
        return load(resolved.split(".")[0])

    def restricted():
        values = {}
        for name in _PROJECT_BUILTIN_NAMES:
            if name == "__import__":
                values[name] = importer
            else:
                if name not in real_dict:
                    _fail()
                values[name] = real_dict[name]
        return values

    return load, function_type


class _Sink:
    def __init__(self):
        self.wrote = False

    def write(self, value):
        self.wrote = True
        return len(value)

    def flush(self):
        return None


def _validate_artifact(raw, profile):
    ranges = _top_array_item_ranges(raw, 9)
    artifact = _cbor_decode(raw)
    if type(artifact) is not list or len(artifact) != 9:
        _fail()
    if artifact[0] != 631302 or type(artifact[0]) is not int or artifact[1] != 1 or type(artifact[1]) is not int:
        _fail()
    collector_profile = artifact[2]
    if type(collector_profile) is not list or len(collector_profile) != 8:
        _fail()
    encoded_profile = raw[ranges[2][0]:ranges[2][1]]
    if encoded_profile != profile:
        _fail()
    if collector_profile[4] != 1 or type(collector_profile[4]) is not int:
        _fail()
    expected_profile = _cbor_decode(profile)
    if collector_profile[4] != expected_profile[4] or collector_profile[5] != expected_profile[5] or collector_profile[6] != expected_profile[6] or collector_profile[7] != expected_profile[7]:
        _fail()
    for item in artifact:
        if type(item) not in (list, int, bytes, str):
            _fail()


def _run():
    _check_startup()
    payload, supplied = _read_input()
    ranges = _top_array_item_ranges(payload, 5)
    if type(supplied) is not list or len(supplied) != 5:
        _fail()
    if supplied[0] != 631302 or type(supplied[0]) is not int or supplied[1] != 1 or type(supplied[1]) is not int:
        _fail()
    profile, manifest, names, packages = _parse_prelaunch_profile(supplied[2])
    profile_item = payload[ranges[2][0]:ranges[2][1]]
    if profile_item != _cbor_encode(profile):
        _fail()
    bound_profile = bytes(bytearray(profile_item))
    if type(bound_profile) is not bytes or bound_profile != profile_item:
        _fail()
    bytes_by_path = _parse_bytes(supplied[3], manifest)
    raw_collector = supplied[4]
    if type(raw_collector) is not bytes:
        _fail()
    _check_execution_profile(profile, bytes_by_path)
    for name in names:
        if name in sys.modules:
            _fail()
    sys.path[:] = []
    sys.path_hooks[:] = []
    sys.path_importer_cache.clear()
    sys.meta_path[:] = []
    sys.dont_write_bytecode = True
    load, function_type = _install_private_loader(names, packages, bytes_by_path)
    old_stdout = sys.stdout
    old_stderr = sys.stderr
    sink = _Sink()
    sys.stdout = sink
    sys.stderr = sink
    try:
        entry = load("evaluation_v6_3_1.m0_diagnostic_census", bound_profile, True)
        if entry.__dict__.get("V631302_BOUND_COLLECTOR_PROFILE_CBOR") is not bound_profile:
            _fail()
        callable_object = entry.__dict__.get("canonicalize_diagnostic_census_v1")
        if type(callable_object) is not function_type:
            _fail()
        if callable_object.__module__ != "evaluation_v6_3_1.m0_diagnostic_census" or callable_object.__globals__ is not entry.__dict__:
            _fail()
        if entry.__dict__.get("V631302_BOUND_COLLECTOR_PROFILE_CBOR") is not bound_profile:
            _fail()
        try:
            result = callable_object(raw_collector)
        except BaseException:
            if entry.__dict__.get("V631302_BOUND_COLLECTOR_PROFILE_CBOR") is not bound_profile:
                _fail()
            raise
        if entry.__dict__.get("V631302_BOUND_COLLECTOR_PROFILE_CBOR") is not bound_profile:
            _fail()
    finally:
        sys.stdout = old_stdout
        sys.stderr = old_stderr
    if sink.wrote or type(result) is not bytes:
        _fail()
    envelope = _cbor_decode(result)
    if type(envelope) is not list or len(envelope) != 4:
        _fail()
    if envelope[0] != 631302 or type(envelope[0]) is not int or envelope[1] != 1 or type(envelope[1]) is not int:
        _fail()
    if type(envelope[2]) is not int or envelope[2] not in (0, 1, 2) or type(envelope[3]) is not bytes:
        _fail()
    if envelope[2] == 1:
        if envelope[3] != b"":
            _fail()
        raise _InventoryFailure()
    if envelope[2] == 2:
        if envelope[3] != b"":
            _fail()
        raise _TemplateFailure()
    if not envelope[3]:
        _fail()
    _validate_artifact(envelope[3], bound_profile)
    frame = _OUT_MAGIC + len(envelope[3]).to_bytes(8, "big") + envelope[3]
    old_stdout.buffer.write(frame)
    old_stdout.flush()


try:
    _run()
except _TemplateFailure:
    sys.exit(_TEMPLATE)
except BaseException:
    sys.exit(_FAIL)
