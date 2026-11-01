"""Java-lite integer decoding before standard protobuf parsing.

The array route consumes permissive overlong varints; the coded route retains
CodedInputStream's ten-byte cap. Neither changes the original envelope retained
for MAC/signature verification. Both Java-compatible profiles use these routes.
"""

from google.protobuf.descriptor import FieldDescriptor as F
from google.protobuf.message import DecodeError

from signal_protocol.integers import uint32

__all__ = ["uint32", "normalize_java_protobuf", "parse_java_protobuf"]


def _varint(data, position, end, bits, max_bytes=None):
    value, shift, count = 0, 0, 0
    while position < end:
        if max_bytes is not None and count >= max_bytes:
            raise DecodeError("Malformed CodedInputStream varint")
        byte = data[position]
        position += 1
        count += 1
        if bits == 32:
            if shift < 35:
                value |= (byte & 0x7F) << shift
        else:
            # Java long shifts mask their distance modulo 64; ArrayDecoders
            # keeps consuming until a terminating byte rather than imposing 10.
            value |= (byte & 0x7F) << (shift & 63)
        if byte < 128:
            return value & ((1 << bits) - 1), position
        shift += 7
    raise DecodeError("Truncated Java protobuf varint")


def _encode(value):
    result = bytearray()
    while value > 127:
        result.append((value & 127) | 128)
        value >>= 7
    result.append(value)
    return bytes(result)


_VARINT32 = {F.TYPE_INT32, F.TYPE_UINT32, F.TYPE_SINT32, F.TYPE_ENUM}


def normalize_java_protobuf(data, descriptor, *, recursion_limit=100, route="array"):
    """Canonicalize wire integers using the selected Java-lite decoding route.

    Invalid tags, truncated values, negative Java lengths, unmatched groups and
    excessive nesting remain errors. Bytes/string fields are copied untouched;
    actual protobuf message fields are normalized recursively.
    ``route="array"`` has no varint byte cap; ``route="coded"`` caps every
    tag, length and scalar varint at ten bytes, matching its ByteString entry.
    """
    data = bytes(data)
    if route not in ("array", "coded"):
        raise ValueError("Java protobuf route must be 'array' or 'coded'")
    max_bytes = 10 if route == "coded" else None
    if recursion_limit < 1:
        raise ValueError("recursion_limit must be positive")

    def scan(position, end, schema, depth, end_group=None):
        if depth >= recursion_limit:
            raise DecodeError("Java protobuf recursion limit exceeded")
        result = bytearray()
        fields = schema.fields_by_number if schema is not None else {}
        while position < end:
            tag, position = _varint(data, position, end, 32, max_bytes)
            number, wire = tag >> 3, tag & 7
            if number == 0 or wire > 5:
                raise DecodeError("Invalid Java protobuf tag")
            if wire == 4:
                if end_group != tag:
                    raise DecodeError("Unexpected Java protobuf end group")
                return bytes(result) + _encode(tag), position
            result += _encode(tag)
            field = fields.get(number)
            if wire == 0:
                bits = 32 if field is not None and field.type in _VARINT32 else 64
                value, position = _varint(data, position, end, bits, max_bytes)
                if field is not None and field.type == F.TYPE_BOOL:
                    value = int(bool(value))
                result += _encode(value)
            elif wire in (1, 5):
                size = 8 if wire == 1 else 4
                if size > end - position:
                    raise DecodeError("Truncated Java protobuf fixed-width value")
                result += data[position : position + size]
                position += size
            elif wire == 2:
                size, position = _varint(data, position, end, 32, max_bytes)
                if size >= 1 << 31 or size > end - position:
                    raise DecodeError("Invalid Java protobuf length")
                finish = position + size
                if field is not None and field.type == F.TYPE_MESSAGE:
                    payload, consumed = scan(position, finish, field.message_type, depth + 1)
                    if consumed != finish:
                        raise DecodeError("Incomplete Java protobuf submessage")
                else:
                    payload = data[position:finish]
                result += _encode(len(payload)) + payload
                position = finish
            else:  # Start group; group contents use unknown-field decoding.
                payload, position = scan(position, end, None, depth + 1, (number << 3) | 4)
                result += payload
        if end_group is not None:
            raise DecodeError("Unterminated Java protobuf group")
        return bytes(result), position

    result, consumed = scan(0, len(data), descriptor, 0)
    if consumed != len(data):
        raise DecodeError("Trailing Java protobuf data")
    return result


def parse_java_protobuf(proto, data, *, recursion_limit=100, route="array"):
    return proto.FromString(
        normalize_java_protobuf(
            data, proto.DESCRIPTOR, recursion_limit=recursion_limit, route=route
        )
    )
