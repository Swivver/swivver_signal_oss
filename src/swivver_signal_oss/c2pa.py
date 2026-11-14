"""Offline C2PA / Content Credentials JUMBF binary parser and integrity verifier.

Inspects JPEG XT APP11, PNG caBX, ISO BMFF / MP4 uuid, and WebP RIFF C2PA chunks
purely offline with zero network calls and zero third-party runtime dependencies.
Verifies JUMBF structure, claim assertion HashedURI digests, asset byte-range
data hashes (c2pa.hash.data / flat BMFF exclusions), and COSE_Sign1 signatures
against embedded leaf X.509 public keys without implying CA trust-list or OCSP
status, editorial truth, or copyright ownership.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import struct
from pathlib import Path

METHOD_ID = "c2pa-jumbf-v1"
STATUSES = ("valid_manifest", "tampered_payload", "unverified_signature", "absent")

C2PA_BMFF_UUID = bytes.fromhex("d8fec3d61b0e483c92975828877ec481")
C2PA_STORE_UUID = bytes.fromhex("6332706100110010800000aa00389b71")
C2PA_MANIFEST_UUID = bytes.fromhex("63326d6100110010800000aa00389b71")
C2PA_ASSERTIONS_UUID = bytes.fromhex("6332617300110010800000aa00389b71")
C2PA_CLAIM_UUID = bytes.fromhex("6332636c00110010800000aa00389b71")
C2PA_SIGNATURE_UUID = bytes.fromhex("6332637300110010800000aa00389b71")

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"

_HASH_FNS = {
    "sha256": hashlib.sha256,
    "sha-256": hashlib.sha256,
    "sha384": hashlib.sha384,
    "sha-384": hashlib.sha384,
    "sha512": hashlib.sha512,
    "sha-512": hashlib.sha512,
}

# NIST P-256 and P-384 curve parameters for offline COSE ES256 / ES384 verification.
_CURVES = {
    "P-256": (
        0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
        0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC,
        0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
        0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
        0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
        0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
        32,
    ),
    "P-384": (
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF,
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC,
        0xB3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF,
        0xAA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7,
        0x3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F,
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973,
        48,
    ),
}

_OID_RSA_ENCRYPTION = bytes.fromhex("06092a864886f70d010101")
_OID_RSASSA_PSS = bytes.fromhex("06092a864886f70d01010a")
_OID_EC_PUBLIC_KEY = bytes.fromhex("06072a8648ce3d0201")
_OID_SECP256R1 = bytes.fromhex("06082a8648ce3d030107")
_OID_SECP384R1 = bytes.fromhex("06052b81040022")

_PKCS1_DIGEST_INFO = {
    "sha256": bytes.fromhex("3031300d060960864801650304020105000420"),
    "sha384": bytes.fromhex("3041300d060960864801650304020205000430"),
    "sha512": bytes.fromhex("3051300d060960864801650304020305000440"),
}


class _C2PAParseError(ValueError):
    """Internal structural error indicating malformed JUMBF, CBOR, or COSE data."""


def _decode_cbor(buf: bytes | memoryview, idx: int = 0, depth: int = 0):
    if depth > 16:
        raise _C2PAParseError("CBOR nesting budget exceeded")
    if idx >= len(buf):
        raise _C2PAParseError("unexpected end of CBOR buffer")
    initial = buf[idx]
    major = initial >> 5
    add = initial & 0x1F
    idx += 1

    if add < 24:
        val = add
    elif add == 24:
        if idx + 1 > len(buf):
            raise _C2PAParseError("truncated CBOR uint8")
        val = buf[idx]
        idx += 1
    elif add == 25:
        if idx + 2 > len(buf):
            raise _C2PAParseError("truncated CBOR uint16")
        val = struct.unpack(">H", buf[idx : idx + 2])[0]
        idx += 2
    elif add == 26:
        if idx + 4 > len(buf):
            raise _C2PAParseError("truncated CBOR uint32")
        val = struct.unpack(">I", buf[idx : idx + 4])[0]
        idx += 4
    elif add == 27:
        if idx + 8 > len(buf):
            raise _C2PAParseError("truncated CBOR uint64")
        val = struct.unpack(">Q", buf[idx : idx + 8])[0]
        idx += 8
    elif add == 31:
        if major == 2:
            chunks = bytearray()
            while True:
                if idx >= len(buf):
                    raise _C2PAParseError("unterminated indefinite bstr")
                if buf[idx] == 0xFF:
                    return bytes(chunks), idx + 1
                piece, idx = _decode_cbor(buf, idx, depth + 1)
                if not isinstance(piece, bytes):
                    raise _C2PAParseError("invalid indefinite bstr chunk")
                chunks.extend(piece)
        if major == 3:
            parts = []
            while True:
                if idx >= len(buf):
                    raise _C2PAParseError("unterminated indefinite tstr")
                if buf[idx] == 0xFF:
                    return "".join(parts), idx + 1
                piece, idx = _decode_cbor(buf, idx, depth + 1)
                if not isinstance(piece, str):
                    raise _C2PAParseError("invalid indefinite tstr chunk")
                parts.append(piece)
        if major == 4:
            arr = []
            while True:
                if idx >= len(buf):
                    raise _C2PAParseError("unterminated indefinite array")
                if buf[idx] == 0xFF:
                    return arr, idx + 1
                if len(arr) >= 10000:
                    raise _C2PAParseError("CBOR array item limit exceeded")
                item, idx = _decode_cbor(buf, idx, depth + 1)
                arr.append(item)
        if major == 5:
            mp = {}
            while True:
                if idx >= len(buf):
                    raise _C2PAParseError("unterminated indefinite map")
                if buf[idx] == 0xFF:
                    return mp, idx + 1
                if len(mp) >= 10000:
                    raise _C2PAParseError("CBOR map item limit exceeded")
                k, idx = _decode_cbor(buf, idx, depth + 1)
                v, idx = _decode_cbor(buf, idx, depth + 1)
                if isinstance(k, (list, dict)):
                    raise _C2PAParseError("unhashable CBOR map key")
                mp[k] = v
        raise _C2PAParseError("unsupported indefinite CBOR major type")
    else:
        raise _C2PAParseError("reserved CBOR additional info")

    if major == 0:
        return val, idx
    if major == 1:
        return -1 - val, idx
    if major == 2:
        if idx + val > len(buf):
            raise _C2PAParseError("truncated CBOR byte string")
        return bytes(buf[idx : idx + val]), idx + val
    if major == 3:
        if idx + val > len(buf):
            raise _C2PAParseError("truncated CBOR text string")
        try:
            return bytes(buf[idx : idx + val]).decode("utf-8"), idx + val
        except UnicodeDecodeError as exc:
            raise _C2PAParseError("invalid UTF-8 in CBOR text string") from exc
    if major == 4:
        if val > 10000:
            raise _C2PAParseError("CBOR array length exceeds budget")
        arr = []
        for _ in range(val):
            item, idx = _decode_cbor(buf, idx, depth + 1)
            arr.append(item)
        return arr, idx
    if major == 5:
        if val > 10000:
            raise _C2PAParseError("CBOR map length exceeds budget")
        mp = {}
        for _ in range(val):
            k, idx = _decode_cbor(buf, idx, depth + 1)
            v, idx = _decode_cbor(buf, idx, depth + 1)
            if isinstance(k, (list, dict)):
                raise _C2PAParseError("unhashable CBOR map key")
            mp[k] = v
        return mp, idx
    if major == 6:
        tagged, idx = _decode_cbor(buf, idx, depth + 1)
        return ("__cbor_tag__", val, tagged), idx
    if major == 7:
        if add == 20:
            return False, idx
        if add == 21:
            return True, idx
        if add in (22, 23):
            return None, idx
        if add == 25:
            return struct.unpack(">e", buf[idx - 2 : idx])[0], idx
        if add == 26:
            return struct.unpack(">f", buf[idx - 4 : idx])[0], idx
        if add == 27:
            return struct.unpack(">d", buf[idx - 8 : idx])[0], idx
        return None, idx
    raise _C2PAParseError("unknown CBOR major type")


def _unwrap_cbor_tag(value):
    while isinstance(value, tuple) and len(value) == 3 and value[0] == "__cbor_tag__":
        value = value[2]
    return value


def _encode_cbor_bstr(b: bytes) -> bytes:
    n = len(b)
    if n < 24:
        hdr = bytes([0x40 | n])
    elif n < 256:
        hdr = bytes([0x58, n])
    elif n < 65536:
        hdr = b"\x59" + struct.pack(">H", n)
    else:
        hdr = b"\x5a" + struct.pack(">I", n)
    return hdr + b


def _encode_cbor_tstr(s: str) -> bytes:
    raw = s.encode("utf-8")
    n = len(raw)
    if n < 24:
        return bytes([0x60 | n]) + raw
    return bytes([0x78, n]) + raw


def _extract_jpeg_jumbf(data: bytes) -> tuple[bytes, list[tuple[int, int]]] | None:
    """Extract JPEG XT APP11 (0xFFEB, CI='JP') JUMBF superbox per ISO/IEC 19566-5."""
    if len(data) < 4 or data[:2] != b"\xff\xd8":
        return None
    pos = 2
    groups: dict[int, list[tuple[int, bytes, int, int]]] = {}
    spans: dict[int, list[tuple[int, int]]] = {}
    while pos + 1 < len(data):
        if data[pos] != 0xFF:
            break
        while pos < len(data) and data[pos] == 0xFF:
            pos += 1
        if pos >= len(data):
            break
        marker = data[pos]
        pos += 1
        if marker in (0xD8, 0xD9) or 0xD0 <= marker <= 0xD7 or marker == 0x01:
            continue
        if marker == 0xDA:  # Start of Scan
            break
        if pos + 2 > len(data):
            break
        seg_start = pos - 2
        seg_len = struct.unpack(">H", data[pos : pos + 2])[0]
        if seg_len < 2 or pos + seg_len > len(data):
            break
        payload = data[pos + 2 : pos + seg_len]
        seg_end = pos + seg_len
        if marker == 0xEB and len(payload) >= 16 and payload[:2] == b"JP":
            en = struct.unpack(">H", payload[2:4])[0]
            z = struct.unpack(">I", payload[4:8])[0]
            lbox = struct.unpack(">I", payload[8:12])[0]
            groups.setdefault(en, []).append((z, payload, lbox, seg_start))
            spans.setdefault(en, []).append((seg_start, seg_end))
        pos = seg_end

    if not groups:
        return None

    for en, segments in groups.items():
        segments.sort(key=lambda item: item[0])
        assembled = bytearray()
        for idx, (z, payload, lbox, _) in enumerate(segments):
            if z != idx + 1:
                raise _C2PAParseError("non-contiguous JPEG XT APP11 packet sequence")
            box_hdr = 16 if lbox == 1 else 8
            if len(payload) < 8 + box_hdr:
                raise _C2PAParseError("truncated JPEG XT APP11 JUMBF header")
            if idx == 0:
                assembled.extend(payload[8:])
            else:
                assembled.extend(payload[8 + box_hdr :])
        if len(assembled) >= 8 and assembled[4:8] == b"jumb":
            return bytes(assembled), spans[en]
    return None


def _extract_png_jumbf(data: bytes) -> tuple[bytes, list[tuple[int, int]]] | None:
    """Extract C2PA JUMBF store from PNG caBX ancillary chunk."""
    if len(data) < 8 or data[:8] != PNG_SIGNATURE:
        return None
    pos = 8
    found = None
    spans = []
    while pos + 12 <= len(data):
        length = struct.unpack(">I", data[pos : pos + 4])[0]
        chunk_type = data[pos + 4 : pos + 8]
        chunk_end = pos + 12 + length
        if chunk_end > len(data):
            if found is not None:
                raise _C2PAParseError("truncated PNG chunk after caBX")
            break
        if chunk_type == b"caBX":
            if found is not None:
                raise _C2PAParseError("multiple PNG caBX chunks are not allowed")
            found = data[pos + 8 : pos + 8 + length]
            spans.append((pos, chunk_end))
        if chunk_type == b"IEND":
            break
        pos = chunk_end
    return (found, spans) if found is not None else None


def _iter_bmff_boxes(data: bytes):
    pos = 0
    while pos + 8 <= len(data):
        size = struct.unpack(">I", data[pos : pos + 4])[0]
        btype = data[pos + 4 : pos + 8]
        hdr = 8
        if size == 1:
            if pos + 16 > len(data):
                return
            size = struct.unpack(">Q", data[pos + 8 : pos + 16])[0]
            hdr = 16
        elif size == 0:
            size = len(data) - pos
        if size < hdr or pos + size > len(data):
            return
        yield pos, pos + size, hdr, btype, data[pos + hdr : pos + size]
        pos += size


def _extract_bmff_jumbf(data: bytes) -> tuple[bytes, list[tuple[int, int]]] | None:
    """Extract C2PA JUMBF store from ISO BMFF / MP4 uuid box."""
    if len(data) < 12 or data[4:8] not in (b"ftyp", b"styp", b"wide", b"moov", b"uuid"):
        return None
    for start, end, _hdr, btype, body in _iter_bmff_boxes(data):
        if btype == b"uuid" and len(body) >= 24 and body[:16] == C2PA_BMFF_UUID:
            inner = body[16:]
            if len(inner) >= 8 and inner[4:8] == b"jumb":
                return inner, [(start, end)]
            # C2PA BMFF uuid box with FullBox version/flags(4) + purpose string + merkle offset(8)
            if len(inner) > 13:
                nul = inner.find(b"\x00", 4)
                if 4 < nul < 64:
                    purpose = inner[4:nul]
                    after = nul + 1
                    if purpose == b"manifest":
                        if after + 16 <= len(inner) and inner[after + 12 : after + 16] == b"jumb":
                            return inner[after + 8 :], [(start, end)]
                        if after + 8 <= len(inner) and inner[after + 4 : after + 8] == b"jumb":
                            return inner[after:], [(start, end)]
            raise _C2PAParseError("unrecognized C2PA BMFF uuid box payload")
    return None


def _extract_webp_jumbf(data: bytes) -> tuple[bytes, list[tuple[int, int]]] | None:
    """Extract C2PA JUMBF store from WebP RIFF C2PA / caBX chunk."""
    if len(data) < 12 or data[:4] != b"RIFF" or data[8:12] != b"WEBP":
        return None
    pos = 12
    while pos + 8 <= len(data):
        fourcc = data[pos : pos + 4]
        size = struct.unpack("<I", data[pos + 4 : pos + 8])[0]
        payload_end = pos + 8 + size
        if payload_end > len(data):
            break
        padded_end = payload_end + (size & 1)
        if fourcc in (b"C2PA", b"caBX", b"JUMB"):
            return data[pos + 8 : payload_end], [(pos, min(padded_end, len(data)))]
        pos = padded_end
    return None


def _parse_iso_boxes(buf: bytes) -> list[dict]:
    boxes = []
    pos = 0
    while pos < len(buf):
        if pos + 8 > len(buf):
            raise _C2PAParseError("truncated JUMBF box header")
        lbox = struct.unpack(">I", buf[pos : pos + 4])[0]
        tbox = buf[pos + 4 : pos + 8]
        hdr = 8
        if lbox == 1:
            if pos + 16 > len(buf):
                raise _C2PAParseError("truncated JUMBF XLBox header")
            lbox = struct.unpack(">Q", buf[pos + 8 : pos + 16])[0]
            hdr = 16
        elif lbox == 0:
            lbox = len(buf) - pos
        if lbox < hdr or pos + lbox > len(buf):
            raise _C2PAParseError("JUMBF box length exceeds parent bounds")
        boxes.append(
            {
                "type": tbox,
                "raw": buf[pos : pos + lbox],
                "body": buf[pos + hdr : pos + lbox],
            }
        )
        pos += lbox
    return boxes


def _parse_jumbf_superbox(buf: bytes, depth: int = 0) -> dict:
    if depth > 12:
        raise _C2PAParseError("JUMBF superbox depth exceeded")
    top = _parse_iso_boxes(buf)
    if len(top) != 1 or top[0]["type"] != b"jumb":
        raise _C2PAParseError("expected single jumb superbox")
    return _decode_jumb_node(top[0], depth=depth)


def _decode_jumb_node(box: dict, depth: int = 0) -> dict:
    if depth > 12:
        raise _C2PAParseError("JUMBF superbox depth exceeded")
    children = _parse_iso_boxes(box["body"])
    if not children or children[0]["type"] != b"jumd":
        raise _C2PAParseError("JUMBF superbox missing leading jumd description box")
    desc = children[0]["body"]
    if len(desc) < 17:
        raise _C2PAParseError("truncated jumd description box")
    type_uuid = desc[:16]
    toggles = desc[16]
    cursor = 17
    label = None
    if toggles & 0x02:
        nul = desc.find(b"\x00", cursor)
        if nul == -1:
            raise _C2PAParseError("unterminated jumd label string")
        label = desc[cursor:nul].decode("utf-8", errors="replace")
        cursor = nul + 1
    if toggles & 0x04:
        if cursor + 4 > len(desc):
            raise _C2PAParseError("truncated jumd ID field")
        cursor += 4
    if toggles & 0x08:
        if cursor + 32 > len(desc):
            raise _C2PAParseError("truncated jumd signature digest")
        cursor += 32

    sub_superboxes = []
    content_boxes = []
    for child in children[1:]:
        if child["type"] == b"jumb":
            sub_superboxes.append(_decode_jumb_node(child, depth + 1))
        else:
            content_boxes.append(child)

    return {
        "uuid": type_uuid,
        "toggles": toggles,
        "label": label,
        "jumb_body": box["body"],
        "raw": box["raw"],
        "children": sub_superboxes,
        "content": content_boxes,
    }


def _parse_der_tlv(buf: bytes, idx: int = 0) -> tuple[int, bytes, int]:
    if idx + 2 > len(buf):
        raise _C2PAParseError("truncated ASN.1 DER header")
    tag = buf[idx]
    length = buf[idx + 1]
    idx += 2
    if length & 0x80:
        nbytes = length & 0x7F
        if nbytes == 0 or nbytes > 4 or idx + nbytes > len(buf):
            raise _C2PAParseError("invalid ASN.1 DER length")
        length = int.from_bytes(buf[idx : idx + nbytes], "big")
        idx += nbytes
    if idx + length > len(buf):
        raise _C2PAParseError("ASN.1 DER value exceeds buffer")
    return tag, buf[idx : idx + length], idx + length


def _extract_cert_public_key(cert_der: bytes) -> dict | None:
    """Extract RSA or NIST P-256/P-384 public key from an X.509 DER certificate."""
    tag, cert_body, _ = _parse_der_tlv(cert_der, 0)
    if tag != 0x30:
        raise _C2PAParseError("X.509 certificate must be a DER SEQUENCE")
    tbs_tag, tbs_body, _ = _parse_der_tlv(cert_body, 0)
    if tbs_tag != 0x30:
        raise _C2PAParseError("TBSCertificate must be a DER SEQUENCE")

    idx = 0
    while idx < len(tbs_body):
        field_tag, field_val, nxt = _parse_der_tlv(tbs_body, idx)
        idx = nxt
        if field_tag != 0x30:
            continue
        try:
            alg_tag, alg_val, spki_pos = _parse_der_tlv(field_val, 0)
            if alg_tag != 0x30 or spki_pos >= len(field_val):
                continue
            bit_tag, bit_val, end_pos = _parse_der_tlv(field_val, spki_pos)
            if bit_tag != 0x03 or end_pos != len(field_val) or len(bit_val) < 2 or bit_val[0] != 0x00:
                continue
        except _C2PAParseError:
            continue

        pubkey_bytes = bit_val[1:]
        if alg_val.startswith(_OID_RSA_ENCRYPTION) or alg_val.startswith(_OID_RSASSA_PSS):
            seq_tag, rsa_seq, _ = _parse_der_tlv(pubkey_bytes, 0)
            if seq_tag != 0x30:
                raise _C2PAParseError("invalid RSA SubjectPublicKey")
            t_n, n_bytes, p_e = _parse_der_tlv(rsa_seq, 0)
            t_e, e_bytes, _ = _parse_der_tlv(rsa_seq, p_e)
            if t_n != 0x02 or t_e != 0x02:
                raise _C2PAParseError("invalid RSA modulus or exponent")
            n = int.from_bytes(n_bytes, "big")
            e = int.from_bytes(e_bytes, "big")
            if n <= 0 or e <= 1:
                raise _C2PAParseError("degenerate RSA key")
            return {"kty": "RSA", "n": n, "e": e}

        if alg_val.startswith(_OID_EC_PUBLIC_KEY):
            curve_name = None
            if _OID_SECP256R1 in alg_val:
                curve_name = "P-256"
            elif _OID_SECP384R1 in alg_val:
                curve_name = "P-384"
            if curve_name and pubkey_bytes[0] == 0x04:
                coord_len = _CURVES[curve_name][6]
                if len(pubkey_bytes) == 1 + 2 * coord_len:
                    qx = int.from_bytes(pubkey_bytes[1 : 1 + coord_len], "big")
                    qy = int.from_bytes(pubkey_bytes[1 + coord_len :], "big")
                    return {"kty": "EC", "curve": curve_name, "x": qx, "y": qy}
    return None


def _verify_rsa_pss(n: int, e: int, msg: bytes, sig: bytes, hash_name: str) -> bool:
    hash_fn = _HASH_FNS[hash_name]
    k = (n.bit_length() + 7) // 8
    if len(sig) != k:
        return False
    s_int = int.from_bytes(sig, "big")
    if s_int >= n:
        return False
    em = pow(s_int, e, n).to_bytes(k, "big")
    h_len = hash_fn().digest_size
    if k < h_len + 2 or em[-1] != 0xBC:
        return False
    masked_db = em[: k - h_len - 1]
    h = em[k - h_len - 1 : -1]
    mask = bytearray()
    counter = 0
    while len(mask) < len(masked_db):
        mask.extend(hash_fn(h + struct.pack(">I", counter)).digest())
        counter += 1
    db = bytearray(a ^ b for a, b in zip(masked_db, mask[: len(masked_db)]))
    top_bits = 8 * k - (n.bit_length() - 1)
    if top_bits > 0:
        db[0] &= 0xFF >> top_bits
    sep = db.find(0x01)
    if sep == -1 or any(b != 0 for b in db[:sep]):
        return False
    salt = bytes(db[sep + 1 :])
    expected_h = hash_fn(b"\x00" * 8 + hash_fn(msg).digest() + salt).digest()
    return hmac.compare_digest(expected_h, h)


def _verify_rsa_pkcs1(n: int, e: int, msg: bytes, sig: bytes, hash_name: str) -> bool:
    hash_fn = _HASH_FNS[hash_name]
    k = (n.bit_length() + 7) // 8
    if len(sig) != k:
        return False
    s_int = int.from_bytes(sig, "big")
    if s_int >= n:
        return False
    em = pow(s_int, e, n).to_bytes(k, "big")
    t = _PKCS1_DIGEST_INFO[hash_name] + hash_fn(msg).digest()
    ps_len = k - len(t) - 3
    if ps_len < 8:
        return False
    expected = b"\x00\x01" + (b"\xff" * ps_len) + b"\x00" + t
    return hmac.compare_digest(em, expected)


def _ec_add(p1, p2, a: int, p: int):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2:
        if (y1 + y2) % p == 0:
            return None
        lam = ((3 * x1 * x1 + a) * pow(2 * y1, -1, p)) % p
    else:
        lam = ((y2 - y1) * pow((x2 - x1) % p, -1, p)) % p
    x3 = (lam * lam - x1 - x2) % p
    y3 = (lam * (x1 - x3) - y1) % p
    return x3, y3


def _ec_mul(k: int, point, a: int, p: int):
    result = None
    addend = point
    while k > 0:
        if k & 1:
            result = _ec_add(result, addend, a, p)
        addend = _ec_add(addend, addend, a, p)
        k >>= 1
    return result


def _parse_der_ecdsa_sig(sig: bytes) -> tuple[int, int] | None:
    try:
        tag, body, end = _parse_der_tlv(sig, 0)
        if tag != 0x30 or end != len(sig):
            return None
        t_r, r_bytes, pos = _parse_der_tlv(body, 0)
        t_s, s_bytes, end2 = _parse_der_tlv(body, pos)
        if t_r != 0x02 or t_s != 0x02 or end2 != len(body):
            return None
        return int.from_bytes(r_bytes, "big"), int.from_bytes(s_bytes, "big")
    except _C2PAParseError:
        return None


def _verify_ecdsa(pub: dict, msg: bytes, sig: bytes, hash_name: str) -> bool:
    p, a, b, gx, gy, n, coord_len = _CURVES[pub["curve"]]
    qx, qy = pub["x"], pub["y"]
    if not (0 <= qx < p and 0 <= qy < p and (qy * qy - (qx * qx * qx + a * qx + b)) % p == 0):
        return False
    if len(sig) == 2 * coord_len:
        r = int.from_bytes(sig[:coord_len], "big")
        s = int.from_bytes(sig[coord_len:], "big")
    else:
        parsed = _parse_der_ecdsa_sig(sig)
        if parsed is None:
            return False
        r, s = parsed
    if not (1 <= r < n and 1 <= s < n):
        return False
    digest = _HASH_FNS[hash_name](msg).digest()
    e = int.from_bytes(digest, "big")
    bit_diff = len(digest) * 8 - n.bit_length()
    if bit_diff > 0:
        e >>= bit_diff
    w = pow(s, -1, n)
    u1 = (e * w) % n
    u2 = (r * w) % n
    pt = _ec_add(_ec_mul(u1, (gx, gy), a, p), _ec_mul(u2, (qx, qy), a, p), a, p)
    if pt is None:
        return False
    return (pt[0] % n) == r


_COSE_ALGS = {
    -37: ("RSA_PSS", "sha256"),
    -38: ("RSA_PSS", "sha384"),
    -39: ("RSA_PSS", "sha512"),
    -257: ("RSA_PKCS1", "sha256"),
    -258: ("RSA_PKCS1", "sha384"),
    -259: ("RSA_PKCS1", "sha512"),
    -7: ("ECDSA", "sha256", "P-256"),
    -35: ("ECDSA", "sha384", "P-384"),
}


def _verify_cose_sign1(sig_cbor_bytes: bytes, detached_claim_bytes: bytes) -> tuple[bool, bool | None]:
    """Parse COSE_Sign1 and verify signature against x5chain leaf public key when supported.

    Returns (signature_present, signature_verified) where signature_verified is:
    - True: cryptographically verified against embedded leaf public key
    - False: signature/header malformed or cryptographic verification failed
    - None: structurally valid COSE_Sign1 present, but x5chain or algorithm cannot be verified offline
    """
    decoded, _ = _decode_cbor(sig_cbor_bytes, 0)
    if isinstance(decoded, tuple) and decoded[0] == "__cbor_tag__":
        if decoded[1] != 18:
            raise _C2PAParseError("unexpected CBOR tag on signature box")
        decoded = decoded[2]
    if not isinstance(decoded, list) or len(decoded) != 4:
        raise _C2PAParseError("COSE_Sign1 must be a 4-element CBOR array")
    protected_bytes, unprotected, payload, signature = decoded
    if not isinstance(protected_bytes, bytes) or not isinstance(unprotected, dict):
        raise _C2PAParseError("invalid COSE_Sign1 headers")
    if payload is not None and not isinstance(payload, bytes):
        raise _C2PAParseError("invalid COSE_Sign1 payload")
    if not isinstance(signature, bytes) or len(signature) < 16:
        return False, None

    protected = {}
    if protected_bytes:
        parsed_prot, _ = _decode_cbor(protected_bytes, 0)
        parsed_prot = _unwrap_cbor_tag(parsed_prot)
        if not isinstance(parsed_prot, dict):
            raise _C2PAParseError("COSE protected header must be a map")
        protected = parsed_prot

    alg = protected.get(1)
    if alg is None:
        return True, None

    x5chain = (
        protected.get(33)
        or protected.get("x5chain")
        or unprotected.get(33)
        or unprotected.get("x5chain")
    )
    if x5chain is None:
        return True, None
    if isinstance(x5chain, list):
        if not x5chain or not isinstance(x5chain[0], bytes):
            raise _C2PAParseError("invalid x5chain certificate list")
        leaf_der = x5chain[0]
    elif isinstance(x5chain, bytes):
        leaf_der = x5chain
    else:
        raise _C2PAParseError("invalid x5chain header type")

    alg_spec = _COSE_ALGS.get(alg)
    if alg_spec is None:
        return True, None

    pubkey = _extract_cert_public_key(leaf_der)
    if pubkey is None:
        return True, None

    target_payload = payload if payload is not None else detached_claim_bytes
    sig_structure = (
        b"\x84"
        + _encode_cbor_tstr("Signature1")
        + _encode_cbor_bstr(protected_bytes)
        + _encode_cbor_bstr(b"")
        + _encode_cbor_bstr(target_payload)
    )

    scheme = alg_spec[0]
    hash_name = alg_spec[1]
    if scheme == "RSA_PSS" and pubkey["kty"] == "RSA":
        return True, _verify_rsa_pss(pubkey["n"], pubkey["e"], sig_structure, signature, hash_name)
    if scheme == "RSA_PKCS1" and pubkey["kty"] == "RSA":
        return True, _verify_rsa_pkcs1(pubkey["n"], pubkey["e"], sig_structure, signature, hash_name)
    if scheme == "ECDSA" and pubkey["kty"] == "EC" and pubkey["curve"] == alg_spec[2]:
        return True, _verify_ecdsa(pubkey, sig_structure, signature, hash_name)
    return True, False


def _verify_data_hash(data: bytes, hash_assertion: dict, default_alg: str) -> bool:
    alg_name = str(hash_assertion.get("alg") or default_alg or "sha256").lower()
    hash_fn = _HASH_FNS.get(alg_name)
    expected = hash_assertion.get("hash")
    if hash_fn is None or not isinstance(expected, bytes) or len(expected) != hash_fn().digest_size:
        raise _C2PAParseError("invalid or unsupported c2pa.hash.data digest")

    inclusions = hash_assertion.get("inclusions")
    exclusions = hash_assertion.get("exclusions")
    digest = hash_fn()

    if inclusions is not None:
        if not isinstance(inclusions, list) or not inclusions:
            raise _C2PAParseError("invalid c2pa.hash.data inclusions")
        for item in inclusions:
            if not isinstance(item, dict):
                raise _C2PAParseError("invalid inclusion range")
            start = item.get("start")
            length = item.get("length")
            if (
                not isinstance(start, int)
                or isinstance(start, bool)
                or not isinstance(length, int)
                or isinstance(length, bool)
                or start < 0
                or length <= 0
                or start + length > len(data)
            ):
                raise _C2PAParseError("c2pa.hash.data inclusion out of bounds")
            digest.update(data[start : start + length])
        return hmac.compare_digest(digest.digest(), expected)

    if not isinstance(exclusions, list) or not exclusions:
        raise _C2PAParseError("c2pa.hash.data requires exclusions or inclusions")

    norm_excl = []
    for item in exclusions:
        if not isinstance(item, dict):
            raise _C2PAParseError("invalid exclusion range")
        start = item.get("start")
        length = item.get("length")
        if (
            not isinstance(start, int)
            or isinstance(start, bool)
            or not isinstance(length, int)
            or isinstance(length, bool)
            or start < 0
            or length <= 0
            or start + length > len(data)
        ):
            raise _C2PAParseError("c2pa.hash.data exclusion out of bounds")
        norm_excl.append((start, start + length))

    norm_excl.sort()
    cursor = 0
    for start, end in norm_excl:
        if start > cursor:
            digest.update(data[cursor:start])
        cursor = max(cursor, end)
    if cursor < len(data):
        digest.update(data[cursor:])
    return hmac.compare_digest(digest.digest(), expected)


def _verify_bmff_flat_hash(data: bytes, bmff_assertion: dict, default_alg: str) -> bool | None:
    """Verify flat (non-Merkle) c2pa.hash.bmff(.v2) box hashes when unambiguous."""
    if bmff_assertion.get("merkle"):
        return None
    alg_name = str(bmff_assertion.get("alg") or default_alg or "sha256").lower()
    hash_fn = _HASH_FNS.get(alg_name)
    expected = bmff_assertion.get("hash")
    exclusions = bmff_assertion.get("exclusions")
    if (
        hash_fn is None
        or not isinstance(expected, bytes)
        or len(expected) != hash_fn().digest_size
        or not isinstance(exclusions, list)
    ):
        return None

    excluded_types = set()
    for ex in exclusions:
        if not isinstance(ex, dict) or ex.get("subset") or ex.get("data"):
            return None
        xpath = ex.get("xpath")
        if not isinstance(xpath, str) or not xpath.startswith("/") or "/" in xpath[1:]:
            return None
        excluded_types.add(xpath[1:].encode("ascii", errors="ignore"))

    digest = hash_fn()
    for start, end, _hdr, btype, _body in _iter_bmff_boxes(data):
        if btype in excluded_types:
            continue
        # Per C2PA BMFF v2 flat hashing, non-excluded boxes hash offset(8B BE) + raw box bytes,
        # while v1 hashes raw box bytes directly. Check both standard conventions.
        digest.update(data[start:end])
    if hmac.compare_digest(digest.digest(), expected):
        return True

    digest_v2 = hash_fn()
    for start, end, _hdr, btype, _body in _iter_bmff_boxes(data):
        if btype in excluded_types:
            continue
        digest_v2.update(struct.pack(">Q", start))
        digest_v2.update(data[start:end])
    return hmac.compare_digest(digest_v2.digest(), expected)


def _format_claim_generator(claim: dict) -> str | None:
    gen = claim.get("claim_generator")
    if isinstance(gen, str) and gen.strip():
        return gen.strip()
    info = claim.get("claim_generator_info")
    items = info if isinstance(info, list) else [info] if isinstance(info, dict) else []
    rendered = []
    for entry in items:
        if isinstance(entry, dict) and isinstance(entry.get("name"), str) and entry["name"].strip():
            name = entry["name"].strip()
            ver = entry.get("version")
            rendered.append(f"{name}/{ver.strip()}" if isinstance(ver, str) and ver.strip() else name)
    return " ".join(rendered) if rendered else None


def _resolve_jumbf_target(url: str, active_manifest: dict, store_boxes: dict[str, dict]) -> dict | None:
    prefix = "self#jumbf="
    if not isinstance(url, str) or not url.startswith(prefix):
        return None
    target = url[len(prefix) :].lstrip("/")
    if target in store_boxes:
        return store_boxes[target]
    active_label = active_manifest.get("label") or ""
    scoped = f"{active_label}/{target}".lstrip("/")
    return store_boxes.get(scoped)


def _index_store_boxes(node: dict, prefix: str = "", out: dict[str, dict] | None = None) -> dict[str, dict]:
    if out is None:
        out = {}
    label = node.get("label")
    path = f"{prefix}/{label}".lstrip("/") if label else prefix
    if path:
        out[path] = node
    for child in node.get("children", []):
        _index_store_boxes(child, path, out)
    return out


def _detect_container(data: bytes) -> tuple[str, tuple[bytes, list[tuple[int, int]]] | None]:
    if data.startswith(b"\xff\xd8"):
        return "jpeg", _extract_jpeg_jumbf(data)
    if data.startswith(PNG_SIGNATURE):
        return "png", _extract_png_jumbf(data)
    if len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "webp", _extract_webp_jumbf(data)
    if len(data) >= 12 and data[4:8] in (b"ftyp", b"styp", b"wide", b"moov", b"uuid"):
        return "bmff", _extract_bmff_jumbf(data)
    return "other", None


def inspect_c2pa_bytes(data: bytes) -> dict:
    """Inspect raw media bytes for an embedded C2PA JUMBF manifest offline."""
    try:
        container, extracted = _detect_container(data)
    except _C2PAParseError:
        return {
            "status": "tampered_payload",
            "container": "other",
            "manifest_label": None,
            "claim_generator": None,
            "assertions": [],
            "signature_present": False,
            "signature_verified": False,
            "data_hash_verified": False,
            "reason": "Malformed C2PA container segment or JUMBF packet sequence.",
        }

    if extracted is None:
        return {
            "status": "absent",
            "container": container,
            "manifest_label": None,
            "claim_generator": None,
            "assertions": [],
            "signature_present": False,
            "signature_verified": None,
            "data_hash_verified": None,
            "reason": "No embedded C2PA Content Credentials manifest found.",
        }

    jumbf_bytes, _container_spans = extracted
    try:
        store = _parse_jumbf_superbox(jumbf_bytes)
        if store["uuid"] != C2PA_STORE_UUID and store.get("label") != "c2pa":
            raise _C2PAParseError("JUMBF superbox is not a C2PA manifest store")

        manifests = [
            child
            for child in store["children"]
            if child["uuid"] == C2PA_MANIFEST_UUID
            or any(
                gc["uuid"] == C2PA_CLAIM_UUID or (gc.get("label") or "").startswith("c2pa.claim")
                for gc in child["children"]
            )
        ]
        if not manifests:
            raise _C2PAParseError("C2PA store contains no manifest superbox")

        active = manifests[-1]
        manifest_label = active.get("label")
        store_index = _index_store_boxes(store)
        if store.get("label") == "c2pa":
            # Also index without leading "c2pa/" prefix for manifest-store-relative URIs.
            for child in store["children"]:
                _index_store_boxes(child, "", store_index)

        assertions_box = next(
            (
                c
                for c in active["children"]
                if c["uuid"] == C2PA_ASSERTIONS_UUID or c.get("label") == "c2pa.assertions"
            ),
            None,
        )
        claim_box = next(
            (
                c
                for c in active["children"]
                if c["uuid"] == C2PA_CLAIM_UUID
                or (c.get("label") or "").startswith("c2pa.claim")
            ),
            None,
        )
        sig_box = next(
            (
                c
                for c in active["children"]
                if c["uuid"] == C2PA_SIGNATURE_UUID or c.get("label") == "c2pa.signature"
            ),
            None,
        )

        if claim_box is None or not claim_box["content"]:
            raise _C2PAParseError("C2PA manifest is missing c2pa.claim content box")

        claim_cbor_box = next((b for b in claim_box["content"] if b["type"] == b"cbor"), None)
        if claim_cbor_box is None:
            raise _C2PAParseError("c2pa.claim does not contain a CBOR box")
        claim_cbor_bytes = claim_cbor_box["body"]
        claim_map, _ = _decode_cbor(claim_cbor_bytes, 0)
        claim_map = _unwrap_cbor_tag(claim_map)
        if not isinstance(claim_map, dict):
            raise _C2PAParseError("c2pa.claim CBOR payload is not a map")

        claim_generator = _format_claim_generator(claim_map)
        default_alg = str(claim_map.get("alg") or "sha256").lower()

        assertion_labels: list[str] = []
        decoded_assertions: dict[str, object] = {}
        if assertions_box is not None:
            for item in assertions_box["children"]:
                lbl = item.get("label") or "unnamed"
                assertion_labels.append(lbl)
                for cbox in item["content"]:
                    if cbox["type"] == b"cbor":
                        val, _ = _decode_cbor(cbox["body"], 0)
                        decoded_assertions[lbl] = _unwrap_cbor_tag(val)
                    elif cbox["type"] == b"json":
                        decoded_assertions[lbl] = json.loads(
                            cbox["body"].decode("utf-8", errors="strict")
                        )

        # Collect HashedURI assertion bindings from C2PA 1.x (assertions) and 2.x (created/gathered).
        claim_refs = []
        for field in ("assertions", "created_assertions", "gathered_assertions"):
            entries = claim_map.get(field)
            if isinstance(entries, list):
                claim_refs.extend(entries)
        if not claim_refs:
            raise _C2PAParseError("c2pa.claim declares no assertion digests")

        for ref in claim_refs:
            ref = _unwrap_cbor_tag(ref)
            if not isinstance(ref, dict):
                raise _C2PAParseError("invalid HashedURI entry in c2pa.claim")
            url = ref.get("url")
            expected_hash = ref.get("hash")
            alg_name = str(ref.get("alg") or default_alg).lower()
            hash_fn = _HASH_FNS.get(alg_name)
            target_box = _resolve_jumbf_target(url, active, store_index)
            if (
                target_box is None
                or hash_fn is None
                or not isinstance(expected_hash, bytes)
                or len(expected_hash) != hash_fn().digest_size
            ):
                return {
                    "status": "tampered_payload",
                    "container": container,
                    "manifest_label": manifest_label,
                    "claim_generator": claim_generator,
                    "assertions": assertion_labels,
                    "signature_present": sig_box is not None,
                    "signature_verified": None,
                    "data_hash_verified": False,
                    "reason": "C2PA claim references a missing or malformed assertion box.",
                }
            actual_jumb_hash = hash_fn(target_box["jumb_body"]).digest()
            if not hmac.compare_digest(actual_jumb_hash, expected_hash):
                return {
                    "status": "tampered_payload",
                    "container": container,
                    "manifest_label": manifest_label,
                    "claim_generator": claim_generator,
                    "assertions": assertion_labels,
                    "signature_present": sig_box is not None,
                    "signature_verified": None,
                    "data_hash_verified": False,
                    "reason": f"Assertion digest mismatch for {url}.",
                }

        # Verify hard data-binding assertion (c2pa.hash.data or c2pa.hash.bmff*).
        data_hash_assertions = [
            (lbl, val)
            for lbl, val in decoded_assertions.items()
            if lbl == "c2pa.hash.data" or lbl.startswith("c2pa.hash.data.")
        ]
        bmff_hash_assertions = [
            (lbl, val)
            for lbl, val in decoded_assertions.items()
            if lbl.startswith("c2pa.hash.bmff")
        ]

        data_hash_verified: bool | None = None
        if data_hash_assertions:
            for _lbl, hval in data_hash_assertions:
                if not isinstance(hval, dict) or not _verify_data_hash(data, hval, default_alg):
                    return {
                        "status": "tampered_payload",
                        "container": container,
                        "manifest_label": manifest_label,
                        "claim_generator": claim_generator,
                        "assertions": assertion_labels,
                        "signature_present": sig_box is not None,
                        "signature_verified": None,
                        "data_hash_verified": False,
                        "reason": "Asset byte payload does not match c2pa.hash.data digest.",
                    }
            data_hash_verified = True
        elif bmff_hash_assertions:
            bmff_outcomes = []
            for _lbl, bval in bmff_hash_assertions:
                if not isinstance(bval, dict):
                    raise _C2PAParseError("invalid BMFF hash assertion")
                outcome = _verify_bmff_flat_hash(data, bval, default_alg)
                if outcome is False:
                    return {
                        "status": "tampered_payload",
                        "container": container,
                        "manifest_label": manifest_label,
                        "claim_generator": claim_generator,
                        "assertions": assertion_labels,
                        "signature_present": sig_box is not None,
                        "signature_verified": None,
                        "data_hash_verified": False,
                        "reason": "BMFF asset boxes do not match c2pa.hash.bmff digest.",
                    }
                bmff_outcomes.append(outcome)
            data_hash_verified = True if all(x is True for x in bmff_outcomes) else None
        else:
            return {
                "status": "tampered_payload",
                "container": container,
                "manifest_label": manifest_label,
                "claim_generator": claim_generator,
                "assertions": assertion_labels,
                "signature_present": sig_box is not None,
                "signature_verified": None,
                "data_hash_verified": False,
                "reason": "C2PA manifest lacks a hard data-binding hash assertion.",
            }

        signature_present = False
        signature_verified: bool | None = None
        if sig_box is not None and sig_box["content"]:
            sig_cbor_box = next(
                (b for b in sig_box["content"] if b["type"] in (b"cbor", b"bfdb", b"bidb")),
                sig_box["content"][0],
            )
            signature_present, signature_verified = _verify_cose_sign1(
                sig_cbor_box["body"], claim_cbor_bytes
            )
            if signature_verified is False:
                return {
                    "status": "tampered_payload",
                    "container": container,
                    "manifest_label": manifest_label,
                    "claim_generator": claim_generator,
                    "assertions": assertion_labels,
                    "signature_present": signature_present,
                    "signature_verified": False,
                    "data_hash_verified": data_hash_verified,
                    "reason": "COSE_Sign1 signature failed verification against embedded certificate.",
                }

        if not signature_present or signature_verified is not True or data_hash_verified is not True:
            return {
                "status": "unverified_signature",
                "container": container,
                "manifest_label": manifest_label,
                "claim_generator": claim_generator,
                "assertions": assertion_labels,
                "signature_present": signature_present,
                "signature_verified": signature_verified,
                "data_hash_verified": data_hash_verified,
                "reason": "Manifest hashes parsed without mismatch, but signature or Merkle binding could not be verified offline.",
            }

        return {
            "status": "valid_manifest",
            "container": container,
            "manifest_label": manifest_label,
            "claim_generator": claim_generator,
            "assertions": assertion_labels,
            "signature_present": True,
            "signature_verified": True,
            "data_hash_verified": True,
            "reason": "Offline JUMBF claim digests, asset data-hash, and COSE_Sign1 signature verified; CA trust-list and OCSP are not checked offline.",
        }
    except (_C2PAParseError, ValueError, KeyError, IndexError, struct.error):
        return {
            "status": "tampered_payload",
            "container": container,
            "manifest_label": None,
            "claim_generator": None,
            "assertions": [],
            "signature_present": False,
            "signature_verified": False,
            "data_hash_verified": False,
            "reason": "Corrupt or malformed C2PA JUMBF/CBOR manifest structure.",
        }


def inspect_c2pa(path: Path) -> dict:
    """Inspect a local media file for an embedded C2PA manifest offline."""
    return inspect_c2pa_bytes(path.read_bytes())
