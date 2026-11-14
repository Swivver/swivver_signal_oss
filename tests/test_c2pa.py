import hashlib
import struct
import unittest
import zlib
from pathlib import Path

from swivver_signal_oss.c2pa import (
    C2PA_ASSERTIONS_UUID,
    C2PA_BMFF_UUID,
    C2PA_CLAIM_UUID,
    C2PA_MANIFEST_UUID,
    C2PA_SIGNATURE_UUID,
    C2PA_STORE_UUID,
    PNG_SIGNATURE,
    inspect_c2pa,
    inspect_c2pa_bytes,
)
from swivver_signal_oss.media import analyze

REAL_FIXTURE_DIR = (
    Path(__file__).resolve().parents[2] / "swivver_signal/data/analysis-v03"
)

# Deterministic 512-bit test RSA prime pair (purely for self-contained unit tests).
_TEST_P = int(
    "d3ef514a608a6fb7c5bd72df4d0dc045e3d65f199f2c8b0bd94b1e86d78df53d", 16
)
_TEST_Q = int(
    "c84f29e0f5f76e9f76b99f6d73c933a7579d690c73be94fd153fa8f9bd237703", 16
)


def _next_probable_prime(seed: int) -> int:
    candidate = seed | 1
    while True:
        if all(
            pow(base, candidate - 1, candidate) == 1
            for base in (2, 3, 5, 7, 11, 13, 17)
        ):
            return candidate
        candidate += 2


def _make_test_rsa_key():
    # Two 512-bit primes -> 1024-bit modulus (128 bytes, sufficient for SHA-256 PSS).
    p = _next_probable_prime(1 << 511 | (_TEST_P << 256) | _TEST_P)
    q = _next_probable_prime(1 << 511 | (_TEST_Q << 256) | _TEST_Q)
    n = p * q
    e = 65537
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    return n, e, d


def _der_len(n: int) -> bytes:
    if n < 128:
        return bytes([n])
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def _der_tlv(tag: int, body: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(body)) + body


def _der_int(val: int) -> bytes:
    raw = val.to_bytes(max(1, (val.bit_length() + 7) // 8), "big")
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    return _der_tlv(0x02, raw)


def _make_test_x509_der(n: int, e: int) -> bytes:
    rsa_pub = _der_tlv(0x30, _der_int(n) + _der_int(e))
    alg_id = _der_tlv(0x30, bytes.fromhex("06092a864886f70d0101010500"))
    spki = _der_tlv(0x30, alg_id + _der_tlv(0x03, b"\x00" + rsa_pub))
    tbs = _der_tlv(0x30, _der_int(1) + spki)
    return _der_tlv(0x30, tbs + alg_id + _der_tlv(0x03, b"\x00"))


def _sign_pss_sha256(n: int, d: int, msg: bytes) -> bytes:
    k = (n.bit_length() + 7) // 8
    h_len = 32
    salt = b"\x42" * 32
    m_hash = hashlib.sha256(msg).digest()
    h = hashlib.sha256(b"\x00" * 8 + m_hash + salt).digest()
    ps_len = k - len(salt) - h_len - 2
    db = (b"\x00" * ps_len) + b"\x01" + salt
    mask = bytearray()
    counter = 0
    while len(mask) < len(db):
        mask.extend(hashlib.sha256(h + struct.pack(">I", counter)).digest())
        counter += 1
    masked_db = bytearray(a ^ b for a, b in zip(db, mask[: len(db)]))
    top_bits = 8 * k - (n.bit_length() - 1)
    if top_bits > 0:
        masked_db[0] &= 0xFF >> top_bits
    em = bytes(masked_db) + h + b"\xbc"
    return pow(int.from_bytes(em, "big"), d, n).to_bytes(k, "big")


def _cbor_encode(value) -> bytes:
    if isinstance(value, bool):
        return b"\xf5" if value else b"\xf4"
    if value is None:
        return b"\xf6"
    if isinstance(value, int):
        if value >= 0:
            return _cbor_head(0, value)
        return _cbor_head(1, -1 - value)
    if isinstance(value, bytes):
        return _cbor_head(2, len(value)) + value
    if isinstance(value, str):
        raw = value.encode("utf-8")
        return _cbor_head(3, len(raw)) + raw
    if isinstance(value, list):
        return _cbor_head(4, len(value)) + b"".join(_cbor_encode(v) for v in value)
    if isinstance(value, dict):
        return _cbor_head(5, len(value)) + b"".join(
            _cbor_encode(k) + _cbor_encode(v) for k, v in value.items()
        )
    raise TypeError(f"unsupported type {type(value)}")


def _cbor_head(major: int, n: int) -> bytes:
    prefix = major << 5
    if n < 24:
        return bytes([prefix | n])
    if n < 256:
        return bytes([prefix | 24, n])
    if n < 65536:
        return bytes([prefix | 25]) + struct.pack(">H", n)
    return bytes([prefix | 26]) + struct.pack(">I", n)


def _iso_box(btype: bytes, body: bytes) -> bytes:
    return struct.pack(">I", 8 + len(body)) + btype + body


def _jumb_superbox(type_uuid: bytes, label: str, children: list[bytes]) -> bytes:
    jumd_body = type_uuid + b"\x03" + label.encode("utf-8") + b"\x00"
    jumd = _iso_box(b"jumd", jumd_body)
    return _iso_box(b"jumb", jumd + b"".join(children))


def _build_manifest_store(
    asset_hash: bytes,
    exclusion_start: int,
    exclusion_length: int,
    *,
    rsa_key: tuple[int, int, int] | None,
    include_cert: bool = True,
    include_signature: bool = True,
) -> bytes:
    actions_cbor = _iso_box(
        b"cbor",
        _cbor_encode({"actions": [{"action": "c2pa.created"}]}),
    )
    actions_jumb = _jumb_superbox(
        bytes.fromhex("63626f7200110010800000aa00389b71"),
        "c2pa.actions",
        [actions_cbor],
    )

    hash_data_cbor = _iso_box(
        b"cbor",
        _cbor_encode(
            {
                "exclusions": [{"start": exclusion_start, "length": exclusion_length}],
                "name": "jumbf manifest",
                "alg": "sha256",
                "hash": asset_hash,
                "pad": b"\x00" * 8,
            }
        ),
    )
    hash_data_jumb = _jumb_superbox(
        bytes.fromhex("63626f7200110010800000aa00389b71"),
        "c2pa.hash.data",
        [hash_data_cbor],
    )

    assertions_jumb = _jumb_superbox(
        C2PA_ASSERTIONS_UUID,
        "c2pa.assertions",
        [actions_jumb, hash_data_jumb],
    )

    claim_payload = _cbor_encode(
        {
            "claim_generator": "swivver-signal-oss-test/1.0",
            "alg": "sha256",
            "assertions": [
                {
                    "url": "self#jumbf=c2pa.assertions/c2pa.actions",
                    "hash": hashlib.sha256(actions_jumb[8:]).digest(),
                },
                {
                    "url": "self#jumbf=c2pa.assertions/c2pa.hash.data",
                    "hash": hashlib.sha256(hash_data_jumb[8:]).digest(),
                },
            ],
        }
    )
    claim_jumb = _jumb_superbox(
        C2PA_CLAIM_UUID,
        "c2pa.claim",
        [_iso_box(b"cbor", claim_payload)],
    )

    manifest_children = [assertions_jumb, claim_jumb]
    if include_signature:
        protected = _cbor_encode({1: -37})
        unprotected = {}
        if rsa_key is not None:
            n, e, d = rsa_key
            if include_cert:
                unprotected[33] = [_make_test_x509_der(n, e)]
            sig_struct = _cbor_encode(["Signature1", protected, b"", claim_payload])
            sig_bytes = _sign_pss_sha256(n, d, sig_struct)
        else:
            sig_bytes = b"\x55" * 128
        cose_sign1 = b"\xd2" + _cbor_encode([protected, unprotected, None, sig_bytes])
        sig_jumb = _jumb_superbox(
            C2PA_SIGNATURE_UUID,
            "c2pa.signature",
            [_iso_box(b"cbor", cose_sign1)],
        )
        manifest_children.append(sig_jumb)

    manifest_jumb = _jumb_superbox(
        C2PA_MANIFEST_UUID,
        "urn:uuid:11111111-2222-3333-4444-555555555555",
        manifest_children,
    )
    return _jumb_superbox(C2PA_STORE_UUID, "c2pa", [manifest_jumb])


class C2PAOfflineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rsa_key = _make_test_rsa_key()

    def _embed_jpeg(self, multi_segment: bool = False, **kwargs) -> bytes:
        prefix = b"\xff\xd8"
        suffix = b"\xff\xdb\x00\x04\x00\x10\xff\xda\x00\x02\x00\x00payload-pixels\xff\xd9"
        asset_hash = hashlib.sha256(prefix + suffix).digest()

        def make_app11(jumbf: bytes) -> bytes:
            if not multi_segment:
                seg_body = b"JP\x00\x01\x00\x00\x00\x01" + jumbf
                return b"\xff\xeb" + struct.pack(">H", 2 + len(seg_body)) + seg_body
            half = len(jumbf) // 2
            p1 = b"JP\x00\x01\x00\x00\x00\x01" + jumbf[:half]
            p2 = b"JP\x00\x01\x00\x00\x00\x02" + jumbf[:8] + jumbf[half:]
            return (
                b"\xff\xeb"
                + struct.pack(">H", 2 + len(p1))
                + p1
                + b"\xff\xeb"
                + struct.pack(">H", 2 + len(p2))
                + p2
            )

        placeholder = make_app11(
            _build_manifest_store(asset_hash, len(prefix), 1000, rsa_key=self.rsa_key, **kwargs)
        )
        final_app11 = make_app11(
            _build_manifest_store(
                asset_hash, len(prefix), len(placeholder), rsa_key=self.rsa_key, **kwargs
            )
        )
        return prefix + final_app11 + suffix

    def _embed_png(self) -> bytes:
        def png_chunk(ctype: bytes, body: bytes) -> bytes:
            crc = zlib.crc32(ctype + body) & 0xFFFFFFFF
            return struct.pack(">I", len(body)) + ctype + body + struct.pack(">I", crc)

        ihdr = png_chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
        idat = png_chunk(b"IDAT", zlib.compress(b"\x00\xff\x00\x00"))
        iend = png_chunk(b"IEND", b"")
        prefix = PNG_SIGNATURE + ihdr
        suffix = idat + iend
        asset_hash = hashlib.sha256(prefix + suffix).digest()
        placeholder = png_chunk(
            b"caBX",
            _build_manifest_store(asset_hash, len(prefix), 1000, rsa_key=self.rsa_key),
        )
        cabx = png_chunk(
            b"caBX",
            _build_manifest_store(
                asset_hash, len(prefix), len(placeholder), rsa_key=self.rsa_key
            ),
        )
        return prefix + cabx + suffix

    def _embed_mp4(self) -> bytes:
        ftyp = _iso_box(b"ftyp", b"isom\x00\x00\x02\x00isomiso2mp41")
        mdat = _iso_box(b"mdat", b"video-sample-payload-bytes")
        asset_hash = hashlib.sha256(ftyp + mdat).digest()
        placeholder = _iso_box(
            b"uuid",
            C2PA_BMFF_UUID
            + _build_manifest_store(asset_hash, len(ftyp), 1000, rsa_key=self.rsa_key),
        )
        uuid_box = _iso_box(
            b"uuid",
            C2PA_BMFF_UUID
            + _build_manifest_store(
                asset_hash, len(ftyp), len(placeholder), rsa_key=self.rsa_key
            ),
        )
        return ftyp + uuid_box + mdat

    def _embed_webp(self) -> bytes:
        vp8l_body = bytes.fromhex("2f00000010071011118888fe0700")
        vp8l = b"VP8L" + struct.pack("<I", len(vp8l_body)) + vp8l_body

        def build(excl_len: int) -> bytes:
            # RIFF header total size changes when C2PA chunk is inserted; compute hash over final non-C2PA bytes.
            dummy_jumbf = _build_manifest_store(b"\x00" * 32, 12 + len(vp8l), excl_len, rsa_key=self.rsa_key)
            pad = b"\x00" if (len(dummy_jumbf) & 1) else b""
            c2pa_len = 8 + len(dummy_jumbf) + len(pad)
            riff_hdr = b"RIFF" + struct.pack("<I", 4 + len(vp8l) + c2pa_len) + b"WEBP"
            prefix = riff_hdr + vp8l
            asset_hash = hashlib.sha256(prefix).digest()
            jumbf = _build_manifest_store(asset_hash, len(prefix), c2pa_len, rsa_key=self.rsa_key)
            return prefix + b"C2PA" + struct.pack("<I", len(jumbf)) + jumbf + pad

        first = build(100)
        c2pa_pos = 12 + len(vp8l)
        return build(len(first) - c2pa_pos)

    def test_synthetic_containers_and_tamper_states(self):
        for label, blob in [
            ("jpeg_single", self._embed_jpeg(multi_segment=False)),
            ("jpeg_multi_app11", self._embed_jpeg(multi_segment=True)),
            ("png_cabx", self._embed_png()),
            ("mp4_uuid", self._embed_mp4()),
            ("webp_riff", self._embed_webp()),
        ]:
            with self.subTest(container=label):
                res = inspect_c2pa_bytes(blob)
                self.assertEqual(res["status"], "valid_manifest")
                self.assertEqual(res["claim_generator"], "swivver-signal-oss-test/1.0")
                self.assertIn("c2pa.hash.data", res["assertions"])
                self.assertTrue(res["signature_present"])
                self.assertTrue(res["signature_verified"])
                self.assertTrue(res["data_hash_verified"])

                mutated = bytearray(blob)
                if label == "webp_riff":
                    mutated[24] ^= 0x01
                else:
                    mutated[-3] ^= 0x01
                tampered = inspect_c2pa_bytes(bytes(mutated))
                self.assertEqual(tampered["status"], "tampered_payload")
                self.assertFalse(tampered["data_hash_verified"])

        # Unsigned / cert-less manifest -> unverified_signature
        no_cert = self._embed_jpeg(include_cert=False)
        res_unverified = inspect_c2pa_bytes(no_cert)
        self.assertEqual(res_unverified["status"], "unverified_signature")
        self.assertTrue(res_unverified["signature_present"])
        self.assertIsNone(res_unverified["signature_verified"])

        no_sig = self._embed_jpeg(include_signature=False)
        res_nosig = inspect_c2pa_bytes(no_sig)
        self.assertEqual(res_nosig["status"], "unverified_signature")
        self.assertFalse(res_nosig["signature_present"])

        # Absent manifest
        clean_jpeg = b"\xff\xd8\xff\xd9"
        self.assertEqual(inspect_c2pa_bytes(clean_jpeg)["status"], "absent")

    @unittest.skipUnless(
        REAL_FIXTURE_DIR.is_dir(), "optional local C2PA reference fixtures"
    )
    def test_real_c2pa_fixtures_and_profile_flags(self):
        res_a = inspect_c2pa(REAL_FIXTURE_DIR / "c2pa-A.jpg")
        self.assertEqual(res_a["status"], "absent")

        res_c = inspect_c2pa(REAL_FIXTURE_DIR / "c2pa-C.jpg")
        self.assertEqual(res_c["status"], "valid_manifest")
        self.assertIn("c2pa-rs", res_c["claim_generator"])
        self.assertIn("c2pa.hash.data", res_c["assertions"])
        self.assertTrue(res_c["signature_verified"])

        res_tampered = inspect_c2pa(REAL_FIXTURE_DIR / "c2pa-tampered.jpg")
        self.assertEqual(res_tampered["status"], "tampered_payload")

        # Also verify end-to-end analyze() on still JPEG C2PA fixtures
        prof_c = analyze(REAL_FIXTURE_DIR / "c2pa-C.jpg")
        self.assertEqual(prof_c["coverage"]["modality"], "image")
        c2pa_sig = next(
            s for s in prof_c["signals"] if s["signal_id"] == "provenance.c2pa"
        )
        self.assertEqual(c2pa_sig["value"]["status"], "valid_manifest")
        self.assertFalse(
            any(f["code"] == "c2pa_tampered_payload" for f in prof_c["flags"])
        )

        prof_bad = analyze(REAL_FIXTURE_DIR / "c2pa-tampered.jpg")
        self.assertTrue(
            any(
                f["code"] == "c2pa_tampered_payload" and f["automatic_action"] == "none"
                for f in prof_bad["flags"]
            )
        )


if __name__ == "__main__":
    unittest.main()
