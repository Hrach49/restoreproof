"""A test-only RFC 3161 token maker for the Cloud's tests (C5.7): the same
shape the Worker's test TSA writes for shared/testdata/timestamp-v1/ (CMS
SignedData v3, one ECDSA/SHA-256 signer named by issuer and serial and by
ESSCertID, a TSTInfo v1 with a SHA-256 imprint), signed with the published
test TSA key of timestamp-v1/keys.json, which is no secret. It exists so a
route test can show a token that verifies over a result the test re-signed;
`verify_bundle.check_timestamp` holds it to `verified` before any route sees it.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
from pathlib import Path

from asn1crypto import algos, cms, core, tsp, x509
from cryptography import x509 as cx509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

KEYS = json.loads((Path(__file__).resolve().parents[2] / "shared" / "testdata" / "timestamp-v1" / "keys.json").read_bytes())
ROOT_PEM = KEYS["root_pem"].encode("ascii")
OTHER_ROOT_PEM = KEYS["other_root_pem"].encode("ascii")
TSA_CERTIFICATE_PEM = KEYS["tsa_certificate_pem"].encode("ascii")
STAMPED_AT = dt.datetime(2026, 10, 6, 12, 0, 0, tzinfo=dt.timezone.utc)


def make_token(digest: bytes, at: dt.datetime = STAMPED_AT, *, serial: int = 4405, nonce: int = 1) -> bytes:
    """One TimeStampToken over the SHA-256 `digest`, at `at` (UTC, whole
    seconds), signed by the test TSA."""
    certificate = cx509.load_pem_x509_certificate(TSA_CERTIFICATE_PEM)
    key = serialization.load_pem_private_key(KEYS["tsa_private_key_pem"].encode("ascii"), password=None)
    cert = x509.Certificate.load(certificate.public_bytes(serialization.Encoding.DER))

    info = tsp.TSTInfo(
        {
            "version": "v1",
            "policy": "1.2.3.4.1",
            "message_imprint": tsp.MessageImprint(
                {"hash_algorithm": algos.DigestAlgorithm({"algorithm": "sha256"}), "hashed_message": digest}
            ),
            "serial_number": serial,
            "gen_time": at.replace(microsecond=0),
            "ordering": False,
            "nonce": nonce,
        }
    )
    content = info.dump()
    signed_attrs = cms.CMSAttributes(
        [
            cms.CMSAttribute({"type": "content_type", "values": [cms.ContentType("tst_info")]}),
            cms.CMSAttribute({"type": "signing_time", "values": [cms.Time({"utc_time": at.replace(microsecond=0)})]}),
            cms.CMSAttribute(
                {
                    "type": "signing_certificate",
                    "values": [
                        tsp.SigningCertificate(
                            {"certs": [tsp.ESSCertID({"cert_hash": hashlib.sha1(cert.dump()).digest()})]}
                        )
                    ],
                }
            ),
            cms.CMSAttribute({"type": "message_digest", "values": [core.OctetString(hashlib.sha256(content).digest())]}),
        ]
    )
    # What is signed is the attributes as a SET OF, not under their context tag.
    signature = key.sign(b"\x31" + signed_attrs.dump()[1:], ec.ECDSA(hashes.SHA256()))
    signer = cms.SignerInfo(
        {
            "version": "v1",
            "sid": cms.SignerIdentifier(
                {
                    "issuer_and_serial_number": cms.IssuerAndSerialNumber(
                        {"issuer": cert.issuer, "serial_number": cert.serial_number}
                    )
                }
            ),
            "digest_algorithm": algos.DigestAlgorithm({"algorithm": "sha256"}),
            "signed_attrs": signed_attrs,
            "signature_algorithm": algos.SignedDigestAlgorithm({"algorithm": "sha256_ecdsa"}),
            "signature": signature,
        }
    )
    signed_data = cms.SignedData(
        {
            "version": "v3",
            "digest_algorithms": [algos.DigestAlgorithm({"algorithm": "sha256"})],
            "encap_content_info": cms.EncapsulatedContentInfo(
                {"content_type": "tst_info", "content": core.ParsableOctetString(content)}
            ),
            "certificates": [cms.CertificateChoices({"certificate": cert})],
            "signer_infos": [signer],
        }
    )
    return cms.ContentInfo({"content_type": "signed_data", "content": signed_data}).dump()
