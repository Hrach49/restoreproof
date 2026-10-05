"""`python -m seeder new-signing-key` (W4.3): the lab's Ed25519 signing key pair. The private key
goes into Credential Manager only; stdout gets the public PEM and `key <key_id>` and nothing else.
Every test here uses a fake store, but the last one, which writes a throwaway entry of its own."""

import base64
import hashlib
import sys
import uuid

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

from seeder import REPO_DIR, cli, signing_key
from seeder.signing_key import SigningKeyError

# RFC 8032 section 7.1, test 1: a published key, never a secret.
RFC_SEED = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
RFC_PRIVATE = "MC4CAQAwBQYDK2VwBCIEIJ1hsZ3v/VpguoRK9JLsLMREScVpezJpGXA7rAMcrn9g"
RFC_PEM = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=\n-----END PUBLIC KEY-----\n"
RFC_KEY_ID = "06e3fd8fda29bb60ab59557de61edb0aecdb231134be30e75b455f8e1b792fa9"
OLD_ENTRY = "MC4CAQAwBQYDK2VwBCIEIOLDOLDOLDOLDOLDOLDOLDOLDOLDOLDOLDOLDOLDOLDO"


class FakeStore:
    """Credential Manager in memory. `fail_write` raises; `lose_write` takes a write and keeps nothing."""

    def __init__(self, entries=None, *, fail_write=False, lose_write=False):
        self.entries = dict(entries or {})
        self.fail_write = fail_write
        self.lose_write = lose_write
        self.writes = []

    def read(self, target):
        return self.entries.get(target)

    def write(self, target, secret):
        if self.fail_write:
            raise SigningKeyError("Credential Manager could not write the entry (Windows error 5).")
        self.writes.append(target)
        if not self.lose_write:
            self.entries[target] = secret


def rfc_pair():
    return signing_key.key_pair_from_seed(RFC_SEED)


def run(store, capsys, **kwargs):
    kwargs.setdefault("make_key_pair", rfc_pair)
    code = signing_key.run_new_signing_key(store=store, **kwargs)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


# ---- refusals first --------------------------------------------------------------------------


def test_an_existing_entry_is_not_replaced_and_no_key_is_made(capsys):
    store = FakeStore({signing_key.CREDENTIAL_TARGET: OLD_ENTRY})

    def never():
        raise AssertionError("no key pair may be made when the command refuses")

    with pytest.raises(SigningKeyError) as refused:
        run(store, capsys, make_key_pair=never)
    message = str(refused.value)
    assert signing_key.CREDENTIAL_TARGET in message
    assert "--replace" in message
    assert "orphans every signature made with the old key" in message
    assert store.entries == {signing_key.CREDENTIAL_TARGET: OLD_ENTRY}
    assert store.writes == []
    assert OLD_ENTRY not in message


def test_an_empty_existing_entry_is_an_entry_too(capsys):
    store = FakeStore({signing_key.CREDENTIAL_TARGET: ""})
    with pytest.raises(SigningKeyError, match="--replace"):
        run(store, capsys)
    assert store.writes == []


@pytest.mark.parametrize(
    "inside",
    [
        REPO_DIR / "worker-signing.pub.pem",
        REPO_DIR / "lab" / "worker-signing.pub.pem",
        REPO_DIR / "lab" / ".." / "docs" / "worker-signing.pub.pem",
        REPO_DIR / "lab" / "no-such-folder" / "worker-signing.pub.pem",
    ],
)
def test_a_public_key_file_inside_the_repository_is_refused_before_anything_is_stored(inside, capsys):
    store = FakeStore()
    try:
        with pytest.raises(SigningKeyError, match="inside the repository"):
            run(store, capsys, public_key_out=inside)
        assert store.entries == {} and store.writes == []
        assert not inside.exists()
    finally:
        inside.unlink(missing_ok=True)  # a regression must not leave a file in the working tree


def test_a_relative_public_key_file_is_read_against_the_working_folder(monkeypatch, capsys):
    monkeypatch.chdir(REPO_DIR / "lab")
    store = FakeStore()
    with pytest.raises(SigningKeyError, match="inside the repository"):
        run(store, capsys, public_key_out=signing_key.Path("worker-signing.pub.pem"))
    assert store.writes == []


def test_a_public_key_file_in_a_folder_that_is_not_there_is_refused(tmp_path, capsys):
    store = FakeStore()
    with pytest.raises(SigningKeyError, match="the folder doesn't exist"):
        run(store, capsys, public_key_out=tmp_path / "nope" / "key.pem")
    assert store.writes == []


def test_a_public_key_file_that_is_a_folder_is_refused(tmp_path, capsys):
    store = FakeStore()
    with pytest.raises(SigningKeyError, match="is a folder"):
        run(store, capsys, public_key_out=tmp_path)
    assert store.writes == []


def test_an_existing_public_key_file_is_kept_without_replace(tmp_path, capsys):
    out = tmp_path / "key.pem"
    out.write_text("the old key's PEM", encoding="ascii")
    store = FakeStore()
    with pytest.raises(SigningKeyError, match="already exists"):
        run(store, capsys, public_key_out=out)
    assert out.read_text(encoding="ascii") == "the old key's PEM"
    assert store.writes == []


def test_a_store_that_cannot_write_prints_no_public_key(capsys):
    store = FakeStore(fail_write=True)
    with pytest.raises(SigningKeyError, match="could not write"):
        signing_key.run_new_signing_key(store=store, make_key_pair=rfc_pair)
    captured = capsys.readouterr()
    assert captured.out == ""
    assert RFC_PRIVATE not in captured.err


def test_a_key_that_does_not_read_back_prints_no_public_key(capsys):
    # A public key printed for a private key that isn't kept would be registered for nothing.
    store = FakeStore(lose_write=True)
    with pytest.raises(SigningKeyError, match="did not read back") as refused:
        signing_key.run_new_signing_key(store=store, make_key_pair=rfc_pair)
    assert capsys.readouterr().out == ""
    assert RFC_PRIVATE not in str(refused.value)


@pytest.mark.parametrize("length", [0, 31, 33, 64])
def test_a_seed_of_another_length_is_refused(length):
    with pytest.raises(SigningKeyError, match="32 bytes"):
        signing_key.key_pair_from_seed(bytes(length))


@pytest.mark.parametrize(
    "text",
    [
        "",
        RFC_PRIVATE[:-1],
        RFC_PRIVATE + "A",
        RFC_PRIVATE + "\n",
        " " + RFC_PRIVATE,
        RFC_PRIVATE.replace("/", "_"),
        "MC4CAQAwBQYDK2VuBCIEIJ1hsZ3v/VpguoRK9JLsLMREScVpezJpGXA7rAMcrn9g",  # X25519's OID
        "-----BEGIN PRIVATE KEY-----",
    ],
)
def test_is_private_key_line_takes_only_the_one_line_of_an_ed25519_pkcs8_key(text):
    assert signing_key.is_private_key_line(text) is False


def test_is_private_key_line_refuses_an_rsa_key():
    der = rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
        serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    assert signing_key.is_private_key_line(base64.b64encode(der).decode("ascii")) is False


# ---- the known values ------------------------------------------------------------------------


def test_rfc_8032_test_1_gives_the_known_encodings():
    pair = rfc_pair()
    assert pair.private_pkcs8_base64 == RFC_PRIVATE
    assert len(pair.private_pkcs8_base64) == 64
    assert pair.public_key_pem == RFC_PEM
    assert pair.key_id == RFC_KEY_ID
    assert signing_key.is_private_key_line(pair.private_pkcs8_base64) is True


def test_the_private_line_is_the_body_line_of_the_pem_openssl_writes():
    pem = ed25519.Ed25519PrivateKey.from_private_bytes(RFC_SEED).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    assert pem.decode("ascii").splitlines() == ["-----BEGIN PRIVATE KEY-----", RFC_PRIVATE, "-----END PRIVATE KEY-----"]


def test_the_key_id_is_the_sha256_of_the_public_keys_der():
    body = "".join(RFC_PEM.splitlines()[1:-1])
    assert hashlib.sha256(base64.b64decode(body)).hexdigest() == RFC_KEY_ID
    assert len(base64.b64decode(body)) == 44


def test_a_key_pair_never_shows_its_private_key():
    pair = rfc_pair()
    assert RFC_PRIVATE not in repr(pair) + str(pair)
    assert RFC_SEED.hex() not in repr(pair)


def test_new_key_pairs_differ_and_are_well_formed():
    first, second = signing_key.new_key_pair(), signing_key.new_key_pair()
    assert first.private_pkcs8_base64 != second.private_pkcs8_base64
    assert first.key_id != second.key_id
    for pair in (first, second):
        assert signing_key.is_private_key_line(pair.private_pkcs8_base64)
        assert len(pair.key_id) == 64 and pair.key_id == pair.key_id.lower()
        key = serialization.load_pem_public_key(pair.public_key_pem.encode("ascii"))
        assert isinstance(key, ed25519.Ed25519PublicKey)


# ---- the command -----------------------------------------------------------------------------


def test_it_stores_the_private_line_and_prints_only_the_public_key_and_its_id(capsys):
    store = FakeStore()
    code, out, err = run(store, capsys)
    assert code == 0
    assert store.entries == {signing_key.CREDENTIAL_TARGET: RFC_PRIVATE}
    assert out == RFC_PEM + f"key {RFC_KEY_ID}\n"
    assert err == f"stored the private key in Credential Manager ('{signing_key.CREDENTIAL_TARGET}')\n"
    assert RFC_PRIVATE not in out + err
    assert RFC_SEED.hex() not in out + err


def test_replace_takes_the_place_of_an_existing_entry(capsys):
    store = FakeStore({signing_key.CREDENTIAL_TARGET: OLD_ENTRY})
    code, out, err = run(store, capsys, replace=True)
    assert code == 0
    assert store.entries == {signing_key.CREDENTIAL_TARGET: RFC_PRIVATE}
    assert out == RFC_PEM + f"key {RFC_KEY_ID}\n"
    assert OLD_ENTRY not in out + err


def test_public_key_out_writes_the_pem_outside_the_repository(tmp_path, capsys):
    out_file = tmp_path / "worker-signing.pub.pem"
    store = FakeStore()
    code, out, err = run(store, capsys, public_key_out=out_file)
    assert code == 0
    assert out_file.read_bytes() == RFC_PEM.encode("ascii")  # LF, as OpenSSL writes it
    assert out == RFC_PEM + f"key {RFC_KEY_ID}\n"
    assert err.splitlines()[1] == f"wrote {out_file.resolve()}"
    assert [p.name for p in tmp_path.iterdir()] == ["worker-signing.pub.pem"]
    assert RFC_PRIVATE not in out_file.read_text(encoding="ascii")


def test_replace_also_replaces_the_public_key_file(tmp_path, capsys):
    out_file = tmp_path / "key.pem"
    out_file.write_text("the old key's PEM", encoding="ascii")
    store = FakeStore({signing_key.CREDENTIAL_TARGET: OLD_ENTRY})
    code, _, _ = run(store, capsys, replace=True, public_key_out=out_file)
    assert code == 0
    assert out_file.read_bytes() == RFC_PEM.encode("ascii")


def test_a_public_key_file_that_cannot_be_written_still_shows_the_public_key(tmp_path, capsys, monkeypatch):
    # The key is stored by then: its public half must not be lost with the file.
    out_file = tmp_path / "key.pem"

    def refuse(path, data, *, replace):
        raise OSError("disk full")

    monkeypatch.setattr(signing_key, "_write_public_key", refuse)
    store = FakeStore()
    with pytest.raises(SigningKeyError, match="could not be written") as refused:
        signing_key.run_new_signing_key(store=store, make_key_pair=rfc_pair, public_key_out=out_file)
    assert "The key is stored" in str(refused.value)
    assert capsys.readouterr().out == RFC_PEM + f"key {RFC_KEY_ID}\n"
    assert store.entries == {signing_key.CREDENTIAL_TARGET: RFC_PRIVATE}


# ---- through the CLI -------------------------------------------------------------------------


@pytest.fixture
def cli_store(monkeypatch):
    store = FakeStore()
    monkeypatch.setattr(cli, "WindowsCredentialStore", lambda: store)
    monkeypatch.setattr(signing_key, "new_key_pair", rfc_pair)
    return store


def test_cli_new_signing_key_prints_the_public_key(cli_store, capsys):
    assert cli.main(["new-signing-key"]) == 0
    captured = capsys.readouterr()
    assert captured.out == RFC_PEM + f"key {RFC_KEY_ID}\n"
    assert RFC_PRIVATE not in captured.out + captured.err
    assert cli_store.entries == {signing_key.CREDENTIAL_TARGET: RFC_PRIVATE}


def test_cli_refusal_is_one_line_and_exit_2(cli_store, capsys):
    cli_store.entries[signing_key.CREDENTIAL_TARGET] = OLD_ENTRY
    assert cli.main(["new-signing-key"]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.startswith("error: Credential Manager already has ")
    assert len(captured.err.strip().splitlines()) == 1
    assert "Traceback" not in captured.err
    assert cli_store.entries[signing_key.CREDENTIAL_TARGET] == OLD_ENTRY


def test_cli_replace_and_public_key_out(cli_store, tmp_path, capsys):
    cli_store.entries[signing_key.CREDENTIAL_TARGET] = OLD_ENTRY
    out_file = tmp_path / "key.pem"
    assert cli.main(["new-signing-key", "--replace", "--public-key-out", str(out_file)]) == 0
    assert out_file.read_bytes() == RFC_PEM.encode("ascii")
    assert cli_store.entries[signing_key.CREDENTIAL_TARGET] == RFC_PRIVATE


def test_cli_public_key_out_inside_the_repository_is_exit_2(cli_store, capsys):
    inside = REPO_DIR / "lab" / "worker-signing.pub.pem"
    assert cli.main(["new-signing-key", "--public-key-out", str(inside)]) == 2
    assert "inside the repository" in capsys.readouterr().err
    assert cli_store.entries == {} and not inside.exists()


def test_the_help_names_the_command(capsys):
    assert cli.main(["--help"]) == 0
    assert "new-signing-key" in capsys.readouterr().out


def test_the_target_name_is_in_the_style_of_the_labs_other_entry():
    from seeder import worker_app

    assert signing_key.CREDENTIAL_TARGET == "RestoreProof Lab - Worker signing key"
    assert signing_key.CREDENTIAL_TARGET != worker_app.CREDENTIAL_TARGET
    assert signing_key.ENV_VAR == "RP_SIGNING_KEY_BASE64"


# ---- the real store, on a throwaway entry of its own (never the lab's) -----------------------


@pytest.mark.skipif(sys.platform != "win32", reason="Credential Manager, Windows only")
def test_the_windows_store_reads_back_what_it_wrote():
    store = signing_key.WindowsCredentialStore()
    target = f"RestoreProof Lab - test {uuid.uuid4()}"
    assert store.read(target) is None
    try:
        store.write(target, RFC_PRIVATE)
        assert store.read(target) == RFC_PRIVATE
        store.write(target, "second-value")
        assert store.read(target) == "second-value"
    finally:
        signing_key.delete_generic_credential(target)
    assert store.read(target) is None
