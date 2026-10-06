"""`python -m seeder new-signing-key` (W4.3): the lab's Ed25519 signing key pair.

Until the Worker's vault lands (W4.5) and the installer makes the key (W7.1), `rpworker test
--evidence` signs with the key in RP_SIGNING_KEY_BASE64: one line of standard Base64 of the
key's PKCS#8 DER, 64 characters, the body line of the PEM OpenSSL writes. This command makes
the pair, keeps that line in Windows Credential Manager and prints the public key's
SubjectPublicKeyInfo PEM and `key <key_id>` (the SHA-256 of the public key's DER, what
`signature.json` names the key by). The private key is never printed, logged or written to a
file; `lab/entra/set-worker-env.ps1` puts it into the variable for one PowerShell session.

The pure parts (the encodings, the key ID, the refusals) take the store as a parameter, so the
tests never touch Credential Manager's lab entry.
"""

import base64
import hashlib
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Protocol

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from seeder import REPO_DIR

CREDENTIAL_TARGET = "RestoreProof Lab - Worker signing key"
CREDENTIAL_USER = "rp-worker-signing-key"
ENV_VAR = "RP_SIGNING_KEY_BASE64"
ENV_SCRIPT = "lab/entra/set-worker-env.ps1"

# PKCS#8 of an Ed25519 private key: these 16 bytes, then the 32-byte seed (RFC 8410).
_PKCS8_PREFIX = bytes.fromhex("302e020100300506032b657004220420")
_SEED_BYTES = 32
_ERROR_NOT_FOUND = 1168
_CRED_TYPE_GENERIC = 1
_CRED_PERSIST_LOCAL_MACHINE = 2


class SigningKeyError(Exception):
    """A refusal or a failure of new-signing-key. Its text never holds a private key."""


@dataclass(frozen=True)
class KeyPair:
    private_pkcs8_base64: str = field(repr=False)  # the secret: one line, 64 characters
    public_key_pem: str  # SubjectPublicKeyInfo, three lines, LF
    key_id: str  # SHA-256 of the SubjectPublicKeyInfo DER, 64 lower-case hex


class CredentialStore(Protocol):
    def read(self, target: str) -> str | None: ...

    def write(self, target: str, secret: str) -> None: ...


def key_pair_from_seed(seed: bytes) -> KeyPair:
    """The key pair of a 32-byte Ed25519 seed, in the three encodings the lab and the Worker use."""
    if len(seed) != _SEED_BYTES:
        raise SigningKeyError(f"An Ed25519 seed is {_SEED_BYTES} bytes, not {len(seed)}.")
    return _encode(ed25519.Ed25519PrivateKey.from_private_bytes(seed))


def new_key_pair() -> KeyPair:
    return _encode(ed25519.Ed25519PrivateKey.generate())


def _encode(key: ed25519.Ed25519PrivateKey) -> KeyPair:
    pkcs8 = key.private_bytes(
        serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    public = key.public_key()
    spki = public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    pem = public.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    line = base64.b64encode(pkcs8).decode("ascii")
    if not is_private_key_line(line):  # the shape the Worker's SigningKey::from_base64 takes
        raise SigningKeyError("The library gave an Ed25519 key in another encoding than PKCS#8 of 48 bytes.")
    return KeyPair(
        private_pkcs8_base64=line,
        public_key_pem=pem.decode("ascii"),
        key_id=hashlib.sha256(spki).hexdigest(),
    )


def is_private_key_line(text: str) -> bool:
    """Whether text is what RP_SIGNING_KEY_BASE64 holds: strict Base64, 64 characters, of the
    48 bytes of an Ed25519 key's PKCS#8 DER. No line break, no PEM armour, no other key type."""
    if len(text) != 64:
        return False
    try:
        der = base64.b64decode(text, validate=True)
    except ValueError:
        return False
    return len(der) == len(_PKCS8_PREFIX) + _SEED_BYTES and der.startswith(_PKCS8_PREFIX)


def check_public_key_out(path: Path, *, replace: bool, repo_dir: Path = REPO_DIR) -> Path:
    """Where --public-key-out may write: a file outside the repository, in a folder that is there."""
    resolved = path.resolve()  # symbolic links and ".." followed, so the rule sees the real place
    repo = repo_dir.resolve()
    if resolved == repo or repo in resolved.parents or _is_in_folder(resolved, repo):
        raise SigningKeyError(
            f"--public-key-out {resolved} is inside the repository ({repo}). "
            "Give a path outside it: the lab's public key isn't committed."
        )
    if not resolved.parent.is_dir():
        raise SigningKeyError(f"--public-key-out {resolved}: the folder doesn't exist.")
    if resolved.is_dir():
        raise SigningKeyError(f"--public-key-out {resolved} is a folder; give a file name.")
    if not replace and (resolved.exists() or resolved.is_symlink()):
        raise SigningKeyError(
            f"--public-key-out {resolved} already exists. It is another key's public half unless "
            "--replace is given, which replaces the key and this file."
        )
    return resolved


def _is_in_folder(path: Path, folder: Path) -> bool:
    """Whether path is folder or below it, by file identity and not by text: one folder has
    many names on Windows (an extended-length `\\\\?\\` path, the drive's admin share, a name
    with a trailing space). Asks path and each folder above it; one that isn't there yet has
    no identity and is passed over, so the nearest existing one and all above it decide."""
    for candidate in (path, *path.parents):
        try:
            if os.path.samefile(candidate, folder):
                return True
        except OSError:  # not there, or not to be opened: not the folder
            continue
    return False


def _write_public_key(path: Path, data: bytes, *, replace: bool) -> None:
    with open(path, "wb" if replace else "xb") as handle:
        handle.write(data)


def run_new_signing_key(
    *,
    store: CredentialStore,
    replace: bool = False,
    public_key_out: Path | None = None,
    make_key_pair: Callable[[], KeyPair] | None = None,
    target: str = CREDENTIAL_TARGET,
) -> int:
    """Makes the pair, stores the private line, prints the public PEM and `key <key_id>` on
    stdout and nothing else there. Every refusal comes before a key is made or stored."""
    out_path = check_public_key_out(public_key_out, replace=replace) if public_key_out is not None else None
    if not replace and store.read(target) is not None:
        raise SigningKeyError(
            f"Credential Manager already has '{target}'. Replacing it orphans every signature made with "
            "the old key: no run folder signed with it verifies against the new public key, and the old "
            "private key can't be brought back. Pass --replace to make a new key all the same."
        )
    pair = (make_key_pair or new_key_pair)()
    store.write(target, pair.private_pkcs8_base64)
    # No public key is shown for a private key that isn't kept: it would be registered for nothing.
    if store.read(target) != pair.private_pkcs8_base64:
        raise SigningKeyError(
            f"The new key did not read back from Credential Manager ('{target}'), so no public key was "
            "printed. Run the command again with --replace."
        )
    sys.stdout.write(pair.public_key_pem + f"key {pair.key_id}\n")
    sys.stdout.flush()
    print(f"stored the private key in Credential Manager ('{target}')", file=sys.stderr)
    if out_path is not None:
        try:
            _write_public_key(out_path, pair.public_key_pem.encode("ascii"), replace=replace)
        except OSError as exc:
            raise SigningKeyError(
                f"--public-key-out {out_path} could not be written ({exc.strerror or type(exc).__name__}). "
                "The key is stored and its public half is printed above; save that instead."
            ) from None
        print(f"wrote {out_path}", file=sys.stderr)
    return 0


def _advapi32():
    """advapi32 with the credential calls typed, and the CREDENTIALW structure."""
    if sys.platform != "win32":
        raise SigningKeyError("Credential Manager is Windows only: run new-signing-key on the Windows lab machine.")
    import ctypes
    from ctypes import wintypes

    class CREDENTIAL(ctypes.Structure):
        _fields_ = [
            ("Flags", wintypes.DWORD),
            ("Type", wintypes.DWORD),
            ("TargetName", wintypes.LPWSTR),
            ("Comment", wintypes.LPWSTR),
            ("LastWritten", wintypes.FILETIME),
            ("CredentialBlobSize", wintypes.DWORD),
            ("CredentialBlob", ctypes.POINTER(ctypes.c_ubyte)),
            ("Persist", wintypes.DWORD),
            ("AttributeCount", wintypes.DWORD),
            ("Attributes", ctypes.c_void_p),
            ("TargetAlias", wintypes.LPWSTR),
            ("UserName", wintypes.LPWSTR),
        ]

    dll = ctypes.WinDLL("advapi32", use_last_error=True)
    dll.CredReadW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(ctypes.POINTER(CREDENTIAL))]
    dll.CredReadW.restype = wintypes.BOOL
    dll.CredWriteW.argtypes = [ctypes.POINTER(CREDENTIAL), wintypes.DWORD]
    dll.CredWriteW.restype = wintypes.BOOL
    dll.CredDeleteW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD]
    dll.CredDeleteW.restype = wintypes.BOOL
    dll.CredFree.argtypes = [ctypes.c_void_p]
    dll.CredFree.restype = None
    return ctypes, dll, CREDENTIAL


class WindowsCredentialStore:
    """Generic credentials of Windows Credential Manager, the secret as UTF-16LE (as
    lab/entra/new-worker-app.ps1 and cmdkey store one, and as set-worker-env.ps1 reads it)."""

    def read(self, target: str) -> str | None:
        ctypes, dll, credential = _advapi32()
        pointer = ctypes.POINTER(credential)()
        if not dll.CredReadW(target, _CRED_TYPE_GENERIC, 0, ctypes.byref(pointer)):
            error = ctypes.get_last_error()
            if error == _ERROR_NOT_FOUND:
                return None
            # Any other failure is never "no entry": the command would then replace a key.
            raise SigningKeyError(f"Credential Manager could not read '{target}' (Windows error {error}).")
        try:
            blob = ctypes.string_at(pointer.contents.CredentialBlob, pointer.contents.CredentialBlobSize)
        finally:
            dll.CredFree(pointer)
        return blob.decode("utf-16-le")

    def write(self, target: str, secret: str) -> None:
        ctypes, dll, credential = _advapi32()
        blob = secret.encode("utf-16-le")
        buffer = (ctypes.c_ubyte * len(blob)).from_buffer_copy(blob)
        entry = credential()
        entry.Type = _CRED_TYPE_GENERIC
        entry.TargetName = target
        entry.UserName = CREDENTIAL_USER
        entry.Persist = _CRED_PERSIST_LOCAL_MACHINE
        entry.CredentialBlobSize = len(blob)
        entry.CredentialBlob = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte))
        try:
            if not dll.CredWriteW(ctypes.byref(entry), 0):
                error = ctypes.get_last_error()
                raise SigningKeyError(f"Credential Manager could not write '{target}' (Windows error {error}).")
        finally:
            ctypes.memset(buffer, 0, len(blob))


def delete_generic_credential(target: str) -> None:
    """Removes a generic credential; one that isn't there is fine. The tests' cleanup of their
    own throwaway entries: no command deletes the lab's key."""
    ctypes, dll, _ = _advapi32()
    if not dll.CredDeleteW(target, _CRED_TYPE_GENERIC, 0):
        error = ctypes.get_last_error()
        if error != _ERROR_NOT_FOUND:
            raise SigningKeyError(f"Credential Manager could not delete '{target}' (Windows error {error}).")
