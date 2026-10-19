"""The installer run against a fake Worker and a fake machine on a temporary root (W7.1).

Nothing here touches %ProgramData%, %ProgramFiles% or the Service Control Manager: the script
gets -Root, -ProgramDir, -Package, -Worker (tests/fake_rpworker.py through a .cmd), -ServiceName
(a service no machine has) and -MachineModule (tests/FakeMachine.psm1, answering from
machine.json). The test's own account keeps full control of the temporary root through
-AlsoFullControl, since the installer's ACL would lock a non-administrator out of it."""

import datetime
import json
import os
import re
import subprocess
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from pwsh import CERT_SCRIPT, FAKE_MACHINE, SCRIPT, SETUP_DIR, TESTS_DIR, UNINSTALL_SCRIPT, ps_string, run

# What the package carries beside the exe and the DLLs (W7.3 point 2: copied into the program folder).
SCRIPTS = ("Install-RestoreProofWorker.ps1", "Uninstall-RestoreProofWorker.ps1", "RestoreProofWorker.psm1",
           "WorkerMachine.psm1", "New-WorkerGraphCertificate.ps1")

SERVICE = "rp-test-w71-no-such-service"
PASSWORD = "Sentinel-Veeam-Password-7f3a"
TOKEN = "Sentinel-Install-Token-5c1e-ABCDEFGHIJKLMNOPQRSTUVW"
USERNAME = "FAKE-HOST\\rp-veeam"
THUMBPRINT = "AC3220B58A2B4C438DA13816C2DD1E25D1F783A7"
ANSWERS = {"veeam_password": PASSWORD, "cloud_install_token": TOKEN}


def current_user_sid() -> str:
    out = subprocess.run(["whoami", "/user", "/fo", "csv", "/nh"], capture_output=True, text=True, check=True).stdout
    return out.strip().split(",")[-1].strip('"')


def self_signed(subject: str, *, host: str | None = None) -> bytes:
    """A self-signed certificate's DER (an RSA key made and dropped)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)])
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
    )
    if host:
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]), critical=False)
    return builder.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)


def sha1_hex(der: bytes) -> str:
    digest = hashes.Hash(hashes.SHA1())
    digest.update(der)
    return digest.finalize().hex().upper()


class InstallLab:
    def __init__(self, folder: Path, *, veeam_here: bool = True, elevated: bool = True, ps_version: str = "7.4.0",
                 installed_service: dict | None = None, remote: dict | None = "own", key_files: dict | None = None,
                 vault: dict | None = None, flags: tuple[str, ...] = (), version: str = "0.1.0",
                 run_in_progress: bool | int = False):
        self.folder = folder
        self.fake = folder / "fake"
        self.package = folder / "package"
        self.program = folder / "program"
        self.root = folder / "root"
        for sub in (self.fake, self.package):
            sub.mkdir()
        self.cmd = self.fake / "rpworker.cmd"
        self.cmd.write_text(f'@"{sys.executable}" "{TESTS_DIR / "fake_rpworker.py"}" %*\r\n', encoding="ascii")
        self.write_package(self.package, version)
        self.veeam_der = self_signed("Veeam Software")
        if remote == "own":
            remote = {"derBase64": "", "inLocalStoreWithKey": True, "chainsToStore": False, "namesHost": False}
        if remote is not None and not remote.get("derBase64"):
            remote["derBase64"] = __import__("base64").b64encode(self.veeam_der).decode("ascii")
        key_file = None
        if key_files is None:
            key_file = self.fake / "machine-key-file.bin"
            key_file.write_bytes(b"not a key")
            key_files = {THUMBPRINT: str(key_file)}
        self.key_file = Path(key_files[THUMBPRINT]) if THUMBPRINT in key_files else key_file
        self.machine = {
            "elevated": elevated,
            "psVersion": ps_version,
            "veeamHere": veeam_here,
            "installedService": installed_service,
            "remote": remote,
            "keyFiles": key_files,
            # W7.3/W7.4: a run in progress for ever (True) or for the first n reads of the record.
            "runInProgress": run_in_progress is True,
            "runInProgressPolls": run_in_progress if isinstance(run_in_progress, int) and run_in_progress is not True else 0,
        }
        self.write_machine()
        if vault is not None:
            self.set_vault(vault)
        else:
            self.flag("missing-vault")
        for flag in flags:
            self.flag(flag)

    @staticmethod
    def write_package(folder: Path, version: str):
        """A package folder as the zip unpacks: a dummy exe carrying its version in its bytes
        (the fake machine's Get-WorkerVersion reads it), a DLL, the five scripts, a file that
        is never copied."""
        folder.mkdir(exist_ok=True)
        (folder / "rpworker.exe").write_bytes(f"MZ fake worker {version} ".encode("ascii") + os.urandom(16))
        (folder / "fake.dll").write_bytes(f"MZ fake dll {version} ".encode("ascii") + os.urandom(16))
        (folder / "README.txt").write_text("not copied", encoding="ascii")
        for name in SCRIPTS:
            (folder / name).write_bytes((SETUP_DIR / name).read_bytes() if (SETUP_DIR / name).exists() else (CERT_SCRIPT).read_bytes())

    def installed(self, *, state: str = "Running"):
        """The machine as it is once the installer ran: the service installed from the program folder."""
        self.machine["installedService"] = {"pathName": f'"{self.program / "rpworker.exe"}" service run', "state": state}
        self.write_machine()

    def entry(self) -> dict | None:
        path = self.fake / "uninstall-entry.json"
        return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None

    def overwritten(self) -> list[str]:
        log = self.fake / "overwritten.log"
        return log.read_text(encoding="utf-8").splitlines() if log.exists() else []

    def write_machine(self):
        (self.fake / "machine.json").write_text(json.dumps(self.machine), encoding="utf-8")

    def flag(self, name: str):
        (self.fake / name).write_text("", encoding="ascii")

    def unflag(self, name: str):
        (self.fake / name).unlink(missing_ok=True)

    def vault(self) -> dict:
        path = self.fake / "vault.json"
        return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}

    def set_vault(self, values: dict):
        (self.fake / "vault.json").write_text(json.dumps(values), encoding="utf-8")
        self.unflag("missing-vault")

    def argv(self) -> list[list[str]]:
        log = self.fake / "argv.log"
        return [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()] if log.exists() else []

    def commands(self) -> list[str]:
        return [" ".join(a) for a in self.argv()]

    def machine_log(self) -> list[str]:
        log = self.fake / "machine.log"
        return log.read_text(encoding="utf-8").splitlines() if log.exists() else []

    def marker(self, name: str) -> bool:
        return (self.fake / name).exists()

    def config(self) -> dict | None:
        path = self.root / "config.json"
        return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None

    def run(self, *extra: str, answers: dict | None = ANSWERS, urls: bool = True, whatif: bool = False,
            worker_name: str = "fake-host-worker", timeout: int = 240, package: Path | None = None) -> subprocess.CompletedProcess:
        params = [
            f"-Package {ps_string(package or self.package)}",
            "-PollSeconds 1",
            f"-ProgramDir {ps_string(self.program)}",
            f"-Root {ps_string(self.root)}",
            f"-Worker {ps_string(self.cmd)}",
            f"-ServiceName {ps_string(SERVICE)}",
            f"-MachineModule {ps_string(FAKE_MACHINE)}",
            f"-AlsoFullControl {ps_string(current_user_sid())}",
            f"-VeeamUsername {ps_string(USERNAME)}",
            f"-WorkerName {ps_string(worker_name)}",
        ]
        if urls:
            params += ["-CloudUrl 'https://cloud.example.invalid'", "-VeeamUrl 'https://veeam.example.invalid:4443'"]
        if answers:
            pairs = "; ".join(f"{k} = {ps_string(v)}" for k, v in answers.items())
            params.append(f"-Answers @{{ {pairs} }}")
        if whatif:
            params.append("-WhatIf")
        params += list(extra)
        # A failure's own line, whole (pwsh's error view wraps and colours a long one), and where
        # it came from (the script's stack), so a test shows both.
        command = (
            f"$env:RP_FAKE_DIR = {ps_string(self.fake)}\n"
            f"try {{ & {ps_string(SCRIPT)} {' '.join(params)} }}\n"
            "catch { [Console]::Error.WriteLine($_.Exception.Message); [Console]::Error.WriteLine($_.ScriptStackTrace); throw }\n"
        )
        return run(command, timeout=timeout)

    def uninstall(self, *extra: str, whatif: bool = False, timeout: int = 240, worker: Path | None = None) -> subprocess.CompletedProcess:
        """Uninstall-RestoreProofWorker.ps1 on the same folders and fakes (W7.3)."""
        params = [
            f"-ProgramDir {ps_string(self.program)}",
            f"-Root {ps_string(self.root)}",
            f"-Worker {ps_string(worker or self.cmd)}",
            f"-ServiceName {ps_string(SERVICE)}",
            f"-MachineModule {ps_string(FAKE_MACHINE)}",
            "-PollSeconds 1",
        ]
        if whatif:
            params.append("-WhatIf")
        params += list(extra)
        command = (
            f"$env:RP_FAKE_DIR = {ps_string(self.fake)}\n"
            f"try {{ & {ps_string(UNINSTALL_SCRIPT)} {' '.join(params)} }}\n"
            "catch { [Console]::Error.WriteLine($_.Exception.Message); [Console]::Error.WriteLine($_.ScriptStackTrace); throw }\n"
            # The script's own `exit 1` (a file that couldn't be removed) is the process's.
            "exit $(if (Test-Path variable:LASTEXITCODE) { $LASTEXITCODE } else { 0 })\n"
        )
        return run(command, timeout=timeout)


def lines(result: subprocess.CompletedProcess) -> list[str]:
    return [line for line in result.stdout.splitlines() if line]


def acl_lines(path: Path) -> str:
    return subprocess.run(["icacls", str(path)], capture_output=True, text=True, check=True).stdout


def explicit_rules(path: Path) -> list[dict]:
    """A folder's explicit rules (IsInherited false), by SID, as PowerShell reads them."""
    from pwsh import run_json

    command = (
        f"$acl = Get-Acl -LiteralPath {ps_string(path)}\n"
        "$rules = @($acl.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier]) | ForEach-Object {\n"
        "  [pscustomobject]@{ sid = $_.IdentityReference.Value; rights = \"$($_.FileSystemRights)\"; type = \"$($_.AccessControlType)\";\n"
        "    inherit = \"$($_.InheritanceFlags)\"; propagation = \"$($_.PropagationFlags)\" } })\n"
        "[pscustomobject]@{ protected = $acl.AreAccessRulesProtected; rules = $rules }"
    )
    return run_json(command)


def secret_shapes() -> list[str]:
    return [PASSWORD, TOKEN]


def assert_no_secret(text: str):
    for shape in secret_shapes():
        assert shape not in text, f"a secret reached: {text[:400]}"


def assert_no_secret_argument(lab: InstallLab):
    for argv in lab.argv():
        for shape in secret_shapes():
            assert shape not in " ".join(argv), argv


WORKER_LINE = re.compile(r"^worker ([0-9a-f-]{36}) key ([0-9a-f]{64})$")
