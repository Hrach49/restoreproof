"""The canary set: the 20 mails and 20 files L1.2 seeds, and where each one goes.

Everything here is fixed. Changing a sentence, the footer, the type cycle or a location
changes the expected set, so it needs a new seed run and a new manifest.
"""

from dataclasses import dataclass
from typing import Literal

from seeder import tenant

MAIL_COUNT = 20
FILE_COUNT = 20

# Mails are sent as plain text with CRLF line breaks (the MIME canonical form). Every line
# stays under 76 characters so no mail system has a reason to wrap it.
MAIL_FOOTER = (
    "RestoreProof canary mail. Do not edit, move or delete this message.\r\n"
    "It is one of the 40 expected items in lab/seed-manifest.json."
)

MAIL_SENTENCES = (
    "The lighthouse keeper counted forty-one ships before dawn.",
    "A copper kettle whistled twice in the empty kitchen.",
    "Seven orange kites drifted over the harbour wall.",
    "The night train to Krakow left three minutes early.",
    "A grey heron stood motionless in the shallow reeds.",
    "Twelve jars of plum jam lined the pantry shelf.",
    "The clockmaker replaced a spring worn thin by time.",
    "Fresh snow covered the bicycle left by the gate.",
    "A violinist tuned the strings beneath the old bridge.",
    "The library smelled of cedar, dust and rain.",
    "Nine paper boats raced down the gutter after the storm.",
    "The baker shaped two hundred rolls before sunrise.",
    "A red fox crossed the frozen field without a sound.",
    "The ferry horn echoed across the misty fjord.",
    "Four chess pieces were missing from the park table.",
    "The gardener planted tulips in a perfect spiral.",
    "A brass compass pointed stubbornly to the north-east.",
    "The museum guard hummed an old waltz at closing time.",
    "Silver rain tapped on the greenhouse roof all night.",
    "The cartographer inked a river that no longer exists.",
)

# File n has type FILE_TYPE_CYCLE[(n - 1) % 5]: 01 pdf, 02 docx, 03 xlsx, 04 txt, 05 png,
# 06 pdf, ..., 20 png. Each location gets two files of every type.
FILE_TYPE_CYCLE = ("pdf", "docx", "xlsx", "txt", "png")

FileKind = Literal["sharepoint_file", "onedrive_file"]


@dataclass(frozen=True)
class CanaryMail:
    number: int  # 1..20
    subject: str  # RP-CANARY-0001 .. RP-CANARY-0020
    sentence: str
    sender: str  # UPN that sends it (the admin)
    recipient: str  # UPN whose mailbox receives it

    @property
    def body(self) -> str:
        """The exact text sent (contentType "text")."""
        return self.sentence + "\r\n\r\n" + MAIL_FOOTER


@dataclass(frozen=True)
class CanaryFile:
    number: int  # 1..20
    name: str  # rp-canary-01.pdf .. rp-canary-20.png
    file_type: str  # one of FILE_TYPE_CYCLE
    kind: FileKind
    sentence: str  # the text the file carries
    uploader: str  # UPN that uploads it (the owner of the location)
    drive_id: str
    folder_id: str
    folder_path: str


def mail_recipient(number: int) -> str:
    """RP-CANARY-0001..0010 go to alice (W1.0 restores 0001 from alice), 0011..0020 to bob."""
    return tenant.ALICE_UPN if number <= 10 else tenant.BOB_UPN


def canary_mails() -> tuple[CanaryMail, ...]:
    return tuple(
        CanaryMail(
            number=n,
            subject=f"RP-CANARY-{n:04d}",
            sentence=MAIL_SENTENCES[n - 1],
            sender=tenant.ADMIN_UPN,
            recipient=mail_recipient(n),
        )
        for n in range(1, MAIL_COUNT + 1)
    )


def canary_files() -> tuple[CanaryFile, ...]:
    """01..10 go to the SharePoint RestoreTest library (uploaded by the admin, who owns
    the site), 11..20 to alice's OneDrive RestoreTest folder (uploaded by alice: delegated
    Graph only reaches the signed-in user's own OneDrive)."""
    files = []
    for n in range(1, FILE_COUNT + 1):
        file_type = FILE_TYPE_CYCLE[(n - 1) % len(FILE_TYPE_CYCLE)]
        sentence = (
            f"Canary file rp-canary-{n:02d} ({file_type}) holds this fixed text "
            "for the RestoreProof restore tests."
        )
        if n <= 10:
            location = dict(
                kind="sharepoint_file",
                uploader=tenant.ADMIN_UPN,
                drive_id=tenant.SHAREPOINT_DRIVE_ID,
                folder_id=tenant.SHAREPOINT_FOLDER_ID,
                folder_path=tenant.SHAREPOINT_FOLDER_PATH,
            )
        else:
            location = dict(
                kind="onedrive_file",
                uploader=tenant.ALICE_UPN,
                drive_id=tenant.ONEDRIVE_DRIVE_ID,
                folder_id=tenant.ONEDRIVE_FOLDER_ID,
                folder_path=tenant.ONEDRIVE_FOLDER_PATH,
            )
        files.append(
            CanaryFile(
                number=n,
                name=f"rp-canary-{n:02d}.{file_type}",
                file_type=file_type,
                sentence=sentence,
                **location,
            )
        )
    return tuple(files)
