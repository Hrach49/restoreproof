"""Test tenant IDs, copied from lab/tenant.md (a test keeps the two in step). IDs only."""

TENANT_DOMAIN = "RestoreProofLab.onmicrosoft.com"
TENANT_ID = "bcd6bd1a-ea42-489d-aa28-2c19a44ad146"

ADMIN_UPN = "HrachyaHarutyunyan@RestoreProofLab.onmicrosoft.com"
ALICE_UPN = "alice@RestoreProofLab.onmicrosoft.com"
BOB_UPN = "bob@RestoreProofLab.onmicrosoft.com"

SHAREPOINT_SITE_ID = (
    "restoreprooflab.sharepoint.com,fe08085d-eb70-42e8-95a6-470189bd98eb,"
    "4ecaf399-cc0e-4d95-b3fe-cd091a09e689"
)
SHAREPOINT_LIST_ID = "7eb0f08a-f57b-418c-8ca6-f2ab81297666"
SHAREPOINT_DRIVE_ID = "b!XQgI_nDr6EKVpkcBib2Y65nzyk4OzJVNs_7NCRoJ5omK8LB-e_WMQYym8quBKXZm"
# Files go in the library's root folder; Graph addresses it as "root".
SHAREPOINT_FOLDER_ID = "root"
SHAREPOINT_FOLDER_PATH = "/"

ONEDRIVE_DRIVE_ID = "b!wA9gbfhlEUitGAluxbfoNBr_z5gEtDhErm5pJ6bMwyXfZJ8a_dkCQ696RX0r7_U3"
ONEDRIVE_FOLDER_ID = "01ZK75LGF7FPAIWTU5MFGIMX6YUFEV7ZC4"
ONEDRIVE_FOLDER_PATH = "/RestoreTest"

# "RestoreProof Lab Seeder" public-client app registration (lab/README.md). A client ID is
# not a secret. Empty until the app exists; --client-id or RP_LAB_CLIENT_ID override it.
SEEDER_CLIENT_ID = ""
