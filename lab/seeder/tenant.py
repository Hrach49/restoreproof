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
# not a secret. --client-id or RP_LAB_CLIENT_ID override it.
SEEDER_CLIENT_ID = "153b6fd7-36c1-41bf-9e90-238326ba2364"

# ---- The Worker's restore targets and the RestoreProof Worker app (L1.5) -----------------
# check-worker-app probes these with the Worker app's own app-only token.

RESTORETEST_UPN = "restoretest@RestoreProofLab.onmicrosoft.com"
SHAREPOINT_HOST = "restoreprooflab.sharepoint.com"
ONEDRIVE_HOST = "restoreprooflab-my.sharepoint.com"
# alice's OneDrive as a site: /personal/<UPN with "@" and "." as "_">.
ALICE_ONEDRIVE_SITE_PATH = "/personal/alice_restoreprooflab_onmicrosoft_com"
RESTORE_TARGET_LIST_ID = "29dfd30b-9223-49fc-ab87-a205a757f896"
RESTORE_TARGET_DRIVE_ID = "b!XQgI_nDr6EKVpkcBib2Y65nzyk4OzJVNs_7NCRoJ5okL098pI5L8SauHogWnV_iW"
ONEDRIVE_TARGET_FOLDER_ID = "01ZK75LGEIWSMV5NCPERHJYGWANJI7YUFB"

# "RestoreProof Worker" app registration (lab/entra/new-worker-app.ps1, lab/tenant.md).
# --client-id or RP_LAB_WORKER_CLIENT_ID override it. Not a secret.
WORKER_CLIENT_ID = "de8d4348-08a9-48ee-a04a-47c7189c5006"
