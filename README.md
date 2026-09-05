# Zero Standing Privilege Gateway for Azure

![ZSP Gateway Architecture](https://nineliveszerotrust.com/images/blog/zsp-azure/zsp-gateway-architecture.svg)

> **Companion repo for the blog post: [Just-In-Time Access for AI Agents: Building a ZSP Gateway in Azure](https://nineliveszerotrust.com/blog/zero-standing-privilege-azure/)**

A serverless gateway that grants time-bounded Azure permissions to AI agents, automation workflows, and service principals. Implements the **Zero Standing Privilege** pattern - identities start with zero permissions and receive temporary access on demand.

## Validation Boundary

This revision is validated with offline Python unit/contract tests, real SDK
registration and mocked transport checks, PowerShell regressions, and Bicep
compilation. It has not been freshly deployed to an Azure/Entra tenant, and no
live role grant, group
membership, Durable Functions lifecycle, audit ingestion, or cleanup was run
for this revision. Treat the smoke test and API responses as runtime checks
that must pass in your own tenant.

## Lifecycle v2 Migration — Required Before Deployment

This release retires the registered `access_lifecycle_orchestrator` and
`revocation_orchestrator` handlers and starts only
`access_lifecycle_orchestrator_v2`. **In-flight legacy histories and timers
cannot replay their retired handlers after the new code is deployed.** Do not
publish this code over a running legacy task hub and assume cleanup will run.

For an existing app, the operator must first:

1. Restrict client admission and disable the backup timer through the approved
   operational change process while leaving the old workers running for drain.
   Inventory every legacy instance and its exact group membership/RBAC assignment
   in the correct task hub; include Pending, Running, Suspended, failed, and
   terminated histories and the standing-privilege audit hunt below.
2. Let authorized legacy workflows finish with the old code. Verify successful
   revocation against the actual exact entitlement IDs in Azure/Graph; elapsed
   duration or terminal orchestration status alone is insufficient. Reconcile
   any stranded grants using the ownership recovery runbook. Do not terminate
   or purge a workflow as a substitute for removing its owned entitlement.
3. Rotate any Durable extension system key previously exposed in a management
   response before reopening admission, and verify the old key no longer
   authenticates. Rotation is an operator security change, not performed by
   these scripts. Restrict access during this work. The source fix cannot
   invalidate already issued keys or management URLs. An extension key holder
   can still invoke Durable APIs or terminate even a v2 workflow.
4. Record the inventory, exact cleanup evidence, and key-rotation result. Then
   deploy the new code and use the updated smoke test to verify admission,
   authenticated status polling, and exact revocation. Retain old evidence.

Microsoft documents that [Durable HTTP APIs use an extension system key](https://learn.microsoft.com/en-us/azure/durable-task/durable-functions/durable-functions-http-api)
with broad management access. This is why management URLs must stay with
operators and previously exposed keys must be rotated.

A fresh isolated app/task hub has no legacy histories to drain, but that fact
must be verified. `-ConfirmLifecycleMigration` is an acknowledgement of this
operator work, **not evidence or an automatic check that it happened**. The
script refuses all changes until it is supplied, including settings changes
when `-SkipFunctionDeploy` is used. Direct Core Tools/zip publishing bypasses
this script guard and still requires the same migration process.

The new orchestration records policy admission in Durable history before any
privilege operation. Preflight and grant activities also recheck current
allowlists, supported roles, workflows, and duration. Revocation retains its
exact ownership checks and does not require that the old grant is still in
current admission policy. Host availability, storage history, permissions,
manual interference, and ownership conflicts can still prevent cleanup;
monitor and verify it rather than promising unconditional removal.

Credential destinations are restricted to public Azure. `Test-Lab.ps1` now
requires `-FunctionAppResourceId` and the original deployment manifest (default
`.zsp-deployment.json`); it verifies the active account, live ownership tags,
and exact ARM `defaultHostName` before sending a Function key. A supplied custom
hostname or another app's Azure hostname is refused. `Configure-Function.ps1`
now requires `-DceResourceId` and verifies the endpoint against that exact DCE
in the active subscription/resource group. Runtime audit ingestion accepts only
Azure Monitor ingestion origins and immutable `dcr-` IDs, and the SDK cannot
follow redirects with its managed-identity token. Sovereign/custom endpoints
require an explicitly reviewed implementation change.

## The Problem

Modern Azure environments can accumulate many non-human identities (NHIs),
often with standing access they use only briefly:

- A backup service principal with 24/7 Key Vault access for a 5-minute nightly job
- A CI/CD pipeline with permanent Contributor rights for occasional deployments
- An AI coding assistant with broad permissions "just in case"

Standing privileges create unnecessary attack surface. If a service principal is compromised, attackers inherit all its permissions immediately.

## The Solution

A centralized gateway that grants temporary, scoped access:

```
Access Request → ZSP Gateway → RBAC Assignment (time-bounded)
                     │
                     ├── Durable Functions (scheduled revocation)
                     └── Log Analytics (audit trail)
```

The gateway:
- Validates requests and creates scoped Azure RBAC role assignments
- Schedules automatic revocation via Durable Functions timers
- Logs all grants/revocations to Log Analytics with workflow IDs

---

## What This Does Not Eliminate

The gateway itself holds standing, tenant-wide `RoleManagement.ReadWrite.Directory`.
That is not an oversight, and it is worth being direct about it in a lab whose whole
subject is removing standing privilege.

**Why it cannot be removed.** Microsoft Graph requires `RoleManagement.ReadWrite.Directory`
to change the membership of a role-assignable group. The narrower
`GroupMember.ReadWrite.All` is not sufficient for those groups. Since group-based
elevation is how the gateway grants Entra roles, the permission is a hard requirement.

**What it actually confers.** This permission can assign *any* directory role,
including Global Administrator. It is not scoped to the roles this lab manages.

**So what the lab really does.** It moves standing privilege off *people* and into
*one audited workload*. That is a genuine improvement — a single identity with
logging, alerting, and a controlled deployment surface is easier to monitor than a
dozen humans with permanent role assignments — but it is a relocation, not an
elimination. **Treat the Function App as a Tier 0 asset.** Anyone who can deploy code
to it, or steal its managed identity token, holds Global Administrator.

**Production alternatives.** [PIM for Groups](https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/concept-pim-for-groups)
and [Entra Entitlement Management](https://learn.microsoft.com/en-us/entra/id-governance/entitlement-management-overview)
deliver the same just-in-time group membership without granting this permission to a
workload you operate yourself. If you are solving this problem for real rather than
learning how it works, start there.

---

## Use Cases

| Identity Type | Example | Access Pattern |
|--------------|---------|----------------|
| **AI Coding Agent** | Coding assistant | 30-min Reader access to an approved lab scope |
| **Backup Automation** | Nightly backup SP | 10-min Key Vault Secrets User during backup window |
| **Security Scanner** | Scheduled vulnerability scan | 60-min Reader access every 6 hours |
| **Human Admin** | IT administrator | 15-min Intune Admin via Entra group membership |
| **CI/CD Pipeline** | GitHub Actions | Scoped Storage Blob Data Contributor access during a backup workflow |

---

## Prerequisites

- Azure subscription with Owner access
- Azure CLI configured (`az login`)
- PowerShell 7+ (`pwsh`)
- Entra ID P1 or P2 license (for group-based role assignment)
- **Privileged Role Administrator** directory role (required to create role-assignable security groups)
- Permission to create applications/service principals, grant the documented
  Microsoft Graph application permissions with admin consent, activate/assign
  the two directory roles, and create Azure role assignments
- Log Analytics Contributor and Monitoring Contributor capabilities used for
  the custom table/DCR, whether supplied directly or through a broader lab role

Use a dedicated lab tenant/subscription. The deployment creates privileged
role-assignable groups, an app/service principal, directory-role assignments,
Graph app-role grants for the Function managed identity, Azure RBAC
assignments, a Key Vault, Storage, Function resources, and Log Analytics
resources. These are tenant/shared security and billing changes, not an
isolated local simulation.

---

## Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/j-dahl7/zsp-azure-lab.git
cd zsp-azure-lab
```

### 2. Deploy

```powershell
./scripts/Deploy-Lab.ps1 -ConfirmLifecycleMigration -ProjectName "zsp-lab" -Location "eastus" -MaxAccessDurationMinutes 480
```

Or with custom settings:

```powershell
./scripts/Deploy-Lab.ps1 -ConfirmLifecycleMigration -ProjectName "my-zsp" -Location "westus2"
```

The script:

1. Deploys Azure resources via Bicep (Resource Group, Key Vault, Storage, Function App, Log Analytics, DCE)
2. Creates Entra ID objects (ZSP groups, directory role assignments, backup SP)
3. Creates the `ZSPAudit_CL` custom table and Data Collection Rule
4. Grants Graph API permissions and RBAC roles to the Function App managed identity
5. Configures the Function App through `Configure-Function.ps1`
6. Deploys Function code
7. Runs an exact-ID smoke test and waits for the temporary role assignment to
   reach the Durable `revoked` state and disappear from Azure RBAC

`Deploy-Lab.ps1` has no `-WhatIf` mode. Running it performs live Azure,
Microsoft Graph, Entra directory-role, RBAC, Function deployment, and test
operations. Inspect the active subscription/tenant and every parameter before
execution.

Current deployment parameters are `-ProjectName`, `-Location`,
`-MaxAccessDurationMinutes` (5–1440; default 480),
`-SkipFunctionDeploy`, `-SkipTest`, `-ManifestPath`, and the four optional
explicit identity assertions:
`-ExpectedIntuneAdminGroupId`, `-ExpectedSecurityReaderGroupId`,
`-ExpectedBackupAppObjectId`, and `-ExpectedBackupSpObjectId`.

`-SkipTest` is an explicit acceptance of an unvalidated deployment. That path
records manifest state `deployed_unvalidated` and prints **Deployment Finished
- Smoke Test Skipped**, never **Deployment Complete**. A missing Function key,
failed Function publish, failed health check, wrong/missing role assignment,
Durable failure, revocation timeout, or failed exact-ID RBAC lookup terminates
deployment without recording `validated` or printing a completion banner.

### Safe Reruns and Object Ownership

Before its first Azure mutation, deployment writes a version-2
`.zsp-deployment.json` at the repository root in `planned` state. The manifest
binds the active tenant and subscription, project, location, exact expected
resource-group ID, stable Azure owner marker, and a unique deployment UUID. The
Bicep deployment writes the same owner marker and UUID to exact `nlzt-owner`
and `nlzt-deployment` resource-group tags. Caller-provided tags cannot override
them, and deployment reads them back before continuing. External tag drift is
detected and refused.

An existing resource group is never adopted by name. Rerun succeeds only when
the manifest, exact live resource-group ID, active tenant/subscription, owner
tag, and deployment tag all agree. A same-named resource group without that
exact manifest and tags is refused before Bicep runs. Version-1 manifests and
older untagged resource groups are intentionally not auto-migrated.

Always enter through `scripts/Deploy-Lab.ps1` or `scripts/Deploy-Azure.ps1`.
Directly invoking `bicep/main.bicep` or `main.bicepparam` is unsupported because
an ARM resource-group upsert cannot perform the wrapper's local-manifest and
live-tag ownership preflight.

The manifest advances conservatively through `planned`, `azure_deployed`,
`identities_configured`, and either `deployed_unvalidated` or `validated`. An
interrupted Bicep deployment retains `planned` state and the same UUID so an
exact retry can finish without adopting foreign infrastructure. Later failures
do not claim a validated deployment.

After resolving Entra objects, the manifest also records immutable group,
application-object, service-principal, and application/client IDs plus their
tenant/project provenance marker. It contains no credentials and is
gitignored. Preserve it because exact-ID cleanup and safe reruns depend on it.

If any same-named Entra object already exists, the deployer refuses to adopt it
by display name. On a normal rerun, a manifest with the full identity set automatically
supplies all four immutable object IDs. You may also provide them explicitly;
any supplied value must match the manifest exactly. For a deliberate first
deployment that reuses already-owned, provenance-marked Entra objects, supply
all four IDs:

```powershell
./scripts/Deploy-Lab.ps1 -ConfirmLifecycleMigration -ProjectName "zsp-lab" `
  -ExpectedIntuneAdminGroupId "<group-object-id>" `
  -ExpectedSecurityReaderGroupId "<group-object-id>" `
  -ExpectedBackupAppObjectId "<application-object-id-not-client-id>" `
  -ExpectedBackupSpObjectId "<service-principal-object-id>"
```

The scripts verify provenance, exact names/IDs, application-to-service-
principal linkage, and that privileged groups have no active direct members
before reuse. Older unmarked objects are not auto-adopted.

### Immutable Function Dependencies

Azure Functions remote build reads `function/requirements.txt`, which enables
pip hash-checking and includes `function/pins.txt`. The pins file locks all 55
resolved Python 3.11 packages and their distribution hashes. CI installs the
same manifest with `--require-hashes` before tests. Edit direct requirements
only in `function/requirements.in`, then regenerate the pins with:

```bash
uv pip compile --python-version 3.11 --universal --generate-hashes \
  function/requirements.in -o function/pins.txt
```

The `.txt` extension lets Dependabot follow the nested pins file, while
`function/.python-version` keeps its resolver on the same Python 3.11 line as
Azure Functions and CI.

Function publishing excludes `local.settings.json`, virtual environments,
tests, caches, private-key files, and arbitrary working-directory content.
Core Tools follows `function/.funcignore`; the zip fallback builds an explicit
allowlist containing only reviewed runtime modules, `host.json`, and the two
dependency manifest files.

### Runtime dependency evidence

`function/requirements.txt` remains the hash-enforced entry point for the
resolved versions in `function/pins.txt`. The existing h2 pin is 4.4.1, which
includes the duplicate-Host-header fix; do not replace the entry point with an
unhashed package list to make dependency metadata appear current.

CI records the actual hash-verified pip installation, checks installed versions
and imports h2, then prepares a bounded dependency snapshot. After a successful
`main` push, a separate job uses GitHub's official dependency submission API to
refresh the `function/requirements.txt` graph from that evidence. Pull requests
only validate and prepare evidence; they cannot submit it. The validation job
has read-only permissions, and only the submission job receives `contents: write`.
See [GitHub dependency submission](https://docs.github.com/en/rest/dependency-graph/dependency-submission).

### 3. Test NHI Access

Request temporary Key Vault access for a service principal:

```bash
curl -X POST "$FUNCTION_URL/api/nhi-access" \
  -H "Content-Type: application/json" \
  -H "x-functions-key: $FUNCTION_KEY" \
  -d '{
    "sp_object_id": "BACKUP_SP_OBJECT_ID",
    "scope": "/subscriptions/.../providers/Microsoft.KeyVault/vaults/zsp-lab-kv-XXXXXX",
    "role": "Key Vault Secrets User",
    "duration_minutes": 10,
    "workflow_id": "manual-test"
  }'
```

The request is asynchronous. A successful admission returns HTTP `202` with a
restricted lifecycle polling response. Admission does not prove access already exists:

```json
{
  "id": "<orchestration-instance-id>",
  "statusQueryGetUri": "https://<function-app>.azurewebsites.net/api/access-status/<orchestration-instance-id>"
}
```

Validate that `statusQueryGetUri` is exactly the same verified Function origin
and `/api/access-status/{id}` path, with no query or fragment. Send the ordinary
Function key in `X-Functions-Key` for every poll, and do not follow redirects:

```bash
curl --max-redirs 0 "$STATUS_QUERY_GET_URI" -H "X-Functions-Key: $FUNCTION_KEY"
```

The key must authorize both the admission and status routes; the lab deployer
uses the host's default Function key. A key limited to another individual
Function may not authorize the status route. Never substitute a Durable
extension system key or a host master key. The response never includes a key,
Durable management URLs, raw orchestration input/output/history, or failure
details. Status includes a bounded phase, expiry, counts, and only assignment
IDs deterministically matching an admitted NHI request. It excludes admin user
and group details. `404` means the instance is unavailable; `403` also covers
legacy or now-disallowed instance context. Operators use their separate Azure
management access for investigation.

Poll `statusQueryGetUri` until `customStatus.status` is `active` and inspect the
returned grants/assignment IDs before using the access. `Pending` or `Running`
without that custom status is not a grant. `Failed`, `Terminated`,
`Canceled`, a timeout, or a missing assignment ID means the request did not
establish usable access. Continue polling/monitoring until revocation is
confirmed; do not assume that elapsed wall-clock time alone proves removal.

The access and status HTTP endpoints use a Function key, so the gateway authenticates possession
of that key rather than an individual requester identity. Protect and rotate
the key. Status access is scoped by the shared key and current resource policy,
not by an individual owner identity. Do not expose the endpoints publicly as a production authorization
service without a stronger caller-identity layer.

---

## Architecture

**Components:**

- **ZSP Function Gateway** - Azure Function App with two endpoints:
  - `/api/nhi-access` - Grants RBAC role assignments to service principals
  - `/api/admin-access` - Grants Entra group membership to human admins
- **Durable Functions** - Schedules and executes automatic revocation
- **Log Analytics** - Custom `ZSPAudit_CL` table for audit trail
- **Data Collection Endpoint/Rule** - Ingests audit events from the Function

Every new grant, revoke, and ownership-guard failure includes two exact
correlation fields:

- `LifecycleId` is the Durable orchestration instance ID.
- `EntitlementId` is the deterministic admin membership ownership key or the
  full deterministic Azure role-assignment resource ID.

`/api/health` is also a readiness signal for this audit dependency. Missing or
malformed `DCR_ENDPOINT`/`DCR_RULE_ID` settings return HTTP 503 with
`status: degraded`. Both request admission and each grant activity check the
same configuration before any privilege side effect, so a stale Durable
instance cannot bypass the gate after an app-setting change.

---

## File Structure

```
zsp-azure-lab/
├── README.md
├── bicep/
│   ├── main.bicep            # Main orchestrator
│   ├── main.bicepparam       # Parameter template
│   └── modules/
│       ├── core.bicep        # RG, Key Vault, Storage
│       ├── function.bicep    # Function App, Plan, Insights
│       └── monitoring.bicep  # Log Analytics, DCE
├── scripts/
│   ├── Deploy-Lab.ps1        # Main deployment script
│   ├── Deploy-Azure.ps1      # Bicep deployment
│   ├── Setup-EntraID.ps1     # Entra ID objects
│   ├── Grant-Permissions.ps1 # Graph API permissions
│   ├── Configure-Function.ps1# Function settings
│   ├── Test-Lab.ps1          # Smoke tests
│   └── Cleanup-Lab.ps1       # Exact-ID, provenance-checked cleanup
├── function/
│   ├── .funcignore           # Excludes local secrets and development files
│   ├── function_app.py       # Main function handlers
│   ├── nhi_access.py         # NHI ZSP logic
│   ├── admin_access.py       # Human ZSP logic
│   ├── audit.py              # Logging utilities
│   ├── .python-version       # Dependabot/pyenv Python 3.11 selection
│   ├── requirements.in       # Direct dependency constraints
│   ├── pins.txt              # Python 3.11 transitive pins + hashes
│   ├── requirements.txt      # Remote-build hash-lock entry point
│   └── host.json
└── .github/workflows/
    └── validate.yml         # SHA-pinned offline validation
```

---

## Supported Roles

| Role | Use Case |
|------|----------|
| Key Vault Secrets User | Read secrets during backup |
| Key Vault Reader | Read vault metadata |
| Storage Blob Data Reader | Read backup data |
| Storage Blob Data Contributor | Write backup data |
| Reader | Read-only access to resources |

These are the bundled defaults. Runtime configuration can further restrict the
allowed role names, service-principal IDs, scopes, workflows, and admin-group
IDs. Requests outside those allowlists are rejected.

---

## Admin Lifecycle Ownership and Recovery

A Durable Entity serializes ownership of each user/group membership. Only the
lifecycle that claimed that entity may revoke the membership it created.

If the entity confirms a different owner, the orchestrator sets
`customStatus.status` to `ownership_lost`. If the ownership lookup itself throws,
it sets `customStatus.status` to `ownership_unverified`. Both paths attempt a
correlated `Result == "Failed"` `AccessRevoke` row in `ZSPAudit_CL`, retain the
owner lock, and fail **without deleting the membership**. That refusal is
deliberate: Graph membership edges carry no owner token, so a blind delete could
remove a newer or independently managed entitlement. The cost is that temporary
privilege can remain live, so either state requires manual recovery.

Recovery runbook:

1. Stop issuing new requests for that user/group pair.
2. Correlate the Durable instance history, Entra ID audit logs, and current group
   membership to establish which lifecycle actually created the membership.
3. Remove the user manually **only after** that attribution is confirmed.
4. Once the entitlement is confirmed absent, repair or purge that owner entity.
   A task-hub reset or redeployment is the fallback in this disposable lab.
5. Verify the membership is gone, then resume normal operation.

Never clear the owner lock first, and never change privileged ZSP group
memberships manually while a lifecycle is active.

### Hunting for standing privilege

`build_kql_query_unrevoked_expired_grants()` in `function/audit.py` returns the
hunt for the failure this design can produce: a grant that is past its expiry
with no successful `AccessRevoke` for that exact `LifecycleId` and
`EntitlementId`. It never guesses using principal and target, because repeated
admin lifecycles and multiple NHI roles on one scope make that heuristic both
false-positive and false-negative prone.

```kusto
let grace = 15m;
let exact_grants =
    ZSPAudit_CL
    | where EventType == "AccessGrant" and Result == "Success"
    | where isnotempty(ExpiresAt)
    | extend Expiry = todatetime(ExpiresAt)
    | where Expiry < ago(grace)
    | where isnotempty(LifecycleId) and isnotempty(EntitlementId)
    | summarize
        GrantTime = min(TimeGenerated),
        LastExpiry = max(Expiry),
        PrincipalId = take_any(PrincipalId),
        Target = take_any(Target),
        Role = take_any(Role),
        IdentityType = take_any(IdentityType)
      by LifecycleId, EntitlementId;
let exact_revokes =
    ZSPAudit_CL
    | where EventType == "AccessRevoke" and Result == "Success"
    | where isnotempty(LifecycleId) and isnotempty(EntitlementId)
    | summarize RevokeTime = max(TimeGenerated) by LifecycleId, EntitlementId;
let exact_findings =
    exact_grants
    | join kind=leftanti exact_revokes on LifecycleId, EntitlementId
    | extend
        MinutesOverdue = datetime_diff('minute', now(), LastExpiry),
        CorrelationStatus = "Exact",
        Finding = "Expired lifecycle entitlement with no successful revoke";
let legacy_findings =
    ZSPAudit_CL
    | where EventType == "AccessGrant" and Result == "Success"
    | where isnotempty(ExpiresAt)
    | extend LastExpiry = todatetime(ExpiresAt)
    | where LastExpiry < ago(grace)
    | where isempty(LifecycleId) or isempty(EntitlementId)
    | project GrantTime = TimeGenerated, LastExpiry, PrincipalId, Target, Role,
              IdentityType, LifecycleId, EntitlementId
    | extend
        MinutesOverdue = datetime_diff('minute', now(), LastExpiry),
        CorrelationStatus = "LegacyUncorrelated",
        Finding = "Legacy expired grant lacks exact lifecycle correlation; review manually";
union exact_findings, legacy_findings
| order by MinutesOverdue desc
```

Recommended alert: a Sentinel scheduled analytics rule running this query every
15 minutes, severity High, with `CorrelationStatus == "Exact"` creating an
incident. Route `LegacyUncorrelated` rows to a separate manual-review queue; they
are intentionally not labeled as confirmed unrevoked grants because old rows do
not contain a safe join key. Pair this with alerts on
`customStatus.status in ("ownership_lost", "ownership_unverified")` and failed
audit rows whose `ErrorMessage` begins with either state name.

---

## Cleanup

Before cleanup, stop new requests, poll all Durable instances, revoke/verify
every active group membership and RBAC grant, and confirm the two privileged
groups have no direct members. Deleting the Function while revocation timers
are outstanding can strand privilege.

Preview exact-ID cleanup using the deployment-generated manifest:

```powershell
./scripts/Cleanup-Lab.ps1 -ConfirmProject "zsp-lab" -WhatIf
```

That preview performs read-only Azure/Graph lookups. Before the first possible
delete, it verifies the current tenant/subscription, exact project
confirmation, manifest state and consistency, the exact live resource-group ID
and both ownership tags, Entra provenance markers, exact display names and IDs,
group emptiness, and application/service-principal linkage. It does not delete
anything and never falls back to display-name discovery. If the recorded
resource group exists with missing or changed ownership tags, cleanup fails
before any Entra or Azure delete.

Remove the manifest-recorded Entra groups, application, and service principal:

```powershell
./scripts/Cleanup-Lab.ps1 -ConfirmProject "zsp-lab"
```

For full lab cleanup, also request deletion of the exact manifest-recorded
Azure resource group:

```powershell
./scripts/Cleanup-Lab.ps1 -ConfirmProject "zsp-lab" -DestroyAzureResources -WhatIf
./scripts/Cleanup-Lab.ps1 -ConfirmProject "zsp-lab" -DestroyAzureResources
```

`-DestroyAzureResources` is optional; without it, the exact owner-tagged Azure
resource group, Function managed identity, its Graph permissions, Azure RBAC
assignments, and manifest remain. With it, cleanup first verifies and deletes
only present exact-ID Entra objects, confirms those exact IDs are absent, and
then requests asynchronous deletion of the exact owner-tagged resource group.
Azure or Graph failures are not suppressed.

The manifest is never removed in the same run that starts asynchronous
resource-group deletion. Rerun cleanup after Azure reports the resource group
absent; already-absent exact Entra IDs are handled safely. Only when every
recorded object and the resource group are confirmed absent does cleanup remove
the manifest. This also makes a partial cleanup failure safely retryable.

Cleanup parameters are mandatory `-ConfirmProject`, optional `-ManifestPath`,
`-DestroyAzureResources`, and PowerShell's common `-WhatIf`. Never replace this
workflow with group/application deletion by display name.

---

## Resources

- [Blog: Just-In-Time Access for AI Agents](https://nineliveszerotrust.com/blog/zero-standing-privilege-azure/)
- [Lab Guide with KQL Queries](https://nineliveszerotrust.com/labs/zsp-azure/)
- [Microsoft Graph PIM APIs](https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-apis)
- [Azure Durable Functions](https://learn.microsoft.com/en-us/azure/azure-functions/durable/durable-functions-overview)

---

## License

MIT License - See [LICENSE](LICENSE) for details.
