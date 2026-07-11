# Zero Standing Privilege Gateway for Azure

![ZSP Gateway Architecture](https://nineliveszerotrust.com/images/blog/zsp-azure/zsp-gateway-architecture.svg)

> **Companion repo for the blog post: [Just-In-Time Access for AI Agents: Building a ZSP Gateway in Azure](https://nineliveszerotrust.com/blog/zero-standing-privilege-azure/)**

A serverless gateway that grants time-bounded Azure permissions to AI agents, automation workflows, and service principals. Implements the **Zero Standing Privilege** pattern - identities start with zero permissions and receive temporary access on demand.

## Verification status

- **Last reviewed:** 2026-07-10
- **Scope:** 58 Python safety/flow tests, Python compilation, PowerShell parser/contract checks, Bicep build, dependency installation checks, secret scan, and website/companion comparison.
- **Status:** Locally verified and synchronized with the reviewed on-site lab implementation.
- **Limitation:** No Azure or Entra resources were created during this review. Live deployment, Durable Entity storage behavior, licenses, quotas, and Graph/RBAC consent must be validated in a disposable tenant/subscription. The ownership entity serializes gateway requests; privileged ZSP groups must not be modified manually during an active lifecycle because Microsoft Graph group memberships do not expose a per-membership ownership token.

## The Problem

Modern Azure environments contain 50-100 non-human identities (NHIs) per human user. Most have standing access they use for only minutes per day:

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
- Serializes each human user/group membership through a Durable Entity owner so concurrent lifecycles cannot adopt or revoke one another's grant
- Schedules automatic revocation via Durable Functions timers
- Records lifecycle state in Durable Functions and attempts best-effort custom audit rows in Log Analytics

---

## Use Cases

| Identity Type | Example | Access Pattern |
|--------------|---------|----------------|
| **AI Coding Agent** | Claude, Copilot | Explicitly approved scoped role for a deployment |
| **Backup Automation** | Nightly backup SP | 10-min Key Vault Secrets User during backup window |
| **Security Scanner** | Scheduled vulnerability scan | 60-min Reader access every 6 hours |
| **Human Admin** | IT administrator | 15-min Intune Admin via Entra group membership |
| **CI/CD Pipeline** | GitHub Actions | Scoped access only during deployment |

---

## Prerequisites

- Azure subscription with Owner access
- Azure CLI configured (`az login`)
- PowerShell 7+ (`pwsh`)
- Entra ID P1 or P2 license (for group-based role assignment)
- **Privileged Role Administrator** directory role (required to create role-assignable security groups)

Expect usage-based Function, Storage, Application Insights, and Log Analytics charges. Function keys are appropriate only for this isolated lab; use Entra authentication, caller authorization, approvals, and narrower RBAC in production.

---

## Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/j-dahl7/zsp-azure-lab.git
cd zsp-azure-lab
```

### 2. Deploy

```powershell
./scripts/Deploy-Lab.ps1
```

Or with custom settings:

```powershell
./scripts/Deploy-Lab.ps1 -ProjectName "my-zsp" -Location "westus2"
```

The script will:
1. Deploy Azure resources via Bicep (Resource Group, Key Vault, Storage, Function App, Log Analytics, DCE)
2. Create Entra ID objects (ZSP groups, directory role assignments, backup SP)
3. Create the `ZSPAudit_CL` custom table and Data Collection Rule
4. Grant Graph API permissions and RBAC roles to the Function App managed identity
5. Deploy Function code and run smoke tests

The first deployment prints all four immutable Entra object IDs and a safe rerun command. Preserve it. Reruns refuse to adopt same-name groups/apps by display name alone, require the complete expected-ID set, and fail if either privileged ZSP group has direct members.

### 3. Test NHI Access

Request temporary Key Vault access for a service principal:

```bash
NHI_RESPONSE="$(curl --fail --silent --show-error -X POST "$FUNCTION_URL/api/nhi-access" \
  -H "Content-Type: application/json" \
  -H "x-functions-key: $FUNCTION_KEY" \
  -d '{
    "sp_object_id": "BACKUP_SP_OBJECT_ID",
    "scope": "/subscriptions/.../providers/Microsoft.KeyVault/vaults/zsp-lab-kv-XXXXXX",
    "role": "Key Vault Secrets User",
    "duration_minutes": 10,
    "workflow_id": "manual-test"
  }')"

STATUS_URL="$(echo "$NHI_RESPONSE" | jq -r '.statusQueryGetUri')"
```

The endpoint returns HTTP 202 with a Durable Functions management payload. That means the lifecycle was accepted, not that privilege is active. Poll until `customStatus.status` is `active`:

```bash
while true; do
  STATUS="$(curl --fail --silent --show-error "$STATUS_URL")"
  echo "$STATUS" | jq '{runtimeStatus, customStatus}'
  [ "$(echo "$STATUS" | jq -r '.customStatus.status // empty')" = "active" ] && break
  [ "$(echo "$STATUS" | jq -r '.runtimeStatus')" = "Failed" ] && exit 1
  sleep 2
done
```

Example management response (URLs abbreviated):
```json
{
  "id": "b10a200905204d0bb10d54fc4e1a73e0",
  "statusQueryGetUri": "https://.../runtime/webhooks/durabletask/instances/..."
}
```

Only use the role after the active status appears. The lifecycle then revokes its own entitlement after the requested duration; a failed or terminated orchestration must not be treated as access.

---

## Architecture

**Components:**

- **ZSP Function Gateway** - Azure Function App with two endpoints:
  - `/api/nhi-access` - Grants RBAC role assignments to service principals
  - `/api/admin-access` - Grants Entra group membership to human admins
- **Durable Functions** - Schedules and executes automatic revocation
- **Log Analytics** - Custom `ZSPAudit_CL` table for audit trail
- **Data Collection Endpoint/Rule** - Ingests audit events from the Function

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
│   └── Test-Lab.ps1          # Smoke tests
└── function/
    ├── function_app.py       # Main function handlers
    ├── access_safety.py      # Validation and deterministic lifecycle helpers
    ├── nhi_access.py         # NHI ZSP logic
    ├── admin_access.py       # Human ZSP logic
    ├── audit.py              # Logging utilities
    ├── requirements.txt
    ├── tests/                # Safety, entitlement, orchestration, and deployment tests
    └── host.json
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

These are the default HTTP allowlist roles. Additional roles/scopes/workflow IDs must be explicitly configured and should remain least-privileged.

---

## Cleanup

```bash
# Delete Azure resources
az group delete --name zsp-lab-rg --yes

# Delete Entra ID objects
az ad group delete --group "<intune-group-object-id>"
az ad group delete --group "<security-reader-group-object-id>"
az ad app delete --id "<backup-application-object-id>"
```

---

## Resources

- [Blog: Just-In-Time Access for AI Agents](https://nineliveszerotrust.com/blog/zero-standing-privilege-azure/)
- [Lab Guide with KQL Queries](https://nineliveszerotrust.com/labs/zsp-azure/)
- [Full Lab (nine-lives-security)](https://github.com/nine-lives-security/nine-lives-zero-trust/tree/main/labs/zsp-azure)
- [Microsoft Graph PIM APIs](https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-apis)
- [Azure Durable Functions](https://learn.microsoft.com/en-us/azure/azure-functions/durable/durable-functions-overview)

---

## License

MIT License - See [LICENSE](LICENSE) for details.
