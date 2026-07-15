# Permissions

CAPVisualizer is designed around **least privilege** and is strictly
**read-only**. It never writes to your tenant.

## Core (always required)

| Capability | Microsoft Graph scope | Type | Notes |
|------------|-----------------------|------|-------|
| Read Conditional Access policies, named locations, authentication strengths, authentication context | `Policy.Read.All` | Delegated **or** Application | Read-only. This is the only scope needed for export, reports, visualization, and delta. |

## Name resolution (on by default)

By default the tool resolves object **GUIDs** to display names for
users/groups/roles/apps. This requires an additional read-only directory scope,
so the interactive default requests **`Policy.Read.All` + `Directory.Read.All`**:

| Capability | Microsoft Graph scope | Type |
|------------|-----------------------|------|
| Resolve users/groups (`directoryObjects/getByIds`), roles (`directoryRoleTemplates`), and apps (`servicePrincipals` by appId) to display names | `Directory.Read.All` | Delegated **or** Application |

`Directory.Read.All` can be replaced by the narrower set
`User.Read.All` + `Group.Read.All` + `Application.Read.All` +
`RoleManagement.Read.Directory` if your organization prefers minimal scopes.

To keep the **minimal `Policy.Read.All`-only** footprint (output then shows
GUIDs), pass **`-SkipResolveNames`**.

## Directory enrichment (on by default)

To power the analysis engines (per-user scope resolution, risk-scored findings,
contradiction and compliance checks), the tool also collects read-only directory
context: groups and their protection state, directory-role assignments, users
and account/sign-in state, and per-user MFA capability. Each dataset is
collected **best-effort** and independently - if a scope is missing, that dataset
is marked unavailable and the dependent checks report "insufficient data" instead
of failing the run.

| Capability | Microsoft Graph scope | Type |
|------------|-----------------------|------|
| Groups + protection state (`groups`, `groups/{id}/owners`) | `Group.Read.All` (or `Directory.Read.All`) | Delegated **or** Application |
| Directory-role assignments (active + PIM-eligible) | `RoleManagement.Read.Directory` (or `Directory.Read.All`) | Delegated **or** Application |
| Users + account state | `User.Read.All` (or `Directory.Read.All`) | Delegated **or** Application |
| Last sign-in activity (`signInActivity`) | `AuditLog.Read.All` | Delegated **or** Application |
| Per-user MFA capability (`reports/authenticationMethods/userRegistrationDetails`) | `AuditLog.Read.All` + `UserAuthenticationMethod.Read.All` (or `Reports.Read.All`) | Delegated **or** Application |

This same aggregate registration report powers the **Auth methods** audit tab
(MFA / passwordless / phishing-resistant / SSPR rollup, gaps, and per-user
table). No additional scope is needed: the tool only reads the aggregate
`userRegistrationDetails` report and never calls the per-user
`/users/{id}/authentication/methods` endpoint, so it never sees actual method
secrets such as phone numbers or security-key names. See
[AUTHMETHODS.md](AUTHMETHODS.md).

The collected enrichment is embedded in `raw/export.json`, so a later
`-FromJson` render (and all analysis engines) run **fully offline** against the
snapshot with no further permissions.

To keep the tool **policy-only** (no directory enrichment), pass
**`-SkipDirectory`**. Note that scope, findings, contradiction, and compliance
checks that rely on directory data will then be limited or unavailable.

## Delegated (interactive) vs Application (unattended)

- **Interactive / delegated** (default): you sign in as yourself. The effective
  permission is the intersection of the consented delegated scope and your
  directory role. A **Security Reader** (or higher) with `Policy.Read.All`
  consented is sufficient. Nothing runs unattended.
- **Application** (app registration with certificate or secret): required for
  **unattended, scheduled** runs. Grant the app the **application** permission
  `Policy.Read.All` (and optionally `Directory.Read.All`) and admin-consent it.
  Prefer a **certificate** over a client secret.

## Directory roles that can read CA policies (interactive)

Any of the following built-in roles can read Conditional Access policies:
**Global Reader**, **Security Reader**, **Security Administrator**,
**Conditional Access Administrator**, **Global Administrator**. Prefer the
least-privileged that fits (Global Reader / Security Reader).

## Why am I prompted to sign in twice?

**On the first run you may see two sign-in prompts. This is expected and
read-only.** The Quickstart is two separate scripts, each running in its own
process and signing in independently:

1. `Test-Prerequisites.ps1` signs in with just `Policy.Read.All` to verify Graph
   connectivity.
2. `Invoke-CapVisualizer.ps1` runs in a fresh process and signs in again. The
   token from step 1 is not shared across processes, so it cannot be reused.

The second prompt may also show a **consent** screen, because the actual run
requests the additional read-only scopes it needs for name resolution and
enrichment (for example `Directory.Read.All`, and with MFA/risk enrichment also
`Group.Read.All`, `User.Read.All`, `RoleManagement.Read.Directory`,
`AuditLog.Read.All`, `UserAuthenticationMethod.Read.All`) that were not consented
during the prerequisites check.

**To get a single sign-in**, skip the prerequisites check and run
`Invoke-CapVisualizer.ps1` directly. Subsequent runs are quieter once the token
is cached and consent has been granted. None of these scopes are write scopes.

## What CAPVisualizer never requests

No write scopes are ever requested (`Policy.ReadWrite.ConditionalAccess`,
directory write scopes, etc. are **not** used). If you are prompted to consent
to anything beyond the read scopes listed above, stop and review.
