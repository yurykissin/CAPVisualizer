# Permissions

CAPVisualizer is designed around **least privilege** and is strictly
**read-only**. It never writes to your tenant.

## Core (always required)

| Capability | Microsoft Graph scope | Type | Notes |
|------------|-----------------------|------|-------|
| Read Conditional Access policies, named locations, authentication strengths, authentication context | `Policy.Read.All` | Delegated **or** Application | Read-only. This is the only scope needed for export, reports, visualization, and delta. |

## Optional: friendly-name resolution (`-ResolveNames`)

By default the tool shows object **GUIDs** for users/groups/roles/apps. If you
add `-ResolveNames`, it resolves those GUIDs to display names, which requires an
additional read-only directory scope:

| Capability | Microsoft Graph scope | Type |
|------------|-----------------------|------|
| Resolve directory object display names (`directoryObjects/getByIds`) | `Directory.Read.All` | Delegated **or** Application |

`Directory.Read.All` can be replaced by the narrower set
`User.Read.All` + `Group.Read.All` + `Application.Read.All` +
`RoleManagement.Read.Directory` if your organization prefers minimal scopes.
Name resolution is **off by default** so the baseline footprint stays at
`Policy.Read.All`.

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

## What CAPVisualizer never requests

No write scopes are ever requested (`Policy.ReadWrite.ConditionalAccess`,
directory write scopes, etc. are **not** used). If you are prompted to consent
to anything beyond the read scopes listed above, stop and review.
