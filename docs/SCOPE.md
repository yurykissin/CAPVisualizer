# Per-user scope resolution (`Get-CapUserScope.ps1`)

Answers "which Conditional Access policies actually target this principal?" fully
offline, from an enriched export.

A policy targets a principal when the principal is **included** (directly, or via
a group or directory role the policy names) **and not excluded**. Exclusion always
wins. This engine expands the principal to its user id + transitive group
memberships + role assignments (from the embedded directory enrichment) and
evaluates every policy against that context.

## How it works

1. **Principal context** - `Resolve-CapPrincipalContext` builds
   `{ id, displayName, isGuest, groupIds[], roleTemplateIds[] }` from
   `enrichment.groups` (transitive members), `enrichment.roleAssignments`, and
   `enrichment.users`. Missing enrichment degrades gracefully with warnings.
2. **Per-policy bucket** - each policy is classified:
   - `InScopeDirect` - the user id is directly included.
   - `InScopeVia` - included through a named group or role (the group/role is
     named in the result).
   - `Excluded` - excluded directly or via a group/role (the excluder is named).
   - `NotInScope` - not targeted.

## Usage

```powershell
./scripts/Get-CapUserScope.ps1 `
    -FromJson ./samples/sample-export-enriched.json `
    -PrincipalId 22222222-2222-2222-2222-222222222222
```

Only groups and roles **referenced by policies** need transitive expansion, so
the enrichment cost is bounded regardless of tenant size.

## Independence

Authored independently against the public Entra Conditional Access assignment
model. No third-party tool code or logic is reused.
