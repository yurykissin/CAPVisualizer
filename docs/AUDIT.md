# Contradiction & misconfiguration audit (CapAudit)

Static logical checks over the normalized policy set that surface self-defeating
configuration - the kind that looks correct in the portal but silently protects
nothing. Runs automatically as part of `Invoke-CapVisualizer.ps1`
(`analysis/audit.json`) and feeds the risk-scored findings.

## Checks

- **App include/exclude overlap** - an application named in a policy's include
  list is cancelled by an exclusion (directly, or because an excluded app
  *grouping* such as `Office365` expands to include it). The policy silently does
  not cover that app.
- **Platform include/exclude overlap** - a platform is both included and
  excluded; the exclusion wins and the platform is uncovered.
- **Principal include/exclude overlap** - a user, group, or role appears in both
  the include and exclude lists; the inclusion is a no-op for them.
- **Legacy authentication coverage** - a tenant-level check that at least one
  enabled policy broadly blocks legacy authentication clients
  (exchangeActiveSync / other) for all users and apps.
- **Exemption exposure** - the union of every user/group/role excluded across all
  enforced policies, as a "who is exempt from what" view, plus explicit findings
  when a **privileged** account is excluded directly or via an excluded group from
  a broad protective policy (using the directory role enrichment and the
  independently authored CISA privileged-role reference pack).

## Output

`Invoke-CapAudit` returns `{ issues[], exemptionExposure[], summary }`. Each issue
carries `checkId`, `severity`, `category`, `title`, `detail`, `policyId/Name`, and
`evidence`. Issues are promoted into the risk-scored findings model (see
[FINDINGS.md](FINDINGS.md)) and rendered on the viewer's **Contradictions** tab.

## Independence

Authored independently against the public Entra Conditional Access evaluation
model and the public CISA highly-privileged role list. No third-party tool code
or logic is reused.
