# Rationalization & consolidation (CapConsolidate)

Cross-policy analysis that answers "how many of these policies do we actually
need?" It compares every Conditional Access policy against every other one to
find duplicates, same-effect overlaps, safe merge candidates, dead weight and
missing baseline controls, then estimates a before -> after policy count. Runs
automatically as part of `Invoke-CapVisualizer.ps1` (`analysis/consolidation.json`)
and is also available standalone via `scripts/Invoke-CapConsolidate.ps1`.

Where [CapAudit](AUDIT.md) looks *inside* a single policy for self-defeating
configuration, CapConsolidate looks *across* the estate for redundancy and gaps.

## How comparison works - the fingerprint

Each policy is reduced to a four-part fingerprint so that functionally identical
policies collapse to the same key regardless of GUID, name or list ordering:

- **controlSig** - the effect: block, or the exact grant (controls, operator,
  authentication strength, MFA/compliant/hybrid requirements) plus whether a
  session control is present.
- **appSig** - the application target: All apps, or the sorted include app IDs +
  groupings + user actions + auth contexts, or the excluded apps.
- **targetSig** - the principal target: sorted include/exclude users, groups and
  roles.
- **condSig** - the remaining conditions: platforms, client apps, locations,
  risk levels, authentication flows and device filter.

`key = controlSig ## appSig ## targetSig ## condSig`. List values are sorted
before hashing, so two policies that differ only in the order of excluded groups
produce the same fingerprint.

## Clusters

- **Exact duplicates** (`duplicates.exact`) - identical `key`, in *any* state.
  These are true copies; keep one, retire the rest.
- **Overlap** (`duplicates.overlap`) - enforced policies with the same
  `controlSig` **and** `appSig`. Flagged `identical` when target and conditions
  also match (a genuine duplicate) versus `differsByTargetOrConditions` when they
  do not - the latter are **distinct controls** on the same apps and must be
  reviewed, not blindly merged.
- **Merge candidates** (`duplicates.merge`) - enforced policies with the same
  control, target and conditions that differ only by application. These can be
  combined into one policy with a merged application list.

> Guardrail: same effect + same app but *different conditions* is treated as two
> deliberate controls, never as a duplicate. The engine surfaces overlaps for a
> human to decide; it never asserts an automatic merge across differing
> conditions.

## Dead weight

`deadWeight[]` lists policies that enforce nothing today, with reasons:

- disabled (enforces nothing),
- report-only (telemetry only, not enforced),
- name signals a test/temporary/retire policy (`test`, `check`, `deprecated`,
  `old`, `do not use`, `delete`, `temp`, `poc`, `demo`, ...).

## Baseline completeness

`completeness[]` scans the estate for best-practice controls that *should* exist
and reports each as present/missing with a severity and a concrete
recommendation. A report-only-only implementation counts as **not enforced**.
Controls checked:

- Block device-code flow (high)
- Control authentication transfer (medium)
- MFA for the Azure management API (high)
- User-risk policy (high)
- Sign-in-risk policy (high)
- Phishing-resistant authentication strength for admins (high)
- Secure security-info registration (medium)
- Token protection / session hardening (info - verify in portal)

> Graph stores `conditions.authenticationFlows.transferMethods` as a single
> comma-joined string (`deviceCodeFlow,authenticationTransfer`); the scan splits
> it before testing membership so device-code detection works whether one or both
> flows are set.

## Exclusion concentration

`exclusionConcentration[]` ranks the users/groups/roles that recur most often as
exclusions across enforced policies, resolving names when a name map is
available. High-recurrence exclusion groups are the real bypass surface and the
prime consolidation target (align every broad protective policy on one
break-glass-only exclusion group).

## Output

`Invoke-CapConsolidate` returns
`{ summary, duplicates{exact,overlap,merge}, deadWeight[], completeness[], exclusionConcentration[] }`.
`summary` carries the state counts, cluster counts, dead-weight and gap counts,
and `estimatedTarget` / `estimatedReduction`. The estimate starts from the
enforced count (report-only and disabled policies are dropped anyway, so they are
never double-counted) and collapses each exact-duplicate and merge cluster among
enabled members.

The standalone runner additionally flattens the clusters and dead weight to
`consolidation-clusters.csv` and `consolidation-deadweight.csv` for reviewers.

## Independence

Authored independently against the public Entra Conditional Access evaluation
model and public Microsoft baseline guidance. No third-party tool code or logic
is reused.
