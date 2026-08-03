# The process - what happens, in what order, and who decides what

This document explains the end-to-end process a run follows, and draws one line
that matters more than any other: **the assessment is produced offline by
deterministic code. No AI is involved in deciding what your tenant looks like or
what is wrong with it.**

If you only want an assessment, everything below stops at stage 4. Stages 5 to 7
exist solely to let someone else - a colleague, a consultant, or a language model
- read the result and propose a plan, without you handing over your tenant's
names.

---

## The stages

```
   1 COLLECT          Microsoft Graph, read-only
        |             -> raw/export.json (structure, no names)
        |             -> raw/names.json  (dictionary, local only)
        v
   2 NORMALIZE        one shape per policy, every Graph variant folded in
        |             -> report/policies.json
        v
   3 ANALYZE          the offline engines, deterministic and reproducible
        |             -> analysis/findings.json, compliance.json,
        |                consolidation.json, audit.json, tests.json
        v
   4 RENDER           self-contained offline viewer
        |             -> visual/index.html
        |
        |  ============ the assessment is complete here ============
        v
   5 SAFE EXPORT      optional, only if you want an outside opinion
        |             -> cap-safe-review-<snapshot>.json (aliased, leak-tested)
        v
   6 REVIEW           a human or a model reads the safe bundle and writes a plan
        |             -> a report that refers to objects by alias
        v
   7 RESTORE          run locally, maps aliases back to real names
                      -> the same report, readable
```

Stages 1 to 4 are a single command. Stages 5 to 7 are opt-in and independent.

---

## Stage 1 - Collect

A read-only Graph sign-in pulls the Conditional Access policies and their
dependencies (named locations, authentication strengths, authentication
contexts), then enriches from the directory: users, groups and owners, privileged
role assignments, sign-in activity, and MFA registration capability from the
aggregate registration report.

Two files are written, never one:

| File | Contains | Share? |
| --- | --- | --- |
| `raw/export.json` | Structure and object ids, **and the tenant id**. No names. | No |
| `raw/names.json` | The alias -> name dictionary. | Never |

See [SAFEEXPORT.md](SAFEEXPORT.md) for why the split exists and why
`raw/export.json` is still not the thing you share.

> [!NOTE]
> Collection is the only stage that touches the network. Everything after it runs
> from the JSON on disk, which is why `-FromJson` can reproduce stages 2 to 4
> exactly without signing in again.

## Stage 2 - Normalize

Graph expresses the same condition in more than one shape, and adds new shapes
over time. Normalization folds every known variant into one internal shape so the
analysis engines have a single thing to reason about.

This stage is where the most damaging class of bug lives, so it is guarded
explicitly. The condition keys the analyzer consumes are declared in one place,
and **any key that is present in the policy but not consumed is reported as a
warning** - in the run log, the report, the safe bundle and the reviewer digest.

The reason is worth stating plainly. If a tool reads only the old shape of a
condition, it does not throw an error when it meets a new one. It reports the
condition as *absent*. Absent targeting reads as "this policy does nothing",
which reads as dead weight, which reads as "delete it". A tool that silently
recommends deleting a working policy is worse than no tool. The guard converts
that silence into a visible warning.

## Stage 3 - Analyze

Every engine listed under **Offline analysis engines** in the
[README](../README.md) runs here. All of them are deterministic: the same export
produces the same findings, every time, with no network and no model.

Each engine writes its own artifact under `analysis/`, and the findings carry
their own rule text, so any conclusion can be traced back to the exact check that
produced it and re-verified against the raw export.

## Stage 4 - Render

A single self-contained HTML file with no external requests. It reads the
name-free export and the local dictionary at build time:

- Dictionary present, the report shows real names.
- Dictionary absent, the report shows object ids and still renders.

**At this point the assessment is done.** Findings, risk scores, the CISA SCuBA
matrix, duplicate and overlap clustering, dead weight, baseline gaps and the
per-user scope answers all exist, on disk, in the report.

---

## Stages 5 to 7 - only if you want an outside opinion

### Stage 5 - Safe export

The **Export safely** button in the report, or
[`Export-CapSafeBundle.ps1`](../scripts/Export-CapSafeBundle.ps1), produces one
JSON file that contains the policy structure plus every analysis result, with
tenant-specific identifiers aliased and no display names.

It **fails closed**. Any surviving name, unallowlisted GUID or IP-shaped string
deletes the bundle and throws, rather than writing a file that looks safe.

### Stage 6 - Review

The reviewer receives aliases and returns aliases. It never learns who
`OBJECT-004` is, and it does not need to in order to say that a policy is a
duplicate of another or that a control is missing.

### Stage 7 - Restore

[`Restore-CapNames.ps1`](../scripts/Restore-CapNames.ps1) maps the reviewer's
output back to real names on your machine, using the dictionary that never left
it. Restore is bound to the snapshot that produced the aliases, so a report
cannot be re-hydrated with the wrong run's dictionary.

---

## What the engine decides, and what a reviewer decides

This is the distinction that matters when judging any output built on top of this
tool.

| | Offline engine (stages 1-4) | Reviewer (stage 6) |
| --- | --- | --- |
| Answers | What **is** | What to **do** |
| How | Deterministic rules over the export | Judgement over the engine's results |
| Reproducible | Yes, byte for byte | No, it is an opinion |
| Examples | This policy is Report-only. These five policies are exact duplicates. MS.AAD.3.1 fails. 4 privileged accounts cannot do MFA. | Fix these three first. Merge this cluster into that survivor. Verify break-glass before enforcing. Here is a sequence. |

**The engine determines what is true. A reviewer decides what to do about it.**

Two consequences follow, and both are deliberate:

1. **You do not need a reviewer, or an AI, to get an assessment.** Stages 1 to 4
   give you the complete factual picture. Stages 5 to 7 add prioritization,
   sequencing and a remediation plan, which is a different kind of value.

2. **A reviewer must never restate the engine's numbers from memory or
   inference.** Every figure in a review should be traceable to an artifact under
   `analysis/`. If a reviewer's headline number disagrees with the engine, the
   reviewer is wrong by definition, because the engine is the thing that measured
   it.

> [!IMPORTANT]
> The failure mode to watch for is a reviewer that is not *given* a number and
> therefore produces a plausible one. The defence is not to instruct the reviewer
> more firmly. It is to make sure the deterministic layer supplies every figure
> the review is allowed to quote, and to check the finished review against those
> figures before anyone reads it.

---

## Related documents

- [SAFEEXPORT.md](SAFEEXPORT.md) - the two-file contract, what is masked, what is
  deliberately not, and the honest residual risk.
- [SECURITY.md](SECURITY.md) - permissions, data handling, threat model.
- [PERMISSIONS.md](PERMISSIONS.md) - the exact Graph scopes and why each is needed.
- [USAGE.md](USAGE.md) - every switch.
- [FINDINGS.md](FINDINGS.md) - the risk model behind the findings.
- [COMPLIANCE.md](COMPLIANCE.md) - how the CISA SCuBA matrix is scored.
- [CONSOLIDATE.md](CONSOLIDATE.md) - duplicate, overlap and dead-weight logic.
