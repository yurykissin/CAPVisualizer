# Offline what-if (`Invoke-CapWhatIf.ps1`)

Simulates a single sign-in for a principal against the policy set and reports the
cumulative outcome (block / MFA / other controls) - fully offline, from an
exported snapshot.

## The definitive vs signal-dependent distinction

Some sign-in facts are only known at authentication time: sign-in risk, user
risk, network location, client app, device state, and authentication flow.
Offline, those are unknown unless you supply them. This engine makes the
uncertainty explicit rather than guessing:

- **Applied (definitive)** - every condition the policy gates on is satisfied by
  the supplied context; the policy *will* apply.
- **Applied (signal-dependent)** - the policy would apply, but its remaining gate
  depends on a signal you did not supply (named in the result).
- **Not applied** - a condition definitively excludes this sign-in (scope,
  resource, or a supplied signal that does not match).

The cumulative outcome (blocked / MFA required / grant controls) is computed only
over **enforced, definitively-applied** policies. Report-only policies are tracked
separately, and a `noDefinitiveEnforcement` flag highlights sign-ins that reach
the resource with nothing enforcing a block or MFA.

## Usage

```powershell
./scripts/Invoke-CapWhatIf.ps1 `
    -FromJson ./samples/sample-export-enriched.json `
    -PrincipalId 77777777-7777-7777-7777-777777777777 `
    -Resource   00000002-0000-0ff1-ce00-000000000000 `
    -ClientApp  browser
```

Optional signals: `-Platform`, `-ClientApp`, `-Location`, `-SignInRisk`,
`-UserRisk`, `-AuthFlow`, `-DeviceState`. Add `-AsJson` for the full result
object. Omitting a signal that a policy gates on renders that policy
signal-dependent - which is often the useful insight.

## Independence

Authored independently against the public Entra Conditional Access evaluation
model. No third-party tool code or logic is reused.
