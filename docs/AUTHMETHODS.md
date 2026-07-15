# Authentication methods audit (CapAuthMethods)

An authentication-method registration audit: who in the tenant is capable of and
registered for MFA, passwordless, phishing-resistant methods, and self-service
password reset (SSPR). Runs automatically as part of `Invoke-CapVisualizer.ps1`
(`analysis/authmethods.json`) and drives the viewer's **Auth methods** tab.

## Data source and privacy

The engine consumes only the **aggregate** authentication method registration
report, Graph beta
`reports/authenticationMethods/userRegistrationDetails`, which is already
collected during directory enrichment (see
[PERMISSIONS.md](PERMISSIONS.md)). It requires no additional consent beyond the
enrichment scopes (`AuditLog.Read.All` + `UserAuthenticationMethod.Read.All`, or
`Reports.Read.All`).

It **never** calls the per-user `/users/{id}/authentication/methods` endpoint, so
it never reads a user's actual method secrets (phone numbers, security-key
names). It reports only capability and registration state plus the method
*types* a user has registered.

The per-user table still identifies individuals and their registration posture.
Treat `analysis/authmethods.json` and the rendered viewer as sensitive and share
accordingly. The viewer shows a sensitivity banner above the audit.

## Output schema

```
{
  available, collectedUtc,
  summary: {
    totalUsers,
    mfaRegistered, mfaRegisteredPct, mfaCapable, mfaCapablePct,
    passwordlessCapable, passwordlessCapablePct,
    phishResistant, phishResistantPct,
    ssprRegistered, ssprRegisteredPct,
    admins, adminsMfaRegistered, adminsPhishResistant,
    methodBreakdown: [ { method, label, count } ]
  },
  gaps: [ { id, title, severity, detail, count, users: [ { id, displayName, userPrincipalName } ] } ],
  users: [ {
    userId, displayName, userPrincipalName, userType, isAdmin,
    isMfaCapable, isMfaRegistered, isPasswordlessCapable,
    isSsprCapable, isSsprRegistered, isSsprEnabled,
    methodsRegistered[], methodCount, hasPhishResistant, defaultMfaMethod
  } ]
}
```

When the registration report was not collected (for example the run used
`-SkipDirectory`, or the scopes were not consented), the engine returns
`{ available: false, reason, summary: null, gaps: [], users: [] }` and the tab
renders the reason instead of an audit.

## Phishing-resistant methods

A user is counted as phishing-resistant when they have registered any of:
`windowsHelloForBusiness`, `fido2SecurityKey`, `passKeyDeviceBound`,
`passKeyDeviceBoundAuthenticator`, `passKeyDeviceBoundWindowsHello`, or
`certificateBasedAuthentication`. This set follows Microsoft and CISA guidance.

## Gaps

| Gap id | Severity | Meaning |
| ------ | -------- | ------- |
| `admin-not-mfa-registered`        | critical | Admin has no registered MFA method (single-factor capable). |
| `admin-no-phishing-resistant`     | high     | Admin is MFA-registered but has no phishing-resistant method. |
| `user-no-mfa-method`              | high     | User has no MFA-capable method (lockout or single-factor risk). |
| `user-mfa-capable-not-registered` | medium   | User can register a strong method but has not. |
| `user-no-methods`                 | medium   | User has registered no authentication method at all. |
| `user-sspr-not-registered`        | low      | User is SSPR-capable but not registered. |

A gap group is emitted only when at least one user matches, so empty categories
never appear.

## Per-user table

The per-user table is interactive and stays fully offline:

- **Search** by display name, UPN, or registered method.
- **Sort** any column by clicking its header (click again to reverse).
- **Show only** filters the table to a single attribute value, for example show
  only users who are not MFA-capable, not registered for MFA, without a
  phishing-resistant method, or admins. Pick the attribute and Yes/No.
- **Export CSV** downloads the current (filtered) view as a UTF-8 CSV with the
  display name, UPN, user type, admin flag, MFA/passwordless/phishing-resistant/
  SSPR state, and registered methods. Export happens client-side; no data leaves
  the file.

## Relationship to Conditional Access

Conditional Access enforces *policy intent* ("require MFA"); this audit reports
*identity reality* (whether a targeted user can actually satisfy that intent).
The two together explain cases where a policy is compliant yet a user in scope is
not capable of MFA. See also the Findings tab, which raises in-scope
MFA-capability gaps as risk-scored findings.

## Independence

Authored fresh against the public Graph report schema and public
Microsoft/CISA guidance on phishing-resistant methods. No code or logic is
copied from any third-party tool.
