# Unattended app and certificate authentication

CAPVisualizer does not create the app registration, grant permissions, upload
the certificate, or install the private key. Complete these steps before using
`-TenantId`, `-ClientId`, and either `-CertificateThumbprint` or
`-CertificatePath`.

## 1. Create the app registration

In **Microsoft Entra admin center**:

1. Open **Identity > Applications > App registrations > New registration**.
2. Create a single-tenant app and record its **Application (client) ID** and
   **Directory (tenant) ID**.
3. Under **API permissions**, add Microsoft Graph **Application permissions**:
   - Policy-only: `Policy.Read.All`.
   - Default full analysis: `Policy.Read.All`, `Directory.Read.All`,
     `Group.Read.All`, `User.Read.All`, `RoleManagement.Read.Directory`,
     `AuditLog.Read.All`, and `UserAuthenticationMethod.Read.All`.
4. Grant tenant-wide admin consent.

These are read permissions. Do not grant Conditional Access or directory write
permissions.

## 2. Create the certificate

Create the key on the machine that will run the schedule. The following OpenSSL
example works on macOS and Linux and can also be used on Windows when OpenSSL is
available:

```bash
umask 077
openssl req -x509 -newkey rsa:3072 -sha256 -days 730 -nodes \
  -subj "/CN=CAPVisualizer" \
  -keyout capvisualizer.key -out capvisualizer.cer
```

Upload `capvisualizer.cer` under the app registration's **Certificates &
secrets > Certificates** page. Never upload or commit the PFX or private key.

On Windows, `New-SelfSignedCertificate` and `Export-Certificate` are a native
alternative. Create the certificate in the same account and store that the
scheduled task will use.

## 3. Make the private key available to the scheduler identity

The account running CAPVisualizer must be able to open the certificate **and
its private key**.

### Windows

Import the PFX into either:

- `Cert:\CurrentUser\My` for a task running as that user; or
- `Cert:\LocalMachine\My` for a service account, then grant that account read
  access to the private key.

If you created the key with OpenSSL, build a password-protected PFX first:

```bash
openssl pkcs12 -export -out capvisualizer.pfx \
  -inkey capvisualizer.key -in capvisualizer.cer
```

Do not test only from an administrator's interactive profile if the task runs
under another identity.

### macOS and Linux

Private-key persistence in the PowerShell certificate store is not consistently
available on Unix platforms. Use `-CertificatePath` with a PFX file instead.

For a non-interactive cron job, create a PFX without a password and protect it
with OS permissions and full-disk encryption:

```bash
openssl pkcs12 -export -passout pass: -out capvisualizer.pfx \
  -inkey capvisualizer.key -in capvisualizer.cer
chmod 600 capvisualizer.pfx
rm capvisualizer.key
```

Move the PFX to a directory readable only by the scheduler account. The PFX is
an authentication credential even though it has a `.pfx` extension; never put
it in the repository or output directory.

For an interactive or secret-manager wrapper, CAPVisualizer also accepts a
password-protected PFX through `-CertificatePassword` as a `SecureString`.

## 4. Verify before scheduling

Sign in as the scheduler identity and run:

```powershell
pwsh ./scripts/Invoke-CapVisualizer.ps1 `
  -TenantId 11111111-2222-3333-4444-555555555555 `
  -ClientId 22222222-3333-4444-5555-666666666666 `
  -CertificateThumbprint A1B2C3D4E5F60718293A4B5C6D7E8F9012345678 `
  -NoOpen -NoTranscript
```

On macOS or Linux:

```bash
pwsh ./scripts/Invoke-CapVisualizer.ps1 \
  -TenantId 11111111-2222-3333-4444-555555555555 \
  -ClientId 22222222-3333-4444-5555-666666666666 \
  -CertificatePath /secure/capvisualizer.pfx \
  -NoOpen -NoTranscript
```

For a `Policy.Read.All`-only app, also pass `-SkipResolveNames -SkipDirectory`.
Verify that the run creates a complete snapshot before registering the
schedule.

## 5. Operate and rotate

- Prefer a dedicated app and certificate for CAPVisualizer.
- Set a certificate-expiry alert and overlap old/new certificates during
  rotation.
- Remove expired certificates from both the app registration and local store.
- Review app sign-in logs and permission grants periodically.
- Keep snapshots on encrypted storage and apply a documented retention period.

See [SCHEDULING.md](SCHEDULING.md) for cron and Task Scheduler examples and
[PERMISSIONS.md](PERMISSIONS.md) for the dataset enabled by each permission.
