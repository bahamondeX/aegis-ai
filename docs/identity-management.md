# Identity management

## OB Auth and Vercel release

The Nuxt server uses the published `@oscarbahamonde/ob-auth@0.1.0` adapter.
Nitro owns `GET /auth/login`, `GET /auth/callback`, `GET /auth/session`
and `POST /auth/logout`. The workspace sign-in page sends the browser to
OB Auth. Registration, email confirmation, authenticator enrollment and
challenge, password recovery, and app-grant revocation are handled there.
[SDK and integration guide](https://github.com/bahamondeX/ob-auth)

Use distinct relying-party clients, confidential credentials, cookie keys
and signing keys for the production and stable candidate origins. The
production registry entry `aegis` already has the exact callback
`https://aegis.oscarbahamonde.com/auth/callback` and logout destination
`https://aegis.oscarbahamonde.com`. The production client was enabled after
verifying TLS and the routed deployment. The `aegis-candidate` client uses
`https://aegis-candidate.vercel.app/auth/callback` and
`https://aegis-candidate.vercel.app`. Both clients require verified email. OB Auth has
one MFA setting per application. Its registration-wide MFA flag is off
for the two AEGIS clients so their server can apply the provider-specific
rule. The other applications retain their own registrations and policies.

Set `NUXT_OB_AUTH_APP_ORIGIN`, `NUXT_OB_AUTH_LOGOUT_URI`,
`NUXT_OB_AUTH_CLIENT_ID`, `NUXT_OB_AUTH_CLIENT_SECRET`,
`NUXT_OB_AUTH_SESSION_KEY` and `NUXT_AEGIS_BRIDGE_SIGNING_KEY` privately on
Vercel. The last two values are independent random 32-byte base64url keys.
The AWS SecureString configured by `ObBridgeParameter` contains a JSON
object keyed by registered client ID. Each value has `client_secret` and
`signing_key`. Keep the cookie encryption keys exclusively on Nitro.

Nitro verifies the canonical host and the origin of state-changing
requests. The SDK seals its grant in a host-only, Secure, HttpOnly cookie.
Nitro sends a signed assertion over TLS to API Gateway. FastAPI checks the
configured signing key, issuer, audience and lifetime and introspects the
grant with OB Auth on every authorization check. A valid Google session
with verified email is eligible without a second authenticator. A valid
password session must additionally carry OB Auth's MFA claim. AEGIS rejects
other providers. Lambda invokes AgentCore
using IAM. AgentCore and MCP verify the same assertion independently,
including current grant validity and workspace membership. AEGIS resolves
workspace access using the immutable OB Auth subject. Matching email
addresses confer no membership or historical record access.

The hosted candidate accepted a real Google session with `emailVerified:
true` and `mfa: false`. After the browser signed out, a consistent read
confirmed that OB Auth had deleted the corresponding AEGIS grant. Native
confirmation and password recovery were exercised with actual mailbox
codes entered in Chrome. Native access remained denied before TOTP. On the
final domain, Chromium completed the exact production callback after native
TOTP, opened the workspace, and received 401 when replaying the old app
cookie after logout. Cognito confirmed that the disposable user was disabled.

For hosted acceptance, record the exact origin and UTC time. Exercise
native registration, mailbox confirmation, TOTP enrollment and a fresh
challenge, recovery, logout and rejected access after revocation. Check
both users' workspace access by immutable subject and verify that replay
and cancellation from the second identity cannot access the first user's
investigation. Verify a Google return with the registered policy. Disable
only the disposable users recorded for the test, then re-read their status.

## Legacy CloudFront Authenticator candidate

Open the hosted workspace at `/login`. Native registration, email confirmation,
password sign-in, the existing Cognito software-token challenge and native
refresh-token revocation use the scoped API and the Cognito SDK. Native
password recovery uses the managed Cognito recovery form. Access and refresh
tokens remain in browser memory. Both sign-in methods must complete the
application Authenticator check before the API or AgentCore serve data.

The Google button opens Cognito's OAuth authorization endpoint with S256 PKCE
and `identity_provider=Google`. In the Google OAuth client, the authorized
redirect URI is
`https://aegis-dev-ops-bdda388cc7.auth.us-east-1.amazoncognito.com/oauth2/idpresponse`.
The existing Cognito browser client returns candidates to
`https://diwmzuqenxczv.cloudfront.net/auth/callback` and production to
`https://d13u8qrh8t434t.cloudfront.net/auth/callback`.

In Authenticator mode, a verified Cognito email and a valid TOTP code open
access for the current session. This applies to native and Google sign-ins.
Cognito still handles email confirmation, password reset and federation.
Accounts remain separate by Cognito subject. The API and AgentCore check MFA
independently. The old administration URL redirects to the workspace.

Enter the displayed setup key manually into any time-based authenticator app.
Each time step is single-use, and failed attempts are limited per subject.
Save the one-time recovery codes after enrollment. Using one closes existing
MFA sessions and retires the old factor immediately. A new code from the
replacement authenticator restores access.

The account profile uses the Google picture supplied by Cognito. Other
accounts and failed photo loads receive a generated, stable avatar.

For hosted validation, use `--authenticator` on the isolated AgentCore and
hosting commands with the existing V2 pin and budget guards. Review and apply
the Cognito browser-client attribute change before mapping Google's `picture`.
Preserve OAuth callbacks, token revocation and existing pool identities.
Run `scripts.smoke_cloud --preview --history-agent --authenticator` for a
disposable fixture and the independent API and AgentCore checks. Complete
real mailbox confirmation and password reset, Google sign-in and TOTP on
both accounts separately. A production cutover also requires disabling data
access on any legacy directly addressable runtime versions. Verify both
providers, pre-MFA denial, session revocation, recovery and avatars before
promotion.

### Authenticator production cutover and rollback

Use the verified pin, accepted static artifact and acceptance receipt recorded in
`STATUS.md`. Capture and verify a fresh hosting rollback baseline before
changing production. Review the hosting change set and the original runtime
role change set before the cutover.

```sh
uv run --locked --no-sync python -m infra.agent_deploy runtime --legacy-runtime-guard review
uv run --locked --no-sync python -m infra.hosting_deploy deploy \
  --authenticator --v2-agent --v2-pins "$pins" --assembly "$production_assembly" \
  --acceptance "$acceptance"
uv run --locked --no-sync python -m infra.agent_deploy runtime --legacy-runtime-guard close
uv run --locked --no-sync python -m infra.hosting_deploy publish-ui \
  --authenticator --v2-agent --v2-pins "$pins" --acceptance "$acceptance" \
  --static-artifact "$static_artifact"
uv run --locked --no-sync python -m scripts.smoke_cloud \
  --v2 --history-agent --authenticator --evidence-dir "$production_smoke"
```

Verify that each original AgentCore version and its DEFAULT endpoint refuse
direct investigation calls. The guard verifies that the versions use the
owned original role. It denies that role Cognito, lake, checkpoints, Athena,
Glue and inference access while preserving the runtime and its versions.
The candidate stack uses a separate execution role for Authenticator.

If a critical production check fails, restore the captured hosting template
and versioned UI first. Then reopen the original runtime role and repeat
the authenticated legacy smoke. The shared Cognito pool and encrypted journals
stay in place, including the existing OAuth callbacks and provider mapping.

```sh
uv run --locked --no-sync python -m infra.v2_hosting_rollback restore "$rollback"
uv run --locked --no-sync python -m infra.agent_deploy runtime --legacy-runtime-guard reopen
uv run --locked --no-sync python -m scripts.smoke_cloud --evidence-dir "$rollback_smoke"
```

## Legacy approval environment

The existing Cognito directory provides native email registration, email verification,
password reset and Google federation. Sign-in returns through the exact
`/auth/callback` URL using authorization code and S256 PKCE. The browser holds
tokens in memory. Its temporary OAuth state and PKCE verifier live in session
storage until the callback consumes them. The original pool has username
sign-in and its classic signup page omits email. The AEGIS registration form
sends the address to the managed Cognito signup API as the username and email
attribute, then confirms the one-time code through Cognito before OAuth login.

New subjects see their own account status. An administrator uses **User
administration** in the workspace to review registrants, apply a confirmed
decision and view its audit history. Approval requires a verified email.
Google and native registrations are independent Cognito subjects. The service
has no linking flow.

| Current state | Administrator actions |
| --- | --- |
| Pending approval | Approve, reject |
| Approved | Suspend |
| Suspended | Restore |
| Rejected | Retained for audit |

A Cognito-disabled identity cannot authenticate. Preserve its application
decision and audit history when retiring a test identity. Verify the pool
and immutable subject against its creation record before disabling it and
verify the result with a fresh directory read. The hosted fixture runner
records the creation and disable request identifiers in private evidence.

The API and AgentCore independently validate Cognito signature, issuer,
token use, expiry, client, OAuth scope and subject against the live directory.
The reserved administrator also requires the current Cognito group, verified
email, native identity and enabled preferred TOTP. Approval decisions and
successful audit events share a conditional write in
`identity/accounts/<subject>.json` in the existing encrypted checkpoint
bucket. The runtime role reads that prefix. Only the hosted API role writes
ordinary decisions. Rejection and suspension record a cutoff using the
original authentication timestamp, so refresh and restore cannot revive a
stale session. Runtime streams recheck live access as they poll and cancel
active work if approval is lost. Logout revokes the application's session
family, attempts Cognito refresh revocation and clears the hosted login cookie.

## Initial administrator

Delivery uses Cognito's direct email invitation to
`admin@oscarbahamonde.com`. The scoped operator invokes the invite command
once after the identity change set completes. It leaves an existing password
alone. The one-day invitation uses Cognito's `NEW_PASSWORD_REQUIRED`
challenge. The mailbox owner completes the password change, independently
verifies the address and enrolls TOTP from a private interactive terminal.
When the QR code appears, scan it from the phone's authenticator and enter
the current code from the AEGIS entry with the setup ID shown in Terminal.
The command prompts once for enrollment and checks the code locally before
sending a single verification request to Cognito. The displayed key supports
manual time-based setup if the terminal QR renderer is unavailable.

```sh
JSII_RUNTIME_PACKAGE_CACHE=disabled uv run --locked --no-sync python -m scripts.platform_admin onboard
```

After activation, wait for the next authenticator code. Select **Sign in** and enter the username
`aegis-platform-admin`, and complete the authenticator challenge. Open **User
administration** inside the signed-in workspace. For a lost authenticator,
verify owner identity through the AWS operator recovery process before
changing any MFA preference. Keep an expired temporary invitation recovery
separate from routine deployments.

The permanent native administrator completed activation on 24 November
2026. The owner authenticated in production and opened **User administration**.
The current native profile, verified email, Cognito group, preferred TOTP
factor, application approval and activation audit were checked independently.

If the password was changed in the hosted login, rerun the onboarding
command with the current password. A sign-out during setup can create a
pending decision containing closed browser sessions. Onboarding resumes
from that record and preserves its session revocations. Use the most
recent Cognito message sent to the administrator mailbox. A mismatched
code can be retried in the same command.

## Email and provider operations

Cognito's default sender handles identity verification and native password
recovery. Existing Google credentials stay in the Cognito provider. A Google
redirect must be registered for the existing Cognito domain with path
`/oauth2/idpresponse`. Live provider success requires completing a real
Google sign-in.

Approval, rejection and pending-registration notifications remain disabled.
The regional SES account reported sandbox mode and zero verified identities.
Decision status and pending requests are available in the dashboard. Confirm
approved sender identity, deliverability and cost before enabling notifications.
