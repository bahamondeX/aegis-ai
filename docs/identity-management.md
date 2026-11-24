# Identity management

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
The enrollment URI belongs only in the owner's authenticator.

```sh
JSII_RUNTIME_PACKAGE_CACHE=disabled uv run --locked --no-sync python -m scripts.platform_admin onboard
```

After activation, wait for the next authenticator code. Select **Sign in** and enter the username
`aegis-platform-admin`, and complete the authenticator challenge. Open **User
administration** inside the signed-in workspace. For a lost authenticator,
verify owner identity through the AWS operator recovery process before
changing any MFA preference. Keep an expired temporary invitation recovery
separate from routine deployments.

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
