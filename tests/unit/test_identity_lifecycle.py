"""Isolated identity fixtures with real decision persistence and application authorization."""

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import UUID, uuid4

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from backend.auth import Auth
from backend.cloud_api import gateway
from backend.identity import ADMIN_EMAIL, ADMIN_USERNAME, Decision, Directory, Status
from backend.investigations.store import SQLiteStore
from pipelines.io import DataError
from scripts.platform_admin import activate_verified_admin, verify_admin_email, verify_admin_totp


def test_lifecycle_uses_current_state_and_isolates_principals(tmp_path, monkeypatch):
    pool_users = {
        name: {
            "Username": name,
            "UserCreateDate": datetime.now(UTC),
            "Enabled": True,
            "UserStatus": "CONFIRMED",
            "UserAttributes": [
                {"Name": "sub", "Value": str(uuid4())},
                {
                    "Name": "email",
                    "Value": ADMIN_EMAIL if name == ADMIN_USERNAME else f"{name}@example.test",
                },
                {"Name": "email_verified", "Value": "true"},
            ],
        }
        for name in (ADMIN_USERNAME, "pilot", "peer")
    }
    pool_users[ADMIN_USERNAME].update(
        PreferredMfaSetting="SOFTWARE_TOKEN_MFA", UserMFASettingList=["SOFTWARE_TOKEN_MFA"]
    )
    pool_users["peer"]["UserAttributes"][1]["Value"] = ADMIN_EMAIL
    pool_users["peer"]["UserAttributes"].append(
        {"Name": "identities", "Value": '[{"providerName":"Google"}]'}
    )

    class Cognito:
        def admin_get_user(self, *, Username, **_):
            return pool_users[Username]

        def admin_list_groups_for_user(self, **_):
            return {"Groups": [{"GroupName": "aegis-test-admins"}]}

        def list_users(self, **_):
            return {"Users": list(pool_users.values())}

    issuer = "https://identity.example.test/pool"
    audience = "test-browser"
    signing = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    directory = Directory(
        Cognito(), "test", SQLiteStore(tmp_path / "decisions.sqlite3"), "aegis-test-admins"
    )
    auth = Auth(
        issuer=issuer,
        audience=audience,
        workspace="aegis-test",
        cognito=True,
        jwks_url=issuer + "/.well-known/jwks.json",
        directory=directory,
    )
    monkeypatch.setattr(
        auth.jwks, "get_signing_key_from_jwt", lambda _: SimpleNamespace(key=signing.public_key())
    )
    administrator = UUID(pool_users[ADMIN_USERNAME]["UserAttributes"][0]["Value"])
    directory.write(administrator, Decision(status=Status.APPROVED), None)

    def bearer(name, **overrides):
        now = int(datetime.now(UTC).timestamp())
        token = jwt.encode(
            {
                "iss": issuer,
                "client_id": audience,
                "exp": now + 60,
                "iat": now,
                "auth_time": now - 10,
                "token_use": "access",
                "scope": "openid",
                "username": name,
                "sub": pool_users[name]["UserAttributes"][0]["Value"],
                "origin_jti": str(uuid4()),
                **overrides,
            },
            signing,
            algorithm="RS256",
        )
        return {"Authorization": "Bearer " + token}

    def change(client, action, status, name="pilot", headers=None):
        return client.post(
            "/api/aegis/v1/admin/users/" + name,
            headers=admin if headers is None else headers,
            json={"action": action, "expected_status": status},
        )

    admin = bearer(ADMIN_USERNAME)
    pilot = bearer("pilot", **{"cognito:groups": ["aegis-test-admins"]})
    peer = bearer("peer", **{"cognito:groups": ["aegis-test-admins"]})
    application = gateway(
        SimpleNamespace(coverage=lambda: [], snapshot=uuid4(), score_date=None), auth, "", None
    )
    with TestClient(application) as client:
        account_url = "/api/aegis/v1/account"
        protected_url = "/api/aegis/v1/coverage"
        listing_url = "/api/aegis/v1/admin/users"
        assert client.get(account_url).status_code == 401
        assert client.get(account_url, headers=pilot).json()["status"] == "PENDING_APPROVAL"
        assert client.get(protected_url, headers=pilot).status_code == 403
        assert client.get(listing_url, headers=pilot).status_code == 403
        peer_account = client.get(account_url, headers=peer).json()
        assert peer_account["provider"] == "Google"
        assert peer_account["status"] == "PENDING_APPROVAL"
        assert peer_account["administrator"] is False
        assert client.get(listing_url, headers=peer).status_code == 403
        assert client.get(listing_url, headers=admin).json()["pending"] == 2
        assert change(client, "approve", "PENDING_APPROVAL", headers=pilot).status_code == 403
        assert change(client, "approve", "PENDING_APPROVAL").status_code == 200
        assert client.get(account_url, headers=pilot).json()["status"] == "APPROVED"
        assert auth.authenticate(pilot["Authorization"], None) != str(administrator)
        assert change(client, "approve", "PENDING_APPROVAL").status_code == 409
        assert change(client, "suspend", "APPROVED").status_code == 200
        assert client.get(protected_url, headers=pilot).status_code == 401
        assert change(client, "restore", "SUSPENDED").status_code == 200
        assert client.get(protected_url, headers=pilot).status_code == 401
        assert change(client, "reject", "PENDING_APPROVAL", name="peer").status_code == 200
        assert client.get(account_url, headers=peer).status_code == 401
        assert change(client, "suspend", "APPROVED", name=ADMIN_USERNAME).status_code == 403
        assert (
            client.get(account_url, headers=bearer("pilot", client_id="wrong")).status_code == 401
        )
        assert client.get(account_url, headers=bearer("pilot", token_use="id")).status_code == 401
        assert (
            client.get(
                account_url, headers=bearer("pilot", scope="aws.cognito.signin.user.admin")
            ).status_code
            == 401
        )
        assert (
            client.get(account_url, headers=bearer("pilot", sub=str(administrator))).status_code
            == 401
        )
        audit = client.get(listing_url + "/pilot/audit", headers=admin).json()
        assert [entry["action"] for entry in audit] == ["approve", "suspend", "restore"]
        assert all(
            entry["actor"] == str(administrator) and entry["outcome"] == "applied"
            for entry in audit
        )
        assert client.post(account_url + "/logout", headers=admin).status_code == 204
        assert client.get(listing_url, headers=admin).status_code == 401
        pool_users[ADMIN_USERNAME]["UserMFASettingList"] = []
        assert client.get(listing_url, headers=bearer(ADMIN_USERNAME)).status_code == 403


def test_verified_email_never_implicitly_approves(tmp_path):
    directory = Directory(object(), "test", SQLiteStore(tmp_path / "decisions.sqlite3"), "admins")
    assert directory.decision(uuid4()) == (Decision(status=Status.PENDING), None)


def test_admin_activation_preserves_pending_logout(tmp_path):
    store = SQLiteStore(tmp_path / "decisions.sqlite3")
    subject = uuid4()
    now = datetime.now(UTC)
    closed = {str(uuid4()): now + timedelta(days=1)}
    pending = Decision(revoked_sessions=closed)
    assert store.put(str(subject), pending.model_dump_json().encode(), None)
    activate_verified_admin(store, subject, now)
    stored = store.get(str(subject))
    assert stored is not None
    approved = Decision.model_validate_json(stored.data)
    assert approved.status == Status.APPROVED
    assert approved.revoked_sessions == closed
    assert approved.revoked_before == int(now.timestamp())
    assert [(entry.actor, entry.target, entry.action) for entry in approved.audit] == [
        (subject, subject, "activate_admin")
    ]


@pytest.mark.parametrize(
    "decision",
    [
        Decision(status=Status.REJECTED),
        Decision(status=Status.SUSPENDED),
        Decision(status=Status.APPROVED),
        Decision(revoked_before=1),
    ],
)
def test_admin_bootstrap_preserves_substantive_decisions(tmp_path, decision):
    store = SQLiteStore(tmp_path / "decisions.sqlite3")
    subject = uuid4()
    assert store.put(str(subject), decision.model_dump_json().encode(), None)
    original = store.get(str(subject))
    with pytest.raises(DataError, match="unexpected existing decision"):
        activate_verified_admin(store, subject, datetime.now(UTC))
    assert store.get(str(subject)) == original


def test_admin_email_mismatch_retries_without_sending_new_code(monkeypatch):
    class CodeMismatch(Exception):
        pass

    class Cognito:
        exceptions = SimpleNamespace(CodeMismatchException=CodeMismatch)
        sent = 0
        attempts = 0

        def get_user_attribute_verification_code(self, **_):
            self.sent += 1

        def verify_user_attribute(self, **_):
            self.attempts += 1
            if self.attempts == 1:
                raise CodeMismatch()

    client = Cognito()
    monkeypatch.setattr("scripts.platform_admin.getpass", lambda _: "000000")
    verify_admin_email(client, "local-test-token")
    assert client.sent == 1
    assert client.attempts == 2


def test_admin_authenticator_retries_using_same_enrollment(monkeypatch):
    class Cognito:
        attempts = 0

        def verify_software_token(self, **_):
            self.attempts += 1
            return {"Status": "ERROR" if self.attempts == 1 else "SUCCESS"}

    client = Cognito()
    monkeypatch.setattr("scripts.platform_admin.getpass", lambda _: "000000")
    verify_admin_totp(client, "local-test-token")
    assert client.attempts == 2
