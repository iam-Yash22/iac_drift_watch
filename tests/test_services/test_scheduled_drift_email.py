import threading
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock

import pytest

from app import presence
from app.models.account import AwsAccount
from app.services import scheduled_drift_email


def test_presence_ttl_shorter_than_token_stays_active_until_token_lifetime(monkeypatch):
    now = [10.0]
    monkeypatch.setattr(presence, "time", SimpleNamespace(monotonic=lambda: now[0]))
    monkeypatch.setattr(presence, "_last_seen", {})
    monkeypatch.setattr(presence, "_lock", threading.Lock())
    monkeypatch.setattr(presence.settings.security, "access_token_expire_minutes", 1)
    monkeypatch.setenv("SESSION_IDLE_TTL_SECONDS", "1")

    presence.clear("test-user")
    presence.touch("test-user")
    now[0] += 2
    assert presence.has_active_users() is True

    presence.touch("test-user")
    now[0] += 59
    assert presence.has_active_users() is True
    now[0] += 2
    assert presence.has_active_users() is False


def test_presence_clear_removes_user(monkeypatch):
    monkeypatch.setattr(presence, "time", SimpleNamespace(monotonic=lambda: 10.0))
    monkeypatch.setattr(presence, "_last_seen", {})
    monkeypatch.setattr(presence, "_lock", threading.Lock())
    presence.touch("test-user")
    assert presence.has_active_users() is True

    presence.clear("test-user")

    assert presence.has_active_users() is False


@pytest.mark.parametrize("port", (465, 587))
def test_drift_email_uses_port_appropriate_tls(monkeypatch, port):
    monkeypatch.setenv("SMTP_HOST", "smtp.example.com")
    monkeypatch.setenv("SMTP_PORT", str(port))
    monkeypatch.setenv("SMTP_USER", "sender@example.com")
    monkeypatch.setenv("SMTP_PASSWORD", "x")
    monkeypatch.setenv("SMTP_FROM", "driftwatch@example.com")
    monkeypatch.setenv("SMTP_RECIPIENTS", "one@example.com,two@example.com")
    smtp = MagicMock()
    smtp.__enter__.return_value = smtp
    smtp.__exit__.return_value = None
    smtp.send_message.return_value = {}
    smtp_factory = Mock(return_value=smtp)
    monkeypatch.setattr(scheduled_drift_email.smtplib, "SMTP_SSL", smtp_factory)
    monkeypatch.setattr(scheduled_drift_email.smtplib, "SMTP", smtp_factory)
    monkeypatch.setattr(scheduled_drift_email.ssl, "create_default_context", Mock())

    scheduled_drift_email._send_drift_email(
        [{
            "account_id": 7,
            "account_name": "production",
            "resource_id": "bucket-1",
            "resource_type": "s3_bucket",
            "severity": "high",
            "summary": "Public access changed",
        }]
    )

    smtp_factory.assert_called_once()
    assert smtp.login.call_args.args == ("sender@example.com", "x")
    message = smtp.send_message.call_args.args[0]
    assert message["To"] == "one@example.com, two@example.com"
    assert "bucket-1" in message.get_content()
    assert "production" in message.get_content()
    if port == 465:
        assert smtp.starttls.called is False
    else:
        smtp.starttls.assert_called_once()


def test_send_alert_email_uses_gmail_smtp(monkeypatch):
    monkeypatch.setenv("SMTP_HOST", "smtp.gmail.com")
    monkeypatch.setenv("SMTP_PORT", "587")
    monkeypatch.setenv("SMTP_USER", "alerts@example.com")
    monkeypatch.setenv("SMTP_PASSWORD", "app-password")
    monkeypatch.setenv("ALERT_TEST_RECIPIENT", "test-recipient@example.com")
    monkeypatch.setattr(scheduled_drift_email.settings, "app_base_url", "http://localhost:5173")

    smtp = MagicMock()
    smtp.__enter__.return_value = smtp
    smtp.__exit__.return_value = None
    smtp.send_message.return_value = {}
    monkeypatch.setattr(scheduled_drift_email.smtplib, "SMTP", Mock(return_value=smtp))
    monkeypatch.setattr(scheduled_drift_email.ssl, "create_default_context", Mock())

    scheduled_drift_email._send_drift_email(
        [{
            "account_id": 1,
            "account_name": "production",
            "resource_id": "bucket-1",
            "resource_type": "s3_bucket",
            "severity": "high",
            "summary": "drift detected",
            "owner_name": "creator",
            "scan_id": 42,
            "diffs": {"tags.Name": {"desired": "bucket-1", "actual": None}},
        }]
    )

    scheduled_drift_email.smtplib.SMTP.assert_called_once_with("smtp.gmail.com", 587, timeout=30)
    smtp.starttls.assert_called_once()
    smtp.login.assert_called_once_with("alerts@example.com", "app-password")
    message = smtp.send_message.call_args.args[0]
    assert message["To"] == "test-recipient@example.com"
    body = message.get_content()
    assert "Account ID: 1" in body
    assert "Hi creator, drift was detected on account 1." in body
    assert "http://localhost:5173/accounts/1/scans/42" in body
    assert "tags.Name" in body
    assert '"desired": "bucket-1"' in body


def test_scheduled_scan_continues_after_account_failure(monkeypatch):
    accounts = [
        SimpleNamespace(id=1, name="failed-account"),
        SimpleNamespace(id=2, name="drifted-account"),
    ]

    class Query:
        def filter(self, *args):
            return self

        def order_by(self, *args):
            return self

        def all(self):
            return accounts

    class Session:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def query(self, model):
            return Query()

        def add(self, scan):
            scan.id = scan.account_id

        def commit(self):
            return None

        def refresh(self, scan):
            return None

    async def scan_account(account_id, **kwargs):
        if account_id == "1":
            raise RuntimeError("scan failed")
        return {
            "comparison": [
                {
                    "resource_id": "resource-2",
                    "resource_type": "test_resource",
                    "severity": "high",
                    "summary": "drift found",
                    "is_drifted": True,
                }
            ]
        }

    logger = Mock()
    send_email = Mock()
    monkeypatch.setattr(scheduled_drift_email, "SessionLocal", Session)
    monkeypatch.setattr(scheduled_drift_email, "orchestrate_account_scan", scan_account)
    monkeypatch.setattr(scheduled_drift_email, "has_active_users", lambda: False)
    monkeypatch.setattr(scheduled_drift_email, "_send_drift_email", send_email)
    monkeypatch.setattr(scheduled_drift_email, "logger", logger)

    scheduled_drift_email._scan_accounts_and_email()

    logger.exception.assert_called_once_with("scheduled drift scan failed account_id=%s", 1)
    send_email.assert_called_once()
    resources = send_email.call_args.args[0]
    assert len(resources) == 1
    assert resources[0]["account_id"] == 2
    assert resources[0]["resource_id"] == "resource-2"


def test_scheduled_email_skips_active_account_owners(monkeypatch):
    accounts = [
        SimpleNamespace(id=1, name="active-account", owner_id=10),
        SimpleNamespace(id=2, name="away-account", owner_id=11),
    ]

    class Query:
        def filter(self, *args):
            return self

        def order_by(self, *args):
            return self

        def all(self):
            return accounts

    class Session:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def query(self, model):
            return Query()

        def add(self, scan):
            scan.id = scan.account_id

        def commit(self):
            return None

        def refresh(self, scan):
            return None

    async def scan_account(account_id, **kwargs):
        items = [
            {"resource_id": f"resource-{account_id}", "resource_type": "test_resource", "severity": "high", "summary": "drift found", "is_drifted": True, "account_id": int(account_id)},
        ]
        if account_id == "2":
            items[0]["resource_id"] = "resource-b"
        return {"comparison": items}

    send_email = Mock()
    monkeypatch.setattr(scheduled_drift_email, "SessionLocal", Session)
    monkeypatch.setattr(scheduled_drift_email, "orchestrate_account_scan", scan_account)
    monkeypatch.setattr(scheduled_drift_email, "has_active_users", lambda: False)
    monkeypatch.setattr(scheduled_drift_email, "is_active", lambda user_id: user_id == 10)
    monkeypatch.setattr(scheduled_drift_email, "_send_drift_email", send_email)

    scheduled_drift_email._scan_accounts_and_email()

    send_email.assert_called_once()
    resources = send_email.call_args.args[0]
    assert [resource["account_id"] for resource in resources] == [2]


def test_scheduled_email_skips_all_active_owners(monkeypatch):
    accounts = [SimpleNamespace(id=1, name="active-account", owner_id=10)]

    class Query:
        def filter(self, *args):
            return self

        def order_by(self, *args):
            return self

        def all(self):
            return accounts

    class Session:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def query(self, model):
            return Query()

        def add(self, scan):
            scan.id = scan.account_id

        def commit(self):
            return None

        def refresh(self, scan):
            return None

    async def scan_account(account_id, **kwargs):
        return {"comparison": [{"resource_id": "resource-a", "resource_type": "test_resource", "severity": "high", "summary": "drift found", "is_drifted": True, "account_id": 1}]}

    send_email = Mock()
    monkeypatch.setattr(scheduled_drift_email, "SessionLocal", Session)
    monkeypatch.setattr(scheduled_drift_email, "orchestrate_account_scan", scan_account)
    monkeypatch.setattr(scheduled_drift_email, "has_active_users", lambda: False)
    monkeypatch.setattr(scheduled_drift_email, "is_active", lambda user_id: True)
    monkeypatch.setattr(scheduled_drift_email, "_send_drift_email", send_email)

    scheduled_drift_email._scan_accounts_and_email()

    send_email.assert_not_called()


def test_scheduled_email_does_not_suppress_missing_owner(monkeypatch):
    accounts = [SimpleNamespace(id=1, name="unowned-account", owner_id=None)]

    class Query:
        def filter(self, *args):
            return self

        def order_by(self, *args):
            return self

        def all(self):
            return accounts

    class Session:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def query(self, model):
            return Query()

        def add(self, scan):
            scan.id = scan.account_id

        def commit(self):
            return None

        def refresh(self, scan):
            return None

    async def scan_account(account_id, **kwargs):
        return {"comparison": [{"resource_id": "resource-a", "resource_type": "test_resource", "severity": "high", "summary": "drift found", "is_drifted": True, "account_id": 1}]}

    send_email = Mock()
    monkeypatch.setattr(scheduled_drift_email, "SessionLocal", Session)
    monkeypatch.setattr(scheduled_drift_email, "orchestrate_account_scan", scan_account)
    monkeypatch.setattr(scheduled_drift_email, "has_active_users", lambda: False)
    monkeypatch.setattr(scheduled_drift_email, "_send_drift_email", send_email)

    scheduled_drift_email._scan_accounts_and_email()

    send_email.assert_called_once()


def test_away_owner_receives_one_digest_for_drifts_in_two_accounts(monkeypatch):
    accounts = [
        SimpleNamespace(id=1, name="first-account", owner_id=10),
        SimpleNamespace(id=2, name="second-account", owner_id=10),
    ]

    class Query:
        def filter(self, *args):
            return self

        def order_by(self, *args):
            return self

        def all(self):
            return accounts

    class Session:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def query(self, model):
            return Query()

        def add(self, scan):
            scan.id = scan.account_id

        def commit(self):
            return None

        def refresh(self, scan):
            return None

    async def scan_account(account_id, **kwargs):
        account_number = int(account_id)
        return {
            "comparison": [{
                "resource_id": f"resource-{account_number}",
                "resource_type": "test_resource",
                "severity": "high",
                "summary": "drift found",
                "is_drifted": True,
            }]
        }

    send_email = Mock()
    monkeypatch.setattr(scheduled_drift_email, "SessionLocal", Session)
    monkeypatch.setattr(scheduled_drift_email, "orchestrate_account_scan", scan_account)
    monkeypatch.setattr(scheduled_drift_email, "has_active_users", lambda: False)
    monkeypatch.setattr(scheduled_drift_email, "is_active", lambda user_id: False)
    monkeypatch.setattr(scheduled_drift_email, "_send_drift_email", send_email)

    scheduled_drift_email._scan_accounts_and_email()

    send_email.assert_called_once()
    digest = send_email.call_args.args[0]
    assert len(digest) == 2
    assert [item["account_id"] for item in digest] == [1, 2]
    assert [item["resource_id"] for item in digest] == ["resource-1", "resource-2"]


@pytest.mark.parametrize(
    ("elapsed_seconds", "expected_send_count"),
    [(120.0, 1), (300.0, 1), (840.0, 1), (870.0, 2)],
    ids=["2-minutes", "5-minutes", "14-minutes", "14m30s-grace-boundary"],
)
def test_scheduled_digest_uses_run_start_and_grace_boundary(
    monkeypatch,
    elapsed_seconds,
    expected_send_count,
):
    accounts = [SimpleNamespace(id=1, name="away-account", owner_id=10)]

    class Query:
        def filter(self, *args):
            return self

        def order_by(self, *args):
            return self

        def all(self):
            return accounts

    class Session:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def query(self, model):
            return Query()

        def add(self, scan):
            scan.id = scan.account_id

        def commit(self):
            return None

        def refresh(self, scan):
            return None

    async def scan_account(account_id, **kwargs):
        return {
            "comparison": [{
                "resource_id": "resource-1",
                "resource_type": "test_resource",
                "severity": "high",
                "summary": "drift found",
                "is_drifted": True,
            }]
        }

    now = [0.0]

    def send_email_with_delay(resources):
        now[0] += 40.0

    send_email = Mock()
    monkeypatch.setattr(scheduled_drift_email, "SessionLocal", Session)
    monkeypatch.setattr(scheduled_drift_email, "orchestrate_account_scan", scan_account)
    monkeypatch.setattr(scheduled_drift_email, "has_active_users", lambda: False)
    monkeypatch.setattr(scheduled_drift_email, "is_active", lambda user_id: False)
    send_email.side_effect = send_email_with_delay
    monkeypatch.setattr(scheduled_drift_email, "_send_drift_email", send_email)
    monkeypatch.setattr(scheduled_drift_email.settings, "drift_email_interval_minutes", 15)
    monkeypatch.setattr(scheduled_drift_email.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(scheduled_drift_email, "_DIGEST_EMAIL_LAST_SENT_BY_OWNER", {})

    scheduled_drift_email._scan_accounts_and_email()
    assert send_email.call_count == 1
    assert scheduled_drift_email._DIGEST_EMAIL_LAST_SENT_BY_OWNER[10] == 0.0

    now[0] = elapsed_seconds
    scheduled_drift_email._scan_accounts_and_email()
    assert send_email.call_count == expected_send_count

    if expected_send_count == 2:
        assert scheduled_drift_email._DIGEST_EMAIL_LAST_SENT_BY_OWNER[10] == elapsed_seconds
    else:
        assert scheduled_drift_email._DIGEST_EMAIL_LAST_SENT_BY_OWNER[10] == 0.0


def test_failed_scheduled_digest_can_retry_one_minute_later(monkeypatch):
    accounts = [SimpleNamespace(id=1, name="away-account", owner_id=10)]

    class Query:
        def filter(self, *args):
            return self

        def order_by(self, *args):
            return self

        def all(self):
            return accounts

    class Session:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def query(self, model):
            return Query()

        def add(self, scan):
            scan.id = scan.account_id

        def commit(self):
            return None

        def refresh(self, scan):
            return None

    async def scan_account(account_id, **kwargs):
        return {
            "comparison": [{
                "resource_id": "resource-1",
                "resource_type": "test_resource",
                "severity": "high",
                "summary": "drift found",
                "is_drifted": True,
            }]
        }

    now = [0.0]
    send_email = Mock(side_effect=[RuntimeError("SMTP failed"), None])
    monkeypatch.setattr(scheduled_drift_email, "SessionLocal", Session)
    monkeypatch.setattr(scheduled_drift_email, "orchestrate_account_scan", scan_account)
    monkeypatch.setattr(scheduled_drift_email, "has_active_users", lambda: False)
    monkeypatch.setattr(scheduled_drift_email, "is_active", lambda user_id: False)
    monkeypatch.setattr(scheduled_drift_email, "_send_drift_email", send_email)
    monkeypatch.setattr(scheduled_drift_email, "_DIGEST_EMAIL_LAST_SENT_BY_OWNER", {})
    monkeypatch.setattr(scheduled_drift_email.time, "monotonic", lambda: now[0])

    with pytest.raises(RuntimeError, match="SMTP failed"):
        scheduled_drift_email._scan_accounts_and_email()
    assert 10 not in scheduled_drift_email._DIGEST_EMAIL_LAST_SENT_BY_OWNER

    now[0] = 60.0
    scheduled_drift_email._scan_accounts_and_email()

    assert send_email.call_count == 2
    assert scheduled_drift_email._DIGEST_EMAIL_LAST_SENT_BY_OWNER[10] == 60.0


def test_event_email_skips_active_owner_and_throttles(monkeypatch):
    from app.services import alert_dispatch_service
    from app.alerts import email_channel

    class Query:
        def filter(self, *args):
            return self

        def one_or_none(self):
            return SimpleNamespace(owner_id=10)

    class Session:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def query(self, model):
            return Query()

    send = Mock(return_value=True)
    monkeypatch.setattr(alert_dispatch_service, "SessionLocal", Session)
    monkeypatch.setattr(alert_dispatch_service, "is_active", lambda user_id: True)
    monkeypatch.setattr(alert_dispatch_service.email_channel, "send", send, raising=False)
    alert_dispatch_service._EMAIL_SEND_THROTTLE_BY_OWNER.clear()

    awaitable = alert_dispatch_service._dispatch_to_channel(email_channel, {}, {"account_id": 7})
    import asyncio
    asyncio.run(awaitable)

    send.assert_not_called()

    monkeypatch.setattr(alert_dispatch_service, "is_active", lambda user_id: False)
    monkeypatch.setattr(alert_dispatch_service.time, "monotonic", lambda: 0)
    alert_dispatch_service._EMAIL_SEND_THROTTLE_BY_OWNER[10] = 0
    send.reset_mock()
    asyncio.run(alert_dispatch_service._dispatch_to_channel(email_channel, {}, {"account_id": 7}))

    send.assert_not_called()

    monkeypatch.setattr(alert_dispatch_service.time, "monotonic", lambda: 1000)
    send.reset_mock()
    alert_dispatch_service._EMAIL_SEND_THROTTLE_BY_OWNER.pop(10, None)
    send.return_value = True
    asyncio.run(alert_dispatch_service._dispatch_to_channel(email_channel, {}, {"account_id": 7}))
    send.assert_called_once()

    send.return_value = False
    alert_dispatch_service._EMAIL_SEND_THROTTLE_BY_OWNER.clear()
    send.reset_mock()
    asyncio.run(alert_dispatch_service._dispatch_to_channel(email_channel, {}, {"account_id": 7}))
    assert 10 not in alert_dispatch_service._EMAIL_SEND_THROTTLE_BY_OWNER


def test_failed_event_email_does_not_throttle_next_attempt(monkeypatch):
    import asyncio

    from app.services import alert_dispatch_service
    from app.alerts import email_channel

    class Query:
        def filter(self, *args):
            return self

        def one_or_none(self):
            return SimpleNamespace(owner_id=10)

    class Session:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def query(self, model):
            return Query()

    send = Mock(side_effect=[False, True])
    monkeypatch.setattr(alert_dispatch_service, "SessionLocal", Session)
    monkeypatch.setattr(alert_dispatch_service, "is_active", lambda user_id: False)
    monkeypatch.setattr(alert_dispatch_service, "time", SimpleNamespace(monotonic=lambda: 100))
    monkeypatch.setattr(alert_dispatch_service, "_EMAIL_SEND_THROTTLE_BY_OWNER", {})
    monkeypatch.setattr(alert_dispatch_service.email_channel, "send", send, raising=False)

    asyncio.run(alert_dispatch_service._dispatch_to_channel(email_channel, {}, {"account_id": 7}))

    assert send.call_count == 1
    assert 10 not in alert_dispatch_service._EMAIL_SEND_THROTTLE_BY_OWNER

    asyncio.run(alert_dispatch_service._dispatch_to_channel(email_channel, {}, {"account_id": 7}))

    assert send.call_count == 2
    assert alert_dispatch_service._EMAIL_SEND_THROTTLE_BY_OWNER[10] == 100