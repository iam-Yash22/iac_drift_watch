"""Scheduled drift scans and consolidated email delivery."""

from __future__ import annotations

import asyncio
import json
import os
import smtplib
import ssl
import threading
import time
from email.message import EmailMessage
from typing import Any

from sqlalchemy.exc import IntegrityError

from app.core.config import settings
from app.core.logging_config import get_logger
from app.db.session import SessionLocal
from app.models.account import AwsAccount
from app.models.scan import Scan
from app.presence import has_active_users, is_active
from app.services.drift_orchestrator import _drift_items, orchestrate_account_scan


logger = get_logger(__name__)
_DIGEST_EMAIL_LAST_SENT_BY_OWNER: dict[int, float] = {}
_DIGEST_EMAIL_THROTTLE_LOCK = threading.Lock()
_DIGEST_EMAIL_THROTTLE_GRACE_SECONDS = 30


def drift_scan_interval_minutes() -> int:
    try:
        return max(1, int(os.getenv("DRIFT_SCAN_INTERVAL_MINUTES", "15")))
    except ValueError:
        return 15


def _smtp_configuration() -> tuple[str, int, str, str, str, list[str]]:
    host = os.getenv("SMTP_HOST", "smtp.gmail.com").strip()
    try:
        port = int(os.getenv("SMTP_PORT", "587"))
    except ValueError as exc:
        raise ValueError("SMTP_PORT must be an integer") from exc

    user = os.getenv("SMTP_USER") or settings.alert_sender_email or settings.gmail_address
    password = os.getenv("SMTP_PASSWORD")
    if not password:
        configured_password = settings.alert_sender_app_password or settings.gmail_app_password
        password = configured_password.get_secret_value() if configured_password else None
    sender = os.getenv("SMTP_FROM") or user
    raw_recipients = (
        os.getenv("SMTP_RECIPIENTS")
        or os.getenv("ALERT_TEST_RECIPIENT")
        or sender
        or ""
    )
    recipients = [address.strip() for address in raw_recipients.split(",") if address.strip()]

    if not host or not user or not password or not sender or not recipients:
        raise RuntimeError("SMTP_HOST, SMTP_USER, SMTP_PASSWORD, SMTP_FROM, and SMTP_RECIPIENTS are required")
    return host, port, user, password, sender, recipients


def _send_drift_email(resources: list[dict[str, Any]]) -> None:
    host, port, user, password, sender, recipients = _smtp_configuration()
    message = EmailMessage()
    message["Subject"] = f"IaC DriftWatch: {len(resources)} drifted resource(s) detected"
    message["From"] = sender
    message["To"] = ", ".join(recipients)
    lines = ["DriftWatch detected the following drifted resources:", ""]
    for resource in resources:
        account_id = resource.get("account_id", "unknown")
        lines.append(
            "- Account {account_name} ({account_id}); resource {resource_id}; "
            "type {resource_type}; severity {severity}; {summary}".format(
                account_name=resource.get("account_name", "unknown"),
                account_id=account_id,
                resource_id=resource.get("resource_id", "unknown"),
                resource_type=resource.get("resource_type", "unknown"),
                severity=resource.get("severity", "unknown"),
                summary=resource.get("summary", "Drift detected."),
            )
        )
        if resource.get("owner_name"):
            lines.append(f"Hi {resource['owner_name']}, drift was detected on account {account_id}.")
        lines.append(f"Account ID: {account_id}")
        if resource.get("scan_id") is not None:
            base_url = settings.app_base_url.rstrip("/")
            lines.append(f"{base_url}/accounts/{account_id}/scans/{resource['scan_id']}")
        if resource.get("diffs"):
            lines.append(json.dumps(resource["diffs"], sort_keys=True))
    message.set_content("\n".join(lines))

    if port == 465:
        with smtplib.SMTP_SSL(host, port, timeout=30, context=ssl.create_default_context()) as smtp:
            smtp.login(user, password)
            refused = smtp.send_message(message)
    else:
        with smtplib.SMTP(host, port, timeout=30) as smtp:
            smtp.ehlo()
            smtp.starttls(context=ssl.create_default_context())
            smtp.ehlo()
            smtp.login(user, password)
            refused = smtp.send_message(message)
    if refused:
        raise RuntimeError(f"SMTP refused recipients: {', '.join(refused)}")


def _scan_accounts_and_email() -> None:
    run_started_at = time.monotonic()

    async def scan_accounts() -> list[dict[str, Any]]:
        drifted_resources: list[dict[str, Any]] = []
        with SessionLocal() as db:
            accounts = (
                db.query(AwsAccount)
                .filter(AwsAccount.is_active.is_(True))
                .order_by(AwsAccount.id)
                .all()
            )
            logger.info("scheduled drift scan started", extra={"account_count": len(accounts)})

            for account in accounts:
                scan = Scan(account_id=account.id, status="queued")
                db.add(scan)
                try:
                    db.commit()
                    db.refresh(scan)
                except IntegrityError:
                    db.rollback()
                    logger.info(
                        "scheduled drift scan skipped account_id=%s reason=scan_in_progress",
                        account.id,
                    )
                    continue

                try:
                    result = await orchestrate_account_scan(
                        str(account.id),
                        trigger="scheduled",
                        db=db,
                        scan_id=scan.id,
                    )
                except Exception:
                    logger.exception("scheduled drift scan failed account_id=%s", account.id)
                    continue

                for item in _drift_items(result.get("comparison")):
                    if not item.get("is_drifted", True):
                        continue
                    drifted_resources.append(
                        {
                            **item,
                            "account_id": account.id,
                            "account_name": account.name,
                            "owner_id": getattr(account, "owner_id", None),
                            "owner_name": getattr(getattr(account, "owner", None), "username", None),
                            "scan_id": scan.id,
                        }
                    )
        return drifted_resources

    resources = asyncio.run(scan_accounts())
    if not resources:
        logger.info("scheduled drift scan completed; no drifted resources")
        return

    eligible_resources = []
    active_owner_ids = set()
    for resource in resources:
        owner_id = resource["owner_id"]
        if owner_id is not None:
            if is_active(owner_id):
                active_owner_ids.add(owner_id)
                continue
        eligible_resources.append(resource)

    if not eligible_resources:
        if active_owner_ids:
            logger.info(
                "scheduled drift email skipped; all drifted-resource owners are active",
                extra={"drifted_resource_count": len(resources)},
            )
        else:
            logger.info("scheduled drift email skipped; no drifted resources remain after filtering")
        return

    logger.info(
        "scheduled drift scan found drift",
        extra={"drifted_resource_count": len(eligible_resources)},
    )
    if has_active_users():
        logger.info(
            "scheduled drift email skipped; active users present",
            extra={"drifted_resource_count": len(eligible_resources)},
        )
        return

    interval_seconds = settings.drift_email_interval_minutes * 60
    with _DIGEST_EMAIL_THROTTLE_LOCK:
        remaining_resources = []
        for resource in eligible_resources:
            owner_id = resource["owner_id"]
            last_sent = (
                _DIGEST_EMAIL_LAST_SENT_BY_OWNER.get(owner_id)
                if owner_id is not None
                else None
            )
            if (
                owner_id is None
                or last_sent is None
                or run_started_at - last_sent
                >= interval_seconds - _DIGEST_EMAIL_THROTTLE_GRACE_SECONDS
            ):
                remaining_resources.append(resource)
        if not remaining_resources:
            logger.info("scheduled drift email skipped; all owners are throttled")
            return

        _send_drift_email(remaining_resources)
        for owner_id in {resource["owner_id"] for resource in remaining_resources}:
            if owner_id is not None:
                _DIGEST_EMAIL_LAST_SENT_BY_OWNER[owner_id] = run_started_at

    logger.info(
        "scheduled drift email sent",
        extra={"drifted_resource_count": len(remaining_resources)},
    )


async def run_scheduled_drift_email_scan() -> None:
    try:
        await asyncio.to_thread(_scan_accounts_and_email)
    except Exception:
        logger.exception("scheduled drift scan/email job failed")