import pytest
from types import SimpleNamespace
from unittest import mock

import boto3
from pydantic import SecretStr
from app.models.scan import Scan

import app.crud.crud_resource as crud_resource_module
import app.models.account as account_model
import app.services.drift_orchestrator as orchestrator
import app.services.aws_client_factory as aws_client_factory


@pytest.mark.asyncio
async def test_orchestrator_calls_crud_and_publishes_event(db_session, monkeypatch):
    mock_account = mock.Mock()
    monkeypatch.setattr(
        orchestrator.crud_account,
        "get_by_id",
        mock.AsyncMock(return_value=mock_account),
        raising=False,
    )
    monkeypatch.setattr(
        orchestrator.aws_client_factory,
        "get_clients_for_account",
        mock.AsyncMock(return_value={"ec2": mock.Mock(), "s3": None, "iam": None, "rds": None}),
        raising=False,
    )
    monkeypatch.setattr(
        orchestrator.aws_resource_fetchers,
        "fetch_ec2_instances",
        mock.AsyncMock(return_value=[{"id": "i-1"}]),
        raising=False,
    )
    monkeypatch.setattr(
        orchestrator.aws_resource_fetchers,
        "fetch_security_groups",
        mock.AsyncMock(return_value=[]),
        raising=False,
    )
    monkeypatch.setattr(
        orchestrator.aws_parser,
        "normalize_live_resources",
        mock.AsyncMock(return_value=[{"id": "r1"}]),
        raising=False,
    )
    monkeypatch.setattr(
        orchestrator.drift_engine,
        "compare_resources",
        mock.AsyncMock(
            return_value=[{
                "resource_id": "r1",
                "resource_type": "ec2_instance",
                "is_drifted": True,
                "diffs": {"resource": {"desired": {"id": "r1"}, "actual": {"id": "r1"}}},
            }]
        ),
        raising=False,
    )

    mock_upsert = mock.AsyncMock()
    mock_create = mock.AsyncMock()
    mock_publish = mock.Mock()
    monkeypatch.setattr(orchestrator.crud_resource, "upsert_many", mock_upsert, raising=False)
    monkeypatch.setattr(orchestrator.crud_drift, "create", mock_create, raising=False)
    monkeypatch.setattr(orchestrator.events, "publish", mock_publish, raising=False)

    account = account_model.AwsAccount(
        account_id="123456789012",
        name="crud and publish account",
        role_arn="arn:aws:iam::123456789012:role/DriftWatch",
        is_active=True,
    )
    db_session.add(account)
    db_session.commit()

    result = await orchestrator.orchestrate_account_scan("123", db=db_session)

    mock_upsert.assert_awaited_once()
    mock_create.assert_awaited_once()
    mock_publish.assert_called_once()
    assert result == {
        "account_id": "123",
        "comparison": [{
            "resource_id": "r1",
            "resource_type": "ec2_instance",
            "is_drifted": True,
            "diffs": {"resource": {"desired": {"id": "r1"}, "actual": {"id": "r1"}}},
        }],
    }


@pytest.mark.asyncio
async def test_orchestrator_skips_unmatched_live_resources(db_session, monkeypatch):
    account = account_model.AwsAccount(
        account_id="123456789012",
        name="unmatched resource account",
        role_arn="arn:aws:iam::123456789012:role/DriftWatch",
        is_active=True,
    )
    db_session.add(account)
    db_session.commit()
    db_session.refresh(account)

    monkeypatch.setattr(orchestrator.crud_account, "get_by_id", mock.AsyncMock(return_value=account), raising=False)
    monkeypatch.setattr(
        orchestrator,
        "_load_terraform_reference",
        mock.Mock(return_value=[{"resource_id": "r1", "resource_type": "ec2_instance"}]),
    )
    monkeypatch.setattr(
        orchestrator.aws_client_factory,
        "get_clients_for_account",
        mock.AsyncMock(return_value={"ec2": mock.Mock(), "s3": None, "iam": None, "rds": None}),
        raising=False,
    )
    monkeypatch.setattr(orchestrator.aws_resource_fetchers, "fetch_ec2_instances", mock.AsyncMock(return_value=[{"id": "r1", "resource_type": "ec2_instance"}]), raising=False)
    monkeypatch.setattr(orchestrator.aws_resource_fetchers, "fetch_security_groups", mock.AsyncMock(return_value=[]), raising=False)
    monkeypatch.setattr(orchestrator.aws_parser, "normalize_live_resources", mock.AsyncMock(return_value=[{"resource_id": "r1", "resource_type": "ec2_instance"}]), raising=False)
    monkeypatch.setattr(
        orchestrator.drift_engine,
        "compare_resources",
        mock.AsyncMock(return_value=[{"resource_id": "r1", "resource_type": "ec2_instance", "is_drifted": True, "diffs": {"resource": {"desired": None, "actual": {"id": "r1"}}}}]),
        raising=False,
    )
    mock_upsert = mock.AsyncMock()
    mock_create = mock.AsyncMock()
    mock_publish = mock.Mock()
    monkeypatch.setattr(orchestrator.crud_resource, "upsert_many", mock_upsert, raising=False)
    monkeypatch.setattr(orchestrator.crud_drift, "create", mock_create, raising=False)
    monkeypatch.setattr(orchestrator.events, "publish", mock_publish, raising=False)

    result = await orchestrator.orchestrate_account_scan(str(account.id), db=db_session)

    mock_upsert.assert_awaited_once()
    mock_create.assert_awaited_once()
    assert mock_create.await_args.kwargs["obj_in"]["comparison"] == []
    mock_publish.assert_not_called()
    assert result["comparison"] == []


@pytest.mark.asyncio
async def test_orchestrator_detects_baselined_ec2_missing_after_successful_fetch(db_session, monkeypatch):
    account = account_model.AwsAccount(
        account_id="123456789012",
        name="missing live resource account",
        role_arn="arn:aws:iam::123456789012:role/DriftWatch",
        is_active=True,
    )
    db_session.add(account)
    db_session.commit()
    db_session.refresh(account)

    resource = orchestrator.crud_resource.crud_resource.model(
        account_id=account.id,
        resource_id="r1",
        resource_type="ec2_instance",
        region="us-east-1",
    )
    db_session.add(resource)
    db_session.commit()
    db_session.refresh(resource)

    baseline = orchestrator.drift_engine.NormalizedResource(
        resource_id="r1",
        resource_type="ec2_instance",
        properties={"instance_type": "t3.micro"},
    )
    monkeypatch.setattr(orchestrator.crud_account, "get_by_id", mock.AsyncMock(return_value=account), raising=False)
    monkeypatch.setattr(orchestrator, "_load_terraform_reference", mock.Mock(return_value=[baseline]))
    monkeypatch.setattr(
        orchestrator.aws_client_factory,
        "get_clients_for_account",
        mock.AsyncMock(return_value={"ec2": mock.Mock(), "s3": None, "iam": None, "rds": None}),
        raising=False,
    )
    monkeypatch.setattr(
        orchestrator.aws_resource_fetchers,
        "fetch_ec2_instances",
        mock.AsyncMock(return_value=[]),
        raising=False,
    )
    monkeypatch.setattr(
        orchestrator.aws_resource_fetchers,
        "fetch_security_groups",
        mock.AsyncMock(return_value=[]),
        raising=False,
    )
    monkeypatch.setattr(orchestrator.aws_parser, "normalize_live_resources", mock.AsyncMock(return_value=[]), raising=False)
    publish = mock.Mock()
    monkeypatch.setattr(orchestrator.events, "publish", publish, raising=False)

    result = await orchestrator.orchestrate_account_scan(str(account.id), db=db_session)

    drift_record = (
        db_session.query(orchestrator.crud_drift.crud_drift.model)
        .filter(orchestrator.crud_drift.crud_drift.model.tracked_resource_id == resource.id)
        .one()
    )
    assert drift_record.reconciled is False
    assert result["comparison"][0].resource_id == "r1"
    assert result["comparison"][0].is_drifted is True
    publish.assert_called_once_with(
        "DriftDetectedEvent",
        {"account_id": account.id, "comparison": result["comparison"]},
    )


@pytest.mark.asyncio
async def test_orchestrator_does_not_mark_unfetched_aws_vpc_as_missing(db_session, monkeypatch):
    account = account_model.AwsAccount(
        account_id="123456789012",
        name="unfetched vpc account",
        role_arn="arn:aws:iam::123456789012:role/DriftWatch",
        is_active=True,
    )
    db_session.add(account)
    db_session.commit()
    db_session.refresh(account)

    baseline = orchestrator.drift_engine.NormalizedResource(
        resource_id="vpc-1",
        resource_type="aws_vpc",
        properties={"resource_id": "vpc-1"},
    )
    monkeypatch.setattr(orchestrator.crud_account, "get_by_id", mock.AsyncMock(return_value=account), raising=False)
    monkeypatch.setattr(orchestrator, "_load_terraform_reference", mock.Mock(return_value=[baseline]))
    monkeypatch.setattr(
        orchestrator.aws_client_factory,
        "get_clients_for_account",
        mock.AsyncMock(return_value={"ec2": None, "s3": None, "iam": None, "rds": None}),
        raising=False,
    )
    monkeypatch.setattr(orchestrator.aws_parser, "normalize_live_resources", mock.AsyncMock(return_value=[]), raising=False)
    publish = mock.Mock()
    monkeypatch.setattr(orchestrator.events, "publish", publish, raising=False)

    result = await orchestrator.orchestrate_account_scan(str(account.id), db=db_session)

    assert result["comparison"] == []
    assert db_session.query(orchestrator.crud_drift.crud_drift.model).count() == 0
    publish.assert_not_called()


@pytest.mark.asyncio
async def test_orchestrator_does_not_mark_ec2_missing_when_fetch_fails(db_session, monkeypatch):
    account = account_model.AwsAccount(
        account_id="123456789012",
        name="failed ec2 fetch account",
        role_arn="arn:aws:iam::123456789012:role/DriftWatch",
        is_active=True,
    )
    db_session.add(account)
    db_session.commit()
    db_session.refresh(account)

    baseline = orchestrator.drift_engine.NormalizedResource(
        resource_id="r1",
        resource_type="ec2_instance",
        properties={"resource_id": "r1"},
    )
    monkeypatch.setattr(orchestrator.crud_account, "get_by_id", mock.AsyncMock(return_value=account), raising=False)
    monkeypatch.setattr(orchestrator, "_load_terraform_reference", mock.Mock(return_value=[baseline]))
    monkeypatch.setattr(
        orchestrator.aws_client_factory,
        "get_clients_for_account",
        mock.AsyncMock(return_value={"ec2": mock.Mock(), "s3": None, "iam": None, "rds": None}),
        raising=False,
    )
    monkeypatch.setattr(
        orchestrator.aws_resource_fetchers,
        "fetch_ec2_instances",
        mock.AsyncMock(side_effect=RuntimeError("EC2 fetch failed")),
        raising=False,
    )
    publish = mock.Mock()
    monkeypatch.setattr(orchestrator.events, "publish", publish, raising=False)

    with pytest.raises(orchestrator.exceptions.ServiceError, match="Failed to fetch live resources"):
        await orchestrator.orchestrate_account_scan(str(account.id), db=db_session)

    assert db_session.query(orchestrator.crud_drift.crud_drift.model).count() == 0
    publish.assert_not_called()


def test_state_baseline_skips_data_and_unmanaged_resources():
    for mode in ("data", "unmanaged"):
        assert orchestrator._state_resource_to_baseline(
            {
                "mode": mode,
                "type": "aws_instance",
                "name": "not-managed",
                "instances": [{"attributes": {"id": "i-1", "name": "not-managed"}}],
            }
        ) is None


@pytest.mark.asyncio
async def test_orchestrator_alerts_only_on_drift_transition_and_reconciles(db_session, monkeypatch):
    account = account_model.AwsAccount(
        account_id="123456789012",
        name="Alert transition account",
        role_arn="arn:aws:iam::123456789012:role/DriftWatch",
        is_active=True,
    )
    db_session.add(account)
    db_session.commit()
    db_session.refresh(account)

    monkeypatch.setattr(orchestrator.crud_account, "get_by_id", mock.AsyncMock(return_value=account), raising=False)
    monkeypatch.setattr(
        orchestrator,
        "_load_terraform_reference",
        mock.Mock(return_value=[{"resource_id": "r1", "resource_type": "ec2_instance"}]),
    )
    monkeypatch.setattr(
        orchestrator.aws_client_factory,
        "get_clients_for_account",
        mock.AsyncMock(return_value={"ec2": mock.Mock(), "s3": None, "iam": None, "rds": None}),
        raising=False,
    )
    monkeypatch.setattr(
        orchestrator.aws_resource_fetchers,
        "fetch_ec2_instances",
        mock.AsyncMock(return_value=[{"id": "r1", "resource_type": "ec2_instance"}]),
        raising=False,
    )
    monkeypatch.setattr(orchestrator.aws_resource_fetchers, "fetch_security_groups", mock.AsyncMock(return_value=[]), raising=False)
    monkeypatch.setattr(
        orchestrator.aws_parser,
        "normalize_live_resources",
        mock.AsyncMock(return_value=[{"resource_id": "r1", "resource_type": "ec2_instance"}]),
        raising=False,
    )
    resource = orchestrator.crud_resource.crud_resource.model(
        account_id=account.id,
        resource_id="r1",
        resource_type="ec2_instance",
        region="us-east-1",
    )
    db_session.add(resource)
    db_session.commit()
    db_session.refresh(resource)

    comparison = [{
        "resource_id": "r1",
        "resource_type": "ec2_instance",
        "is_drifted": True,
        "diffs": {"resource": {"desired": {"id": "r1"}, "actual": {"id": "r1", "changed": True}}},
    }]
    compare = mock.AsyncMock(side_effect=[comparison, comparison, [{**comparison[0], "is_drifted": False, "diffs": {"resource": {"desired": {"id": "r1"}, "actual": {"id": "r1"}}}}]])
    monkeypatch.setattr(orchestrator.drift_engine, "compare_resources", compare, raising=False)
    monkeypatch.setattr(orchestrator.events, "publish", mock.Mock(), raising=False)

    await orchestrator.orchestrate_account_scan(str(account.id), db=db_session)
    await orchestrator.orchestrate_account_scan(str(account.id), db=db_session)
    await orchestrator.orchestrate_account_scan(str(account.id), db=db_session)

    assert compare.await_count == 3
    assert (
        db_session.query(orchestrator.Alert)
        .filter(orchestrator.Alert.resource_id == "r1")
        .count()
        == 1
    )
    latest_record = (
        db_session.query(orchestrator.crud_drift.crud_drift.model)
        .filter(orchestrator.crud_drift.crud_drift.model.tracked_resource_id == resource.id)
        .order_by(orchestrator.crud_drift.crud_drift.model.id.desc())
        .first()
    )
    assert latest_record is not None
    assert latest_record.reconciled is True


@pytest.mark.asyncio
async def test_skipped_resource_reconciles_old_drift_and_is_excluded_from_scheduled_digest(db_session, monkeypatch):
    import asyncio

    from app.services import scheduled_drift_email

    account = account_model.AwsAccount(
        account_id="123456789012",
        name="scheduled reconcile account",
        role_arn="arn:aws:iam::123456789012:role/DriftWatch",
        is_active=True,
    )
    db_session.add(account)
    db_session.commit()
    db_session.refresh(account)

    desired = orchestrator.drift_engine.NormalizedResource(
        resource_id="r1",
        resource_type="ec2_instance",
        tags={"environment": "desired"},
    )
    live = orchestrator.drift_engine.NormalizedResource(
        resource_id="r1",
        resource_type="ec2_instance",
        tags={"environment": "live"},
    )
    baseline_calls = iter(([desired], []))
    monkeypatch.setattr(orchestrator.crud_account, "get_by_id", mock.AsyncMock(return_value=account), raising=False)
    monkeypatch.setattr(
        orchestrator,
        "_load_terraform_reference",
        mock.Mock(side_effect=lambda *args: next(baseline_calls)),
    )
    monkeypatch.setattr(orchestrator.terraform_parser, "normalize_resources", mock.Mock(return_value=[]))
    monkeypatch.setattr(
        orchestrator.aws_client_factory,
        "get_clients_for_account",
        mock.AsyncMock(return_value={"ec2": None, "s3": None, "iam": None, "rds": None}),
        raising=False,
    )
    monkeypatch.setattr(orchestrator.aws_parser, "normalize_live_resources", mock.AsyncMock(return_value=[live]), raising=False)

    await orchestrator.orchestrate_account_scan(str(account.id), db=db_session)
    tracked_resource = (
        db_session.query(orchestrator.crud_resource.crud_resource.model)
        .filter(
            orchestrator.crud_resource.crud_resource.model.account_id == account.id,
            orchestrator.crud_resource.crud_resource.model.resource_id == "r1",
        )
        .one()
    )
    old_drift = (
        db_session.query(orchestrator.crud_drift.crud_drift.model)
        .filter(orchestrator.crud_drift.crud_drift.model.tracked_resource_id == tracked_resource.id)
        .one()
    )
    assert old_drift.reconciled is False
    old_drift_id = old_drift.id

    monkeypatch.setattr(scheduled_drift_email, "SessionLocal", lambda: db_session)
    monkeypatch.setattr(
        scheduled_drift_email,
        "orchestrate_account_scan",
        lambda account_id, **kwargs: orchestrator.orchestrate_account_scan(
            account_id,
            db=db_session,
            scan_id=kwargs["scan_id"],
        ),
    )
    monkeypatch.setattr(scheduled_drift_email, "has_active_users", lambda: False)
    send_digest = mock.Mock()
    monkeypatch.setattr(scheduled_drift_email, "_send_drift_email", send_digest)

    await asyncio.to_thread(scheduled_drift_email._scan_accounts_and_email)

    reconciled_record = (
        db_session.query(orchestrator.crud_drift.crud_drift.model)
        .filter(orchestrator.crud_drift.crud_drift.model.id == old_drift_id)
        .one()
    )
    assert reconciled_record.reconciled is True
    send_digest.assert_not_called()


@pytest.mark.asyncio
async def test_orchestrator_with_no_drift_does_not_publish_event(db_session, monkeypatch):
    mock_account = mock.Mock()
    monkeypatch.setattr(
        orchestrator.crud_account,
        "get_by_id",
        mock.AsyncMock(return_value=mock_account),
        raising=False,
    )
    monkeypatch.setattr(
        orchestrator.aws_client_factory,
        "get_clients_for_account",
        mock.AsyncMock(return_value={"ec2": None, "s3": None, "iam": None, "rds": None}),
        raising=False,
    )
    monkeypatch.setattr(
        orchestrator.aws_parser,
        "normalize_live_resources",
        mock.AsyncMock(return_value=[]),
        raising=False,
    )
    monkeypatch.setattr(
        orchestrator.drift_engine,
        "compare_resources",
        mock.AsyncMock(return_value=[]),
        raising=False,
    )

    mock_publish = mock.Mock()
    monkeypatch.setattr(orchestrator.crud_resource, "upsert_many", mock.AsyncMock(), raising=False)
    monkeypatch.setattr(orchestrator.crud_drift, "create", mock.AsyncMock(), raising=False)
    monkeypatch.setattr(orchestrator.events, "publish", mock_publish, raising=False)

    account = account_model.AwsAccount(
        account_id="123456789012",
        name="no drift publish account",
        role_arn="arn:aws:iam::123456789012:role/DriftWatch",
        is_active=True,
    )
    db_session.add(account)
    db_session.commit()

    await orchestrator.orchestrate_account_scan("123", db=db_session)

    mock_publish.assert_not_called()


@pytest.mark.asyncio
async def test_orchestrator_persists_scan_result(db_session, monkeypatch):
    account = account_model.AwsAccount(
        account_id="123456789012",
        name="Scan result account",
        role_arn="arn:aws:iam::123456789012:role/DriftWatch",
        is_active=True,
    )
    db_session.add(account)
    db_session.commit()
    db_session.refresh(account)
    scan = Scan(account_id=account.id, status="queued")
    db_session.add(scan)
    db_session.commit()
    db_session.refresh(scan)

    monkeypatch.setattr(
        orchestrator.crud_account,
        "get_by_id",
        mock.AsyncMock(return_value=account),
        raising=False,
    )
    monkeypatch.setattr(
        orchestrator.aws_client_factory,
        "get_clients_for_account",
        mock.AsyncMock(return_value={"ec2": None, "s3": None, "iam": None, "rds": None}),
        raising=False,
    )
    monkeypatch.setattr(orchestrator.aws_parser, "normalize_live_resources", mock.AsyncMock(return_value=[]), raising=False)
    monkeypatch.setattr(
        orchestrator.drift_engine,
        "compare_resources",
        mock.AsyncMock(return_value=[]),
        raising=False,
    )
    monkeypatch.setattr(orchestrator.crud_resource, "upsert_many", mock.AsyncMock(), raising=False)
    monkeypatch.setattr(orchestrator.crud_drift, "create", mock.AsyncMock(), raising=False)

    await orchestrator.orchestrate_account_scan(str(account.id), db=db_session, scan_id=scan.id)

    db_session.refresh(scan)
    assert scan.status == "completed"
    assert scan.result["summary"]["total_resources"] == 0
    assert scan.result["drifts"] == []


def test_assume_role_uses_standard_aws_environment_fallback(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIASTANDARD123")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "standard-secret")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "standard-session-token")
    monkeypatch.setattr(
        aws_client_factory.config,
        "settings",
        SimpleNamespace(
            cloud=SimpleNamespace(
                aws_access_key_id=None,
                aws_secret_access_key=None,
                aws_session_token=None,
                region="us-east-1",
            )
        ),
    )
    aws_client_factory._CREDENTIALS_CACHE.clear()

    fake_sts = mock.Mock()
    fake_sts.assume_role.return_value = {
        "Credentials": {
            "AccessKeyId": "ASIAASSUMED123",
            "SecretAccessKey": "assumed-secret",
            "SessionToken": "assumed-token",
            "Expiration": __import__("datetime").datetime.now(__import__("datetime").timezone.utc),
        }
    }
    fake_session = mock.Mock()
    fake_session.client.return_value = fake_sts
    fake_session_class = mock.Mock(return_value=fake_session)
    monkeypatch.setattr(boto3, "Session", fake_session_class)

    creds = aws_client_factory.assume_role("arn:aws:iam::123456789012:role/DriftWatch")

    assert creds["AccessKeyId"] == "ASIAASSUMED123"
    assert fake_session_class.call_args.kwargs["aws_access_key_id"] == "AKIASTANDARD123"
    assert fake_session_class.call_args.kwargs["aws_secret_access_key"] == "standard-secret"
    assert fake_session_class.call_args.kwargs["aws_session_token"] == "standard-session-token"
    fake_session.client.assert_called_once_with("sts")


def test_upsert_many_persists_live_resources_for_account(db_session):
    account = account_model.AwsAccount(
        account_id="123456789012",
        name="Live account",
        role_arn="arn:aws:iam::123456789012:role/DriftWatch",
        is_active=True,
    )
    db_session.add(account)
    db_session.commit()
    db_session.refresh(account)

    resources = [{
        "account_id": account.id,
        "resource_id": "i-abc123",
        "resource_type": "ec2_instance",
        "region": "us-east-1",
        "tags": {"env": "dev"},
        "configuration": {"instance_type": "t3.micro"},
    }]

    inserted = crud_resource_module.crud_resource.upsert_many(db_session, account_id=account.id, resources=resources)

    assert len(inserted) == 1
    assert inserted[0].account_id == account.id
    assert inserted[0].resource_id == "i-abc123"
