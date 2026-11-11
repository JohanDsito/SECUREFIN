from __future__ import annotations

import hashlib
import json

from django.db import transaction

from apps.core import clock
from apps.finance.models import (
    AccountStatus,
    Currency,
    DemoAccount,
    FinancialTransaction,
    TransactionKind,
    TransactionStatus,
)
from apps.finance.policies.limits import LimitExceeded, required_approvals, validate_transfer_limits
from apps.finance.policies.permissions import require_permission
from apps.finance.services.audit import record_finance_event
from apps.finance.services.ledger import InsufficientFunds, InvalidLedgerPosting, LedgerLine, post_entries
from apps.iam.models import Role, User
from apps.iam.policies.matrix import FINANCE_TRANSFERS_CREATE


class TransferError(ValueError):
    pass


class TransferAccountNotFound(TransferError):
    pass


class IdempotencyConflict(TransferError):
    pass


def _require_client(user):
    require_permission(user, FINANCE_TRANSFERS_CREATE)
    if user.role != Role.CLIENT:
        raise PermissionError("Las transferencias simuladas solo están disponibles para Clientes.")


def _fingerprint(source_account_id, destination_account_id, amount_minor, currency, description) -> str:
    payload = {
        "source_account_id": str(source_account_id),
        "destination_account_id": str(destination_account_id),
        "amount_minor": amount_minor,
        "currency": currency,
        "description": description,
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    ).hexdigest()


def _accounts_for_transfer(user, source_id, destination_id, *, lock=False):
    if source_id == destination_id:
        raise TransferError("El origen y el destino deben ser cuentas distintas.")
    accounts_query = DemoAccount.objects.filter(pk__in=[source_id, destination_id]).order_by("pk")
    if lock:
        accounts_query = accounts_query.select_for_update()
    accounts = {account.pk: account for account in accounts_query}
    source = accounts.get(source_id)
    destination = accounts.get(destination_id)
    if source is not None and source.owner_id != user.pk:
        source = None
    if source is None or destination is None or destination.is_system:
        raise TransferAccountNotFound("No se encontró una cuenta disponible para la operación.")
    if source.status != AccountStatus.ACTIVE or destination.status != AccountStatus.ACTIVE:
        raise TransferError("Ambas cuentas deben estar activas.")
    if source.currency != destination.currency:
        raise TransferError("Las cuentas deben usar la misma moneda.")
    return source, destination


def _validate_amount(amount_minor, currency):
    if not isinstance(amount_minor, int) or isinstance(amount_minor, bool) or amount_minor <= 0:
        raise TransferError("El importe debe ser un entero positivo.")
    if currency not in Currency.values:
        raise TransferError("La moneda no está habilitada.")


def preview_transfer(user, source_account_id, destination_account_id, amount_minor, currency, description=""):
    _require_client(user)
    _validate_amount(amount_minor, currency)
    source, destination = _accounts_for_transfer(user, source_account_id, destination_account_id)
    if source.currency != currency or destination.currency != currency:
        raise TransferError("La moneda no coincide con ambas cuentas.")
    try:
        approvals = validate_transfer_limits(user, amount_minor, currency)
    except LimitExceeded as exc:
        raise TransferError(str(exc)) from exc
    if source.available_balance_minor < amount_minor:
        raise TransferError("Saldo insuficiente.")
    return {
        "source_account": source.masked_number,
        "destination_account": destination.masked_number,
        "amount_minor": amount_minor,
        "currency": currency,
        "description": description,
        "fee_minor": 0,
        "approval_count_required": approvals,
        "status": (
            TransactionStatus.PENDING_APPROVAL if approvals else TransactionStatus.COMPLETED
        ),
    }


def create_transfer(
    user,
    source_account_id,
    destination_account_id,
    amount_minor: int,
    currency: str,
    description: str,
    idempotency_key: str,
) -> FinancialTransaction:
    _require_client(user)
    _validate_amount(amount_minor, currency)
    if not description or len(description) > 140:
        if description and len(description) > 140:
            raise TransferError("La descripción no puede superar 140 caracteres.")
        description = ""

    fingerprint = _fingerprint(
        source_account_id, destination_account_id, amount_minor, currency, description
    )
    with transaction.atomic():
        User.objects.select_for_update().get(pk=user.pk)
        existing = FinancialTransaction.objects.filter(
            creator=user, idempotency_key=idempotency_key
        ).first()
        if existing is not None:
            if existing.request_fingerprint != fingerprint:
                raise IdempotencyConflict(
                    "La clave de idempotencia ya se utilizó con otros datos."
                )
            return existing

        source, destination = _accounts_for_transfer(
            user, source_account_id, destination_account_id, lock=True
        )
        if source.currency != currency or destination.currency != currency:
            raise TransferError("La moneda no coincide con ambas cuentas.")

        try:
            approvals = validate_transfer_limits(user, amount_minor, currency)
        except LimitExceeded as exc:
            raise TransferError(str(exc)) from exc

        if source.available_balance_minor < amount_minor:
            raise TransferError("Saldo insuficiente.")

        status_value = (
            TransactionStatus.PENDING_APPROVAL if approvals else TransactionStatus.COMPLETED
        )
        financial_transaction = FinancialTransaction.objects.create(
            kind=TransactionKind.TRANSFER,
            status=status_value,
            creator=user,
            source_account=source,
            destination_account=destination,
            amount_minor=amount_minor,
            currency=currency,
            description=description,
            idempotency_key=idempotency_key,
            request_fingerprint=fingerprint,
            risk_level="low",
            approval_count_required=approvals,
            resolved_at=clock.now() if not approvals else None,
        )
        record_finance_event(
            "finance_transfer_created",
            "success",
            actor=user,
            target_type="finance_transaction",
            target_id=financial_transaction.pk,
            metadata={
                "transaction_id": financial_transaction.pk,
                "amount_minor": amount_minor,
                "currency": currency,
                "status": status_value,
                "correlation_id": financial_transaction.correlation_id,
            },
        )
        if approvals:
            return financial_transaction

        try:
            post_entries(
                financial_transaction,
                [LedgerLine(source.pk, -amount_minor), LedgerLine(destination.pk, amount_minor)],
            )
        except InsufficientFunds as exc:
            raise TransferError("Saldo insuficiente.") from exc
        except InvalidLedgerPosting as exc:
            raise TransferError(str(exc)) from exc
        record_finance_event(
            "finance_transfer_completed",
            "success",
            actor=user,
            target_type="finance_transaction",
            target_id=financial_transaction.pk,
            metadata={
                "transaction_id": financial_transaction.pk,
                "amount_minor": amount_minor,
                "currency": currency,
                "correlation_id": financial_transaction.correlation_id,
            },
        )
        return financial_transaction
