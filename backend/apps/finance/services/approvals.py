from __future__ import annotations

import re

from django.db import IntegrityError, transaction

from apps.core import clock
from apps.finance.models import (
    ApprovalDecision,
    Decision,
    FinancialTransaction,
    TransactionKind,
    TransactionStatus,
)
from apps.finance.policies.limits import LimitExceeded, required_approvals, validate_transfer_limits
from apps.finance.policies.permissions import FinancePermissionDenied, require_permission
from apps.finance.services.audit import record_finance_event
from apps.finance.services.ledger import InsufficientFunds, InvalidLedgerPosting, LedgerLine, post_entries
from apps.finance.services.transfers import (
    TransferAccountNotFound,
    TransferError,
    _accounts_for_transfer,
    _fingerprint,
)
from apps.iam.models import Role, User
from apps.iam.policies.matrix import FINANCE_APPROVALS_DECIDE
from apps.iam.services.mfa_state import user_mfa_enabled


class ApprovalError(ValueError):
    pass


class ApprovalNotFound(ApprovalError):
    pass


_SENSITIVE_REASON = re.compile(
    r"(?:\b(?:pan|cvv|cvc|pin|password|contrase(?:ñ|n)a|token)\b)|(?:\d[\s-]?){12,19}",
    re.IGNORECASE,
)


def _validate_reason(reason: str, decision: str) -> str:
    reason = (reason or "").strip()
    if decision == Decision.REJECTED and not reason:
        raise ApprovalError("El motivo del rechazo es obligatorio.")
    if len(reason) > 240:
        raise ApprovalError("El motivo no puede superar 240 caracteres.")
    if _SENSITIVE_REASON.search(reason):
        raise ApprovalError("No incluyas credenciales ni datos de tarjeta en el motivo.")
    return reason


def _require_approver(user):
    try:
        require_permission(user, FINANCE_APPROVALS_DECIDE)
    except FinancePermissionDenied as exc:
        raise ApprovalError(str(exc)) from exc
    if user.role != Role.ADMIN or not user_mfa_enabled(user):
        raise ApprovalError("Se requiere Administrador con MFA habilitado.")


def _reject_pending(financial_transaction, reason: str):
    financial_transaction.status = TransactionStatus.REJECTED
    financial_transaction.rejection_reason = reason or "No se pudo completar la operación."
    financial_transaction.resolved_at = clock.now()
    financial_transaction.save(
        update_fields=["status", "rejection_reason", "resolved_at"]
    )
    record_finance_event(
        "finance_transfer_rejected",
        "denied",
        target_type="finance_transaction",
        target_id=financial_transaction.pk,
        metadata={"transaction_id": financial_transaction.pk, "reason": "revalidation_failed"},
    )


def decide_transfer(admin, transaction_id, decision: str, reason: str = "") -> FinancialTransaction:
    _require_approver(admin)
    if decision not in Decision.values:
        raise ApprovalError("La decisión no está permitida.")
    reason = _validate_reason(reason, decision)

    with transaction.atomic():
        try:
            financial_transaction = (
                FinancialTransaction.objects.select_for_update()
                .get(pk=transaction_id, kind=TransactionKind.TRANSFER)
            )
        except FinancialTransaction.DoesNotExist as exc:
            raise ApprovalNotFound("No se encontró la solicitud.") from exc

        if financial_transaction.status != TransactionStatus.PENDING_APPROVAL:
            raise ApprovalError("La solicitud ya fue resuelta.")
        if financial_transaction.creator_id == admin.pk:
            raise ApprovalError("El creador no puede aprobar ni rechazar su operación.")
        if ApprovalDecision.objects.filter(
            transaction=financial_transaction, approver=admin
        ).exists():
            raise ApprovalError("Este Administrador ya tomó una decisión sobre la solicitud.")

        creator = User.objects.select_for_update().get(pk=financial_transaction.creator_id)
        expected_fingerprint = _fingerprint(
            financial_transaction.source_account_id,
            financial_transaction.destination_account_id,
            financial_transaction.amount_minor,
            financial_transaction.currency,
            financial_transaction.description,
        )
        if expected_fingerprint != financial_transaction.request_fingerprint:
            raise ApprovalError("Los detalles de la solicitud cambiaron; no se puede aprobar.")

        try:
            ApprovalDecision.objects.create(
                transaction=financial_transaction,
                approver=admin,
                decision=decision,
                request_fingerprint=expected_fingerprint,
                reason=reason,
            )
        except IntegrityError as exc:
            raise ApprovalError("Este Administrador ya tomó una decisión.") from exc

        record_finance_event(
            "finance_approval_decided",
            "success" if decision == Decision.APPROVED else "denied",
            actor=admin,
            target_type="finance_transaction",
            target_id=financial_transaction.pk,
            metadata={
                "transaction_id": financial_transaction.pk,
                "decision": decision,
                "reason": "decision_recorded",
            },
        )

        if decision == Decision.REJECTED:
            financial_transaction.status = TransactionStatus.REJECTED
            financial_transaction.rejection_reason = reason
            financial_transaction.resolved_at = clock.now()
            financial_transaction.save(
                update_fields=["status", "rejection_reason", "resolved_at"]
            )
            record_finance_event(
                "finance_transfer_rejected",
                "denied",
                actor=admin,
                target_type="finance_transaction",
                target_id=financial_transaction.pk,
                metadata={
                    "transaction_id": financial_transaction.pk,
                    "reason": "admin_rejected",
                },
            )
            return financial_transaction

        approval_count = ApprovalDecision.objects.filter(
            transaction=financial_transaction, decision=Decision.APPROVED
        ).count()
        if approval_count < financial_transaction.approval_count_required:
            return financial_transaction

        try:
            source, destination = _accounts_for_transfer(
                creator,
                financial_transaction.source_account_id,
                financial_transaction.destination_account_id,
                lock=True,
            )
            approvals_now = validate_transfer_limits(
                creator,
                financial_transaction.amount_minor,
                financial_transaction.currency,
                exclude_transaction_id=financial_transaction.pk,
            )
            if approvals_now != financial_transaction.approval_count_required:
                raise TransferError("La política de aprobación cambió.")
            if source.available_balance_minor < financial_transaction.amount_minor:
                raise InsufficientFunds("Saldo insuficiente.")
            financial_transaction.status = TransactionStatus.COMPLETED
            financial_transaction.resolved_at = clock.now()
            financial_transaction.save(update_fields=["status", "resolved_at"])
            post_entries(
                financial_transaction,
                [
                    LedgerLine(source.pk, -financial_transaction.amount_minor),
                    LedgerLine(destination.pk, financial_transaction.amount_minor),
                ],
            )
        except (TransferAccountNotFound, TransferError, LimitExceeded, InsufficientFunds, InvalidLedgerPosting) as exc:
            _reject_pending(financial_transaction, str(exc))
            return financial_transaction

        record_finance_event(
            "finance_transfer_completed",
            "success",
            actor=admin,
            target_type="finance_transaction",
            target_id=financial_transaction.pk,
            metadata={
                "transaction_id": financial_transaction.pk,
                "amount_minor": financial_transaction.amount_minor,
                "currency": financial_transaction.currency,
                "correlation_id": financial_transaction.correlation_id,
            },
        )
        return financial_transaction
