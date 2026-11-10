from django.db import migrations


DEFAULTS = {
    "COP": {
        "per_transaction": (1_000_000_000, None, None),
        "daily": (2_000_000_000, None, None),
        "monthly": (10_000_000_000, None, None),
        "frequency": (None, 20, 86_400),
    },
    "USD": {
        "per_transaction": (250_000, None, None),
        "daily": (500_000, None, None),
        "monthly": (2_500_000, None, None),
        "frequency": (None, 20, 86_400),
    },
}


def seed_limits(apps, schema_editor):
    FinancialLimit = apps.get_model("finance", "FinancialLimit")
    for currency, limits in DEFAULTS.items():
        for kind, (amount, count, period) in limits.items():
            FinancialLimit.objects.get_or_create(
                scope_type="role",
                scope_id="client",
                currency=currency,
                limit_kind=kind,
                defaults={
                    "amount_minor": amount,
                    "operation_count": count,
                    "period_seconds": period,
                    "active": True,
                    "reason": "Política inicial de demostración",
                },
            )


def remove_seed_limits(apps, schema_editor):
    FinancialLimit = apps.get_model("finance", "FinancialLimit")
    FinancialLimit.objects.filter(
        scope_type="role",
        scope_id="client",
        reason="Política inicial de demostración",
    ).delete()


class Migration(migrations.Migration):
    dependencies = [("finance", "0002_protect_ledger")]

    operations = [migrations.RunPython(seed_limits, remove_seed_limits)]
