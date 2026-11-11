from django.apps import AppConfig
from django.db.models.signals import pre_migrate


class CoreConfig(AppConfig):
    name = "apps.core"
    label = "core"
    verbose_name = "SecureFin core"

    def ready(self):
        from django.conf import settings

        from apps.core import keys

        # T027: validación de claves y del rol del proceso al arrancar (falla de forma cerrada).
        keys.validate_all(db_user=settings.DATABASES["default"].get("USER"))
        # Django solo emite pre_migrate para apps con modelos (core no tiene): se conecta sin
        # restringir el emisor; las sentencias son idempotentes.
        pre_migrate.connect(_grant_default_privileges, dispatch_uid="securefin_default_privileges")


def _grant_default_privileges(sender, using="default", **kwargs):
    """Privilegios por defecto para el rol de ejecución (R14).

    Antes de migrar, las tablas que cree el usuario que ejecuta las migraciones conceden DML a
    ``securefin_app``. La migración de auditoría revoca después UPDATE, DELETE y TRUNCATE sobre su
    tabla. Si el rol no existe (p. ej. un entorno sin la inicialización de PostgreSQL), no hace nada.
    """
    from django.db import connections

    connection = connections[using]
    if connection.vendor != "postgresql":
        return
    with connection.cursor() as cursor:
        cursor.execute(
            """
            DO $$
            BEGIN
              IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'securefin_app') THEN
                EXECUTE format('GRANT USAGE ON SCHEMA %I TO securefin_app', current_schema());
                EXECUTE format(
                  'ALTER DEFAULT PRIVILEGES IN SCHEMA %I '
                  'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO securefin_app',
                  current_schema());
                EXECUTE format(
                  'ALTER DEFAULT PRIVILEGES IN SCHEMA %I '
                  'GRANT USAGE, SELECT ON SEQUENCES TO securefin_app',
                  current_schema());
              END IF;
            END $$;
            """
        )
