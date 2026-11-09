"""Motor de sesión que solo persiste verificadores HMAC (T034; research R2.4).

Garantías:
- El identificador en claro (256 bits, CSPRNG) solo viaja al navegador. En PostgreSQL solo se
  guarda ``"<versión>$" + HMAC-SHA-256(SESSION_HMAC_KEYS[versión], "securefin:session:" + clave)``.
- La carga nunca adopta un identificador que el servidor no emitió (anti-fijación).
- Caducidad absoluta desde el ``created_at`` inicial (heredado en cada rotación; nunca extendida)
  e inactividad de 15 min medida con ``last_activity_at`` (renovada sin reemitir la cookie).
- Una sesión revocada nunca se resucita: las actualizaciones usan UPDATE y fallan si la fila no existe.
- No se persisten sesiones anónimas (I1).
- La API asíncrona de Django no está soportada (proyecto WSGI): lanza NotImplementedError.
"""

from __future__ import annotations

import secrets
import uuid
from datetime import datetime, timedelta

from django.conf import settings
from django.contrib.sessions.backends.base import CreateError, UpdateError
from django.contrib.sessions.backends.db import SessionStore as DBSessionStore
from django.db import IntegrityError, transaction

from apps.core import clock
from apps.iam.crypto import hmac_verifiers
from apps.iam.sessions import keys as K

SESSION_KEY_BYTES = 32  # 256 bits


def _cfg(name: str) -> int:
    return settings.SECUREFIN_SESSION[name]


def _parse(ts: str | None) -> datetime | None:
    return datetime.fromisoformat(ts) if ts else None


class SessionStore(DBSessionStore):
    def __init__(self, session_key=None):
        super().__init__(session_key)
        self._row_verifier: str | None = None  # verificador de la fila cargada
        self._row = None
        self.client_meta: tuple[str | None, str | None] = (None, None)  # (ip, user_agent)

    @classmethod
    def get_model_class(cls):
        from apps.iam.models import UserSession

        return UserSession

    # --- Generación -----------------------------------------------------------------------------
    def _get_new_session_key(self) -> str:
        while True:
            key = secrets.token_urlsafe(SESSION_KEY_BYTES)
            if not self.exists(key):
                return key

    # --- Carga ----------------------------------------------------------------------------------
    def _get_session_from_db(self):  # pragma: no cover - sustituido por load()
        raise NotImplementedError("Usa load(): el motor nunca consulta por la clave en claro.")

    def _find_row(self, session_key: str):
        model = self.model
        verifiers = hmac_verifiers.session_verifiers_accepted(session_key)
        rows = {r.key_verifier: r for r in model.objects.filter(key_verifier__in=verifiers)}
        for verifier in verifiers:  # versión activa primero
            if verifier in rows:
                return rows[verifier]
        return None

    def load(self):
        self._row = None
        self._row_verifier = None
        if not self.session_key or not self._validate_session_key(self.session_key):
            self._session_key = None
            return {}
        row = self._find_row(self.session_key)
        if row is None:
            # Cookie aleatoria, mal formada, de versión retirada o ya purgada: nunca se adopta y
            # no genera eventos (SC17, SC19).
            self._session_key = None
            return {}
        reason = self._expiry_reason(row)
        if reason:
            self._expire(row, reason)
            self._session_key = None
            return {}
        self._row = row
        self._row_verifier = row.key_verifier
        return self.decode(row.session_data)

    def _expiry_reason(self, row) -> str | None:
        now = clock.now()
        if row.expire_date <= now:
            return "pre_auth_timeout" if row.auth_level == K.PRE_AUTH else "absolute"
        if now - row.created_at >= timedelta(seconds=_cfg("ABSOLUTE_LIFETIME")):
            return "absolute"
        if now - row.last_activity_at > timedelta(seconds=_cfg("IDLE_TIMEOUT")):
            return "idle"
        return None

    def _expire(self, row, reason: str) -> None:
        user_id = row.user_id
        level = row.auth_level
        row.delete()
        if user_id:  # solo sesiones válidas con propietario (I1 rev. 3)
            from apps.audit.services import record_event

            record_event(
                "session_expired",
                "success",
                actor_id=user_id,
                target_type="session",
                target_id=row.public_id,
                metadata={"reason": reason, "auth_level": level},
            )

    # --- Existencia y borrado -------------------------------------------------------------------
    def exists(self, session_key):
        verifiers = hmac_verifiers.session_verifiers_accepted(session_key)
        return self.model.objects.filter(key_verifier__in=verifiers).exists()

    def delete(self, session_key=None):
        if session_key is None:
            if self.session_key is None:
                return
            session_key = self.session_key
        verifiers = hmac_verifiers.session_verifiers_accepted(session_key)
        self.model.objects.filter(key_verifier__in=verifiers).delete()

    # --- Creación y guardado --------------------------------------------------------------------
    def create(self):
        while True:
            self._session_key = self._get_new_session_key()
            try:
                self.save(must_create=True)
            except CreateError:
                continue
            self.modified = True
            return

    def create_model_instance(self, data):  # pragma: no cover - sustituido por save()
        raise NotImplementedError("Usa save(): el motor construye la fila con su verificador.")

    def _metadata(self, data: dict) -> dict:
        level = data.get(K.LEVEL)
        if level not in (K.PRE_AUTH, K.FULL):
            raise RuntimeError(
                "Las sesiones anónimas no se persisten: fija el nivel pre_auth o full antes de guardar."
            )
        now = clock.now()
        created_at = _parse(data.get(K.CREATED_AT))
        if created_at is None:
            created_at = now
            data[K.CREATED_AT] = created_at.isoformat()
        if level == K.PRE_AUTH:
            ttl = int(data.get(K.PRE_AUTH_TTL) or _cfg("PRE_AUTH_TTL"))
            expire_date = created_at + timedelta(seconds=ttl)
        else:
            expire_date = created_at + timedelta(seconds=_cfg("ABSOLUTE_LIFETIME"))
        user_id = data.get(K.DJANGO_USER) or data.get(K.PENDING_USER)
        return {
            "auth_level": level,
            "user_id": uuid.UUID(str(user_id)) if user_id else None,
            "created_at": created_at,
            "expire_date": expire_date,
            "authenticated_at": _parse(data.get(K.AUTHENTICATED_AT)),
        }

    def save(self, must_create=False):
        if self.session_key is None:
            return self.create()
        data = self._get_session(no_load=must_create)
        meta = self._metadata(data)
        encoded = self.encode(data)
        model = self.model
        if must_create:
            ip, user_agent = self.client_meta
            verifier = hmac_verifiers.session_verifier(self._session_key)
            row = model(
                key_verifier=verifier,
                key_version=hmac_verifiers.active_session_version(),
                session_data=encoded,
                public_id=uuid.uuid4(),
                last_activity_at=clock.now(),
                ip_address=ip,
                user_agent=(user_agent or "")[:200] or None,
                **meta,
            )
            try:
                with transaction.atomic():
                    row.save(force_insert=True)
            except IntegrityError as exc:
                raise CreateError from exc
            self._row = row
            self._row_verifier = verifier
            return
        verifier = self._row_verifier or hmac_verifiers.session_verifier(self._session_key)
        # UPDATE sin upsert: si la fila se revocó entretanto, no se resucita (SC11).
        updated = model.objects.filter(key_verifier=verifier).update(session_data=encoded, **meta)
        if updated == 0:
            raise UpdateError

    # --- Actividad (sin reemitir la cookie; C2) ---------------------------------------------------
    def touch(self) -> bool:
        """Renueva last_activity_at sin modificar session_data ni marcar la sesión como modificada."""
        if self._row is None or self._row_verifier is None:
            return False
        now = clock.now()
        if (now - self._row.last_activity_at).total_seconds() < _cfg("TOUCH_GRANULARITY"):
            return False
        ip, user_agent = self.client_meta
        fields = {"last_activity_at": now}
        if ip:
            fields["ip_address"] = ip
        if user_agent:
            fields["user_agent"] = user_agent[:200]
        self.model.objects.filter(key_verifier=self._row_verifier).update(**fields)
        self._row.last_activity_at = now
        return True

    @property
    def row(self):
        """Fila cargada (para public_id y metadatos); None si no hay sesión persistida."""
        return self._row

    # --- Rotación: hereda created_at porque viaja en los datos de sesión ---------------------------
    def cycle_key(self):
        data = self._session
        key = self.session_key
        self.create()
        self._session_cache = data
        if key:
            self.delete(key)

    # --- Limpieza ---------------------------------------------------------------------------------
    @classmethod
    def clear_expired(cls):
        model = cls.get_model_class()
        now = clock.now()
        model.objects.filter(expire_date__lt=now).delete()
        model.objects.filter(created_at__lt=now - timedelta(seconds=_cfg("ABSOLUTE_LIFETIME"))).delete()
        model.objects.filter(last_activity_at__lt=now - timedelta(seconds=_cfg("IDLE_TIMEOUT"))).delete()

    # --- API asíncrona: no soportada (proyecto WSGI; R2.4) ----------------------------------------
    async def aload(self):
        raise NotImplementedError("El motor de sesión de SecureFin es solo síncrono.")

    async def asave(self, must_create=False):
        raise NotImplementedError("El motor de sesión de SecureFin es solo síncrono.")

    async def acreate(self):
        raise NotImplementedError("El motor de sesión de SecureFin es solo síncrono.")

    async def aexists(self, session_key):
        raise NotImplementedError("El motor de sesión de SecureFin es solo síncrono.")

    async def adelete(self, session_key=None):
        raise NotImplementedError("El motor de sesión de SecureFin es solo síncrono.")

    async def acycle_key(self):
        raise NotImplementedError("El motor de sesión de SecureFin es solo síncrono.")

    @classmethod
    async def aclear_expired(cls):
        raise NotImplementedError("El motor de sesión de SecureFin es solo síncrono.")
