# Validación rápida: Simulación financiera

Validar exclusivamente en el entorno Docker Compose local. Todos los datos/usuarios deben ser ficticios. Las operaciones no mueven dinero real. No conectar proveedores externos.

## Requisitos

- Docker Desktop/Compose funcional y Node.js 22.
- `securefin.local` resuelve a `127.0.0.1`; stack original IAM saludable.
- Administrador con MFA activo, y al menos dos Clientes ficticios activos.

## Aplicar cambios

Desde la raíz del repositorio (PowerShell):

```powershell
docker compose -f infra/compose.yaml ps
docker compose -f infra/compose.yaml --profile oneoff run --rm migrate
docker compose -f infra/compose.yaml up -d --build --wait
docker compose -f infra/compose.yaml ps
```

Esperado: PostgreSQL, backend, mailer, Mailpit y Nginx saludables; los cinco pueden acceder a la aplicación a través de `https://securefin.local`.

## Historias de cliente

1. Inicia sesión con un Cliente ficticio.
2. Abre `https://securefin.local/finance`. Verifica cuenta COP inicial de COP 5.000.000, moneda y saldo identificados como demostración.
3. Abre una cuenta USD adicional. Verifica saldo cero y que no exista conversión COP/USD.
4. Consulta historial; filtra por período/tipo/estado. Abre una sesión privada con otro Cliente y verifica que las cuentas/movimientos no se cruzan.
5. Busca un segundo Cliente por alias/cuenta enmascarada. Previsualiza una transferencia y confirma una de bajo importe. Verifica débito, crédito, moneda, estados y actividad en ambas cuentas.
6. Reenvía la misma petición con la misma clave idempotente: debe devolver la misma operación; cambia el importe con esa clave: debe dar conflicto y no cambiar saldo.
7. Prueba saldo insuficiente, cuenta ajena, misma cuenta, moneda distinta, cuenta inactiva, importe inválido y límites; ningún rechazo produce asiento de transferencia ni saldo parcial.
8. Congela/descongela una tarjeta de demostración y verifica que nunca se muestra PAN ni CVV.

## Aprobación y riesgo

1. En COP, prueba montos inmediatamente bajo/en/sobre COP 1M, COP 5M y COP 10M; en USD, USD 250, USD 1.250 y USD 2.500.
2. Verifica transferencia de un solo aprobador y de dos aprobadores distintos; crea sesión autenticada con MFA para cada Administrador.
3. Confirma que el creador no puede aprobar, que una persona no puede duplicar aprobación y que Cliente/Auditor reciben 403 en mutaciones.
4. Dispara reglas de velocidad, exceso reiterado de límite, monto inusual, destinatario nuevo e inicio sospechoso; inspecciona el motivo y la acción.
5. El Auditor consulta historial y alertas, pero no puede aprobar, rechazar ni cambiar límites.
6. Verifica que cambios de límite, alertas y decisiones quedan en auditoría y que eventos/asientos no se pueden modificar como `securefin_app`.

## Comandos de pruebas

```powershell
Push-Location backend
..\.venv\Scripts\python.exe -m pytest -m unit -q
..\.venv\Scripts\python.exe -m pytest -m "integration or security or contract or acceptance" -q
Pop-Location

Push-Location frontend
.\node_modules\.bin\playwright.cmd test
Pop-Location
```

Éxito: exit code 0 en cada comando; sin saltos no explicados, saldos conciliados, ningún acceso BOLA, operación financiera parcial ni duplicada. PostgreSQL Docker es requisito para pruebas críticas de atomicidad/concurrencia; no sustituir por SQLite.
