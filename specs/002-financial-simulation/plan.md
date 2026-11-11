# Plan de implementación: Simulación financiera SecureFin

**Rama**: `002-financial-simulation` | **Fecha**: 2026-11-10 | **Spec**: [spec.md](./spec.md)

**Entrada**: Especificación [spec.md](./spec.md)

**Artefactos**: [research.md](./research.md) · [data-model.md](./data-model.md) ·
[contrato API](./contracts/finance-api.md) · [quickstart.md](./quickstart.md)

## Resumen

Ampliar el producto IAM con una simulación financiera utilizable, sin fondos ni integraciones reales. Se añadirá una aplicación financiera modular al monolito Django existente, una capa de servicios que concentra autorización y políticas, un libro contable de doble partida con asientos inmutables y transacciones atómicas, contratos DRF de lista permitida, un panel React y un flujo de aprobación/riesgo. Los saldos de COP y USD se mantienen separados; no habrá conversión.

La primera cuenta de cada Cliente será COP 5.000.000 de crédito ficticio de bienvenida. El crédito se compensará con una cuenta interna de fondos de demostración y un asiento auditable. Cuentas adicionales comienzan en cero y no existe abono manual. Los importes se expresan como unidades menores enteras, nunca como coma flotante.

## Contexto técnico

**Lenguaje/Versiones**: Python 3.13, JavaScript moderno, Node 22 para construir el SPA.

**Dependencias principales**: Django 5.2, Django REST Framework 3.18, PostgreSQL 17, React 19, Vite 7, Playwright. Sin nueva dependencia de ejecución prevista.

**Almacenamiento**: PostgreSQL 17, esquema `securefin`; transacciones con bloqueo de filas, restricciones e historial contable append-only. Sin Redis ni servicios financieros externos.

**Pruebas**: Pytest/pytest-django contra PostgreSQL para lógica, API, concurrencia, migraciones y permisos; Playwright para SPA; pytest existente y suites de seguridad. Las pruebas nuevas deben ser alcanzables desde los comandos canónicos existentes.

**Plataforma destino**: Docker Compose local, Nginx/TLS, backend y SPA del mismo origen.

**Tipo de proyecto**: aplicación web mixta (API + SPA).

**Objetivos de rendimiento**: en el entorno de laboratorio de decenas de usuarios, consultas normales del panel e historial visibles en menos de 1 s; no hacer operaciones financieras dependientes de servicios externos.

**Restricciones**:
- Solo datos ficticios. El sistema no es banco, no custodia dinero, no procesa pagos y no debe insinuar que los saldos son redimibles.
- Mantener monolito, sesiones seguras, CSRF, permisos de servidor, denegación por defecto y PostgreSQL existente.
- El acceso de Administrador/Auditor requiere sesión completa y MFA existente.
- Importes en unidades menores enteras (`BigInteger` con cotas), códigos ISO COP/USD; no usar `float`, no mezclar saldos entre monedas.
- La cuenta de demostración interna financia únicamente el crédito inicial fijo; queda fuera del panel y no es operable por usuarios.
- Asientos publicados y auditoría append-only. Correcciones futuras, si se requieren, serán compensatorias, nunca edición de historia.
- Los límites COP y USD son políticas configurables de laboratorio; los umbrales iniciales son los acordados en la spec.
- Nginx conserva CSP estricta y los archivos visuales permanecen locales, sin CDN ni fuentes remotas.

**Tamaño/alcance**: seis historias; APIs de panel, cuentas, movimientos, transferencias, tarjetas ficticias y operaciones administrativas de límites, aprobación y alertas.

## Comprobación de la constitución

| Principio | Requisito | Decisión de diseño | Resultado |
|---|---|---|---|
| I. Seguridad por diseño | STRIDE antes de implementar; mitigación verificable | Tabla de amenazas de esta sección, enlazada con criterios y pruebas | Cumple |
| II. Autenticación/autorización | MFA en roles privilegiados; RBAC y objeto en servidor; sesión/CSRF | Reutilizar la sesión segura IAM, ampliar matriz de permisos y validar propietario en cada servicio | Cumple |
| III. Criptografía/secrets | TLS; claves únicas; datos ficticios y sin secretos | No introducir secretos financieros; datos ficticios; no crear o guardar PAN/CVV | Cumple |
| IV. API | Serializers estrictos; ORM; Nginx como única entrada; CSP | API de lista permitida, consultas parametrizadas ORM, mismo origen y CSP local | Cumple |
| V. Verificación | Pytest negativo, SAST/SCA/Trivy y evidencia | Pruebas de propiedad, concurrencia, idempotencia, umbrales, fraude, permisos y auditoría; E2E | Cumple |
| VI. Auditoría | Eventos mínimos, sin secretos, protegidos | Eventos financieros append-only con actor, operación, monto/moneda y correlación; no PAN ni números completos | Cumple |
| VII. Privacidad | Solo identidades/datos ficticios y minimización | Datos sintéticos marcados como demo; cuentas parcialmente enmascaradas; sin datos bancarios reales | Cumple |
| VIII. Simplicidad | Monolito; justificar cada dependencia | Aplicación Django interna y modelos PostgreSQL; ninguna dependencia ni servicio nuevo | Cumple |

### Modelo de amenazas STRIDE

| Amenaza | Activo/impacto | Mitigación | Criterio de aceptación | Prueba verificable |
|---|---|---|---|---|
| Suplantación (S) | Usuario obtiene fondos de otro cliente | Sesión completa; MFA para roles privilegiados; endpoints autenticados; datos/identificadores ficticios | Una sesión anónima, `pre_auth` o vencida no puede consultar ni operar | Pruebas de API de sesión y MFA |
| Manipulación (T) | Saldos inconsistentes, duplicación o alteración del libro | Doble partida, montos enteros, transacción atómica, bloqueo ordenado, idempotencia única, asientos append-only | Transferencia confirmada balancea; fallos no dejan asiento parcial; reintentos crean una sola transferencia | Pruebas de transacción, concurrencia, idempotencia y permisos SQL |
| Repudio (R) | Negación de operación o decisión | Eventos financieros append-only con actor, resultado, correlación y motivo | Operación, decisión, cambio de límite y alerta quedan trazables | Pruebas de presencia, contenido permitido e inmutabilidad |
| Revelación de información (I) | Exposición de saldos, cuentas, tarjetas o actividad ajena | Autorización por objeto; mínimos campos; enmascarado; auditoría sin datos completos | Consultar IDs ajenos produce 404/denegación sin devolver datos | Matriz BOLA para todos los recursos |
| Denegación de servicio (D) | Saturación de transferencias o consultas | Throttles con límites razonables, paginación, límites de tamaño y consultas indexadas | Entradas excesivas se rechazan; paginación y throttling protegen endpoints | Pruebas de límites y API |
| Elevación de privilegios (E) | Cliente/Auditor aprueba o modifica límites | Matriz RBAC en el servidor; Administrador con MFA; auditor solo lectura; separación de funciones | Cliente/Auditor reciben 403 en mutaciones; creador no aprueba su operación | Pruebas negativas por rol y actor |

### Estructura del proyecto

```text
backend/apps/finance/
├── apps.py
├── models/
├── policies/
├── services/
└── api/
    ├── serializers/
    └── views/
backend/tests/
├── unit/
├── integration/
├── security/
├── contract/
└── acceptance/
frontend/src/
├── components/finance/
└── pages/finance/
specs/002-financial-simulation/
├── contracts/
├── data-model.md
├── plan.md
├── quickstart.md
└── research.md
```

**Decisión de estructura**: la aplicación nueva `apps.finance` queda separada de IAM y auditoría, pero usa el mismo proceso, base de datos, ORM, API y despliegue. Los servicios de dominio hacen las escrituras y las vistas solo validan/serializan/llaman servicios, siguiendo patrones de IAM.

## Fases de implementación

### Fase 1: Datos contables y controles base

1. Añadir permisos de cliente, operaciones privilegiadas y auditoría al catálogo existente.
2. Crear cuentas, transacciones, asientos, políticas, aprobaciones, alertas, notificaciones y tarjetas ficticias.
3. Implementar restricciones de moneda, montos, estados, unicidad de idempotencia e inmutabilidad de asientos.
4. Provisionar exactamente una cuenta COP de bienvenida por cliente creado, con contrapartida interna; sin duplicar la provisión si la operación se reintenta.
5. Añadir pruebas de migración, modelo, permisos y concurrencia antes de endpoints.

### Fase 2: Panel, cuentas e historial

1. Servicios y endpoints de panel, cuentas propias, apertura de cuentas adicionales y movimientos paginados/filtrados.
2. Aplicar permisos RBAC y BOLA antes de serializar información de recursos.
3. E2E de panel, apertura de cuenta, actividad y aislamiento entre clientes.

### Fase 3: Transferencias y límites

1. Servicio de vista previa y confirmación con clave idempotente, validación de moneda, cuenta, saldo, límite y throttling.
2. Bloqueo de cuentas en orden determinista, revalidación de saldos/límites bajo el bloqueo y débito/crédito/asientos en una transacción.
3. Distinguir resultado inmediato, pendiente de aprobación y rechazo; nunca debitar antes de la aprobación.
4. Pruebas con carreras, repetición de claves, fondos insuficientes, fallos forzados y umbrales adyacentes.

### Fase 4: Aprobaciones, riesgo, límites administrativos y auditoría

1. Reglas de riesgo basadas en frecuencia, importe, límites, destinatarios nuevos y eventos de login recientes; salida nivel/razón/acción.
2. Bandeja de operaciones pendientes y alertas; aprobación/rechazo con MFA, separación de funciones y estados terminales.
3. Gestión de políticas por administrador con validación y auditoría; vistas de solo lectura para auditores.
4. Notificaciones in-app no sensibles; estadísticas agregadas.

### Fase 5: Tarjetas ficticias e interfaz

1. Tarjetas de demostración sin PAN/CVV ni credenciales de pago; consulta enmascarada y congelar/descongelar.
2. Panel financiero y rutas accesibles para cliente, administrador y auditor.
3. Flujos de transferencia, confirmación, pendientes, historial, límites, alertas y tarjetas.
4. Playwright para los flujos principales, respuesta móvil y accesibilidad básica.

### Fase 6: Revisión y validación

1. Ejecutar unidad, integración PostgreSQL, seguridad, contratos y aceptación.
2. Ejecutar E2E del navegador contra el stack Docker real.
3. Ejecutar migraciones desde una base fresca y comprobar que la base de laboratorio existente migra sin pérdida.
4. Ejecutar las puertas SAST/SCA configuradas y documentar evidencia y gaps.

## Estrategia de pruebas

**appType**: aplicación web mixta (API REST + SPA).

### Viajes críticos

1. Cliente ve panel, cuentas propias y saldo inicial, y revisa movimientos.
2. Cliente abre cuenta adicional y la utiliza para recibir una transferencia.
3. Dos clientes transfieren y consultan el débito, crédito y estados con persistencia.
4. Transferencia inválida, duplicada, concurrente, de moneda incompatible o que excede límites no altera saldos incorrectamente.
5. Transferencia de alto importe se aprueba conforme a umbral por Administradores distintos; Cliente/Auditor no aprueban.
6. Operación sospechosa genera alerta y queda rastreable por los roles autorizados.
7. Cliente congela su tarjeta ficticia; intento de otro usuario es denegado.

### Herramientas, capacidades y gaps

| Capacidad | Principal | Alternativa solo si falla esa capacidad | Gap |
|---|---|---|---|
| Infraestructura | PostgreSQL real del Compose/Docker | No degradar integridad financiera a SQLite; detenerse y resolver Docker | Sin validación de locks, triggers, permisos ni SQL PostgreSQL |
| API/integración | pytest-django contra PostgreSQL real | Ninguna para tests contables críticos | Un mock no demuestra persistencia, atomicidad ni carrera |
| Navegador | Playwright con Chromium contra Nginx/SPA | Pruebas HTTP nativas solo si Node/browser no está disponible tras intentar instalar | No verifica render, rutas ni interacción real del SPA |

Docker y Node/browser son ejes independientes: la ausencia de uno nunca justifica omitir la prueba primaria del otro. Docker funcional y Node/Playwright disponibles en el entorno actual; verificar de nuevo al ejecutar.

### Entorno, datos y dependencias

- **Requisitos**: Docker funcional, Compose v2, Node.js y Chromium Playwright; TLS de laboratorio y servicios saludables.
- **DB**: PostgreSQL real mediante Compose; SQLite queda excluida por locking, restricciones, SQL, esquema y triggers.
- **Correo**: Mailpit solo para avisos locales, sin relay; la lógica financiera no depende de la entrega.
- **Otros servicios**: ninguna API bancaria, de pagos, tarjeta, FX ni proveedor de fraude externo; motor de riesgo determinista local.
- **SPA/API**: contrato DRF versionado y Playwright sobre mismo origen; fixtures in-process con pytest-django para pruebas de contrato.
- **Base común**: fixtures compartidos para usuarios/roles/MFA, cuentas propias y ajenas, reloj controlable, sesión y API; cleanup por transacción.
- **Datos**: montos sintéticos reproducibles con UUIDs y aislados por test; seeded welcome balance se prueba explícitamente y no se asumen cuentas ajenas preexistentes.
- **Módulos**: tests de arranque/`check` de Django; tests de startup/health del Compose; smoke de SPA/PWA no aplica.
- **Regla de ejecución**: cada tarea de implementación ejecuta y reporta los tests de módulo tocados; fallo significa tarea incompleta.

### Criterio de aceptación y revisión

Una historia pasa si su escenario se prueba end-to-end con el estado persistido, sin filtración de otra persona, sin movimiento parcial ni duplicación. Umbrales se verifican bajo, igual y sobre el límite; aprobaciones exigen identidad/MFA y dejan rastro. Revisor final verifica cada capacidad del stack, resultados/códigos de salida, cobertura de viajes, inmutabilidad, permisos y que no existe salida a infraestructura de dinero real.

## Seguimiento de complejidad

No se añaden dependencias, microservicios ni servicios financieros. La tabla de saldos es una proyección transaccional del libro; requiere mecanismo explícito de reconciliación y pruebas de invariantes. PostgreSQL real y el bloqueo de filas son requisitos, no optimizaciones opcionales, para la corrección concurrente.
