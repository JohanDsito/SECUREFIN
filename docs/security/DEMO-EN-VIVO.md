# Demo en vivo — SecureFin Gateway

Guion para mostrar, con el sistema funcionando, dónde se aplica cada tema del curso. Cada bloque dice
**qué ejecutar, qué se verá y qué explicar**. La matriz completa tema → control → código está en
[README.md](README.md) y los resultados guardados, en [`evidence/`](evidence/).

Todos los comandos se ejecutan en **Git Bash** desde la raíz del repositorio. El script
`docs/security/demo/demo.sh` agrupa los comandos de terminal por tema (solo usa credenciales ficticias).

---

## 0. Preparación (la noche antes o 30 min antes)

1. **Levantar el stack** (base de datos → migraciones → resto):

   ```bash
   docker compose -f infra/compose.yaml up -d --wait db
   docker compose -f infra/compose.yaml --profile oneoff run --rm migrate
   docker compose -f infra/compose.yaml up -d --build --wait
   bash docs/security/demo/demo.sh estado      # los 5 contenedores en "healthy"
   ```

2. **Descargar las imágenes de las herramientas** (para no esperar en clase):

   ```bash
   docker pull instrumentisto/nmap:7.95; docker pull httpd:2.4-alpine
   docker pull busybox:1.37; docker pull aquasec/trivy:0.70.0
   ```

3. **Crear tu cuenta de Administrador** (solo hay que hacerlo una vez; usa tu correo de laboratorio):

   ```bash
   docker compose -f infra/compose.yaml exec backend \
     python manage.py iam_bootstrap_admin --email admin@lab.securefin.local --name "Tu nombre"
   ```

   - Abre el buzón de laboratorio en **https://127.0.0.1:8025** (usuario y contraseña de Mailpit).
   - Abre el correo "Activa tu cuenta", pulsa el enlace, fija una contraseña larga (15+ caracteres).
   - Entra en **https://securefin.local/login**: te pedirá configurar el MFA. Escanea el QR con
     Google Authenticator / Microsoft Authenticator y **guarda los 10 códigos de recuperación**.
   - Crea también una cuenta de **Cliente** desde https://securefin.local/register (para la demo de roles).

4. **Navegador**: el certificado es de la CA del laboratorio, así que el navegador avisará la primera
   vez; acepta el riesgo para `securefin.local`. (Opcional: importar `secrets/lab_ca.pem` como CA de
   confianza del usuario y quitarla después de la presentación.)

5. **Servicios ajenos al proyecto**: tu Windows tiene **MySQL (3306)** y **PostgreSQL (5432)** nativos
   escuchando en todas las interfaces. Detenlos antes de la demo (Servicios de Windows) o explica que
   no son de SecureFin si aparecen en Nmap.

6. **Wireshark** abierto en el adaptador **"Adapter for loopback traffic capture"**, sin filtro de
   captura (en este equipo el filtro de captura no funciona sobre loopback; usa el de visualización).

---

## Orden recomendado (≈ 25 minutos)

### 1. Arquitectura y segmentación — Semanas 3, 6 (Zero Trust, VLAN, DMZ) · 2 min

```bash
bash docs/security/demo/demo.sh red
```

- **Se verá**: cuatro redes; solo `edge_net` es pública. Desde la DMZ la base de datos y el backend
  están **BLOQUEADOS**; el backend **no tiene salida a Internet**.
- **Explicar**: es el equivalente a VLANs con un firewall entre zonas y política de **denegar por
  defecto**. Solo Nginx publica puertos (`infra/compose.yaml`).

### 2. Criptografía — Semana 1 · 3 min

```bash
bash docs/security/demo/demo.sh cripto
```

- **Se verá**: el mismo texto da el mismo SHA-256 (por eso la **salt**); AES-256 cifra y descifra;
  RSA-3072 cifra con la pública y descifra con la privada; ECC P-256 firma y verifica. Al final, el
  formato real de las contraseñas en la base: `argon2$argon2id$v=19$m=65536,t=3,p=1$<salt>$<hash>`.
- **Mostrar el código**: `backend/apps/iam/policies/hashers.py` (Argon2id) y
  `backend/apps/iam/crypto/aead.py` (AES-256-GCM de los secretos TOTP).
- **Explicar**: SHA-256 es rápido (malo para contraseñas); Argon2id es lento y usa memoria a propósito.

### 3. HTTP vs HTTPS con Wireshark — Semana 2 (MITM) · 3 min

En Wireshark (loopback) aplica el filtro de visualización `tcp.port == 80 || tcp.port == 443` y ejecuta:

```bash
curl -s -o /dev/null -X POST http://127.0.0.1/api/v1/auth/login -H "Content-Type: application/json" \
  --data '{"email":"demo@lab.securefin.local","password":"ClaveFicticia-Clase"}'
curl -sk --ssl-no-revoke -o /dev/null -X POST https://securefin.local/api/v1/auth/login \
  -H "Content-Type: application/json" --data '{"email":"demo@lab.securefin.local","password":"ClaveFicticia-Clase"}'
bash docs/security/demo/demo.sh tls
```

- **Se verá**: en el puerto 80, clic derecho → *Follow → HTTP Stream*: la contraseña **en claro**. En
  el 443 solo *Client Hello (SNI)* y *Application Data* cifrado. `tls` muestra TLS 1.3/1.2 aceptados y
  **TLS 1.1 rechazado**, y el certificado RSA-3072.
- **Explicar**: la redirección 301 llega tarde para esa primera petición; por eso existe **HSTS**.

### 4. Bastionado web — Semana 5 · 2 min

```bash
bash docs/security/demo/demo.sh cabeceras
```

- **Se verá**: `Server: nginx` **sin versión**, `X-Frame-Options: DENY`, `X-Content-Type-Options`,
  CSP, HSTS; HTTP → 301; `TRACE` → 405.
- **Mostrar**: `infra/nginx/nginx.conf` (`server_tokens off`, `add_header …`) e
  `infra/nginx/Dockerfile` (`USER nginx`: Nginx **no corre como root**).

### 5. IAM en el navegador — Semana 4 (AAA, MFA, RBAC) · 6 min

En **https://securefin.local**:

1. **Autenticación + MFA**: inicia sesión con tu Administrador → pide el **código TOTP** del móvil.
2. **Autorización (RBAC)**: en otra ventana privada entra como **Cliente** e intenta abrir
   `https://securefin.local/admin/users` → "No tienes permiso" (el servidor responde **403**).
3. **Administración**: como Administrador, en *Usuarios* crea un **Auditor** → el correo de
   activación llega a Mailpit (**https://127.0.0.1:8025**) → el Auditor activa su cuenta y el sistema
   le **obliga a configurar MFA** antes de operar.
4. **Revocación inmediata**: desactiva al Cliente → su sesión abierta en la otra ventana deja de
   funcionar al recargar.
5. **Auto-protección**: en *Usuarios*, tu propia fila dice "Tu cuenta" y no ofrece acciones. La
   interfaz es solo comodidad: aunque alguien llamara a la API directamente para cambiar su propio
   rol o desactivarse, el servidor responde **403 `self_action_forbidden`**, y nunca deja al sistema sin
   un Administrador activo (409) — lo cubren `tests/acceptance/test_us4_admin.py` (escenarios 3 y 4).
6. **Auditoría**: `bash docs/security/demo/demo.sh auditoria` → los eventos de todo lo anterior.

- **Explicar**: autenticación (contraseña + TOTP), autorización (matriz de permisos, denegar por
  defecto, control por objeto contra IDOR) y auditoría (registro *append-only*).

### 6. Reconocimiento con Nmap — Semana 8 · 2 min

```bash
bash docs/security/demo/demo.sh nmap
```

- **Se verá**: 80/443 abiertos con `nginx` sin versión; 8000 (backend) y 1025 (correo) **cerrados**.
- **Contar el hallazgo real** (ver `evidence/E3-nmap.txt`): Nmap marcó **CVE-2011-3192** como
  vulnerable. Era un falso positivo de producto (es de Apache), pero el vector existía (respuestas con
  muchos rangos) y se mitigó con `max_ranges 1;`.

### 7. Inyección SQL — Semana 8 · 2 min

```bash
bash docs/security/demo/demo.sh sqli
```

También se puede escribir `' OR 1=1 --` como correo en el formulario de login del navegador.

- **Se verá**: todos los payloads → el mismo **401 genérico**; `"role":"admin"` → **400 campo no
  permitido**; la tabla de usuarios sigue intacta.
- **Explicar**: ORM con consultas **parametrizadas**, listas permitidas de campos y un usuario de base
  de datos **sin permisos de DDL** (`bash docs/security/demo/demo.sh privilegios`).

### 8. DoS / inundación HTTP y rate limiting — Semanas 9 y 10 · 3 min

```bash
bash docs/security/demo/demo.sh dos
```

Mientras corre, **recarga https://securefin.local en el navegador**: sigue cargando al instante.

- **Se verá**: 3000 peticiones en ~3 s, ~2750 respondidas con **429 Too Many Requests**.
- **Mostrar**: `limit_req_zone`, `limit_conn`, `limit_req_status 429` en `infra/nginx/nginx.conf`.
- **Explicar**: el exceso se descarta en el proxy antes de llegar a Django/PostgreSQL → se protege la
  **Disponibilidad**. Límite honesto: un DDoS desde miles de IPs requiere CDN/WAF.

### 9. Fuerza bruta contra el login — Semana 10 (segunda capa) · 2 min

```bash
bash docs/security/demo/demo.sh fuerzabruta
```

- **Se verá**: intentos 1–20 → **401** (idénticos a propósito) y desde el 21 → **429 con
  `Retry-After`**. El resumen final de auditoría muestra lo que no se ve desde fuera: solo **5**
  contraseñas se evaluaron (`invalid_credentials`); las siguientes se rechazaron **sin evaluarlas**
  (`throttled`) porque la cuenta entró en retraso de 30 s.
- **Mostrar**: `backend/apps/iam/services/throttling.py` (30 s → 900 s de tope, sin bloqueo
  permanente) y `backend/apps/iam/api/throttles.py` (login 20/min por IP).
- **Explicar**: dos capas. Por IP frena a un atacante; **por cuenta** frena a una botnet que ataca la
  misma cuenta desde muchas IPs. Por qué no bloqueo rígido: un atacante podría dejar a la víctima sin
  acceso (ver `docs/security/throttling.md`).
- **Ojo**: espera 1 minuto después de la demo de SQLi (comparten el contador de login de tu IP).

### 10. DevSecOps — Semana 7 · 2 min

```bash
bash docs/security/demo/demo.sh trivy
```

- **Se verá**: `securefin-nginx:lab` → **0** CVE HIGH/CRITICAL; backend → 47 sin parche publicado.
- **Contar la historia** (`evidence/E8-devsecops.txt`): Trivy encontró **73 CVE** en la imagen de
  Nginx y 54 en la del backend; se corrigió actualizando a **Nginx 1.30**, aplicando parches del
  sistema, quitando `pip` de la imagen y ejecutando Nginx **sin root**.
- **Mostrar**: `.github/workflows/ci.yml` (Semgrep, Bandit, pip-audit, npm audit, Trivy) y la pestaña
  *Actions* de GitHub.

---

## Si algo falla durante la demo

| Síntoma | Causa probable | Solución |
|---|---|---|
| La API responde **400** | Se entró por `https://127.0.0.1` | Usar **https://securefin.local** (Django solo acepta ese nombre) |
| Login devuelve **429** antes de tiempo | Muchos intentos en el último minuto desde tu IP | Esperar 1 minuto |
| `demo.sh` se queda colgado en `dos` | Docker Desktop saturado | Repetir; el ataque se lanza desde la red `edge_net`, no desde Windows |
| Wireshark no captura nada | Filtro de **captura** activo | Quitarlo y usar solo el filtro de **visualización** |
| No llega el correo de activación | Mailer arrancando | `docker compose -f infra/compose.yaml ps` y esperar unos segundos |

## Riesgos abiertos (para responder con honestidad)

- Límite por IP y NAT compartida: usuarios detrás de la misma IP pública comparten el límite por IP
  (la limitación por cuenta con retrasos progresivos sí es individual; ver `throttling.md`).
- Recuperación de contraseña por correo (US7) y consulta de auditoría para el rol Auditor (US6):
  pendientes.
- 47 CVE de Debian sin parche en la imagen del backend: aceptadas y vigiladas con Trivy.
