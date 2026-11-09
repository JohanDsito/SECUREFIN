<!--
Sync Impact Report
==================
Versión: 1.0.0 → 1.1.0 (MINOR: guía ampliada y precisada; ningún principio eliminado ni renombrado)

Principios modificados (títulos sin cambios):
- I. STRIDE: alcance explícito (seguridad, autenticación, autorización, datos financieros,
  infraestructura); cada mitigación exige criterio de aceptación + prueba verificable.
- II. IAM: RBAC a nivel de función y de objeto; elección cookies de sesión vs. tokens Bearer
  diferida a la especificación técnica; CSRF/CORS acordes al mecanismo elegido.
- III. Criptografía: TLS según límites de confianza con excepciones documentadas; roles separados
  de Argon2id, SHA-256, AES-256-GCM, RSA-OAEP (cifrado) y ECDSA (firma); prohibición explícita de
  reutilizar nonces con la misma clave AES-GCM.
- IV. API: CSRF/CORS remiten al Principio II.
- V. DevSecOps: SAST (Semgrep/Bandit), SCA y análisis de contenedores diferenciados; Trivy como
  complementario; gestión documentada de falsos positivos.
- VI. Auditoría: lista de datos prohibidos en registros; se permiten identificadores internos o
  seudonimizados y metadatos mínimos.

Secciones modificadas: Marco de Referencia y Stack (ECDSA, SHA-256), Flujo de Desarrollo,
Gobernanza (registro de excepciones y falsos positivos).
Secciones añadidas/eliminadas: ninguna.
Plantillas: no modificadas. TODOs diferidos: ninguno.
-->

# Constitución de SecureFin Gateway

## Principios Fundamentales

### I. Seguridad desde el Diseño y Modelado de Amenazas (NO NEGOCIABLE)

- MUST realizarse un análisis STRIDE documentado en el `plan.md`, **antes** de implementar, para
  toda funcionalidad o cambio que afecte a: controles de seguridad, autenticación, autorización,
  datos financieros o personales, o infraestructura (Nginx, Docker, TLS, red, base de datos).
- Cada amenaza identificada MUST registrar: categoría STRIDE, activo afectado, impacto, mitigación
  elegida, **criterio de aceptación** de la mitigación y la **prueba verificable** que la demuestra.
- Los criterios de aceptación de las mitigaciones MUST trasladarse a la especificación de la
  funcionalidad y sus pruebas a las tareas de implementación.
- Ninguna mitigación se considera implementada sin su prueba o evidencia verificable.
- Los valores por defecto MUST ser seguros: denegar por defecto, mínimo privilegio, fallar de forma
  cerrada y no exponer detalles internos en mensajes de error.

**Justificación**: corregir una falla de diseño después de implementada es mucho más costoso que
prevenirla; STRIDE ofrece un análisis sistemático y el vínculo mitigación → criterio → prueba lo
hace verificable.

### II. Autenticación Robusta y Control de Acceso

- Las contraseñas MUST almacenarse únicamente como hash Argon2id con parámetros documentados
  (ver Principio III).
- Las cuentas MUST poder activar MFA mediante TOTP, y MFA MUST ser obligatorio para todos los
  roles administrativos.
- La autorización MUST aplicarse en el servidor con RBAC en dos niveles: **función** (qué
  operaciones puede invocar cada rol; prevención de BFLA) y **objeto** (sobre qué registros
  concretos; prevención de BOLA/IDOR). El frontend nunca es una frontera de confianza.
- El mecanismo de autenticación (cookies de sesión o tokens Bearer) MUST elegirse y justificarse
  durante la especificación técnica, documentando su modelo de amenazas. Los controles derivados
  MUST ser coherentes con la elección:
  - **Cookies de sesión**: atributos `Secure`, `HttpOnly` y `SameSite`, y protección CSRF activa
    en toda operación que modifique estado.
  - **Tokens Bearer**: vida corta, mecanismo de revocación y almacenamiento en el cliente
    justificado frente a XSS; CSRF basado en tokens solo es exigible si el token viaja de forma
    automática (p. ej. en una cookie).
  - **CORS**, en ambos casos: orígenes explícitos, nunca `*` junto con credenciales.
- Con cualquier mecanismo, las sesiones o tokens MUST tener expiración, revocación (cierre de
  sesión) y protección contra fuerza bruta (limitación de intentos o bloqueo temporal).
- Los mensajes de error de autenticación MUST ser genéricos para impedir la enumeración de usuarios.

**Justificación**: la autenticación y el control de acceso rotos encabezan los riesgos de OWASP Top 10
y OWASP API Security Top 10; en un sistema de corte financiero son el control más crítico. Diferir
la elección del mecanismo evita fijar controles CSRF/CORS que no correspondan.

### III. Protección Criptográfica de Datos y Secretos

**Transporte (TLS)**

- Todo endpoint protegido y toda comunicación que cruce un límite de confianza (como mínimo,
  cliente ↔ Nginx) MUST usar HTTPS/TLS 1.2 o superior, preferiblemente 1.3. En ese límite, HTTP
  plano solo se permite para redirigir a HTTPS.
- Credenciales, tokens, secretos TOTP y datos financieros MUST NOT viajar sin TLS a través de un
  límite de confianza bajo ninguna excepción.
- Se permiten, como **excepciones documentadas** según la sección de Gobernanza:
  - segmentos internos en redes locales aisladas que no cruzan un límite de confianza (p. ej. la
    red interna de Docker entre Nginx, Django y PostgreSQL), siempre que no se expongan al host ni a
    redes externas;
  - demostraciones HTTP deliberadamente vulnerables (p. ej. captura de tráfico con Wireshark),
    que MUST ejecutarse aisladas de los componentes protegidos de SecureFin, usar solo datos
    ficticios e identificarse como vulnerables a propósito.

**Primitivas y su uso exclusivo**

| Primitiva | Uso permitido | Uso prohibido |
|---|---|---|
| **Argon2id** | Hash de contraseñas | Cifrado o integridad de datos |
| **SHA-256** | Integridad y huellas de datos no secretos; HMAC-SHA-256 para autenticar mensajes | Hash de contraseñas por sí solo |
| **AES-256-GCM** | Cifrado autenticado de datos sensibles en reposo (p. ej. secretos TOTP) | Modos sin autenticación (ECB, CBC sin MAC) |
| **RSA-OAEP** (demostrativo) | Cifrado asimétrico de datos pequeños o envoltura de claves (≥ 3072 bits, SHA-256) | Firmas digitales; relleno PKCS#1 v1.5 para cifrar |
| **ECDSA** (demostrativo) | Firmas digitales: autenticidad e integridad (P-256 con SHA-256) | Cifrado de datos |

- Con AES-256-GCM, un nonce MUST NOT reutilizarse **nunca** con la misma clave: cada operación de
  cifrado MUST usar un nonce de 96 bits único, generado con un CSPRNG o con un contador garantizado
  sin repetición. Reutilizarlo compromete tanto la confidencialidad como la autenticidad.
- El cifrado (RSA-OAEP) y la firma (ECDSA) son operaciones distintas con pares de claves distintos;
  una misma clave MUST NOT usarse para más de un propósito.
- Las demostraciones con RSA-OAEP y ECDSA MUST identificarse como tales.
- MUST usarse bibliotecas criptográficas reconocidas (p. ej. `cryptography`, `argon2-cffi`,
  OpenSSL); está prohibido implementar primitivas propias.
- Secretos, claves y credenciales MUST cargarse desde variables de entorno o archivos excluidos del
  control de versiones; ningún secreto real puede aparecer en el repositorio, en imágenes Docker ni
  en registros.

**Justificación**: la criptografía mal aplicada da una falsa sensación de seguridad. Asignar a cada
primitiva un único propósito evita confusiones habituales (hashear con SHA-256, firmar con claves
de cifrado, reutilizar nonces); delimitar TLS por límites de confianza lo hace verificable sin
impedir las demostraciones del laboratorio.

### IV. Validación de Entradas y Defensa de la API

- Toda entrada externa MUST validarse en el servidor mediante serializers de Django REST Framework
  con tipos, longitudes y formatos explícitos; se rechaza por defecto todo campo no esperado.
- El acceso a datos MUST hacerse con el ORM de Django o consultas parametrizadas; está prohibido
  concatenar entradas en SQL o en comandos del sistema.
- Nginx MUST actuar como único punto de entrada de SecureFin (API Gateway / Reverse Proxy) y
  aplicar limitación de tasa, límites de tamaño de petición y cabeceras de seguridad (HSTS, CSP,
  X-Content-Type-Options y `frame-ancestors` o X-Frame-Options).
- CSRF y CORS MUST configurarse según el mecanismo de autenticación elegido (Principio II).
- Los endpoints MUST evitar la exposición excesiva de datos: las respuestas devuelven solo los
  campos necesarios para el caso de uso.

**Justificación**: la API es la superficie de ataque principal; OWASP API Security Top 10 define los
controles mínimos para interfaces REST.

### V. Verificación de Seguridad Automatizada (NO NEGOCIABLE)

- Cada control de seguridad MUST tener pruebas con Pytest que incluyan casos negativos (acceso no
  autorizado, entradas maliciosas, tokens vencidos, MFA inválido, acceso a objetos ajenos).
- El pipeline de GitHub Actions MUST ejecutar en cada pull request, como análisis diferenciados:
  - **Pruebas** automatizadas (Pytest).
  - **SAST** (análisis estático del código propio): Semgrep y/o Bandit.
  - **SCA** (vulnerabilidades en dependencias de Python y JavaScript): la herramienta se fija en
    el plan técnico.
  - **Análisis de contenedores y archivos** (imágenes Docker, configuración): Trivy, como
    herramienta complementaria.
- Ningún cambio se integra a la rama principal con pruebas fallidas o con hallazgos de severidad
  alta o crítica sin resolver, salvo que estén tratados como falso positivo o excepción según los
  puntos siguientes.
- **Falso positivo** (hallazgo sin riesgo real): la supresión MUST ser específica (regla y
  ubicación concretas, nunca reglas desactivadas globalmente), llevar justificación escrita y
  aprobarse en la revisión del pull request.
- **Excepción** (riesgo real aceptado temporalmente): MUST registrarse según la sección de
  Gobernanza.
- Las pruebas manuales de API (Postman, cURL) y de laboratorio MUST dejar evidencia reproducible
  (colecciones, comandos o capturas) en la documentación de la funcionalidad.

**Justificación**: un control sin verificación es solo una suposición. SAST, SCA y el análisis de
contenedores detectan clases distintas de fallos, y documentar supresiones evita que los falsos
positivos oculten riesgos reales.

### VI. Registro, Auditoría y Trazabilidad

- MUST registrarse los eventos de seguridad: inicios de sesión exitosos y fallidos, cambios de MFA,
  cambios de rol o permisos, accesos denegados y operaciones sobre datos financieros.
- Cada evento MUST incluir, en formato estructurado, únicamente los metadatos mínimos para la
  trazabilidad y la investigación: marca de tiempo, tipo de evento, actor (mediante identificador
  interno o seudonimizado), recurso afectado, resultado y, cuando sea necesario para investigar, la
  dirección IP de origen.
- Los registros MUST NOT contener contraseñas, tokens, cookies de sesión, claves, secretos (incluidos
  los TOTP) ni datos financieros sensibles (p. ej. números completos de cuenta o tarjeta).
- Los registros de auditoría MUST protegerse contra modificación por usuarios de la aplicación.

**Justificación**: sin trazabilidad no es posible detectar ni investigar incidentes (funciones
Detectar y Responder de NIST CSF 2.0); limitar el contenido de los registros evita que se conviertan
en una fuente de fuga de datos.

### VII. Privacidad y Datos Ficticios

- El proyecto MUST usar exclusivamente datos ficticios; está prohibido cargar datos personales o
  financieros reales en cualquier entorno.
- Toda funcionalidad que trate datos personales MUST aplicar minimización: recolectar solo lo
  necesario y documentar su finalidad.
- El diseño MUST considerar los principios de la Ley 1581 de 2012 (finalidad, libertad,
  seguridad, confidencialidad y acceso) como referencia de privacidad.

**Justificación**: es un laboratorio académico; usar datos reales introduciría riesgos legales y
éticos sin aportar valor formativo.

### VIII. Simplicidad y Proporcionalidad

- La arquitectura MUST ser un monolito modular con Django REST Framework; los microservicios están
  fuera de alcance.
- Cada dependencia, servicio o componente nuevo (p. ej. Redis) MUST justificarse en el `plan.md`
  con la necesidad concreta que resuelve.
- Los controles de seguridad MUST ser proporcionales al alcance académico del proyecto y contar con
  un mecanismo de verificación; se descarta la complejidad que no pueda demostrarse.

**Justificación**: cada componente adicional amplía la superficie de ataque y el esfuerzo de
verificación; la simplicidad es en sí misma un control de seguridad.

## Marco de Referencia y Stack Tecnológico

**Estándares de referencia.** Los siguientes marcos se usan como referencias técnicas y criterios de
verificación. SecureFin Gateway MUST NOT afirmar que posee certificaciones oficiales ni que cumple
íntegramente con ninguno de ellos.

- **OWASP Top 10 2025** y **OWASP ASVS 5.0.0**: seguridad de la aplicación web.
- **OWASP API Security Top 10**: seguridad de las interfaces REST.
- **STRIDE**: modelado de amenazas (Principio I).
- **NIST CSF 2.0**: marco para organizar los controles; **ISO/IEC 27001** como referencia
  complementaria.
- **Ley 1581 de 2012 (Colombia)**: privacidad y protección de datos personales (Principio VII).

**Stack base (preliminar).** Las versiones definitivas, dependencias y configuraciones se fijan y
justifican durante `/speckit-plan`.

- **Frontend**: React, Vite, JavaScript, diseño responsive.
- **Backend**: Python 3, Django, Django REST Framework.
- **Datos**: PostgreSQL; Redis solo si una funcionalidad lo requiere y se justifica.
- **Infraestructura**: Nginx (API Gateway y Reverse Proxy), Docker y Docker Compose, HTTPS/TLS.
- **Seguridad**: Argon2id, SHA-256, AES-256-GCM, RSA-OAEP y ECDSA (demostrativos), MFA TOTP, RBAC.
- **DevSecOps y pruebas**: Git, GitHub, GitHub Actions, Semgrep y/o Bandit (SAST), herramienta SCA
  por definir, Trivy (contenedores y archivos), Pytest, Postman, cURL.
- **Laboratorio**: Wireshark, Cisco Packet Tracer, Nmap, OWASP Juice Shop, Apache Benchmark,
  OpenSSL.

**Uso ético de herramientas.** Las herramientas de análisis y ataque (Nmap, Wireshark, Apache
Benchmark, etc.) MUST usarse únicamente contra el entorno de laboratorio propio, OWASP Juice Shop u
otros objetivos con autorización explícita. Las pruebas de carga MUST limitarse al entorno local.

## Flujo de Desarrollo y Puertas de Calidad

1. **Especificación**: cada funcionalidad inicia con `/speckit-specify`; los requisitos de seguridad
   y los criterios de aceptación de las mitigaciones se expresan de forma verificable. Si la
   funcionalidad involucra autenticación, la especificación técnica justifica el mecanismo elegido
   (Principio II).
2. **Planificación**: `plan.md` MUST incluir, cuando aplique, el análisis STRIDE (Principio I), los
   requisitos OWASP/ASVS de referencia, las excepciones de TLS u otras previstas, y la evaluación
   "Constitution Check" contra los principios I–VIII.
3. **Implementación**: el trabajo se realiza en ramas y se integra mediante pull requests en GitHub;
   no se permiten commits directos a la rama principal.
4. **Revisión**: cada pull request MUST verificar el cumplimiento de esta constitución, pasar el
   pipeline completo (pruebas, SAST, SCA y análisis de contenedores), justificar toda supresión de
   hallazgos y no introducir secretos.
5. **Reproducibilidad**: el sistema completo MUST levantarse con Docker Compose a partir del
   repositorio y de un archivo de ejemplo de variables de entorno sin secretos reales.
6. **Evidencia**: cada funcionalidad de seguridad cierra con evidencia de verificación (resultados de
   pruebas, reportes de herramientas o capturas de laboratorio) enlazada desde su documentación.

## Gobernanza

- Esta constitución prevalece sobre cualquier otra práctica o guía del proyecto. Ante un conflicto,
  se aplica la constitución o se enmienda formalmente.
- **Enmiendas**: se proponen con `/speckit-constitution`, deben indicar la justificación del cambio
  y el impacto en especificaciones y planes existentes, y quedan registradas en el control de
  versiones.
- **Versionado semántico**: MAJOR para eliminar o redefinir principios de forma incompatible; MINOR
  para añadir principios o secciones o ampliar materialmente una guía; PATCH para aclaraciones y
  correcciones de redacción.
- **Excepciones**: toda desviación de un principio (incluidas las excepciones de TLS del
  Principio III y los hallazgos reales aceptados temporalmente del Principio V) MUST registrarse en
  la sección "Complexity Tracking" del `plan.md` correspondiente, indicando: justificación, riesgo
  residual, control compensatorio si existe, responsable y fecha de revisión o condición de cierre.
  No se admiten excepciones a las prohibiciones absolutas (reutilizar nonces AES-GCM, credenciales
  sin TLS a través de un límite de confianza, secretos en el repositorio, datos reales).
- **Falsos positivos**: se gestionan según el Principio V y se revisan en el pull request que los
  introduce.
- **Revisión de cumplimiento**: se verifica en cada "Constitution Check" de `/speckit-plan`, en cada
  pull request y en el análisis `/speckit-analyze` antes de implementar.
- La guía operativa de desarrollo en tiempo de ejecución se mantiene en `CLAUDE.md` y MUST ser
  coherente con esta constitución.

**Versión**: 1.1.0 | **Ratificada**: 2026-11-08 | **Última enmienda**: 2026-11-08
