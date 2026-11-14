# Preparar un equipo nuevo (Windows) para continuar SecureFin con Claude Code

Tiempo aproximado: 30–60 min, casi todo descargas. Al terminar tendrás el repositorio, las
herramientas, las skills de diseño, el stack funcionando y Claude Code con todo el contexto
(`CLAUDE.md` se carga solo al abrir la carpeta).

## 1. Git y el repositorio

En **PowerShell como administrador**:

```powershell
winget install --id Git.Git -e
winget install --id GitHub.cli -e
```

Cierra y abre **una PowerShell normal** (para que el PATH se actualice) y ejecuta:

```powershell
gh auth login                      # inicia sesión en GitHub (cuenta JohanDsito)
cd $HOME\Desktop
git clone https://github.com/JohanDsito/SECUREFIN.git
cd SECUREFIN
git checkout 001-iam-access-control
git config --global user.name "Johan Delgado"
git config --global user.email "134401808+JohanDsito@users.noreply.github.com"
```

Usa ese mismo correo `noreply` para que los commits sigan saliendo a tu nombre sin exponer tu correo.

## 2. Herramientas (instala lo que falte y actualiza lo que ya tengas)

En **PowerShell como administrador**, dentro de la carpeta del repositorio:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\setup\install-tools.ps1
```

Instala o actualiza Git, Docker Desktop, Node.js LTS, Python 3.12, VS Code, Claude Code y su
extensión, GitHub CLI y Wireshark; activa WSL 2 y añade `127.0.0.1 securefin.local` al archivo hosts.
Con `-CheckOnly` solo informa de qué hay; con `-SkipWireshark` omite Wireshark.

Después:

1. **Reinicia** el equipo si se instaló WSL o Docker Desktop por primera vez.
2. Abre **Docker Desktop**, acepta los términos y espera a que diga "Engine running".
3. Wireshark (solo para la demo de tráfico): si la captura en loopback no aparece, instala Npcap desde
   https://npcap.com con *Support loopback traffic* activado.

## 3. Skills de diseño de Claude Code

En una **PowerShell normal**, dentro del repositorio:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\setup\install-claude-skills.ps1
```

Instala las 23 skills (impeccable, ui-ux-pro-max, design-taste-frontend, huashu-design y las 19 de Emil
Kowalski) **en los mismos commits que se revisaron**; si un commit no coincide, esa skill no se instala.
Las skills de Spec Kit ya vienen dentro del repositorio.

## 4. Claude Code

Abre la carpeta del repositorio en **VS Code** (`code .`), abre el panel de Claude Code e **inicia
sesión con la misma cuenta** de este equipo. También puedes usar la terminal: `claude` y luego
`/login`.

## 5. Secretos y stack

En **Git Bash**, dentro del repositorio:

```bash
bash scripts/setup.sh
```

Genera secretos **nuevos** para este equipo (los de `secrets/` nunca se copian ni se suben a GitHub),
levanta la base de datos, aplica las migraciones y arranca el resto. **Anota la contraseña de Mailpit**
que aparece: solo se muestra una vez (si la pierdes: `bash scripts/setup.sh mailpit`).

Comprueba en el navegador: **https://securefin.local** (acepta el aviso del certificado de laboratorio).

La base de datos de este equipo empieza **vacía**. Para la demo, crea tu Administrador:

```bash
docker compose -f infra/compose.yaml exec backend \
  python manage.py iam_bootstrap_admin --email admin@lab.securefin.local --name "Tu nombre"
```

y actívalo desde el buzón (https://127.0.0.1:8025) como indica `docs/security/DEMO-EN-VIVO.md`.

## 6. Dependencias del frontend y pruebas

```bash
cd frontend && npm ci && npx playwright install chromium && cd ..
bash scripts/dev/run-backend-tests.sh      # la primera vez construye la imagen de pruebas (~4 min)
```

Resultado esperado: **740 passed**.

## 7. Retomar con Claude

Abre Claude Code en la carpeta del repositorio y escribe:

> Lee CLAUDE.md y seguimos con el rediseño.

Claude cargará el estado, las decisiones del rediseño y tus reglas de trabajo.

## Problemas frecuentes

| Síntoma | Solución |
|---|---|
| `winget` no existe | Instala "App Installer" desde Microsoft Store |
| El script `.ps1` no se ejecuta | Usa `powershell -ExecutionPolicy Bypass -File …` como en los ejemplos |
| Docker: "WSL 2 is not installed" | `wsl --install --no-distribution` como administrador y reinicia |
| `docker` no responde | Abre Docker Desktop y espera a "Engine running" |
| La API responde 400 | Entra por https://securefin.local, no por 127.0.0.1 |
| Claude no ve las skills | Cierra y vuelve a abrir Claude Code después de instalarlas |
