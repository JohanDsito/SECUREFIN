# Laboratorio de red en Cisco Packet Tracer — Semanas 2, 3, 4 y 6

Docker reproduce la segmentación de SecureFin con **redes virtuales** (equivalentes a VLAN), pero
algunos temas del curso necesitan **equipos de red reales**: VLAN 802.1Q, Wi-Fi WPA2/WPA3, un servidor
AAA con **RADIUS/TACACS+**, ACL *stateless* frente a un firewall *stateful* y NAC en el switch. Este
laboratorio los monta en Packet Tracer con la **misma arquitectura por zonas** que la aplicación.

| Zona de SecureFin (Docker) | VLAN en Packet Tracer | Red | Quién vive ahí |
|---|---|---|---|
| Usuarios de Internet | VLAN 10 `CLIENTES` | 192.168.10.0/24 | PC-Cliente1, PC-Cliente2 |
| Personal (Admin/Auditor) | VLAN 20 `ADMIN` | 192.168.20.0/24 | PC-Admin |
| `edge_net` (DMZ) | VLAN 30 `DMZ` | 192.168.30.0/24 | SRV-Web (192.168.30.20), SRV-AAA (192.168.30.10) |
| Gestión de equipos | VLAN 99 `GESTION` | 192.168.99.0/24 | IP de gestión del switch |

Al terminar, **guarda el archivo** como `docs/security/evidence/securefin-red.pkt` y toma capturas
de cada prueba (son la evidencia de estas semanas).

---

## 1. Topología (5 min)

Arrastra estos equipos y conéctalos con cable directo (cobre):

```
                 [R1  ISR 2911]  (router-on-a-stick + AAA + firewall)
                       │ G0/0  (trunk 802.1Q)
                       │
                 [S1  2960-24TT]  G0/1
   ┌──────────┬────────┼─────────┬──────────┐
 Fa0/1      Fa0/2    Fa0/6     Fa0/11     Fa0/12
PC-Cliente1 PC-Cliente2 PC-Admin SRV-Web   SRV-AAA
 (VLAN 10)  (VLAN 10) (VLAN 20) (VLAN 30)  (VLAN 30)
```

IP estáticas (Desktop → IP Configuration):

| Equipo | IP | Máscara | Gateway |
|---|---|---|---|
| PC-Cliente1 | 192.168.10.11 | 255.255.255.0 | 192.168.10.1 |
| PC-Cliente2 | 192.168.10.12 | 255.255.255.0 | 192.168.10.1 |
| PC-Admin | 192.168.20.11 | 255.255.255.0 | 192.168.20.1 |
| SRV-Web | 192.168.30.20 | 255.255.255.0 | 192.168.30.1 |
| SRV-AAA | 192.168.30.10 | 255.255.255.0 | 192.168.30.1 |

En **SRV-Web** → Services → HTTP: deja HTTP y HTTPS en *On* y edita `index.html` con el texto
`SecureFin DMZ`.

---

## 2. Semana 3 — VLAN y segmentación LAN (S1)

```
enable
configure terminal
hostname S1
vlan 10
 name CLIENTES
vlan 20
 name ADMIN
vlan 30
 name DMZ
vlan 99
 name GESTION
vlan 999
 name NATIVA-SIN-USO
exit
interface range fa0/1 - 5
 switchport mode access
 switchport access vlan 10
interface range fa0/6 - 10
 switchport mode access
 switchport access vlan 20
interface range fa0/11 - 15
 switchport mode access
 switchport access vlan 30
! Trunk hacia el router; la VLAN nativa NO es la 1 (mitiga VLAN hopping por doble etiqueta)
interface g0/1
 switchport mode trunk
 switchport trunk native vlan 999
 switchport trunk allowed vlan 10,20,30,99
! Denegar por defecto en capa 2: los puertos sin uso se apagan y se aparcan en una VLAN muerta
interface range fa0/16 - 24 , g0/2
 switchport mode access
 switchport access vlan 999
 shutdown
interface vlan 99
 ip address 192.168.99.2 255.255.255.0
 no shutdown
ip default-gateway 192.168.99.1
end
write memory
```

**Prueba**: antes de configurar el router, `ping 192.168.20.11` desde PC-Cliente1 **falla**: dos
VLAN son dos dominios de difusión distintos. `show vlan brief` y `show interfaces trunk` → captura.

---

## 3. Enrutamiento entre VLAN (R1, router-on-a-stick)

```
enable
configure terminal
hostname R1
interface g0/0
 no shutdown
interface g0/0.10
 encapsulation dot1Q 10
 ip address 192.168.10.1 255.255.255.0
interface g0/0.20
 encapsulation dot1Q 20
 ip address 192.168.20.1 255.255.255.0
interface g0/0.30
 encapsulation dot1Q 30
 ip address 192.168.30.1 255.255.255.0
interface g0/0.99
 encapsulation dot1Q 99
 ip address 192.168.99.1 255.255.255.0
interface g0/0.999
 encapsulation dot1Q 999 native
end
```

Ahora **todo** se comunica con todo (un cliente llega al PC-Admin). Eso es justo lo que la
**Semana 6** corrige con el firewall.

---

## 4. Semana 4 — AAA centralizado con RADIUS y TACACS+

### 4.1 Servidor AAA (SRV-AAA → Services → AAA)

1. **Service: On**.
2. *Network Configuration* → añade el cliente AAA:
   - Client Name `R1`, Client IP `192.168.30.1`, Secret `SecureFin-AAA-2026`, ServerType **Radius** → *Add*.
3. *User Setup* → añade usuarios (ficticios):
   - `admin.red` / `Adm1n-Lab-2026!`
   - `auditor.red` / `Aud1t-Lab-2026!`

### 4.2 Router como cliente RADIUS (Autenticación + Auditoría)

```
configure terminal
! Usuario local de emergencia (break-glass), solo si el servidor AAA no responde
username breakglass privilege 15 secret BreakGlass-Lab-2026!
ip domain-name securefin.local
crypto key generate rsa general-keys modulus 2048
ip ssh version 2
aaa new-model
radius-server host 192.168.30.10 key SecureFin-AAA-2026
aaa authentication login default group radius local
aaa authorization exec default group radius local
line vty 0 4
 transport input ssh
 login authentication default
line console 0
 login authentication default
end
```

**Prueba**: desde PC-Admin → Desktop → Command Prompt:
`ssh -l admin.red 192.168.20.1` → pide contraseña y entra. Con una contraseña errónea, rechaza.
Apaga el servicio AAA en SRV-AAA y vuelve a probar: solo funciona `breakglass` (respaldo local).

> **Relación con SecureFin**: el router no guarda los usuarios; **pregunta a un servidor central**,
> igual que todas las rutas de SecureFin preguntan al servicio IAM (`backend/apps/iam/`). Las tres A:
> **Autenticación** (RADIUS valida la contraseña), **Autorización** (privilegio devuelto) y
> **Auditoría** (`show aaa sessions`; en SecureFin, la tabla `audit_securityevent`).

### 4.3 Variante TACACS+ (para comparar)

En SRV-AAA cambia el cliente `R1` a ServerType **Tacacs** y en R1:

```
configure terminal
no radius-server host 192.168.30.10
tacacs-server host 192.168.30.10 key SecureFin-AAA-2026
aaa authentication login default group tacacs+ local
aaa authorization exec default group tacacs+ local
aaa accounting exec default start-stop group tacacs+
end
```

| | RADIUS | TACACS+ |
|---|---|---|
| Transporte | UDP 1812/1813 (PT: 1645/1646) | TCP 49 |
| Cifrado | Solo la contraseña | **Todo** el cuerpo del paquete |
| AAA | Autenticación y autorización juntas | Las tres A separadas (autorización por comando) |
| Uso típico | Acceso de usuarios (Wi-Fi 802.1X, VPN) | Administración de equipos de red |

**MFA**: Packet Tracer no lo simula. En SecureFin el segundo factor (TOTP) es obligatorio para
Administrador y Auditor — muéstralo en el navegador (ver `DEMO-EN-VIVO.md` §5).

---

## 5. Semana 3 — Wi-Fi segura WPA2/WPA3-AES con RADIUS (WPA2-Enterprise)

Escenario aparte, en la misma hoja: **Wireless Router WRT300N** (`WR-SecureFin`) + **Server-PT**
(`SRV-RADIUS-WIFI`) por cable a un puerto LAN del router + **Laptop-PT** (cambia su tarjeta por
`WPC300N`: apaga el equipo, arrastra el módulo, enciende).

1. `WR-SecureFin` → GUI → Setup: IP LAN `192.168.0.1/24`, DHCP activo.
2. `SRV-RADIUS-WIFI`: IP `192.168.0.10/24`, gateway `192.168.0.1`. Services → AAA → On;
   cliente `WR-SecureFin`, IP `192.168.0.1`, secret `Wifi-Radius-2026`, tipo Radius; usuario
   `empleado1` / `Empl3ado-Lab-2026!`.
3. `WR-SecureFin` → Wireless → Basic: SSID `SecureFin-Staff`, **SSID Broadcast: Disabled**
   (opcional, no es seguridad real, solo ruido).
4. Wireless → Security: **Security Mode: WPA2 Enterprise**, Encryption **AES**, RADIUS Server
   `192.168.0.10`, Shared Secret `Wifi-Radius-2026` → Save.
5. Laptop → Desktop → PC Wireless → Connect / Profiles → SSID `SecureFin-Staff`,
   *WPA2-Enterprise*, usuario `empleado1` y su contraseña → Connect.

**Pruebas y explicación**:

- Con contraseña errónea, la laptop **no se asocia**: cada empleado tiene su propia credencial y se
  revoca en el servidor sin cambiar la clave de toda la red (lo que pasaría con WPA2-Personal/PSK).
- Cambia a *WPA2 Personal* con passphrase `Una-Frase-Larga-2026` para comparar: una sola clave para
  todos.
- **WPA3**: si tu versión de Packet Tracer lo ofrece en el menú de seguridad, elige **WPA3-Personal
  (SAE)** y conecta igual. Si no aparece, explica la diferencia: WPA3 sustituye el *4-way handshake*
  PSK por **SAE (Dragonfly)**, que resiste ataques de diccionario *offline* aunque se capture el
  handshake, obliga a **PMF** (802.11w, anti-desautenticación) y en modo Enterprise permite suite de
  192 bits. **Nunca** WEP ni TKIP.
- **Zero Trust local**: estar conectado a la Wi-Fi no da acceso a SecureFin; cada petición sigue
  pasando por TLS + sesión + MFA (Semana 4).

---

## 6. Semana 6 (y Semana 2) — Firewall: ACL *stateless* frente a inspección *stateful*

### 6.1 ACL extendida (stateless) con denegar por defecto

```
configure terminal
ip access-list extended CLIENTES-IN
 remark Zero Trust: un cliente solo puede usar la web de la DMZ
 permit tcp 192.168.10.0 0.0.0.255 host 192.168.30.20 eq 443
 permit tcp 192.168.10.0 0.0.0.255 host 192.168.30.20 eq 80
 deny   ip any any
ip access-list extended DMZ-IN
 remark Stateless: hay que permitir A MANO el trafico de vuelta (flag ACK = established)
 permit tcp host 192.168.30.20 eq 443 192.168.10.0 0.0.0.255 established
 permit tcp host 192.168.30.20 eq 80  192.168.10.0 0.0.0.255 established
 permit udp host 192.168.30.10 any eq 1645
 permit udp host 192.168.30.10 eq 1645 any
 permit tcp host 192.168.30.10 eq 49 any established
 deny   ip 192.168.30.0 0.0.0.255 192.168.10.0 0.0.0.255
 deny   ip 192.168.30.0 0.0.0.255 192.168.20.0 0.0.0.255
 permit ip any any
interface g0/0.10
 ip access-group CLIENTES-IN in
interface g0/0.30
 ip access-group DMZ-IN in
end
```

**Pruebas** (captura cada una):

| Desde | Hacia | Resultado esperado | Por qué |
|---|---|---|---|
| PC-Cliente1 (navegador) | `https://192.168.30.20` | ✅ carga | 443 permitido |
| PC-Cliente1 | `ping 192.168.30.20` | ❌ | ICMP no está en la lista → denegar por defecto |
| PC-Cliente1 | `ping 192.168.20.11` | ❌ | Un cliente nunca llega a la VLAN de administración |
| SRV-Web | `ping 192.168.10.11` | ❌ | Si la DMZ se compromete, no pivota hacia los clientes |
| PC-Admin | `ssh -l admin.red 192.168.20.1` | ✅ | Gestión desde la VLAN de administración |

`show access-lists` muestra los contadores de cada regla (*matches*) → captura.

> **Stateless** = cada paquete se evalúa solo, sin memoria. Por eso `DMZ-IN` necesita reglas
> `established` para la respuesta, y un atacante puede forjar paquetes con el flag ACK.

### 6.2 Firewall por zonas (stateful, Zone-Based Firewall)

Requiere la licencia de seguridad del 2911 (en Packet Tracer basta con activarla):

```
configure terminal
license boot module c2900 technology-package securityk9
end
write memory
reload
```

Quita primero las ACL (`interface g0/0.10` → `no ip access-group CLIENTES-IN in`, ídem en `.30`) y:

```
configure terminal
zone security CLIENTES
zone security DMZ
class-map type inspect match-any WEB
 match protocol http
 match protocol https
policy-map type inspect CLIENTES-A-DMZ
 class type inspect WEB
  inspect
 class class-default
  drop
zone-pair security CLI-DMZ source CLIENTES destination DMZ
 service-policy type inspect CLIENTES-A-DMZ
interface g0/0.10
 zone-member security CLIENTES
interface g0/0.30
 zone-member security DMZ
end
```

(Si tu versión no admite `zone-member` en subinterfaces, usa una interfaz física por zona: G0/0
para clientes y G0/1 para la DMZ con IP propia.)

**Prueba**: el cliente abre la web (✅) y **no hace falta ninguna regla de vuelta**: el router
recuerda la conexión (`show policy-map type inspect zone-pair sessions`). La DMZ no puede iniciar
nada hacia CLIENTES porque no existe un *zone-pair* en ese sentido → **denegar por defecto**.

> **Stateful** = el firewall mantiene una **tabla de conexiones**. Es lo que hacen las redes de
> Docker de SecureFin (iptables + conntrack) y Nginx como proxy: el exterior solo puede *responder*
> a conexiones abiertas desde dentro, y solo `edge_net` acepta conexiones nuevas desde Internet.

---

## 7. Semana 6 — NAC en el puerto del switch (port security)

```
configure terminal
interface range fa0/1 - 5
 switchport port-security
 switchport port-security maximum 1
 switchport port-security mac-address sticky
 switchport port-security violation shutdown
end
```

**Prueba**: haz ping desde PC-Cliente1 (el switch aprende su MAC). Desconéctalo y conecta en el
mismo puerto un **PC nuevo** (intruso) → el puerto pasa a `err-disabled`
(`show port-security interface fa0/1`). Para reactivarlo: `shutdown` + `no shutdown` en el puerto.

> **NAC** = solo entra a la red el dispositivo autorizado. En una empresa se hace con 802.1X contra
> el mismo RADIUS; en SecureFin el equivalente lógico es "solo entra quien supera TLS + sesión + MFA
> de su rol" (`backend/apps/iam/api/permissions.py`).

---

## 8. Semana 2 — Capas OSI en el modo Simulación

1. Pulsa **Simulation** (abajo a la derecha). En *Edit Filters* deja solo HTTP, TCP, ARP, ICMP.
2. Desde PC-Cliente1 abre `http://192.168.30.20` en el navegador y pulsa **Play**.
3. Haz clic en un sobre (PDU) → pestaña *OSI Model*: verás **Capa 2** (Ethernet, MAC y etiqueta
   802.1Q en el trunk), **Capa 3** (IP origen/destino), **Capa 4** (TCP, puerto 80) y **Capa 7**
   (HTTP GET). En *Inbound PDU Details* el contenido HTTP es **legible**.
4. Repite con `https://`: la capa 7 aparece como datos cifrados.
5. Repite el `ping` bloqueado: el sobre se marca con una ✗ roja **en R1** → ahí actúa el firewall.

Para el análisis con tráfico real (modo promiscuo, DPI y la contraseña en claro por HTTP), usa
Wireshark sobre SecureFin: [`README.md` de la raíz §6](../../README.md) y `evidence/E9-trafico-http-vs-https.txt`.
