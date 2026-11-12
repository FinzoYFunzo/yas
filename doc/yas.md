# yas — Yet another Sudo

Separación de privilegios para yay. Proyecto del ramo Seguridad Computacional (2026-2).

`yas` es yay con un modo nuevo, `--privsep`. En vez de invocar `sudo pacman`
cada vez que necesita root (y mantener viva la credencial de sudo con
`--sudoloop`), yay lanza **una sola vez** un proceso privilegiado pequeño, el
*broker*. Desde ahí le pide que ejecute pacman por un canal privado.

## Problema que resuelve

| Defecto en yay | Consecuencia |
|---|---|
| `updateSudo()` reintentaba `sudo -v` sin límite ni pausa cuando fallaba | Cada prompt sin respuesta es un fallo para `pam_faillock`; con `deny=3` la cuenta se bloquea durante actualizaciones desatendidas (issue Jguer/yay#2170) |
| Con `timestamp_timeout=0` el sudoloop no puede funcionar | yay terminaba bloqueando la cuenta en vez de desactivarse |
| Para que el sudoloop funcione, la credencial de sudo queda viva en la terminal toda la sesión | Cualquier proceso en esa terminal, incluido el `build()` de un PKGBUILD del AUR, puede ejecutar `sudo` como root sin contraseña |

## Arquitectura

```
          sin privilegios (usuario)                      root
 ┌───────────────────────────────────┐     ┌──────────────────────────────────┐
 │ yas (yay)                         │ 1.  │ sudo ─► broker (lanzador)        │
 │  ├─ crea socket en dir 0700 ──────┼────►│          └─ re-exec + setsid ─┐  │
 │  │                                │     │                               ▼  │
 │  │◄──── 2. conecta + SO_PEERCRED ─┼─────┼──── broker (daemon)            │
 │  ├─ 3. sudo -k                    │     │       ├─ valida lista blanca     │
 │  ├─ órdenes (-S/-U/-D/-R) ────────┼────►│       └─ pacman en una pty nueva │
 │  ├─ teclado ⇄ pty de pacman ◄─────┼────►│                                  │
 │  └─ makepkg con no_new_privs      │     │  termina con EOF (yay se fue)    │
 └───────────────────────────────────┘     └──────────────────────────────────┘
```

1. **Una autenticación.** yay ejecuta `sudo yas --yas-privsep-broker ...` al
   inicio, cuando el usuario está presente. El broker valida sus argumentos, se
   re-ejecuta desacoplado (`setsid`) y el `sudo` original termina de inmediato.
   Así sudo nunca queda leyendo la terminal durante la sesión.
2. **Canal privado y autenticado en ambos extremos** (`SO_PEERCRED`, verificado
   por el kernel):
   - El broker solo acepta un socket cuyo dueño sea **exactamente el PID y UID**
     del yay que lo lanzó.
   - yay solo acepta un broker que corra como **root**. Otro proceso del mismo
     usuario no puede hacerse pasar por ninguno de los dos.
   - El socket vive en un directorio `0700` que se borra apenas se establece la
     conexión.
3. **Sin credencial reutilizable.** Apenas el broker se conecta, yay ejecuta
   `sudo -k` (o `doas -L`).
4. **Lista blanca.** El cliente envía una orden estructurada
   (`{op, flags, targets}`), nunca un argv crudo. El broker arma el argv él
   mismo (`pkg/privsep/policy.go`):
   - Solo acepta las operaciones `-S`, `-U`, `-R`, `-D`, `-Fy` y `-Qk`, con sus
     opciones conocidas.
   - Rechaza `--root`, `--sysroot`, `--dbpath`, `--config`, `--cachedir`,
     `--gpgdir`, `--hookdir`, `--logfile` y `--arch`.
   - `-U` acepta solo archivos locales regulares `*.pkg.tar*` con ruta
     absoluta: nada de URLs ni symlinks.
   - Los nombres de paquete no pueden empezar con `-`.
   - El binario de pacman y `pacman.conf` quedan fijos al momento del
     lanzamiento.
5. **Terminal real para pacman.** pacman corre en una pty nueva, así que los
   prompts `[S/n]`, las barras de progreso y `^C` funcionan. yay retransmite el
   teclado solo mientras pacman corre, para no robar entradas de sus propios
   menús.
6. **Ciclo de vida acotado.** El broker termina cuando yay cierra el socket,
   incluso con `kill -9` o Ctrl+C.
7. **Defensa en profundidad.** Con `--privsep`, makepkg corre bajo
   `setpriv --no-new-privs`, y así un PKGBUILD **no puede usar sudo** ni otros
   binarios setuid.
8. **Auditoría.** Cada sesión, orden ejecutada, orden denegada y código de
   salida queda en el journal: `journalctl -t yas-broker`.

Además, el `--sudoloop` clásico ahora **falla de forma segura**:
- Hace un solo intento interactivo y nunca reintenta.
- La renovación en segundo plano usa `sudo -n -v`, que nunca pide contraseña y
  por eso no puede sumar fallos a faillock.
- Si sudo no guarda credenciales en caché (`timestamp_timeout=0`), avisa y se
  desactiva.

## Compilar

Requiere Go ≥ 1.26 y pacman (libalpm), igual que yay.

```sh
cd "/home/nial/U/2026-2/Seguridad Computacional/yas"
git switch yas/privsep
go build -o yas .
```

El broker ejecuta como root **este mismo binario**. Para uso real conviene
instalarlo en una ruta de root (`sudo install -Dm755 yas /usr/local/bin/yas`).
Si se ejecuta desde un directorio del usuario, otro proceso de ese usuario
podría reemplazar el binario antes del lanzamiento (ver *Limitaciones*).

## Probar con un downgrade real

`php-sqlite` es un buen candidato: pesa ~40 KB, nadie depende de él y en la
caché están la `8.5.12-4` (instalada) y la `8.5.12-1`.

```sh
pacman -Q php-sqlite                    # php-sqlite 8.5.12-4
faillock --user "$USER"                 # anota los fallos actuales

./yas --privsep -U /var/cache/pacman/pkg/php-sqlite-8.5.12-1-x86_64.pkg.tar.zst
#   -> UNA sola contraseña; pacman pregunta "¿Continuar? [S/n]" como siempre

pacman -Q php-sqlite                    # php-sqlite 8.5.12-1  (downgrade hecho)
sudo -n true                            # "a password is required": no quedó credencial (sudo -k)
ps -eo args | grep -F -- --yas-privsep-broker | grep -v grep   # vacío: el broker terminó
journalctl -t yas-broker --since -10min # session start / EXEC ... -U ... / EXIT 0 / session end

./yas --privsep -U /var/cache/pacman/pkg/php-sqlite-8.5.12-4-x86_64.pkg.tar.zst   # volver
```

La prueba funciona igual con `timestamp_timeout=0` en sudoers, que es el caso
que rompía `--sudoloop`. Para una prueba larga sirve
`./yas --privsep -Syu`: se pide la contraseña una vez al inicio y nunca más,
aunque la compilación dure horas o el equipo se suspenda.

## Demo: un PKGBUILD que intenta obtener root

```sh
sudo -v && yay -B scripts/yas/sudo-probe              # yay original: "!!! obtuvo root (uid=0)"
sudo -v && ./yas --privsep -B scripts/yas/sudo-probe  # yas: "OK: sudo bloqueado ... no new privileges"
```

La sonda falla a propósito y nunca se instala. Con yay original, la credencial
recién creada por `sudo -v` (o mantenida por `--sudoloop`) queda disponible para
el PKGBUILD.

## Tests

```sh
go test ./pkg/privsep/ ./pkg/settings/exe/ -v   # política, protocolo, e2e con pty, impostores, sudoloop
TZ=UTC go test ./...                            # suite completa
sh scripts/yas/e2e-fake.sh                      # binario real sin root (sudo y pacman falsos)
```

- `TestBrokerEndToEnd`: el broker y el cliente reales sobre un socket y una pty
  reales, con un pacman falso interactivo. Verifica que llega la entrada del
  usuario, que hay TTY, que se propaga el código de salida y que se rechazan
  opciones prohibidas.
- `TestBrokerRejectsImpostorListener` / `TestClientRejectsUnprivilegedBroker`:
  ninguno de los extremos acepta un par falso.
- `TestBuildArgvDenied`: 29 órdenes maliciosas rechazadas (`--hookdir`,
  `--root`, URLs, symlinks, inyección de opciones, path traversal…).
- `TestSudoLoopFailsSafe`: con un sudo que siempre falla hay **una**
  invocación. La versión original hacía cientos por segundo (632 en 2 s en la
  prueba de concepto).

Nota: `pkg/text` `TestFormatTime` falla fuera de UTC también en la rama
original (depende de la zona horaria); por eso se usa `TZ=UTC`.

## Archivos

| Archivo | Contenido |
|---|---|
| `pkg/privsep/protocol.go` | Formato de los frames del canal |
| `pkg/privsep/policy.go` | Lista blanca y construcción del argv (núcleo de seguridad) |
| `pkg/privsep/broker.go` | Broker: lanzador, daemon, verificación del par, ejecución en pty, auditoría |
| `pkg/privsep/client.go` | Lado de yay: socket privado, lanzamiento, relay de terminal |
| `pkg/privsep/sys_linux.go` | pty y `SO_PEERCRED` |
| `pkg/privsep/testmode_*.go` | Modo de prueba sin root, solo con `-tags privseptest` |
| `pkg/settings/exe/cmd_builder.go` | Integración: ruteo de `sudo pacman` al broker, `no_new_privs`, sudoloop seguro |
| `cmd.go`, `main.go`, `pkg/settings/*` | Flag `--privsep` / opción `privsep`, entrada oculta del broker |
| `scripts/yas/` | Sonda PKGBUILD y prueba e2e con fakes |

## Limitaciones y riesgo residual

- **Instalar un paquete sigue siendo ejecutar código como root.** Los
  scriptlets `.install` y los hooks del paquete corren como root. El broker
  limita *quién* puede pedir instalaciones y *cómo*, no *qué* hace un paquete
  malicioso.
- **El canal equivale a root para quien lo controla.** La seguridad descansa en
  que solo el yay lanzador lo tiene (`SO_PEERCRED`, fd no heredable) y en
  `kernel.yama.ptrace_scope=1`, el valor por defecto de Arch. Con
  `ptrace_scope=0`, otro proceso del usuario podría inyectarse en yay.
- **El binario lanzado como root pertenece al usuario** si no se instala en una
  ruta de root.
- `su` no está soportado con `--privsep`. `run0` y `pkexec` deberían funcionar,
  pero no se probaron; `sudo` y `doas` son los soportados.
- Si el broker no puede iniciarse de forma diferida (por ejemplo, en `-B`, donde
  no se pide root al inicio), yay avisa y vuelve al `sudo pacman` clásico.
