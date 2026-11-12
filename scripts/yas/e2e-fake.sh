#!/bin/sh
# Prueba de extremo a extremo SIN root: compila yas con -tags privseptest
# (el broker acepta correr sin privilegios) y usa un sudo y un pacman falsos.
# Ejercita: lanzamiento vía "sudo", re-ejecución desacoplada del broker,
# verificación SO_PEERCRED, relay de pty, propagación del código de salida,
# denegación por política y cierre del broker al terminar yas.
#
# Uso: scripts/yas/e2e-fake.sh   (desde la raíz del repositorio)
set -eu

repo=$(cd "$(dirname "$0")/../.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/bin"

(cd "$repo" && go build -tags privseptest -o "$tmp/yas-test" .)

cat > "$tmp/bin/sudo" <<'EOS'
#!/bin/sh
echo "[sudo falso] $*" | cut -c1-120 >> "$(dirname "$0")/../sudo.log"
[ "$1" = "-k" ] && exit 0
exec "$@"
EOS

cat > "$tmp/bin/pacman" <<'EOS'
#!/bin/sh
echo "[pacman falso] args: $*"
[ -t 0 ] && echo "[pacman falso] stdin es una TTY: $(tty)"
printf ":: ¿Continuar con la instalación? [S/n] "
read ans
echo "[pacman falso] respuesta: '$ans'"
exit 7
EOS
chmod +x "$tmp/bin/sudo" "$tmp/bin/pacman"
: > "$tmp/foo-1.0-1-x86_64.pkg.tar.zst"

cd "$tmp"
echo "### 1) -U de un paquete local: debe pedir 'sudo' una vez y propagar el exit 7"
printf 's\n' | script -qec "./yas-test --privsep --sudo $tmp/bin/sudo --pacman $tmp/bin/pacman -U foo-1.0-1-x86_64.pkg.tar.zst; echo \"exit=\$?\"" /dev/null

echo
echo "### 2) -U desde una URL: el broker debe rechazarlo"
script -qec "./yas-test --privsep --sudo $tmp/bin/sudo --pacman $tmp/bin/pacman -U https://evil.example/x-1-1-any.pkg.tar.zst; echo \"exit=\$?\"" /dev/null </dev/null

echo
echo "### 3) invocaciones del elevador (una por sesión + sudo -k):"
cat sudo.log

sleep 1
echo
if ps -eo args | grep -F -- "--yas-privsep-broker --daemon" | grep -qv grep; then
  echo "### 4) FALLO: quedó un broker vivo"; exit 1
else
  echo "### 4) OK: ningún broker sigue vivo tras terminar yas"
fi
