#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [[ $EUID -eq 0 ]]; then
  echo "Ejecuta el script como usuario normal; solo el loader necesita sudo." >&2
  exit 2
fi
command -v sudo >/dev/null || { echo "Falta sudo" >&2; exit 2; }
[[ -x ./poc_mmap && -x ./poc_readonly && -x ./poc_race_safe ]] || { echo "Compila primero con make user" >&2; exit 2; }
TMPDIR_TEST="$(mktemp -d)"
LOADER_PID=""
cleanup() {
  if [[ -n "$LOADER_PID" ]] && kill -0 "$LOADER_PID" 2>/dev/null; then sudo kill -TERM "$LOADER_PID" 2>/dev/null || true; wait "$LOADER_PID" 2>/dev/null || true; fi
  rm -rf "$TMPDIR_TEST"
}
trap cleanup EXIT
FILE="$TMPDIR_TEST/protegido.txt"
printf 'archivo de prueba protegido\n' > "$FILE"
chmod 666 "$FILE"

printf '[1/4] Prueba positiva: mmap de solo lectura debe permitirse...\n'
./poc_readonly "$FILE"

printf '[2/4] Simulación segura de concurrencia madvise/lectura (no es exploit)...\n'
./poc_race_safe "$FILE"
printf '[3/4] Iniciando política BPF LSM para el archivo de prueba...\n'
sudo -v
sudo ./shield_loader "$FILE" >"$TMPDIR_TEST/loader.log" 2>&1 &
LOADER_PID=$!
for _ in $(seq 1 50); do
  if grep -q 'Política activa' "$TMPDIR_TEST/loader.log"; then break; fi
  if ! kill -0 "$LOADER_PID" 2>/dev/null; then cat "$TMPDIR_TEST/loader.log"; echo "No se pudo iniciar el hook LSM." >&2; exit 1; fi
  sleep 0.2
done
if ! grep -q 'Política activa' "$TMPDIR_TEST/loader.log"; then cat "$TMPDIR_TEST/loader.log"; echo "Timeout esperando al loader." >&2; exit 1; fi
cat "$TMPDIR_TEST/loader.log"

printf '[4/4] Prueba negativa: mmap compartido y escribible debe ser rechazado...\n'
set +e
./poc_mmap "$FILE"
rc=$?
set -e
if [[ $rc -ne 0 ]]; then echo "FALLO: la política no rechazó el mapeo (código $rc)." >&2; exit 1; fi
echo "OK: el hook rechazó el mapeo y permitió la lectura privada."
