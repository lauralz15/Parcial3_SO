#!/usr/bin/env bash
# Mide overhead de mmap/page faults sin y con el hook BPF LSM activo.
# Uso: bash tests/bench.sh [iteraciones] [repeticiones]
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; cd "$ROOT"
ITERS="${1:-100000}"; REPS="${2:-7}"
[[ -x ./bench_mmap && -x ./shield_loader ]] || { echo "Ejecuta make primero" >&2; exit 2; }
T="$(mktemp -d)"; LP=""
cleanup() { [[ -n "$LP" ]] && sudo kill -TERM "$LP" 2>/dev/null || true; rm -rf "$T"; }
trap cleanup EXIT
head -c 65536 /dev/urandom > "$T/datos.bin"   # archivo NO protegido (16 paginas)
head -c 4096 /dev/urandom > "$T/protegido.bin"

run() { for _ in $(seq "$REPS"); do ./bench_mmap "$T/datos.bin" "$ITERS"; done | sort -t= -k2 -n | sed -n "$(( (REPS+1)/2 ))p"; }

echo "== Sin hook (mediana de $REPS corridas) =="; BASE="$(run)"; echo "$BASE"
sudo -v
sudo ./shield_loader "$T/protegido.bin" >"$T/loader.log" 2>&1 & LP=$!
for _ in $(seq 50); do grep -q 'Política activa' "$T/loader.log" && break; sleep 0.2; done
grep -q 'Política activa' "$T/loader.log" || { cat "$T/loader.log"; echo "Loader no inicio" >&2; exit 1; }
echo "== Con hook (mediana de $REPS corridas) =="; HOOK="$(run)"; echo "$HOOK"
uname -r
