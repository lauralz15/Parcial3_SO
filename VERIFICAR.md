# Guía de verificación (para el equipo)

Estado: el código **compila limpio** (probado en WSL2) y las pruebas 1/4 y 2/4 pasan. La prueba 4/4 (hook BPF LSM rechazando mmap con EPERM) **aún no se ha ejecutado**: el kernel de WSL2 no tiene `CONFIG_BPF_LSM`. Necesitamos que alguien la corra en un Linux real (VM o instalación) y nos pase la salida.

## 1. Entorno
Ubuntu 22.04/24.04/26.04 en VM o instalado (NO WSL; `uname -r` no debe contener "microsoft").

```bash
sudo apt update
sudo apt install -y build-essential clang llvm libbpf-dev pkg-config linux-tools-common linux-tools-generic bpftool
cat /sys/kernel/security/lsm     # debe incluir "bpf"
ls /sys/kernel/btf/vmlinux       # debe existir
```

Si `bpf` NO aparece en la lista de LSM:
```bash
sudo nano /etc/default/grub
# en GRUB_CMDLINE_LINUX agregar:  lsm=<lista actual de arriba>,bpf
sudo update-grub && sudo reboot
```
(Con Secure Boot activo, el modo lockdown puede restringir BPF; si falla, desactivarlo en la VM/BIOS.)

## 2. Ejecutar
Copiar el proyecto a una carpeta de Linux (por ejemplo `~/Parcial3_SO`, no una carpeta compartida con Windows):
```bash
cd ~/Parcial3_SO
(uname -r; cat /sys/kernel/security/lsm; make clean && make && make test && make bench) 2>&1 | tee evidencia.txt
```
Resultado esperado de `make test`: `[RESULTADO] mmap fue rechazado: errno=1 (Operation not permitted)` y `OK: el hook rechazó el mapeo...`

## 3. Qué enviar al grupo
- `evidencia.txt` y una captura de pantalla.
- Si falla: el mensaje de error completo.

## 4. Puntos a vigilar
- Se corrigió en el loader la conversión de `st_dev` (`(major<<20)|minor`) y **no se ha probado**. Si `poc_mmap` responde "mmap permitido" con el hook activo, revisar esa línea en `src/shield_loader.c`.
- Con la salida real: completar la sección 4.4 y la tabla de la 4.5 del informe PDF (casillas "[medir]").
