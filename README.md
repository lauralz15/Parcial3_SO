
```markdown
# Parcial 3 — Seguridad de archivos mediante mmap en capa de kernel

Laura Sofia Lizarazo, Isabella Hernández Posada, Jaime Jesús Cotes y Cristóbal
Rodríguez

## Alcance real de esta implementación

Esta versión utiliza **BPF LSM** y el hook `lsm/mmap_file` para aplicar una política demostrable: rechazar `mmap()` con `PROT_WRITE | MAP_SHARED` sobre un archivo regular que se registra al iniciar el loader. Los mapeos de solo lectura/privados no se rechazan por esta regla. La decisión se toma en el kernel; no es un wrapper de libc.

**Limitaciones importantes:** es una demostración académica, no un sistema de protección completo. No bloquea `write(2)`, `pwrite(2)`, otras rutas de acceso ni protege el contenido frente a administradores/root. No es una mitigación de Dirty COW ni cifra archivos. El mapa usa dispositivo + inode; si el archivo se reemplaza, hay que reiniciar el loader para registrar el nuevo inode.

## Requisitos

- Linux con BPF LSM disponible (kernel >= 5.7), BTF en `/sys/kernel/btf/vmlinux` y `CONFIG_BPF_LSM=y`.
- El LSM BPF debe estar habilitado en la lista de LSM del kernel. Verifica con `cat /sys/kernel/security/lsm`.
- `clang` con backend BPF, `bpftool`, `libbpf-dev`, `pkg-config`, GCC y `sudo`.
- Permisos administrativos/CAP_BPF y CAP_SYS_ADMIN según kernel y configuración.

> **Nota para entornos WSL2 (Ubuntu):**  
> Si `bpftool` genera errores de dependencias al compilar, instala las herramientas genéricas y crea el enlace simbólico ejecutando:  
> `sudo apt update && sudo apt install -y linux-tools-generic libbpf-dev`  
> `sudo ln -sf /usr/lib/linux-tools/6.8.0-147-generic/bpftool /usr/local/bin/bpftool`

## Compilar

```bash
make clean && make

```

Si solo quieres compilar las pruebas de espacio de usuario:

```bash
make user

```

## Ejecutar las pruebas

Para ejecutar la suite automatizada completa de 4 etapas:

```bash
bash tests/test_kernel_mmap.sh

```

El script comprueba que un mapeo de lectura privada siga funcionando y que el mapeo compartido y escribible del archivo registrado sea rechazado con `EPERM`. El test falla si no puede iniciar el hook o si el resultado no es el esperado.

También se puede iniciar manualmente:

```bash
sudo ./shield_loader /ruta/absoluta/archivo.txt

```

Mientras el loader está activo, abre otra terminal y ejecuta:

```bash
./poc_mmap /ruta/absoluta/archivo.txt
./poc_readonly /ruta/absoluta/archivo.txt

```

Detén el loader con `Ctrl+C`.

## Arquitectura

1. `bpf/mmap_shield.bpf.c`: programa BPF LSM conectado a `lsm/mmap_file`.
2. `src/shield_loader.c`: obtiene el dispositivo/inode del archivo, lo inserta en el mapa BPF Hash (`protected_files`) y conecta el hook.
3. `exploits/poc_mmap.c`: espera que un mapeo compartido/escribible sea rechazado por la política.
4. `exploits/poc_readonly.c`: comprueba que un mapeo de lectura privada siga permitido.
5. `exploits/poc_race_safe.c`: prueba concurrentemente lecturas y `MADV_DONTNEED` como simulación segura; no explota ni afirma mitigar Dirty COW.
6. `tests/test_kernel_mmap.sh`: automatiza pruebas con comprobación de resultados y limpieza.

## Interpretación de resultados

* `EPERM` en `poc_mmap` mientras el hook está activo: el hook rechazó la solicitud.
* `poc_readonly` exitoso: la política no bloquea ese acceso de lectura.
* Si el loader falla, no declares las pruebas aprobadas. Revisa kernel, BTF, configuración LSM, paquetes y permisos.

## Seguridad y compatibilidad

El programa no usa kprobes sobre funciones internas ni modifica la tabla de llamadas al sistema. La política es intencionalmente acotada y explícita. El mecanismo de autorización debe ser validado en el kernel destino antes de presentar resultados.

## Medición de overhead

`make bench` (o `bash tests/bench.sh 100000 7`) mide `mmap`+acceso+`munmap` y fallos de página menores sobre un archivo no protegido, sin y con el hook activo, y reporta la mediana. Pega la salida real y la versión del kernel en el informe.

```

```
