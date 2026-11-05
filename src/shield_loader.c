#define _GNU_SOURCE
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

struct file_key { uint64_t dev; uint64_t ino; };
static volatile sig_atomic_t stop_requested;
static void on_signal(int sig) { (void)sig; stop_requested = 1; }

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "Uso: sudo %s /ruta/archivo_protegido\n", argv[0]);
        return 2;
    }
    struct stat st;
    if (stat(argv[1], &st) != 0) { perror("stat"); return 1; }
    if (!S_ISREG(st.st_mode)) {
        fprintf(stderr, "Error: para esta demo se requiere un archivo regular.\n");
        return 1;
    }

    struct bpf_object *obj = bpf_object__open_file("bpf/mmap_shield.bpf.o", NULL);
    long err = libbpf_get_error(obj);
    if (err) { fprintf(stderr, "No se pudo abrir el objeto BPF: %s\n", strerror((int)-err)); return 1; }
    if (bpf_object__load(obj) != 0) { fprintf(stderr, "No se pudo cargar BPF. Verifica BTF, CONFIG_BPF_LSM, permisos y kernel.\n"); bpf_object__close(obj); return 1; }

    int map_fd = bpf_object__find_map_fd_by_name(obj, "protected_files");
    if (map_fd < 0) { fprintf(stderr, "No se encontró el mapa protected_files.\n"); bpf_object__close(obj); return 1; }
    /* El kernel usa s_dev = MKDEV(major, minor) = major<<20 | minor; st_dev de glibc usa otra codificacion. */
    struct file_key key = { .dev = ((uint64_t)major(st.st_dev) << 20) | minor(st.st_dev), .ino = (uint64_t)st.st_ino };
    uint8_t value = 1;
    if (bpf_map_update_elem(map_fd, &key, &value, BPF_ANY) != 0) {
        perror("bpf_map_update_elem"); bpf_object__close(obj); return 1;
    }

    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "mmap_shield_file_mmap");
    if (!prog) { fprintf(stderr, "No se encontró el programa LSM.\n"); bpf_object__close(obj); return 1; }
    struct bpf_link *link = bpf_program__attach_lsm(prog);
    err = libbpf_get_error(link);
    if (err) { fprintf(stderr, "No se pudo conectar el hook LSM: %s\n", strerror((int)-err)); bpf_object__close(obj); return 1; }

    printf("[SHIELD] Política activa para %s (dev=%llu, inode=%llu).\n", argv[1],
           (unsigned long long)key.dev, (unsigned long long)key.ino);
    printf("[SHIELD] Bloquea mmap(PROT_WRITE | MAP_SHARED) para este archivo. Ctrl+C para salir.\n");
    fflush(stdout);
    signal(SIGINT, on_signal); signal(SIGTERM, on_signal);
    while (!stop_requested) pause();

    bpf_link__destroy(link);
    bpf_object__close(obj);
    puts("[SHIELD] Hook retirado.");
    return 0;
}
