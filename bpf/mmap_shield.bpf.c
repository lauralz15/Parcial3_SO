// BPF LSM: deniega mmap compartido y escribible sobre un archivo protegido.
// Solo para laboratorio: no reemplaza permisos POSIX ni protege write(2).
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define SHIELD_PROT_WRITE 0x2UL
#define SHIELD_MAP_SHARED 0x01UL
#define SHIELD_EPERM 1

char LICENSE[] SEC("license") = "GPL";

struct file_key {
    __u64 dev;
    __u64 ino;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, struct file_key);
    __type(value, __u8);
} protected_files SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 3);
    __type(key, __u32);
    __type(value, __u64);
} counters SEC(".maps");

static __always_inline void count_event(__u32 index)
{
    __u64 *value = bpf_map_lookup_elem(&counters, &index);
    if (value)
        __sync_fetch_and_add(value, 1);
}

SEC("lsm/mmap_file")
int BPF_PROG(mmap_shield_file_mmap, struct file *file,
             unsigned long reqprot, unsigned long prot,
             unsigned long flags)
{
    (void)reqprot;

    count_event(0); // solicitudes inspeccionadas

    // Solo se bloquea escritura compartida en el archivo registrado.
    if ((prot & SHIELD_PROT_WRITE) && (flags & SHIELD_MAP_SHARED)) {
        struct file_key key = {};
        key.ino = BPF_CORE_READ(file, f_inode, i_ino);
        key.dev = BPF_CORE_READ(file, f_inode, i_sb, s_dev);
        if (bpf_map_lookup_elem(&protected_files, &key)) {
            count_event(1); // intentos bloqueados
            return -SHIELD_EPERM;
        }
    }

    count_event(2); // solicitudes permitidas por esta política
    return 0;
}
