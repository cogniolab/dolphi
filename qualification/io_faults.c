/* Linux-only qualification interposer. Never linked into the product.
 * Rules: OP KIND MODE SKIP. All matching is confined to a synthetic /tmp root.
 * No keys, payload bytes, SQL or network traffic are logged. */
#define _GNU_SOURCE
#define _LARGEFILE64_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sendfile.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

static _Atomic unsigned long matched;
static const char *fault_root, *control_path, *log_path;

__attribute__((constructor)) static void configure(void) {
    fault_root = getenv("DOLPHI_FAULT_ROOT");
    control_path = getenv("DOLPHI_FAULT_CONTROL");
    log_path = getenv("DOLPHI_FAULT_LOG");
    if (!fault_root || strncmp(fault_root, "/tmp/dolphi-storage-", 20) ||
        !control_path || !log_path) fault_root = NULL;
}

static void event(const char *op, const char *kind, const char *mode, long amount) {
    char message[256];
    int length = snprintf(message, sizeof(message),
        "{\"op\":\"%s\",\"kind\":\"%s\",\"mode\":\"%s\",\"amount\":%ld}\n",
        op, kind, mode, amount);
    int fd = syscall(SYS_openat, AT_FDCWD, log_path, O_WRONLY|O_APPEND|O_CREAT|O_CLOEXEC, 0600);
    if (fd >= 0) { (void)syscall(SYS_write, fd, message, length); syscall(SYS_close, fd); }
}

/* 0 normal, -1 injected errno, 1 short, 2 pause, 3 partial then pause. */
static int action(const char *op, int fd, char *selected_kind, char *selected_mode) {
    if (!fault_root) return 0;
    char link[64], path[4096], rule[128], want_op[24], want_kind[24], mode[24];
    snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
    ssize_t length = syscall(SYS_readlinkat, AT_FDCWD, link, path, sizeof(path)-1);
    if (length < 0) return 0;
    path[length] = 0;
    size_t root_length = strlen(fault_root);
    if (strncmp(path, fault_root, root_length) || path[root_length] != '/') return 0;
    const char *name = strrchr(path, '/'); name = name ? name + 1 : path;
    const char *kind = "other";
    if (strstr(path, "/backup/")) kind = "backup";
    else if (strstr(path, "/report/")) kind = "report";
    else if (strstr(path, "/dolphi-migration-")) kind = "copy";
    else if (!strncmp(name, ".dolphi-restore-", 16)) kind = "stage";
    else if (strlen(name) >= 4 && !strcmp(name + strlen(name)-4, "-wal")) kind = "wal";
    else if (strlen(name) >= 3 && !strcmp(name + strlen(name)-3, ".db")) kind = "db";
    else if (!strcmp(name, "backup")) kind = "backupdir";
    else if (!strcmp(name, "restore")) kind = "restoredir";
    else if (!strcmp(name, "report")) kind = "reportdir";
    unsigned long skip;
    int input = syscall(SYS_openat, AT_FDCWD, control_path, O_RDONLY|O_CLOEXEC, 0);
    if (input < 0) return 0;
    ssize_t count = syscall(SYS_read, input, rule, sizeof(rule)-1); syscall(SYS_close, input);
    if (count <= 0) return 0;
    rule[count] = 0;
    if (sscanf(rule, "%23s %23s %23s %lu", want_op, want_kind, mode, &skip) != 4) return 0;
    if (strcmp(want_op, op) || strcmp(want_kind, kind)) return 0;
    unsigned long nth = atomic_fetch_add(&matched, 1);
    if (nth < skip) return 0;
    strcpy(selected_kind, kind); strcpy(selected_mode, mode);
    if (!strcmp(mode, "trace")) {event(op,kind,mode,0);return 0;}
    if (!strcmp(mode, "short") && nth > skip) return 0;
    if ((!strcmp(mode, "short") || !strcmp(mode, "short_full")) && nth == skip) return 1;
    if (!strcmp(mode, "pause")) return 2;
    if (!strcmp(mode, "tear_pause")) return 3;
    event(op, kind, mode, -1);
    errno = (!strcmp(mode, "full") || !strcmp(mode, "short_full")) ? ENOSPC : EIO;
    return -1;
}

static void pause_here(const char *op, const char *kind, const char *mode, long n) {
    event(op, kind, mode, n);
    syscall(SYS_kill, getpid(), SIGSTOP);
}

static ssize_t positioned(int fd, const void *buffer, size_t count, off64_t offset) {
    char kind[24], mode[24]; int selected = action("pwrite", fd, kind, mode);
    if (selected < 0) return -1;
    if (selected == 1 || selected == 3) {
        size_t amount = count > 1 ? count/2 : count;
        ssize_t result = syscall(SYS_pwrite64, fd, buffer, amount, offset);
        if (selected == 3) pause_here("pwrite", kind, mode, result);
        else event("pwrite", kind, mode, result);
        return result;
    }
    if (selected == 2) pause_here("pwrite", kind, mode, 0);
    return syscall(SYS_pwrite64, fd, buffer, count, offset);
}
ssize_t pwrite(int fd, const void *b, size_t n, off_t o) { return positioned(fd,b,n,o); }
ssize_t pwrite64(int fd, const void *b, size_t n, off64_t o) { return positioned(fd,b,n,o); }

ssize_t write(int fd, const void *buffer, size_t count) {
    char kind[24], mode[24]; int selected = action("write",fd,kind,mode);
    if (selected < 0) return -1;
    if (selected == 2) pause_here("write",kind,mode,0);
    size_t amount = selected == 1 || selected == 3 ? (count > 1 ? count/2 : count) : count;
    ssize_t result = syscall(SYS_write,fd,buffer,amount);
    if (selected == 3) pause_here("write",kind,mode,result);
    else if (selected == 1) event("write",kind,mode,result);
    return result;
}
ssize_t writev(int fd, const struct iovec *vectors, int count) {
    char kind[24], mode[24]; int selected = action("write",fd,kind,mode);
    if (selected < 0) return -1;
    if (selected == 2) pause_here("write",kind,mode,0);
    if ((selected == 1 || selected == 3) && count > 0) {
        size_t n = vectors[0].iov_len; if (n > 1) n/=2;
        ssize_t result = syscall(SYS_write,fd,vectors[0].iov_base,n);
        if (selected == 3) pause_here("write",kind,mode,result);
        else event("write",kind,mode,result);
        return result;
    }
    return syscall(SYS_writev,fd,vectors,count);
}
static int synchronize(int fd, long number) {
    char kind[24], mode[24]; int selected = action("sync",fd,kind,mode);
    if (selected < 0) return -1;
    if (selected == 2) pause_here("sync",kind,mode,0);
    return syscall(number,fd);
}
int fsync(int fd) { return synchronize(fd,SYS_fsync); }
int fdatasync(int fd) { return synchronize(fd,SYS_fdatasync); }
int ftruncate(int fd, off_t length) {
    char kind[24], mode[24]; int selected=action("truncate",fd,kind,mode);
    if (selected < 0) return -1;
    if (selected == 2) pause_here("truncate",kind,mode,0);
    return syscall(SYS_ftruncate,fd,length);
}
int ftruncate64(int fd, off64_t length) { return ftruncate(fd,length); }
ssize_t copy_file_range(int in, off64_t *oi, int out, off64_t *oo, size_t n, unsigned flags) {
    char kind[24], mode[24]; int selected=action("write",out,kind,mode);
    if (selected < 0) return -1;
    if (selected == 2) pause_here("write",kind,mode,0);
    return syscall(SYS_copy_file_range,in,oi,out,oo,n,flags);
}
ssize_t sendfile(int out, int in, off_t *offset, size_t count) {
    char kind[24], mode[24]; int selected=action("write",out,kind,mode);
    if (selected < 0) return -1;
    if (selected == 2) pause_here("write",kind,mode,0);
    return syscall(SYS_sendfile,out,in,offset,count);
}
