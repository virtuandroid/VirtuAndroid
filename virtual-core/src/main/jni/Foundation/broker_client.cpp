#include <linux/audit.h>
#include <stdatomic.h>
#include <sys/ucontext.h>
#include "broker_proto.h"
#include "fb/ALog.h"
#include <cerrno>
#include <fcntl.h>
#include <netinet/in.h>
#include <csignal>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <ctime>
#include <unistd.h>
#include <cstdlib>
#include <jni.h>
#include <linux/seccomp.h>
#include <linux/prctl.h>
#include <sys/prctl.h>
#include <linux/bpf_common.h>
#include <linux/filter.h>

static int g_broker_fd = -1;
static pid_t g_self_pid;
static std::atomic_flag g_lock = ATOMIC_FLAG_INIT;

static inline void lock() {
    while (atomic_flag_test_and_set_explicit(&g_lock, memory_order_acquire)) {}
}

static inline void unlock() { atomic_flag_clear_explicit(&g_lock, memory_order_release); }

// Static (lock-protected) request buffer keeps handler stack usage tiny.
static struct req_buf {
    struct broker_req_hdr h;
    uint8_t data[2 * PATH_MAX + BROKER_MAX_BLOB];
} g_req;

// Fault-safe copies from our own address space: -EFAULT instead of SIGSEGV in the handler.
// The seccomp filter must allow process_vm_readv with arg0 == this tgid.
static long copy_from_self(void *dst, const void *src, size_t n) {
    struct iovec l = {dst, n}, r = {(void *) src, n};
    ssize_t k = syscall(__NR_process_vm_readv, g_self_pid, &l, 1, &r, 1, 0);
    return k == (ssize_t) n ? 0 : -EFAULT;
}

static long copy_cstr(char *dst, const char *src, size_t cap) {   // returns strlen or -errno
    size_t done = 0;
    while (done < cap) {
        uintptr_t p = (uintptr_t) src + done;
        size_t chunk = 4096 - (p & 4095);                          // never cross a page
        if (chunk > cap - done) chunk = cap - done;
        long e = copy_from_self(dst + done, (const void *) p, chunk);
        if (e) return e;
        char *z = static_cast<char *>(memchr(dst + done, 0, chunk));
        if (z) return z - dst;
        done += chunk;
    }
    return -ENAMETOOLONG;
}

struct rpc {
    uint32_t op;
    int64_t a[4];
    int fd[2];              // fds to attach; -1 = AT_FDCWD / none
    const char *path[2];         // client-memory pointers; NULL = absent
    const void *blob;
    uint32_t blob_len;
    void *out;
    uint32_t out_cap;
    bool cloexec;
    int recv_fd;
};

static long broker_rpc(struct rpc *r) {
    r->recv_fd = -1;
    if (r->blob_len > BROKER_MAX_BLOB || r->out_cap > BROKER_MAX_OUT) return -EINVAL;

    lock();
    struct broker_req_hdr *h = &g_req.h;
    memset(h, 0, sizeof *h);
    h->magic = BROKER_MAGIC;
    h->op = r->op;
    h->out_cap = r->out_cap;
    memcpy(h->a, r->a, sizeof h->a);

    size_t off = 0;
    long e;
    for (int i = 0; i < 2; i++) {
        if (!r->path[i]) continue;
        long n = copy_cstr((char *) g_req.data + off, r->path[i], PATH_MAX);
        if (n < 0) {
            unlock();
            return n;
        }
        h->path_len[i] = (uint32_t) n;
        off += n;
    }
    if (r->blob_len) {
        if ((e = copy_from_self(g_req.data + off, r->blob, r->blob_len))) {
            unlock();
            return e;
        }
        h->blob_len = r->blob_len;
        off += r->blob_len;
    }

    int fds[2], nf = 0;
    for (int i = 0; i < 2; i++)
        if (r->fd[i] >= 0) {
            h->fdmask |= 1u << i;
            fds[nf++] = r->fd[i];
        }

    union {
        char b[CMSG_SPACE(2 * sizeof(int))];
        struct cmsghdr a;
    } sc{};
    struct iovec siov = {&g_req, offsetof(struct req_buf, data) + off};
    struct msghdr sm = {.msg_iov = &siov, .msg_iovlen = 1};
    if (nf) {
        memset(&sc, 0, sizeof sc);
        sm.msg_control = sc.b;
        sm.msg_controllen = CMSG_SPACE(nf * sizeof(int));
        struct cmsghdr *c = CMSG_FIRSTHDR(&sm);
        c->cmsg_level = SOL_SOCKET;
        c->cmsg_type = SCM_RIGHTS;
        c->cmsg_len = CMSG_LEN(nf * sizeof(int));
        memcpy(CMSG_DATA(c), fds, nf * sizeof(int));
    }
    ssize_t n;
    do { n = sendmsg(g_broker_fd, &sm, MSG_NOSIGNAL); } while (n < 0 && errno == EINTR);
    if (n < 0) {
        unlock();
        return -EIO;
    }

    // Output lands directly in the caller's buffer; the kernel handles bad pointers.
    struct broker_resp_hdr resp{};
    struct iovec riov[2] = {{&resp,  sizeof resp},
                            {r->out, r->out_cap}};
    union {
        char b[CMSG_SPACE(sizeof(int))];
        struct cmsghdr a;
    } rc{};
    struct msghdr rm = {.msg_iov = riov, .msg_iovlen = static_cast<size_t>(r->out_cap ? 2 : 1),
            .msg_control = rc.b, .msg_controllen = sizeof rc.b};
    do { n = recvmsg(g_broker_fd, &rm, r->cloexec ? MSG_CMSG_CLOEXEC : 0); }
    while (n < 0 && errno == EINTR);
    unlock();
    if (n < 0) return -EFAULT;      // most likely a bad output pointer

    int fd = -1;
    for (struct cmsghdr *c = CMSG_FIRSTHDR(&rm); c; c = CMSG_NXTHDR(&rm, c))
        if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_RIGHTS && fd < 0 &&
            c->cmsg_len == CMSG_LEN(sizeof(int)))
            memcpy(&fd, CMSG_DATA(c), sizeof(int));

    if (n < (ssize_t) sizeof resp || resp.magic != BROKER_MAGIC ||
        (rm.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) || resp.out_len > r->out_cap ||
        (size_t) n != sizeof resp + resp.out_len) {
        if (fd >= 0) close(fd);
        return -EIO;
    }
    if (resp.result < 0 && fd >= 0) {
        close(fd);
        fd = -1;
    }
    r->recv_fd = fd;
    return resp.result;
}

#define I(n)   ((long)UC_ARG(uc, n))
#define P(n)   ((const char*)UC_ARG(uc, n))
#define DFD(n) (((int)I(n) == AT_FDCWD) ? -1 : (int)I(n))
#define CLAMP_OUT(v) ((v) > BROKER_MAX_OUT ? BROKER_MAX_OUT : (uint32_t)(v))

#if defined(__NR_newfstatat)
#define STAT_SZ sizeof(struct stat)
#else
#define STAT_SZ sizeof(struct stat64)
#endif

static long proxy_syscall(ucontext_t *uc, int nr) {
    struct rpc r = {.fd = {-1, -1}};
    switch (nr) {
#ifdef __NR_open
        case __NR_open:                                       // (path, flags, mode)
            r.op = OP_OPENAT;
            r.fd[0] = -1;                                     // same encoding DFD() gives AT_FDCWD
            r.path[0] = P(0);
            r.a[0] = I(1);                                    // flags
            r.a[1] = I(2);                                    // mode
            r.cloexec = I(1) & O_CLOEXEC;
            break;
#endif
        case __NR_openat:
            r.op = OP_OPENAT;
            r.fd[0] = DFD(0);
            r.path[0] = P(1);
            r.a[0] = I(2);
            r.a[1] = I(3);
            r.cloexec = I(2) & O_CLOEXEC;
            break;
#ifdef __NR_newfstatat
        case __NR_newfstatat:
#endif
#ifdef __NR_fstatat64
            case __NR_fstatat64:
#endif
            r.op = OP_FSTATAT;
            r.fd[0] = DFD(0);
            r.path[0] = P(1);
            r.out = (void *) I(2);
            r.out_cap = STAT_SZ;
            r.a[0] = I(3);
            break;
        case __NR_statfs:
            r.op = OP_STATFS;
            r.path[0] = P(0);
            r.out = (void *) I(1);
            r.out_cap = sizeof(struct statfs);
            break;
#ifdef __NR_statfs64
            case __NR_statfs64:                                   // (path, size, buf)
                if (I(1) <= 0 || I(1) > BROKER_MAX_OUT) return -EINVAL;
                r.op = OP_STATFS; r.path[0] = P(0); r.a[0] = I(1); r.out = (void*)I(2); r.out_cap = I(1);
                break;
#endif
        case __NR_fchownat:
            r.op = OP_FCHOWNAT;
            r.fd[0] = DFD(0);
            r.path[0] = P(1);
            r.a[0] = I(2);
            r.a[1] = I(3);
            r.a[2] = I(4);
            break;
#ifdef __NR_renameat
        case __NR_renameat:
            r.op = OP_RENAMEAT;
            r.fd[0] = DFD(0);
            r.path[0] = P(1);
            r.fd[1] = DFD(2);
            r.path[1] = P(3);
            break;
#endif
        case __NR_renameat2:
            r.op = OP_RENAMEAT;
            r.fd[0] = DFD(0);
            r.path[0] = P(1);
            r.fd[1] = DFD(2);
            r.path[1] = P(3);
            r.a[0] = I(4);
            break;
        case __NR_mkdirat:
            r.op = OP_MKDIRAT;
            r.fd[0] = DFD(0);
            r.path[0] = P(1);
            r.a[0] = I(2);
            break;
        case __NR_mknodat:
            r.op = OP_MKNODAT;
            r.fd[0] = DFD(0);
            r.path[0] = P(1);
            r.a[0] = I(2);
            r.a[1] = I(3);
            break;
#ifdef __LP64__
        case __NR_truncate:
            r.op = OP_TRUNCATE;
            r.path[0] = P(0);
            r.a[0] = I(1);
            break;
#endif
        case __NR_linkat:
            r.op = OP_LINKAT;
            r.fd[0] = DFD(0);
            r.path[0] = P(1);
            r.fd[1] = DFD(2);
            r.path[1] = P(3);
            r.a[0] = I(4);
            break;
        case __NR_readlinkat:
            if (I(3) <= 0) return -EINVAL;
            r.op = OP_READLINKAT;
            r.fd[0] = DFD(0);
            r.path[0] = P(1);
            r.out = (void *) I(2);
            r.out_cap = CLAMP_OUT(I(3));
            break;
        case __NR_unlinkat:
            r.op = OP_UNLINKAT;
            r.fd[0] = DFD(0);
            r.path[0] = P(1);
            r.a[0] = I(2);
            break;
        case __NR_symlinkat:                                  // (target, newdirfd, linkpath)
            r.op = OP_SYMLINKAT;
            r.path[0] = P(0);
            r.fd[1] = DFD(1);
            r.path[1] = P(2);
            break;
        case __NR_utimensat:
            r.op = OP_UTIMENSAT;
            r.fd[0] = DFD(0);
            r.a[0] = I(3);
            if (P(1)) r.path[0] = P(1); else r.a[1] = 1;      // NULL path == futimens(fd)
            if (I(2)) {
                r.blob = (void *) I(2);
                r.blob_len = 2 * sizeof(struct timespec);
            }
            break;
        case __NR_chdir:
            r.op = OP_CHDIR;
            r.path[0] = P(0);
            break;
        case __NR_getcwd:
            if (I(1) <= 0) return -EINVAL;
            r.op = OP_GETCWD;
            r.out = (void *) I(0);
            r.out_cap = CLAMP_OUT(I(1));
            break;
        case __NR_kill:
            r.op = OP_KILL;
            r.a[0] = (int) I(0);
            r.a[1] = (int) I(1);
            break;
        case __NR_connect:
            r.fd[0] = (int) I(0);
            if (r.fd[0] < 0) return -EBADF;
            if (I(2) < 0 || I(2) > (long) BROKER_MAX_BLOB) return -EINVAL;
            r.op = OP_CONNECT;
            r.blob = (void *) I(1);
            r.blob_len = (uint32_t) I(2);
            break;
        default:
            return -ENOSYS;
    }

    long res = broker_rpc(&r);
    if (r.op == OP_OPENAT && res >= 0) return r.recv_fd;   // openat's result is the received fd
    return res;
}

static void sigsys_handler(int sig, siginfo_t *info, void *ucontext) {
    int syscall_nr = info->si_syscall;   // blocked syscall number
    int arch = info->si_arch;      // AUDIT_ARCH_* value
    void *addr = info->si_call_addr; // address of the syscall instruction

    ALOGD("syscall=%d arch=0x%x addr=%p", syscall_nr, arch, addr);

    (void) sig;
    int saved_errno = errno;
    auto *uc = (ucontext_t *) ucontext;
    if (info->si_code != SYS_SECCOMP) {
        errno = saved_errno;
        return;
    }
    long ret = (info->si_arch != AUDIT_ARCH_CURRENT) ? -ENOSYS
                                                     : proxy_syscall(uc, info->si_syscall);
    ALOGD("Returned: %d from syscall: %d", ret, info->si_syscall);

    UC_RET(uc) = (typeof(UC_RET(uc))) ret;
    errno = saved_errno;
}

int broker_client_install(int sock_fd) {
    g_broker_fd = sock_fd;
    g_self_pid = getpid();                    // call after fork, before loading the filter
    struct sigaction sa{};
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = sigsys_handler;
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
    sigfillset(&sa.sa_mask);
    return sigaction(SIGSYS, &sa, nullptr);
}

void apply_seccomp_filter() {
    // 1. Prevent gaining new privileges via setuid/setgid binaries
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) {
        ALOGD("Failed to set PR_SET_NO_NEW_PRIVS");
        return;
    }

    // 2. Define the BPF Filter Instructions
    struct sock_filter filter[] = {
            // [0] Load architecture number from system call data frame into accumulator
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),

            // [1] Verify architecture matches target (prevents arch-switching exploits)
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_CURRENT, 1, 0),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),

            // [2] Load system call number into accumulator
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),

#ifdef __NR_open
            // [3] Check if Syscall is 'open'
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_open, 3, 0),
#endif
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_kill, 2, 0),

            // [4] Check if Syscall is 'openat'
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_openat, 1, 0),

            // [5] If not open/openat, ALLOW the syscall
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),

            // [6] If open/openat matched, RETURN TRAP
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP)
    };

    struct sock_fprog prog = {
            .len = static_cast<unsigned short>(sizeof(filter) / sizeof(filter[0])),
            .filter = filter,
    };

    // 3. Apply the filter using prctl
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) == -1) {
        ALOGD("Failed to apply Seccomp filter");
        return;
    }

    ALOGD("Applied Seccomp filter successfully");
}

extern "C"
JNIEXPORT void JNICALL
Java_com_lody_virtual_server_security_SyscallBroker_brokerClientInstall(JNIEnv *env, jobject thiz,
                                                                        jint fd) {
    ALOGI("Installing client fd: %d", fd);
    broker_client_install(fd);
    apply_seccomp_filter();
}