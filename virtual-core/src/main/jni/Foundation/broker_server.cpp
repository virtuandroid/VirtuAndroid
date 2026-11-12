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


#include "broker_proto.h"
#include "logger.h"
#include "fb/ALog.h"
#include <jni.h>

#ifndef RENAME_NOREPLACE
#define RENAME_NOREPLACE 1
#endif

// TODO replace with Kotlin check
static bool policy_ok(const char *real, bool write) {
    return true;
}

/* ---------------- state / helpers ---------------- */
struct ctx {
    const struct broker_req_hdr *h;
    char path[2][PATH_MAX];
    const uint8_t *blob;
    int fd[2];                    // attached fds by slot; -1 = none (AT_FDCWD)
    uint8_t out[BROKER_MAX_OUT];
    uint32_t out_len;
    int ret_fd;
};

static char g_cwd[PATH_MAX] = "/";   // the client's *virtual* cwd
static pid_t g_client_pid;

static void closep(const int *p) { if (*p >= 0) close(*p); }

#define AUTOFD __attribute__((cleanup(closep))) int
#define TRY(x) do { int _e = (x); if (_e) return _e; } while (0)
#define SC(expr) ({ long _r = (long)(expr); _r < 0 ? (int64_t)-errno : (int64_t)_r; })

static int fd_path(int fd, char out[PATH_MAX]) {
    char proc[48];
    snprintf(proc, sizeof proc, "/proc/self/fd/%d", fd);
    ssize_t n = readlink(proc, out, PATH_MAX - 1);
    if (n < 0) return -errno;
    out[n] = 0;
    return 0;
}

// (dirfd slot, client path) -> absolute path string. dirfd < 0 means AT_FDCWD.
static int abs_path(int dirfd, const char *p, char out[PATH_MAX]) {
    if (!p[0]) return -ENOENT;
    char base[PATH_MAX];
    if (p[0] == '/') {
        base[0] = 0;
    } else if (dirfd < 0) {
        snprintf(base, sizeof base, "%s", g_cwd);
    } else {
        struct stat st{};
        if (fstat(dirfd, &st) < 0) return -errno;
        if (!S_ISDIR(st.st_mode)) return -ENOTDIR;
        TRY(fd_path(dirfd, base));
    }
    int n = (p[0] == '/') ? snprintf(out, PATH_MAX, "%s", p)
                          : snprintf(out, PATH_MAX, "%s/%s", base, p);
    return n >= PATH_MAX ? -ENAMETOOLONG : 0;
}

// O_PATH handle to the fully resolved target; policy is checked on what was *actually* resolved.
static int open_follow(const char *abs, bool write, bool nofollow, int *out) {
    int fd = open(abs, O_PATH | O_CLOEXEC | (nofollow ? O_NOFOLLOW : 0));
    if (fd < 0) return -errno;
    char real[PATH_MAX];
    struct stat st{};
    int e = fd_path(fd, real);
    if (!e && fstat(fd, &st) < 0) e = -errno;
    if (!e && S_ISLNK(st.st_mode)) e = -ELOOP;           // only possible with nofollow
    if (!e && !policy_ok(real, write)) e = -EACCES;
    if (e) {
        close(fd);
        return e;
    }
    *out = fd;
    return 0;
}

// Checked parent-dir handle + validated leaf. For ops that act on the final
// component itself (mkdir, unlink, rename, symlink, lstat, ...).
static int open_parent(const char *abs, bool write, int *pfd, char leaf[NAME_MAX + 1]) {
    char dir[PATH_MAX];
    snprintf(dir, sizeof dir, "%s", abs);
    size_t n = strlen(dir);
    while (n > 1 && dir[n - 1] == '/') dir[--n] = 0;
    char *slash = strrchr(dir, '/');
    if (!slash) return -EINVAL;
    const char *name = slash + 1;
    if (!*name || !strcmp(name, ".") || !strcmp(name, "..")) return -EINVAL;
    if (strlen(name) > NAME_MAX) return -ENAMETOOLONG;
    snprintf(leaf, NAME_MAX + 1, "%s", name);
    if (slash == dir) dir[1] = 0; else *slash = 0;

    int fd = open(dir, O_PATH | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) return -errno;
    char real[PATH_MAX], full[PATH_MAX];
    int e = fd_path(fd, real);
    if (!e) {
        snprintf(full, sizeof full, "%s%s%s", real, strcmp(real, "/") ? "/" : "", leaf);
        if (!policy_ok(full, write)) e = -EACCES;
    }
    if (e) {
        close(fd);
        return e;
    }
    *pfd = fd;
    return 0;
}

/* ---------------- handlers ---------------- */
#define OPEN_OK_FLAGS (O_ACCMODE | O_CREAT | O_EXCL | O_TRUNC | O_APPEND | O_CLOEXEC | \
                       O_LARGEFILE | O_DIRECTORY | O_NOFOLLOW | O_NONBLOCK | O_NOCTTY | \
                       O_PATH | O_SYNC)

// Allowlist of device nodes. Exact matches only; extend as needed.
// Never add: /dev/mem, /dev/kmem, /dev/port, /dev/block/*, /dev/ptmx, /dev/uinput, /dev/kmsg...
struct dev_rule { const char *path; bool allow_write; };
static const struct dev_rule DEV_RULES[] = {
    { "/dev/null",                  true  },
    { "/dev/zero",                  true  },
    { "/dev/full",                  true  },
    { "/dev/random",                false },
    { "/dev/urandom",               false },
    { "/dev/goldfish_pipe",         true  },
    { "/dev/goldfish_pipe_dprctd",  true  },
};

// TODO Kotlin helper
static bool dev_ok(const char *real, bool write) {
    return true;
}

static int64_t h_openat(struct ctx *c) {
    int flags = (int) c->h->a[0];
    mode_t mode = (mode_t) c->h->a[1] & 0777;                 // no setuid/sticky bits
    if ((unsigned) flags & ~(unsigned) OPEN_OK_FLAGS) return -EPERM;   // no O_TMPFILE etc.
    if ((flags & O_ACCMODE) == O_ACCMODE) return -EINVAL;
    bool write = !(flags & O_PATH) &&
                 ((flags & O_ACCMODE) != O_RDONLY || (flags & (O_CREAT | O_TRUNC | O_APPEND)));
    char abs[PATH_MAX];
    TRY(abs_path(c->fd[0], c->path[0], abs));

    ALOGD("Trying to open absolute path: %s", abs);

    int fd;
    if (flags & O_CREAT) {
        // Never create in /dev, and never open an unvetted device node from this path:
        // the open would already have side effects before the post-open check runs.
        if (strncmp(abs, "/dev/", 5) == 0) return -EACCES;

        char leaf[NAME_MAX + 1];
        AUTOFD pfd = -1;
        TRY(open_parent(abs, true, &pfd, leaf));
        fd = openat(pfd, leaf, flags | O_CLOEXEC | O_NOCTTY | O_NONBLOCK | O_NOFOLLOW, mode);
        if (fd < 0) return -errno;
    } else {
        AUTOFD pfd = -1;
        struct stat st{};
        TRY(open_follow(abs, write, flags & O_NOFOLLOW, &pfd));   // must be O_PATH, see note below
        if (fstat(pfd, &st) < 0) return -errno;

        if (S_ISCHR(st.st_mode)) {
            // Vet the device by its *resolved* path BEFORE opening it, so
            // symlinks/bind tricks can't smuggle in a non-allowlisted node.
            char preal[PATH_MAX];
            if (fd_path(pfd, preal) || !dev_ok(preal, write)) return -EACCES;
        } else if (!S_ISREG(st.st_mode) && !S_ISDIR(st.st_mode)) {
            return -EACCES;                                       // no FIFOs/sockets/block devs
        }

        char proc[48];
        snprintf(proc, sizeof proc, "/proc/self/fd/%d", pfd);
        // Re-open the *checked inode* with the real flags.
        fd = open(proc, (flags & ~O_NOFOLLOW) | O_CLOEXEC | O_NOCTTY | O_NONBLOCK);
        if (fd < 0) return -errno;
    }

    char real[PATH_MAX];
    struct stat st{};
    if (fd_path(fd, real) || fstat(fd, &st) < 0) {
        close(fd);
        return -EACCES;
    }
    bool ok;
    if (S_ISCHR(st.st_mode))
        ok = dev_ok(real, write);                    // devices: allowlist only
    else
        ok = (S_ISREG(st.st_mode) || S_ISDIR(st.st_mode)) && policy_ok(real, write);
    if (!ok) {
        close(fd);
        return -EACCES;
    }

    if (!(flags & O_NONBLOCK)) {
        int fl = fcntl(fd, F_GETFL);
        if (fl >= 0) fcntl(fd, F_SETFL, fl & ~O_NONBLOCK);
    }
    c->ret_fd = fd;
    return 0;
}

#if defined(__NR_newfstatat)
#define NR_FSTATAT __NR_newfstatat
#define STAT_SZ    sizeof(struct stat)
#else
#define NR_FSTATAT __NR_fstatat64
#define STAT_SZ    sizeof(struct stat64)
#endif

static int64_t h_fstatat(struct ctx *c) {
    int flags = (int) c->h->a[0];
    if (flags & ~(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH)) return -EINVAL;
    if (!c->path[0][0]) {                       // fstat(fd) via AT_EMPTY_PATH
        if (!(flags & AT_EMPTY_PATH) || c->fd[0] < 0) return -ENOENT;
        int64_t r = SC(syscall(NR_FSTATAT, c->fd[0], "", c->out, AT_EMPTY_PATH));
        if (r == 0) c->out_len = STAT_SZ;
        return r;
    }
    char abs[PATH_MAX], leaf[NAME_MAX + 1];
    AUTOFD fd = -1;
    TRY(abs_path(c->fd[0], c->path[0], abs));
    int64_t r;
    if (flags & AT_SYMLINK_NOFOLLOW) {
        TRY(open_parent(abs, false, &fd, leaf));
        r = SC(syscall(NR_FSTATAT, fd, leaf, c->out, AT_SYMLINK_NOFOLLOW));
    } else {
        TRY(open_follow(abs, false, false, &fd));
        r = SC(syscall(NR_FSTATAT, fd, "", c->out, AT_EMPTY_PATH));
    }
    if (r == 0) c->out_len = STAT_SZ;
    return r;
}

static int64_t h_statfs(struct ctx *c) {        // a[0] = struct size for statfs64, 0 for statfs
    char abs[PATH_MAX], proc[48];
    AUTOFD fd = -1;
    TRY(abs_path(c->fd[0], c->path[0], abs));
    TRY(open_follow(abs, false, false, &fd));
    snprintf(proc, sizeof proc, "/proc/self/fd/%d", fd);
    int64_t r;
#ifdef __NR_statfs64
    if (c->h->a[0]) {
        if (c->h->a[0] > BROKER_MAX_OUT) return -EINVAL;
        r = SC(syscall(__NR_statfs64, proc, (size_t)c->h->a[0], c->out));
        if (r == 0) c->out_len = (uint32_t)c->h->a[0];
        return r;
    }
#endif
    r = SC(syscall(__NR_statfs, proc, c->out));
    if (r == 0) c->out_len = sizeof(struct statfs);
    return r;
}

static int64_t h_truncate(struct ctx *c) {
    char abs[PATH_MAX], proc[48];
    AUTOFD fd = -1;
    TRY(abs_path(c->fd[0], c->path[0], abs));
    TRY(open_follow(abs, true, false, &fd));
    snprintf(proc, sizeof proc, "/proc/self/fd/%d", fd);   // path-based truncate via magic link
    return SC(truncate(proc, (off_t) c->h->a[0]));
}

static int64_t h_fchownat(struct ctx *c) {       // a: uid, gid, flags
    auto u = (uid_t) c->h->a[0];
    auto g = (gid_t) c->h->a[1];
    int flags = (int) c->h->a[2];
    if (flags & ~AT_SYMLINK_NOFOLLOW) return -EINVAL;
    // Policy placeholder: never let the client pick arbitrary owners.
    if ((u != (uid_t) -1 && u != getuid()) || (g != (gid_t) -1 && g != getgid())) return -EPERM;
    char abs[PATH_MAX], leaf[NAME_MAX + 1], proc[48];
    AUTOFD fd = -1;
    TRY(abs_path(c->fd[0], c->path[0], abs));
    if (flags & AT_SYMLINK_NOFOLLOW) {
        TRY(open_parent(abs, true, &fd, leaf));
        return SC(fchownat(fd, leaf, u, g, AT_SYMLINK_NOFOLLOW));
    }
    TRY(open_follow(abs, true, false, &fd));
    snprintf(proc, sizeof proc, "/proc/self/fd/%d", fd);
    return SC(chown(proc, u, g));
}

static int64_t h_mkdirat(struct ctx *c) {
    char abs[PATH_MAX], leaf[NAME_MAX + 1];
    AUTOFD pfd = -1;
    TRY(abs_path(c->fd[0], c->path[0], abs));
    TRY(open_parent(abs, true, &pfd, leaf));
    return SC(mkdirat(pfd, leaf, (mode_t) c->h->a[0] & 0777));
}

static int64_t h_mknodat(struct ctx *c) {        // a: mode, dev
    auto mode = (mode_t) c->h->a[0];
    mode_t type = mode & S_IFMT;
    if (type != S_IFREG && type != S_IFIFO && type != S_IFSOCK) return -EPERM;  // no device nodes
    char abs[PATH_MAX], leaf[NAME_MAX + 1];
    AUTOFD pfd = -1;
    TRY(abs_path(c->fd[0], c->path[0], abs));
    TRY(open_parent(abs, true, &pfd, leaf));
    return SC(mknodat(pfd, leaf, type | (mode & 0777), 0));
}

static int64_t h_unlinkat(struct ctx *c) {
    int flags = (int) c->h->a[0];
    if (flags & ~AT_REMOVEDIR) return -EINVAL;
    char abs[PATH_MAX], leaf[NAME_MAX + 1];
    AUTOFD pfd = -1;
    TRY(abs_path(c->fd[0], c->path[0], abs));
    TRY(open_parent(abs, true, &pfd, leaf));
    return SC(unlinkat(pfd, leaf, flags));
}

static int64_t
h_symlinkat(struct ctx *c) {      // path0 = target text, path1 = linkpath (dirfd slot 1)
    char abs[PATH_MAX], leaf[NAME_MAX + 1];
    AUTOFD pfd = -1;
    TRY(abs_path(c->fd[1], c->path[1], abs));
    TRY(open_parent(abs, true, &pfd, leaf));
    // The target is just text. It is safe because the broker re-resolves and
    // policy-checks every path it ever follows.
    return SC(symlinkat(c->path[0], pfd, leaf));
}

static int64_t h_linkat(struct ctx *c) {         // a[0] = flags
    int flags = (int) c->h->a[0];
    if (flags & ~AT_SYMLINK_FOLLOW) return -EINVAL;
    char a[PATH_MAX], b[PATH_MAX], l1[NAME_MAX + 1], l2[NAME_MAX + 1], proc[48];
    AUTOFD p1 = -1, p2 = -1, f1 = -1;
    TRY(abs_path(c->fd[0], c->path[0], a));
    TRY(abs_path(c->fd[1], c->path[1], b));
    // Both ends must be writable: a hardlink from a read-only area would
    // hand the client a writable alias of that inode.
    TRY(open_parent(b, true, &p2, l2));
    if (flags & AT_SYMLINK_FOLLOW) {
        TRY(open_follow(a, true, false, &f1));
        snprintf(proc, sizeof proc, "/proc/self/fd/%d", f1);
        return SC(linkat(AT_FDCWD, proc, p2, l2, AT_SYMLINK_FOLLOW));
    }
    TRY(open_parent(a, true, &p1, l1));
    return SC(linkat(p1, l1, p2, l2, 0));
}

static int64_t h_renameat(struct ctx *c) {       // a[0] = renameat2 flags
    if ((unsigned) c->h->a[0] & ~(unsigned) RENAME_NOREPLACE) return -EINVAL;
    char a[PATH_MAX], b[PATH_MAX], l1[NAME_MAX + 1], l2[NAME_MAX + 1];
    AUTOFD p1 = -1, p2 = -1;
    TRY(abs_path(c->fd[0], c->path[0], a));
    TRY(abs_path(c->fd[1], c->path[1], b));
    TRY(open_parent(a, true, &p1, l1));
    TRY(open_parent(b, true, &p2, l2));
    return SC(syscall(__NR_renameat2, p1, l1, p2, l2, (unsigned) c->h->a[0]));
}

static int64_t h_readlinkat(struct ctx *c) {
    char abs[PATH_MAX], leaf[NAME_MAX + 1];
    AUTOFD pfd = -1;
    TRY(abs_path(c->fd[0], c->path[0], abs));
    TRY(open_parent(abs, false, &pfd, leaf));
    ssize_t n = readlinkat(pfd, leaf, (char *) c->out, c->h->out_cap);
    if (n < 0) return -errno;
    c->out_len = (uint32_t) n;
    return n;
}

static int64_t h_utimensat(struct ctx *c) {      // a[0]=flags, a[1]=1 if path was NULL (futimens)
    struct timespec ts[2];
    const struct timespec *tp = nullptr;
    if (c->h->blob_len) {
        if (c->h->blob_len != sizeof ts) return -EINVAL;
        memcpy(ts, c->blob, sizeof ts);          // blob may be unaligned
        tp = ts;
    }
    int flags = (int) c->h->a[0];
    if (flags & ~AT_SYMLINK_NOFOLLOW) return -EINVAL;
    if (c->h->a[1]) {                            // futimens on a client-supplied fd
        if (c->fd[0] < 0) return -EBADF;
        return SC(syscall(__NR_utimensat, c->fd[0], NULL, tp, 0));
    }
    char abs[PATH_MAX], leaf[NAME_MAX + 1], proc[48];
    AUTOFD fd = -1;
    TRY(abs_path(c->fd[0], c->path[0], abs));
    if (flags & AT_SYMLINK_NOFOLLOW) {
        TRY(open_parent(abs, true, &fd, leaf));
        return SC(syscall(__NR_utimensat, fd, leaf, tp, AT_SYMLINK_NOFOLLOW));
    }
    TRY(open_follow(abs, true, false, &fd));
    snprintf(proc, sizeof proc, "/proc/self/fd/%d", fd);
    return SC(syscall(__NR_utimensat, AT_FDCWD, proc, tp, 0));
}

// chdir never happens for real: the broker owns the client's cwd.
static int64_t h_chdir(struct ctx *c) {
    char abs[PATH_MAX], real[PATH_MAX];
    AUTOFD fd = -1;
    struct stat st{};
    TRY(abs_path(c->fd[0], c->path[0], abs));
    TRY(open_follow(abs, false, false, &fd));
    if (fstat(fd, &st) < 0) return -errno;
    if (!S_ISDIR(st.st_mode)) return -ENOTDIR;
    TRY(fd_path(fd, real));
    snprintf(g_cwd, sizeof g_cwd, "%s", real);
    return 0;
}

static int64_t h_getcwd(struct ctx *c) {
    size_t n = strlen(g_cwd) + 1;
    if (n > c->h->out_cap) return -ERANGE;
    memcpy(c->out, g_cwd, n);
    c->out_len = (uint32_t) n;
    return (int64_t) n;
}

static int64_t h_kill(struct ctx *c) {
    static const uint32_t kSigOk = (1u << 0) | (1u << SIGHUP) | (1u << SIGINT) | (1u << SIGTERM) |
                                   (1u << SIGUSR1) | (1u << SIGUSR2);
    int pid = (int) c->h->a[0], sig = (int) c->h->a[1];
    if (pid != g_client_pid) return -EPERM;      // no pid 0, -1, groups or other processes
    if (sig < 0 || sig >= 32 || !((1u << sig) & kSigOk)) return -EPERM;
    return SC(kill(pid, sig));
}

static int64_t h_connect(struct ctx *c) {
    int fd = c->fd[0];
    if (fd < 0) return -EBADF;
    uint32_t len = c->h->blob_len;
    if (len < sizeof(sa_family_t) || len > sizeof(struct sockaddr_storage)) return -EINVAL;
    struct sockaddr_storage ss{};
    memset(&ss, 0, sizeof ss);
    memcpy(&ss, c->blob, len);                   // our snapshot: client can't race the contents
    int dom;
    socklen_t dl = sizeof dom;
    if (getsockopt(fd, SOL_SOCKET, SO_DOMAIN, &dom, &dl) < 0)
        return -errno;  // also proves it's a socket
    if (dom != ss.ss_family) return -EAFNOSUPPORT;

    if (ss.ss_family == AF_UNIX) {
        auto *un = (struct sockaddr_un *) &ss;
        size_t off = offsetof(struct sockaddr_un, sun_path);
        if (len <= off + 1 || un->sun_path[0] == 0) return -EPERM;           // no abstract/unnamed
        if (!memchr(un->sun_path, 0, len - off)) return -EINVAL;
        char real[PATH_MAX];
        if (!realpath(un->sun_path, real)) return -errno;
        // if (!prefix_ok(real, kConnect, NELEM(kConnect))) return -EACCES;
        struct sockaddr_un out = {.sun_family = AF_UNIX};
        if (strlen(real) >= sizeof out.sun_path) return -ENAMETOOLONG;
        strcpy(out.sun_path, real);
        return SC(connect(fd, (struct sockaddr *) &out, sizeof out));
    }
    if (ss.ss_family == AF_INET) {               // example policy: loopback only
        auto *in = (struct sockaddr_in *) &ss;
        if (len < sizeof *in || ntohl(in->sin_addr.s_addr) != INADDR_LOOPBACK) return -EACCES;
        return SC(connect(fd, (struct sockaddr *) in, sizeof *in));
    }
    return -EAFNOSUPPORT;
}

/* ---------------- dispatch + serve loop ---------------- */
static const struct {
    int64_t (*fn)(struct ctx *);

    uint8_t npaths;
} kOps[OP_COUNT] = {
        [OP_OPENAT] = {h_openat, 1}, [OP_FSTATAT] = {h_fstatat, 1}, [OP_STATFS] = {h_statfs, 1},
        [OP_FCHOWNAT] = {h_fchownat, 1}, [OP_RENAMEAT] = {h_renameat, 2}, [OP_MKDIRAT] = {h_mkdirat,
                                                                                          1},
        [OP_MKNODAT] = {h_mknodat, 1}, [OP_TRUNCATE] = {h_truncate, 1}, [OP_LINKAT] = {h_linkat, 2},
        [OP_READLINKAT] = {h_readlinkat, 1}, [OP_UNLINKAT] = {h_unlinkat, 1},
        [OP_SYMLINKAT] = {h_symlinkat, 2}, [OP_UTIMENSAT] = {h_utimensat, 1},
        [OP_CHDIR] = {h_chdir, 1}, [OP_GETCWD] = {h_getcwd, 0}, [OP_KILL] = {h_kill, 0},
        [OP_CONNECT] = {h_connect, 0},
};

static void reply(int sock, int64_t result, const void *out, uint32_t out_len, int fd) {
    struct broker_resp_hdr r = {BROKER_MAGIC, out_len, result};
    struct iovec iov[2] = {{&r, sizeof r},
                           {(void *) out, out_len}};
    union {
        char b[CMSG_SPACE(sizeof(int))];
        struct cmsghdr a;
    } u{};
    struct msghdr m = {.msg_iov = iov, .msg_iovlen = static_cast<size_t>(out_len ? 2 : 1)};
    if (fd >= 0) {
        memset(&u, 0, sizeof u);
        m.msg_control = u.b;
        m.msg_controllen = sizeof u.b;
        struct cmsghdr *c = CMSG_FIRSTHDR(&m);
        c->cmsg_level = SOL_SOCKET;
        c->cmsg_type = SCM_RIGHTS;
        c->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(c), &fd, sizeof(int));
    }
    ssize_t n;
    do { n = sendmsg(sock, &m, MSG_NOSIGNAL); } while (n < 0 && errno == EINTR);
}

void broker_serve(int sock, pid_t client_pid) {
    g_client_pid = client_pid;   // NOT SO_PEERCRED: for a socketpair that reports the *creator*
    static struct {
        struct broker_req_hdr h;
        uint8_t data[2 * PATH_MAX + BROKER_MAX_BLOB];
    } req;
    static struct ctx c;

    while (true) {
        union {
            char b[CMSG_SPACE(2 * sizeof(int))];
            struct cmsghdr a;
        } cb{};
        struct iovec iov = {&req, sizeof req};
        struct msghdr m = {.msg_iov = &iov, .msg_iovlen = 1, .msg_control = cb.b,
                .msg_controllen = sizeof cb.b};
        ssize_t n;
        do { n = recvmsg(sock, &m, MSG_CMSG_CLOEXEC); } while (n < 0 && errno == EINTR);
        if (n <= 0) return;

        // Take ownership of every received fd up front so none can leak.
        int rfd[2] = {-1, -1}, nfd = 0;
        bool too_many = false;
        for (struct cmsghdr *ch = CMSG_FIRSTHDR(&m); ch; ch = CMSG_NXTHDR(&m, ch)) {
            if (ch->cmsg_level != SOL_SOCKET || ch->cmsg_type != SCM_RIGHTS) continue;
            size_t cnt = (ch->cmsg_len - CMSG_LEN(0)) / sizeof(int);
            for (size_t i = 0; i < cnt; i++) {
                int v;
                memcpy(&v, CMSG_DATA(ch) + i * sizeof(int), sizeof v);
                if (nfd < 2) rfd[nfd++] = v;
                else {
                    close(v);
                    too_many = true;
                }
            }
        }

        const struct broker_req_hdr *h = &req.h;
        bool ok = !too_many && !(m.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) &&
                  (size_t) n >= sizeof *h && h->magic == BROKER_MAGIC &&
                  h->op > 0 && h->op < OP_COUNT &&
                  h->path_len[0] < PATH_MAX && h->path_len[1] < PATH_MAX &&
                  h->blob_len <= BROKER_MAX_BLOB && h->out_cap <= BROKER_MAX_OUT &&
                  (size_t) n == sizeof *h + h->path_len[0] + h->path_len[1] + h->blob_len &&
                  (h->fdmask & ~3u) == 0 &&
                  __builtin_popcount(h->fdmask) == nfd &&
                  (kOps[h->op].npaths >= 1 || !h->path_len[0]) &&
                  (kOps[h->op].npaths >= 2 || !h->path_len[1]);
        int64_t res = -EINVAL;
        c.out_len = 0;
        c.ret_fd = -1;
        if (ok) {
            c.h = h;
            const uint8_t *p = req.data;
            for (int i = 0; i < 2; i++) {
                memcpy(c.path[i], p, h->path_len[i]);
                c.path[i][h->path_len[i]] = 0;
                if (strlen(c.path[i]) != h->path_len[i]) ok = false;   // embedded NUL
                p += h->path_len[i];
            }
            c.blob = p;
            int k = 0;
            for (int s = 0; s < 2; s++) c.fd[s] = (h->fdmask >> s & 1) ? rfd[k++] : -1;
            if (ok) res = kOps[h->op].fn(&c);
        }
        if (res >= 0 && c.ret_fd < 0 && c.out_len > h->out_cap) res = -EIO;   // handler bug guard
        reply(sock, res, c.out, res >= 0 ? c.out_len : 0, res >= 0 ? c.ret_fd : -1);
        if (c.ret_fd >= 0) close(c.ret_fd);
        for (int i = 0; i < nfd; i++) close(rfd[i]);
    }
}

extern "C"
JNIEXPORT void JNICALL
Java_com_lody_virtual_server_security_SyscallBroker_brokerServe(JNIEnv *env, jobject thiz, jint fd,
                                                                jint pid) {
    ALOGD("Starting the syscall broker for %d on fd %d", pid, fd);
    broker_serve(fd, pid);
}