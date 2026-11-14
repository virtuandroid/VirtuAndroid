// Syscall broker: services filesystem/socket requests on behalf of a sandboxed client process.
//
// Every absolute path the broker touches is resolved to its *real* location first
// (via O_PATH + /proc/self/fd) and then validated by the Kotlin side through
// SyscallBroker.isPathAllowed(String). Nothing is trusted based on the client's string.

#include <cerrno>
#include <climits>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <unistd.h>

#include <jni.h>

#include "broker_proto.h"
#include "fb/ALog.h"
#include "logger.h"

#ifndef RENAME_NOREPLACE
#define RENAME_NOREPLACE 1
#endif

/* ========================================================================== */
/* Global state                                                               */
/* ========================================================================== */

// Handle to the Kotlin policy object. Set once in brokerServe() and only used from
// that same thread (a JNIEnv is thread-bound), so no global refs are required.
struct JavaPolicy {
    JNIEnv *env = nullptr;
    jobject sandbox = nullptr;
    jmethodID check_method = nullptr;   // boolean isPathAllowed(String)
};

static JavaPolicy g_policy;
static char g_cwd[PATH_MAX] = "/";      // the client's *virtual* cwd (never a real chdir)
static pid_t g_client_pid;

// Per-request context handed to every handler.
struct ctx {
    const struct broker_req_hdr *h;
    char path[2][PATH_MAX];
    const uint8_t *blob;
    int fd[2];                          // attached fds by slot; -1 = none (AT_FDCWD)
    uint8_t out[BROKER_MAX_OUT];
    uint32_t out_len;
    int ret_fd;                         // fd to pass back to the client, or -1
};

/* ========================================================================== */
/* Policy                                                                     */
/* ========================================================================== */

// Asks the Kotlin side whether `path` (an absolute, fully resolved path) is allowed.
// Fails closed: any JNI error means "not allowed".
static bool isPathAllowed(const char *path) {
    JNIEnv *env = g_policy.env;

    jstring jpath = env->NewStringUTF(path);
    if (jpath == nullptr) {             // OOM or exception pending
        env->ExceptionClear();
        return false;
    }

    jboolean allowed = env->CallBooleanMethod(g_policy.sandbox, g_policy.check_method, jpath);
    env->DeleteLocalRef(jpath);

    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        return false;
    }
    return allowed == JNI_TRUE;
}

/* ========================================================================== */
/* Small helpers                                                              */
/* ========================================================================== */

#define PROC_PATH_SIZE 48

static void closep(const int *p) { if (*p >= 0) close(*p); }

// Declares an int that is automatically closed when it goes out of scope.
#define AUTOFD __attribute__((cleanup(closep))) int

// Early-return the error code if `x` evaluates to non-zero.
#define TRY(x) do { int _e = (x); if (_e) return _e; } while (0)

// Run a syscall expression, converting failure into a negative errno.
#define SC(expr) ({ long _r = (long)(expr); _r < 0 ? (int64_t)-errno : (int64_t)_r; })

// "/proc/self/fd/N": lets path-based syscalls act on an already-vetted inode.
static void proc_path(int fd, char out[PROC_PATH_SIZE]) {
    snprintf(out, PROC_PATH_SIZE, "/proc/self/fd/%d", fd);
}

// Resolves an open fd to its real filesystem path.
static int fd_path(int fd, char out[PATH_MAX]) {
    char proc[PROC_PATH_SIZE];
    proc_path(fd, proc);
    ssize_t n = readlink(proc, out, PATH_MAX - 1);
    if (n < 0) return -errno;
    out[n] = 0;
    return 0;
}

/* ========================================================================== */
/* Path resolution                                                            */
/* ========================================================================== */

// (dirfd, client path) -> absolute path string. dirfd < 0 means "relative to virtual cwd".
// This only builds a string; nothing is vetted until one of the open_* helpers runs.
static int abs_path(int dirfd, const char *p, char out[PATH_MAX]) {
    if (!p[0]) return -ENOENT;

    if (p[0] == '/') {
        int n = snprintf(out, PATH_MAX, "%s", p);
        return n >= PATH_MAX ? -ENAMETOOLONG : 0;
    }

    char base[PATH_MAX];
    if (dirfd < 0) {
        snprintf(base, sizeof base, "%s", g_cwd);
    } else {
        struct stat st{};
        if (fstat(dirfd, &st) < 0) return -errno;
        if (!S_ISDIR(st.st_mode)) return -ENOTDIR;
        TRY(fd_path(dirfd, base));
    }
    int n = snprintf(out, PATH_MAX, "%s/%s", base, p);
    return n >= PATH_MAX ? -ENAMETOOLONG : 0;
}

// Opens an O_PATH handle to the fully resolved target and checks the *real* path
// against the policy. Use for operations that act on the target itself.
static int open_follow(const char *abs, bool nofollow, int *out) {
    int fd = open(abs, O_PATH | O_CLOEXEC | (nofollow ? O_NOFOLLOW : 0));
    if (fd < 0) return -errno;

    char real[PATH_MAX];
    struct stat st{};
    int e = fd_path(fd, real);
    if (!e && fstat(fd, &st) < 0) e = -errno;
    if (!e && S_ISLNK(st.st_mode)) e = -ELOOP;      // only possible with nofollow
    if (!e && !isPathAllowed(real)) e = -EACCES;

    if (e) {
        close(fd);
        return e;
    }
    *out = fd;
    return 0;
}

// Opens a checked handle to the *parent directory* and returns the validated leaf name.
// Use for operations that act on the final component itself (mkdir, unlink, rename, ...).
// The policy is checked on <real parent>/<leaf>.
static int open_parent(const char *abs, int *pfd, char leaf[NAME_MAX + 1]) {
    char dir[PATH_MAX];
    snprintf(dir, sizeof dir, "%s", abs);

    // Strip trailing slashes, then split into directory and leaf.
    size_t n = strlen(dir);
    while (n > 1 && dir[n - 1] == '/') dir[--n] = 0;
    char *slash = strrchr(dir, '/');
    if (!slash) return -EINVAL;

    const char *name = slash + 1;
    if (!*name || !strcmp(name, ".") || !strcmp(name, "..")) return -EINVAL;
    if (strlen(name) > NAME_MAX) return -ENAMETOOLONG;
    snprintf(leaf, NAME_MAX + 1, "%s", name);

    if (slash == dir) dir[1] = 0; else *slash = 0;   // parent of "/x" is "/"

    int fd = open(dir, O_PATH | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) return -errno;

    char real[PATH_MAX], full[PATH_MAX];
    int e = fd_path(fd, real);
    if (!e) {
        snprintf(full, sizeof full, "%s%s%s", real, strcmp(real, "/") ? "/" : "", leaf);
        if (!isPathAllowed(full)) e = -EACCES;
    }

    if (e) {
        close(fd);
        return e;
    }
    *pfd = fd;
    return 0;
}

/* ========================================================================== */
/* Handlers: opening files                                                    */
/* ========================================================================== */

#define OPEN_OK_FLAGS (O_ACCMODE | O_CREAT | O_EXCL | O_TRUNC | O_APPEND | O_CLOEXEC | \
                       O_LARGEFILE | O_DIRECTORY | O_NOFOLLOW | O_NONBLOCK | O_NOCTTY | \
                       O_PATH | O_SYNC)

// Only regular files, directories and character devices may be handed to the client.
// (No FIFOs, sockets or block devices.)
static bool is_allowed_file_type(mode_t m) {
    return S_ISREG(m) || S_ISDIR(m) || S_ISCHR(m);
}

// a[0] = open flags, a[1] = mode. Returns the opened fd via c->ret_fd.
static int64_t h_openat(struct ctx *c) {
    int flags = (int) c->h->a[0];
    mode_t mode = (mode_t) c->h->a[1] & 0777;                           // no setuid/sticky bits

    if ((unsigned) flags & ~(unsigned) OPEN_OK_FLAGS) return -EPERM;    // no O_TMPFILE etc.
    if ((flags & O_ACCMODE) == O_ACCMODE) return -EINVAL;

    char abs[PATH_MAX];
    TRY(abs_path(c->fd[0], c->path[0], abs));
    pid_t pid = syscall(SYS_getpid);
    ALOGD("Trying to open absolute path: %s on %d", abs, pid);

    // Flags used for the real open: never block on open, never acquire a controlling tty.
    const int safe_flags = flags | O_CLOEXEC | O_NOCTTY | O_NONBLOCK;

    int fd;
    if (flags & O_CREAT) {
        // Never create in /dev: the open itself would already have side effects.
        if (strncmp(abs, "/dev/", 5) == 0) return -EACCES;

        char leaf[NAME_MAX + 1];
        AUTOFD pfd = -1;
        TRY(open_parent(abs, &pfd, leaf));
        fd = openat(pfd, leaf, safe_flags | O_NOFOLLOW, mode);
        if (fd < 0) return -errno;
    } else {
        // Vet the target through an O_PATH handle first (no side effects, even for devices),
        // then re-open that exact inode so symlink/bind tricks can't swap it in between.
        AUTOFD pfd = -1;
        struct stat st{};
        TRY(open_follow(abs, flags & O_NOFOLLOW, &pfd));
        if (fstat(pfd, &st) < 0) return -errno;
        if (!is_allowed_file_type(st.st_mode)) return -EACCES;

        char proc[PROC_PATH_SIZE];
        proc_path(pfd, proc);
        fd = open(proc, safe_flags & ~O_NOFOLLOW);
        if (fd < 0) return -errno;
    }

    // Final check on what we actually opened (covers the O_CREAT path and any races).
    char real[PATH_MAX];
    struct stat st{};
    if (fd_path(fd, real) || fstat(fd, &st) < 0 ||
        !is_allowed_file_type(st.st_mode) || !isPathAllowed(real)) {
        close(fd);
        return -EACCES;
    }

    // We forced O_NONBLOCK for the open; restore blocking mode unless the client asked for it.
    if (!(flags & O_NONBLOCK)) {
        int fl = fcntl(fd, F_GETFL);
        if (fl >= 0) fcntl(fd, F_SETFL, fl & ~O_NONBLOCK);
    }

    c->ret_fd = fd;
    return 0;
}

/* ========================================================================== */
/* Handlers: metadata                                                         */
/* ========================================================================== */

#if defined(__NR_newfstatat)
#define NR_FSTATAT __NR_newfstatat
#define STAT_SZ    sizeof(struct stat)
#else
#define NR_FSTATAT __NR_fstatat64
#define STAT_SZ    sizeof(struct stat64)
#endif

// a[0] = flags (AT_SYMLINK_NOFOLLOW / AT_EMPTY_PATH)
static int64_t h_fstatat(struct ctx *c) {
    int flags = (int) c->h->a[0];
    if (flags & ~(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH)) return -EINVAL;

    // fstat(fd) via AT_EMPTY_PATH
    if (!c->path[0][0]) {
        if (!(flags & AT_EMPTY_PATH) || c->fd[0] < 0) return -ENOENT;
        int64_t r = SC(syscall(NR_FSTATAT, c->fd[0], "", c->out, AT_EMPTY_PATH));
        if (r == 0) c->out_len = STAT_SZ;
        return r;
    }

    char abs[PATH_MAX], leaf[NAME_MAX + 1];
    AUTOFD fd = -1;
    TRY(abs_path(c->fd[0], c->path[0], abs));

    int64_t r;
    if (flags & AT_SYMLINK_NOFOLLOW) {          // lstat: act on the leaf itself
        TRY(open_parent(abs, &fd, leaf));
        r = SC(syscall(NR_FSTATAT, fd, leaf, c->out, AT_SYMLINK_NOFOLLOW));
    } else {                                    // stat: act on the resolved target
        TRY(open_follow(abs, false, &fd));
        r = SC(syscall(NR_FSTATAT, fd, "", c->out, AT_EMPTY_PATH));
    }
    if (r == 0) c->out_len = STAT_SZ;
    return r;
}

// a[0] = struct size for statfs64, 0 for plain statfs
static int64_t h_statfs(struct ctx *c) {
    char abs[PATH_MAX], proc[PROC_PATH_SIZE];
    AUTOFD fd = -1;
    TRY(abs_path(c->fd[0], c->path[0], abs));
    TRY(open_follow(abs, false, &fd));
    proc_path(fd, proc);

    int64_t r;
#ifdef __NR_statfs64
    if (c->h->a[0]) {
        if (c->h->a[0] > BROKER_MAX_OUT) return -EINVAL;
        r = SC(syscall(__NR_statfs64, proc, (size_t) c->h->a[0], c->out));
        if (r == 0) c->out_len = (uint32_t) c->h->a[0];
        return r;
    }
#endif
    r = SC(syscall(__NR_statfs, proc, c->out));
    if (r == 0) c->out_len = sizeof(struct statfs);
    return r;
}

// a[0] = length
static int64_t h_truncate(struct ctx *c) {
    char abs[PATH_MAX], proc[PROC_PATH_SIZE];
    AUTOFD fd = -1;
    TRY(abs_path(c->fd[0], c->path[0], abs));
    TRY(open_follow(abs, false, &fd));
    proc_path(fd, proc);                        // path-based truncate via magic link
    return SC(truncate(proc, (off_t) c->h->a[0]));
}

// a: uid, gid, flags
static int64_t h_fchownat(struct ctx *c) {
    auto uid = (uid_t) c->h->a[0];
    auto gid = (gid_t) c->h->a[1];
    int flags = (int) c->h->a[2];
    if (flags & ~AT_SYMLINK_NOFOLLOW) return -EINVAL;

    // Policy: the client may only "chown" to our own ids (or -1 = leave unchanged).
    if ((uid != (uid_t) -1 && uid != getuid()) || (gid != (gid_t) -1 && gid != getgid()))
        return -EPERM;

    char abs[PATH_MAX], leaf[NAME_MAX + 1], proc[PROC_PATH_SIZE];
    AUTOFD fd = -1;
    TRY(abs_path(c->fd[0], c->path[0], abs));

    if (flags & AT_SYMLINK_NOFOLLOW) {
        TRY(open_parent(abs, &fd, leaf));
        return SC(fchownat(fd, leaf, uid, gid, AT_SYMLINK_NOFOLLOW));
    }
    TRY(open_follow(abs, false, &fd));
    proc_path(fd, proc);
    return SC(chown(proc, uid, gid));
}

// a[0] = flags, a[1] = 1 if path was NULL (futimens); blob = struct timespec[2] or empty
static int64_t h_utimensat(struct ctx *c) {
    struct timespec ts[2];
    const struct timespec *times = nullptr;
    if (c->h->blob_len) {
        if (c->h->blob_len != sizeof ts) return -EINVAL;
        memcpy(ts, c->blob, sizeof ts);         // blob may be unaligned
        times = ts;
    }

    int flags = (int) c->h->a[0];
    if (flags & ~AT_SYMLINK_NOFOLLOW) return -EINVAL;

    // futimens on a client-supplied fd
    if (c->h->a[1]) {
        if (c->fd[0] < 0) return -EBADF;
        return SC(syscall(__NR_utimensat, c->fd[0], NULL, times, 0));
    }

    char abs[PATH_MAX], leaf[NAME_MAX + 1], proc[PROC_PATH_SIZE];
    AUTOFD fd = -1;
    TRY(abs_path(c->fd[0], c->path[0], abs));

    if (flags & AT_SYMLINK_NOFOLLOW) {
        TRY(open_parent(abs, &fd, leaf));
        return SC(syscall(__NR_utimensat, fd, leaf, times, AT_SYMLINK_NOFOLLOW));
    }
    TRY(open_follow(abs, false, &fd));
    proc_path(fd, proc);
    return SC(syscall(__NR_utimensat, AT_FDCWD, proc, times, 0));
}

// a[0] = buffer capacity is c->h->out_cap
static int64_t h_readlinkat(struct ctx *c) {
    char abs[PATH_MAX], leaf[NAME_MAX + 1];
    AUTOFD pfd = -1;
    TRY(abs_path(c->fd[0], c->path[0], abs));
    TRY(open_parent(abs, &pfd, leaf));

    ssize_t n = readlinkat(pfd, leaf, (char *) c->out, c->h->out_cap);
    if (n < 0) return -errno;
    c->out_len = (uint32_t) n;
    return n;
}

/* ========================================================================== */
/* Handlers: creating / removing / renaming                                   */
/* ========================================================================== */

// a[0] = mode
static int64_t h_mkdirat(struct ctx *c) {
    char abs[PATH_MAX], leaf[NAME_MAX + 1];
    AUTOFD pfd = -1;
    TRY(abs_path(c->fd[0], c->path[0], abs));
    TRY(open_parent(abs, &pfd, leaf));
    return SC(mkdirat(pfd, leaf, (mode_t) c->h->a[0] & 0777));
}

// a: mode, dev
static int64_t h_mknodat(struct ctx *c) {
    auto mode = (mode_t) c->h->a[0];
    mode_t type = mode & S_IFMT;
    if (type != S_IFREG && type != S_IFIFO && type != S_IFSOCK) return -EPERM;  // no device nodes

    char abs[PATH_MAX], leaf[NAME_MAX + 1];
    AUTOFD pfd = -1;
    TRY(abs_path(c->fd[0], c->path[0], abs));
    TRY(open_parent(abs, &pfd, leaf));
    return SC(mknodat(pfd, leaf, type | (mode & 0777), 0));
}

// a[0] = flags (AT_REMOVEDIR)
static int64_t h_unlinkat(struct ctx *c) {
    int flags = (int) c->h->a[0];
    if (flags & ~AT_REMOVEDIR) return -EINVAL;

    char abs[PATH_MAX], leaf[NAME_MAX + 1];
    AUTOFD pfd = -1;
    TRY(abs_path(c->fd[0], c->path[0], abs));
    TRY(open_parent(abs, &pfd, leaf));
    return SC(unlinkat(pfd, leaf, flags));
}

// path0 = target text, path1 = link path (resolved against dirfd slot 1)
static int64_t h_symlinkat(struct ctx *c) {
    char abs[PATH_MAX], leaf[NAME_MAX + 1];
    AUTOFD pfd = -1;
    TRY(abs_path(c->fd[1], c->path[1], abs));
    TRY(open_parent(abs, &pfd, leaf));
    // The target is just text. That is safe because the broker re-resolves and
    // policy-checks every path it ever follows.
    return SC(symlinkat(c->path[0], pfd, leaf));
}

// a[0] = flags (AT_SYMLINK_FOLLOW)
static int64_t h_linkat(struct ctx *c) {
    int flags = (int) c->h->a[0];
    if (flags & ~AT_SYMLINK_FOLLOW) return -EINVAL;

    char src[PATH_MAX], dst[PATH_MAX], src_leaf[NAME_MAX + 1], dst_leaf[NAME_MAX + 1];
    char proc[PROC_PATH_SIZE];
    AUTOFD src_dir = -1, dst_dir = -1, src_fd = -1;
    TRY(abs_path(c->fd[0], c->path[0], src));
    TRY(abs_path(c->fd[1], c->path[1], dst));

    TRY(open_parent(dst, &dst_dir, dst_leaf));

    if (flags & AT_SYMLINK_FOLLOW) {
        TRY(open_follow(src, false, &src_fd));
        proc_path(src_fd, proc);
        return SC(linkat(AT_FDCWD, proc, dst_dir, dst_leaf, AT_SYMLINK_FOLLOW));
    }
    TRY(open_parent(src, &src_dir, src_leaf));
    return SC(linkat(src_dir, src_leaf, dst_dir, dst_leaf, 0));
}

// a[0] = renameat2 flags
static int64_t h_renameat(struct ctx *c) {
    if ((unsigned) c->h->a[0] & ~(unsigned) RENAME_NOREPLACE) return -EINVAL;

    char from[PATH_MAX], to[PATH_MAX], from_leaf[NAME_MAX + 1], to_leaf[NAME_MAX + 1];
    AUTOFD from_dir = -1, to_dir = -1;
    TRY(abs_path(c->fd[0], c->path[0], from));
    TRY(abs_path(c->fd[1], c->path[1], to));
    TRY(open_parent(from, &from_dir, from_leaf));
    TRY(open_parent(to, &to_dir, to_leaf));
    return SC(syscall(__NR_renameat2, from_dir, from_leaf, to_dir, to_leaf,
                      (unsigned) c->h->a[0]));
}

/* ========================================================================== */
/* Handlers: virtual cwd                                                      */
/* ========================================================================== */

// chdir never happens for real: the broker owns the client's cwd.
static int64_t h_chdir(struct ctx *c) {
    char abs[PATH_MAX], real[PATH_MAX];
    AUTOFD fd = -1;
    struct stat st{};
    TRY(abs_path(c->fd[0], c->path[0], abs));
    TRY(open_follow(abs, false, &fd));
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

/* ========================================================================== */
/* Handlers: signals and sockets                                              */
/* ========================================================================== */

// a[0] = pid, a[1] = signal. The client may only signal itself, with a safe signal.
static int64_t h_kill(struct ctx *c) {
    static const uint32_t kAllowedSignals =
            (1u << 0)                           // sig 0: existence probe
            | (1u << SIGHUP) | (1u << SIGINT) | (1u << SIGTERM)
            | (1u << SIGUSR1) | (1u << SIGUSR2);

    int pid = (int) c->h->a[0];
    int sig = (int) c->h->a[1];
    if (pid != g_client_pid) return -EPERM;     // no pid 0, -1, groups or other processes
    if (sig < 0 || sig >= 32 || !((1u << sig) & kAllowedSignals)) return -EPERM;
    return SC(kill(pid, sig));
}

// Socket fd in slot 0, sockaddr in the blob.
static int64_t h_connect(struct ctx *c) {
    int fd = c->fd[0];
    if (fd < 0) return -EBADF;

    uint32_t len = c->h->blob_len;
    if (len < sizeof(sa_family_t) || len > sizeof(struct sockaddr_storage)) return -EINVAL;

    // Work on our own snapshot so the client can't race the contents.
    struct sockaddr_storage ss{};
    memcpy(&ss, c->blob, len);

    // The address family must match the socket's domain (this also proves fd is a socket).
    int domain;
    socklen_t dl = sizeof domain;
    if (getsockopt(fd, SOL_SOCKET, SO_DOMAIN, &domain, &dl) < 0) return -errno;
    if (domain != ss.ss_family) return -EAFNOSUPPORT;

    if (ss.ss_family == AF_UNIX) {
        auto *un = (struct sockaddr_un *) &ss;
        size_t off = offsetof(struct sockaddr_un, sun_path);
        if (len <= off + 1 || un->sun_path[0] == 0) return -EPERM;      // no abstract/unnamed
        if (!memchr(un->sun_path, 0, len - off)) return -EINVAL;        // must be NUL-terminated

        char real[PATH_MAX];
        if (!realpath(un->sun_path, real)) return -errno;
        if (!isPathAllowed(real)) return -EACCES;

        struct sockaddr_un out = {.sun_family = AF_UNIX};
        if (strlen(real) >= sizeof out.sun_path) return -ENAMETOOLONG;
        strcpy(out.sun_path, real);
        return SC(connect(fd, (struct sockaddr *) &out, sizeof out));
    }

    if (ss.ss_family == AF_INET) {              // policy: loopback only
        auto *in = (struct sockaddr_in *) &ss;
        if (len < sizeof *in || ntohl(in->sin_addr.s_addr) != INADDR_LOOPBACK) return -EACCES;
        return SC(connect(fd, (struct sockaddr *) in, sizeof *in));
    }

    return -EAFNOSUPPORT;
}

/* ========================================================================== */
/* Dispatch table                                                             */
/* ========================================================================== */

static const struct {
    int64_t (*fn)(struct ctx *);
    uint8_t npaths;                             // how many path strings the op accepts
} kOps[OP_COUNT] = {
        [OP_OPENAT]    = {h_openat,    1},
        [OP_FSTATAT]   = {h_fstatat,   1},
        [OP_STATFS]    = {h_statfs,    1},
        [OP_FCHOWNAT]  = {h_fchownat,  1},
        [OP_RENAMEAT]  = {h_renameat,  2},
        [OP_MKDIRAT]   = {h_mkdirat,   1},
        [OP_MKNODAT]   = {h_mknodat,   1},
        [OP_TRUNCATE]  = {h_truncate,  1},
        [OP_LINKAT]    = {h_linkat,    2},
        [OP_READLINKAT]= {h_readlinkat,1},
        [OP_UNLINKAT]  = {h_unlinkat,  1},
        [OP_SYMLINKAT] = {h_symlinkat, 2},
        [OP_UTIMENSAT] = {h_utimensat, 1},
        [OP_CHDIR]     = {h_chdir,     1},
        [OP_GETCWD]    = {h_getcwd,    0},
        [OP_KILL]      = {h_kill,      0},
        [OP_CONNECT]   = {h_connect,   0},
};

/* ========================================================================== */
/* Serve loop                                                                 */
/* ========================================================================== */

// Sends the response header, optional output payload and optional fd (SCM_RIGHTS).
static void reply(int sock, int64_t result, const void *out, uint32_t out_len, int fd) {
    struct broker_resp_hdr resp = {BROKER_MAGIC, out_len, result};
    struct iovec iov[2] = {{&resp,         sizeof resp},
                           {(void *) out,  out_len}};

    union {
        char buf[CMSG_SPACE(sizeof(int))];
        struct cmsghdr align;
    } control{};

    struct msghdr msg = {};
    msg.msg_iov = iov;
    msg.msg_iovlen = out_len ? 2 : 1;

    if (fd >= 0) {
        msg.msg_control = control.buf;
        msg.msg_controllen = sizeof control.buf;
        struct cmsghdr *cm = CMSG_FIRSTHDR(&msg);
        cm->cmsg_level = SOL_SOCKET;
        cm->cmsg_type = SCM_RIGHTS;
        cm->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(cm), &fd, sizeof(int));
    }

    ssize_t n;
    do { n = sendmsg(sock, &msg, MSG_NOSIGNAL); } while (n < 0 && errno == EINTR);
}

// Validates the request framing. `nfd` is the number of fds received with it.
static bool request_is_valid(const struct broker_req_hdr *h, ssize_t n, int nfd,
                             bool too_many_fds, int msg_flags) {
    if (too_many_fds || (msg_flags & (MSG_TRUNC | MSG_CTRUNC))) return false;
    if ((size_t) n < sizeof *h || h->magic != BROKER_MAGIC) return false;
    if (h->op <= 0 || h->op >= OP_COUNT) return false;

    if (h->path_len[0] >= PATH_MAX || h->path_len[1] >= PATH_MAX) return false;
    if (h->blob_len > BROKER_MAX_BLOB || h->out_cap > BROKER_MAX_OUT) return false;
    if ((size_t) n != sizeof *h + h->path_len[0] + h->path_len[1] + h->blob_len) return false;

    if ((h->fdmask & ~3u) != 0 || __builtin_popcount(h->fdmask) != nfd) return false;

    // The op must actually accept as many paths as were supplied.
    const uint8_t npaths = kOps[h->op].npaths;
    if (npaths < 1 && h->path_len[0]) return false;
    if (npaths < 2 && h->path_len[1]) return false;
    return true;
}

static void broker_serve(int sock, pid_t client_pid) {
    g_client_pid = client_pid;   // NOT SO_PEERCRED: for a socketpair that reports the *creator*

    static struct {
        struct broker_req_hdr h;
        uint8_t data[2 * PATH_MAX + BROKER_MAX_BLOB];
    } req;
    static struct ctx c;

    while (true) {
        // ---- receive one request (+ up to 2 fds) ----
        union {
            char buf[CMSG_SPACE(2 * sizeof(int))];
            struct cmsghdr align;
        } control{};
        struct iovec iov = {&req, sizeof req};
        struct msghdr msg = {};
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.buf;
        msg.msg_controllen = sizeof control.buf;

        ssize_t n;
        do { n = recvmsg(sock, &msg, MSG_CMSG_CLOEXEC); } while (n < 0 && errno == EINTR);
        if (n <= 0) return;      // client closed the socket (or error): stop serving

        // ---- take ownership of every received fd up front so none can leak ----
        int rfd[2] = {-1, -1}, nfd = 0;
        bool too_many_fds = false;
        for (struct cmsghdr *ch = CMSG_FIRSTHDR(&msg); ch; ch = CMSG_NXTHDR(&msg, ch)) {
            if (ch->cmsg_level != SOL_SOCKET || ch->cmsg_type != SCM_RIGHTS) continue;
            size_t count = (ch->cmsg_len - CMSG_LEN(0)) / sizeof(int);
            for (size_t i = 0; i < count; i++) {
                int v;
                memcpy(&v, CMSG_DATA(ch) + i * sizeof(int), sizeof v);
                if (nfd < 2) {
                    rfd[nfd++] = v;
                } else {
                    close(v);
                    too_many_fds = true;
                }
            }
        }

        // ---- validate + unpack ----
        const struct broker_req_hdr *h = &req.h;
        bool ok = request_is_valid(h, n, nfd, too_many_fds, msg.msg_flags);

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
            for (int slot = 0; slot < 2; slot++)
                c.fd[slot] = ((h->fdmask >> slot) & 1) ? rfd[k++] : -1;

            if (ok) res = kOps[h->op].fn(&c);
        }

        // ---- reply ----
        if (res >= 0 && c.ret_fd < 0 && c.out_len > h->out_cap) res = -EIO;   // handler bug guard
        reply(sock, res, c.out, res >= 0 ? c.out_len : 0, res >= 0 ? c.ret_fd : -1);

        // ---- cleanup ----
        if (c.ret_fd >= 0) close(c.ret_fd);
        for (int i = 0; i < nfd; i++) close(rfd[i]);
    }
}

/* ========================================================================== */
/* JNI entry point                                                            */
/* ========================================================================== */

extern "C"
JNIEXPORT void JNICALL
Java_com_lody_virtual_server_security_SyscallBroker_brokerServe(JNIEnv *env, jobject thiz,
                                                                jint fd, jint pid,
                                                                jobject sandbox) {
    jclass cls = env->GetObjectClass(sandbox);
    jmethodID check_method = env->GetMethodID(cls, "isPathAllowed", "(Ljava/lang/String;)Z");
    env->DeleteLocalRef(cls);
    if (check_method == nullptr) {
        env->ExceptionClear();
        return;
    }

    g_policy.env = env ;
    g_policy.sandbox = sandbox;
    g_policy.check_method = check_method;

    ALOGD("Starting the syscall broker for %d on fd %d", pid, fd);
    broker_serve(fd, pid);
}