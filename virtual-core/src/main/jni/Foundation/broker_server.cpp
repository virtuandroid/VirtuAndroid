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
#include <sys/ioctl.h>
#include <jni.h>
#include <atomic>
#include <map>
#include <linux/seccomp.h>
#include <linux/audit.h>
#include <algorithm>
#include <string>
#include <unordered_map>
#include "broker_proto.h"
#include "fb/ALog.h"
#include "logger.h"

#ifndef RENAME_NOREPLACE
#define RENAME_NOREPLACE 1
#endif

/* ========================================================================== */
/* Global state                                                               */
/* ========================================================================== */

// Handle to the Kotlin storage sandbox object. Set once in brokerServe()
// This is because we want to have safe path whitelist logic in Kotlin, as opposed
// to making the C++ code too complex.
struct JavaPolicy {
    JNIEnv *env = nullptr;
    jobject sandbox = nullptr;
    bool running = false;
    jmethodID check_method = nullptr;   // boolean isPathAllowed(String)
    jmethodID redirect_method = nullptr;   // String getRedirectPath(String)
};

// Thread-safe container for multiple server instances
pthread_mutex_t g_servers_mutex = PTHREAD_MUTEX_INITIALIZER;
std::map<pid_t, JavaPolicy*> g_servers;

static thread_local JavaPolicy g_policy;
static thread_local char g_cwd[PATH_MAX] = "/";
static thread_local pid_t g_client_pid;

// Must match StorageSandbox.kt
constexpr int READ = 1;
constexpr int WRITE = 1 << 1;

#ifndef SECCOMP_IOCTL_NOTIF_ADDFD
struct seccomp_notif_addfd {
    __u64 id; __u32 flags; __u32 srcfd; __u32 newfd; __u32 newfd_flags;
};
#define SECCOMP_IOCTL_NOTIF_ADDFD _IOW('!', 3, struct seccomp_notif_addfd)
#endif

#if defined(__NR_newfstatat)
#define NR_FSTATAT __NR_newfstatat      // arm64 / x86_64 (libc: fstatat64)
#else
#define NR_FSTATAT __NR_fstatat64       // 32-bit
#endif
#if defined(__NR_renameat2)
#define NR_RENAME __NR_renameat2
#else
#define NR_RENAME __NR_renameat
#endif

/* ========================================================================== */
/* Per-notification context + reply helpers                                   */
/* ========================================================================== */
struct Ctx {
    int notif_fd;
    const seccomp_notif *req;
    seccomp_notif_resp *resp;
    int memfd = -1;

    Ctx(int fd, const seccomp_notif *r, seccomp_notif_resp *p) : notif_fd(fd), req(r), resp(p) {}

    ~Ctx() { if (memfd >= 0) close(memfd); }

    Ctx(const Ctx &) = delete;

    uint64_t arg(int i) const { return req->data.args[i]; }

    pid_t tid() const { return (pid_t) req->pid; }

    bool valid() const {
        __u64 id = req->id;
        return ioctl(notif_fd, SECCOMP_IOCTL_NOTIF_ID_VALID, &id) == 0;
    }

    int mem() {   // /proc/<tid>/mem, opened lazily, read+write
        if (memfd < 0) {
            char p[64];
            snprintf(p, sizeof p, "/proc/%d/mem", (int) tid());
            memfd = open(p, O_RDWR | O_CLOEXEC);
        }
        return memfd;
    }

    void cont() const {
        resp->val = 0;
        resp->error = 0;
        resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
    }

    void fail(int e) const {
        resp->val = 0;
        resp->error = -e;
        resp->flags = 0;
    }

    void ok(int64_t v) const {
        resp->val = v;
        resp->error = 0;
        resp->flags = 0;
    }
};

using Handler = void (*)(Ctx &);

/* ========================================================================== */
/* Tracee memory access                                                       */
/* ========================================================================== */
// arm64 Android uses tagged pointers (HWASan/MTE). The kernel untags syscall
// args, but seccomp_data.args holds the raw value, so /proc/pid/mem needs it stripped.
static inline uint64_t untag(uint64_t p) {
#if defined(__aarch64__)
    return p & 0x00FFFFFFFFFFFFFFULL;
#else
    return p;
#endif
}

static bool read_remote(Ctx &c, uint64_t addr, void *buf, size_t len) {
    if (c.mem() < 0) return false;
    auto *out = static_cast<char *>(buf);
    size_t done = 0;
    while (done < len) {
        ssize_t r = pread(c.mem(), out + done, len - done, (off_t) (addr + done));
        if (r <= 0) return false;
        done += (size_t) r;
    }
    return true;
}

static bool write_remote(Ctx &c, uint64_t addr, const void *buf, size_t len) {
    if (c.mem() < 0) return false;
    auto *in = static_cast<const char *>(buf);
    size_t done = 0;
    while (done < len) {
        ssize_t r = pwrite(c.mem(), in + done, len - done, (off_t) (addr + done));
        if (r <= 0) return false;
        done += (size_t) r;
    }
    return true;
}

// Reads a NUL-terminated string, page by page so we never straddle into an unmapped page.
static int read_cstr(Ctx &c, uint64_t addr, char *buf, size_t cap) {
    if (c.mem() < 0) return ESRCH;
    size_t n = 0;
    while (n < cap) {
        size_t chunk = std::min(cap - n, (size_t) (4096 - ((addr + n) & 4095)));
        ssize_t r = pread(c.mem(), buf + n, chunk, (off_t) (addr + n));
        if (r <= 0) return EFAULT;
        if (memchr(buf + n, 0, (size_t) r)) return 0;
        n += (size_t) r;
    }
    return ENAMETOOLONG;
}

/* ========================================================================== */
/* Path resolution + policy                                                   */
/* ========================================================================== */
static bool getRedirectPath(const char *path, char out[PATH_MAX]) {
    JNIEnv *env = g_policy.env;
    if (!env) return false;

    jstring jpath = env->NewStringUTF(path);
    if (jpath == nullptr) {             // OOM or exception pending
        env->ExceptionClear();
        return false;
    }

    auto jResult = (jstring) env->CallObjectMethod(g_policy.sandbox,
                                                   g_policy.redirect_method, jpath);
    env->DeleteLocalRef(jpath);

    if (env->ExceptionCheck()) {
        env->ExceptionDescribe();
        env->ExceptionClear();
        return false;
    }
    if (!jResult) return false;

    bool redirected = false;
    const char *chars = env->GetStringUTFChars(jResult, nullptr);
    if (chars) {
        // Only accept if it fits; otherwise keep the original path
        if (snprintf(out, PATH_MAX, "%s", chars) < PATH_MAX) {
            redirected = true;
        }
        env->ReleaseStringUTFChars(jResult, chars);
    }
    env->DeleteLocalRef(jResult);
    return redirected;
}

static bool isPathAllowed(const char *path, int mode) {
    JNIEnv *env = g_policy.env;
    if (!env || mode == 0) return false;

    jstring jpath = env->NewStringUTF(path);
    if (jpath == nullptr) {
        env->ExceptionClear();
        return false;
    }

    jboolean allowed = env->CallBooleanMethod(g_policy.sandbox, g_policy.check_method,
                                              jpath, (jint) mode);
    env->DeleteLocalRef(jpath);

    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        return false;
    }
    return allowed == JNI_TRUE;
}

struct PathResult {
    std::string path;        // final path the broker should operate on
    bool redirected = false;
    uint64_t addr = 0;       // tracee address of the original string (for patching)
    size_t raw_len = 0;      // strlen of the original string
};
constexpr int PASSTHRU = -1; // empty path / NULL path: operates on an already-open fd

// "/proc/self" would resolve to the *broker*, so rewrite it to the tracee.
static void fix_proc_self(std::string &p, pid_t tid) {
    static const char kSelf[] = "/proc/self", kThread[] = "/proc/thread-self";
    auto starts = [&](const char *pre, size_t n) {
        return p.compare(0, n, pre) == 0 && (p.size() == n || p[n] == '/');
    };
    std::string t = std::to_string(tid);
    if (starts(kSelf, sizeof(kSelf) - 1))
        p = "/proc/" + t + p.substr(sizeof(kSelf) - 1);
    else if (starts(kThread, sizeof(kThread) - 1))
        p = "/proc/" + t + "/task/" + t + p.substr(sizeof(kThread) - 1);
}

// Makes `raw` absolute (relative to tracee cwd / dirfd) and resolves symlinks.
// follow=false => the last component is NOT resolved (lstat/unlink/readlink semantics),
// only its parent directory is.
static int resolve_path(Ctx &c, int dirfd, const char *raw, bool follow, std::string &out) {
    std::string p(raw);
    if (p.empty()) return ENOENT;

    if (p[0] != '/') {
        char link[64], base[PATH_MAX];
        if (dirfd == AT_FDCWD) snprintf(link, sizeof link, "/proc/%d/cwd", (int) c.tid());
        else snprintf(link, sizeof link, "/proc/%d/fd/%d", (int) c.tid(), dirfd);
        ssize_t n = readlink(link, base, sizeof(base) - 1);
        if (n < 0) {
            if (dirfd == AT_FDCWD && g_cwd[0] == '/') {
                strncpy(base, g_cwd, sizeof base - 1);
                n = (ssize_t) strlen(base);
            } else return dirfd == AT_FDCWD ? errno : EBADF;
        }
        base[n] = 0;
        if (base[0] != '/') return ENOTDIR;
        p = std::string(base) + "/" + p;
    }
    fix_proc_self(p, c.tid());
    while (p.size() > 1 && p.back() == '/') p.pop_back();

    char buf[PATH_MAX];
    size_t slash = p.rfind('/');
    std::string last = p.substr(slash + 1);
    bool special = last.empty() || last == "." || last == "..";

    if (follow || special) {
        if (realpath(p.c_str(), buf)) {
            out = buf;
            return 0;
        }
        if (special || errno != ENOENT) return errno;
        // final component doesn't exist (create case): fall through to parent + name
    }
    std::string parent = slash == 0 ? "/" : p.substr(0, slash);
    if (!realpath(parent.c_str(), buf)) return errno;
    out = buf;
    if (out != "/") out += '/';
    out += last;
    return 0;
}

// Order: redirect first (the sandbox decides where this path really lives),
// otherwise the path must be allowed for the requested access mode.
static int authorize(const std::string &resolved, int mode, PathResult &r) {
    char redirected[PATH_MAX];
    char *currentPath = const_cast<char *>(resolved.c_str());

    if (getRedirectPath(currentPath, redirected)) {
        r.redirected = true;
        currentPath = redirected;
    }

    if (!isPathAllowed(resolved.c_str(), mode)) return EACCES;
    r.path = resolved;
    r.redirected = false;
    return 0;
}

static int
resolve_and_authorize(Ctx &c, int dirfd, const char *raw, bool follow, int mode, PathResult &r) {
    std::string resolved;
    int e = resolve_path(c, dirfd, raw, follow, resolved);
    if (e) {
        return e;
    }
    return authorize(resolved, mode, r);
}

// Read the path argument, resolve, authorize. Returns 0, errno, or PASSTHRU.
static int prepare_path(Ctx &c, int dirfd, int path_arg, bool follow, int mode,
                        bool allow_empty, PathResult &r) {
    r.addr = untag(c.arg(path_arg));
    if (!r.addr) return allow_empty ? PASSTHRU : EFAULT;
    char raw[PATH_MAX];
    int e = read_cstr(c, r.addr, raw, sizeof raw);
    if (e) return e;
    if (!c.valid()) return ESRCH;                  // tracee gone / syscall interrupted
    if (!raw[0]) return allow_empty ? PASSTHRU : ENOENT;
    r.raw_len = strlen(raw);
    return resolve_and_authorize(c, dirfd, raw, follow, mode, r);
}

// TODO Review all FAIL_OR_PASS
#define FAIL_OR_PASS(e)  do { if ((e) == PASSTHRU) return c.cont(); if (e) return c.fail(e); } while (0)
#define FAIL_ON(e)       do { if (e) return c.fail(e); } while (0)

/* ========================================================================== */
/* Handlers                                                                   */
/* ========================================================================== */
static void do_open(Ctx &c, int dirfd, int path_arg, int flags_arg, int mode_arg) {
    // TODO this cannot load /linkerconfig, make cont bypass whenever a process is forked, but not after
    int flags = (int) c.arg(flags_arg);
    auto mode = (mode_t) c.arg(mode_arg);
    int acc = flags & O_ACCMODE;
    int need = (acc == O_WRONLY) ? WRITE : (acc == O_RDWR) ? (READ | WRITE) : READ;
    if (flags & (O_CREAT | O_TRUNC | O_APPEND)) {
        need |= WRITE;
    }
    if (flags & O_PATH) {
        need = READ;
    }

    PathResult p;
    int e = prepare_path(c, dirfd, path_arg, !(flags & O_NOFOLLOW), need, false, p);

    FAIL_ON(e);

    // Path is already fully resolved, so O_NOFOLLOW closes the dangling-symlink+O_CREAT escape.
    int fd = (int) syscall(__NR_openat, AT_FDCWD, p.path.c_str(), flags | O_CLOEXEC | O_NOFOLLOW,
                           mode);
    if (fd < 0) return c.fail(errno);

    seccomp_notif_addfd add{};
    add.id = c.req->id;
    add.srcfd = (uint32_t) fd;
    add.newfd = 0;
    add.newfd_flags = (flags & O_CLOEXEC) ? O_CLOEXEC : 0;
    int newfd = (int) ioctl(c.notif_fd, SECCOMP_IOCTL_NOTIF_ADDFD, &add);
    int saved = errno;
    close(fd);
    if (newfd < 0) return c.fail(saved);
    c.ok(newfd);
}

static void h_openat(Ctx &c) { do_open(c, (int) c.arg(0), 1, 2, 3); }

#ifdef __NR_open

static void h_open(Ctx &c) { do_open(c, AT_FDCWD, 0, 1, 2); }

#endif

// fchownat(dirfd, path, uid, gid, flags)
static void h_fchownat(Ctx &c) {
    int flags = (int) c.arg(4);
    PathResult p;
    int e = prepare_path(c, (int) c.arg(0), 1, !(flags & AT_SYMLINK_NOFOLLOW), WRITE,
                         flags & AT_EMPTY_PATH, p);
    FAIL_OR_PASS(e);
    long r = syscall(__NR_fchownat, AT_FDCWD, p.path.c_str(), (uid_t) c.arg(2), (gid_t) c.arg(3),
                     AT_SYMLINK_NOFOLLOW);
    r < 0 ? c.fail(errno) : c.ok(0);
}

// renameat(olddirfd, old, newdirfd, new) / renameat2(..., flags)
static void do_rename(Ctx &c, int flags_arg) {
    PathResult o, n;
    int e = prepare_path(c, (int) c.arg(0), 1, false, READ | WRITE, false, o);
    if (!e) e = prepare_path(c, (int) c.arg(2), 3, false, WRITE, false, n);
    FAIL_ON(e);
    unsigned flags = flags_arg >= 0 ? (unsigned) c.arg(flags_arg) : 0;
    long r = syscall(NR_RENAME, AT_FDCWD, o.path.c_str(), AT_FDCWD, n.path.c_str(), flags);
    r < 0 ? c.fail(errno) : c.ok(0);
}

#ifdef __NR_renameat

static void h_renameat(Ctx &c) { do_rename(c, -1); }

#endif
#ifdef __NR_renameat2

static void h_renameat2(Ctx &c) { do_rename(c, 4); }

#endif

// fstatat64 (kernel: newfstatat / fstatat64): (dirfd, path, statbuf, flags)
static void h_fstatat(Ctx &c) {
    int flags = (int) c.arg(3);
    PathResult p;
    int e = prepare_path(c, (int) c.arg(0), 1, !(flags & AT_SYMLINK_NOFOLLOW), READ,
                         flags & AT_EMPTY_PATH, p);
    FAIL_OR_PASS(e);
    struct stat64 st{};
    long r = syscall(NR_FSTATAT, AT_FDCWD, p.path.c_str(), &st, AT_SYMLINK_NOFOLLOW);
    if (r < 0) return c.fail(errno);
    if (!write_remote(c, untag(c.arg(2)), &st, sizeof st)) return c.fail(EFAULT);
    c.ok(0);
}

// statfs(path, buf)  [LP64]   /   statfs64(path, size, buf)  [32-bit]
static void statfs_impl(Ctx &c, int buf_arg, int size_arg) {
    PathResult p;
    int e = prepare_path(c, AT_FDCWD, 0, true, READ, false, p);
    FAIL_ON(e);
    char kbuf[256];
    size_t sz;
    long r;
#if defined(__LP64__)
    (void) size_arg;
    sz = sizeof(struct statfs);
    r = syscall(__NR_statfs, p.path.c_str(), kbuf);
#else
    if (size_arg < 0) return c.cont();          // legacy statfs: authorize only
    sz = std::min<size_t>((size_t) c.arg(size_arg), sizeof kbuf);
    r = syscall(__NR_statfs64, p.path.c_str(), sz, kbuf);
#endif
    if (r < 0) return c.fail(errno);
    if (!write_remote(c, untag(c.arg(buf_arg)), kbuf, sz)) return c.fail(EFAULT);
    c.ok(0);
}

#ifdef __NR_statfs

static void h_statfs(Ctx &c) { statfs_impl(c, 1, -1); }

#endif
#ifdef __NR_statfs64
static void h_statfs64(Ctx &c) { statfs_impl(c, 2, 1); }
#endif

// mkdirat(dirfd, path, mode)
static void h_mkdirat(Ctx &c) {
    PathResult p;
    int e = prepare_path(c, (int) c.arg(0), 1, false, WRITE, false, p);
    FAIL_ON(e);
    long r = syscall(__NR_mkdirat, AT_FDCWD, p.path.c_str(), (mode_t) c.arg(2));
    r < 0 ? c.fail(errno) : c.ok(0);
}

// mknodat(dirfd, path, mode, dev)
static void h_mknodat(Ctx &c) {
    PathResult p;
    int e = prepare_path(c, (int) c.arg(0), 1, false, WRITE, false, p);
    FAIL_ON(e);
    long r = syscall(__NR_mknodat, AT_FDCWD, p.path.c_str(), (mode_t) c.arg(2),
                     (unsigned) c.arg(3));
    r < 0 ? c.fail(errno) : c.ok(0);
}

// truncate(path, length)
static void h_truncate(Ctx &c) {
    PathResult p;
    int e = prepare_path(c, AT_FDCWD, 0, true, WRITE, false, p);
    FAIL_ON(e);
    long r = syscall(__NR_truncate, p.path.c_str(), (off_t) c.arg(1));
    r < 0 ? c.fail(errno) : c.ok(0);
}

// linkat(olddirfd, old, newdirfd, new, flags)
static void h_linkat(Ctx &c) {
    int flags = (int) c.arg(4);
    PathResult o, n;
    int e = prepare_path(c, (int) c.arg(0), 1, flags & AT_SYMLINK_FOLLOW, READ, false, o);
    if (!e) e = prepare_path(c, (int) c.arg(2), 3, false, WRITE, false, n);
    FAIL_ON(e);
    long r = syscall(__NR_linkat, AT_FDCWD, o.path.c_str(), AT_FDCWD, n.path.c_str(), 0);
    r < 0 ? c.fail(errno) : c.ok(0);
}

// readlinkat(dirfd, path, buf, bufsiz)
static void h_readlinkat(Ctx &c) {
    PathResult p;
    int e = prepare_path(c, (int) c.arg(0), 1, false, READ, false, p);
    FAIL_ON(e);
    char tmp[PATH_MAX];
    size_t cap = std::min<size_t>((size_t) c.arg(3), sizeof tmp);
    long r = syscall(__NR_readlinkat, AT_FDCWD, p.path.c_str(), tmp, cap);
    if (r < 0) return c.fail(errno);
    if (!write_remote(c, untag(c.arg(2)), tmp, (size_t) r)) return c.fail(EFAULT);
    c.ok(r);
}

// unlinkat(dirfd, path, flags)
static void h_unlinkat(Ctx &c) {
    PathResult p;
    int e = prepare_path(c, (int) c.arg(0), 1, false, WRITE, false, p);
    FAIL_ON(e);
    long r = syscall(__NR_unlinkat, AT_FDCWD, p.path.c_str(), (int) c.arg(2));
    r < 0 ? c.fail(errno) : c.ok(0);
}

// symlinkat(target, newdirfd, linkpath). `target` is just data; it is checked when later followed.
static void h_symlinkat(Ctx &c) {
    char target[PATH_MAX];
    int e = read_cstr(c, untag(c.arg(0)), target, sizeof target);
    FAIL_ON(e);
    PathResult p;
    e = prepare_path(c, (int) c.arg(1), 2, false, WRITE, false, p);
    FAIL_ON(e);
    long r = syscall(__NR_symlinkat, target, AT_FDCWD, p.path.c_str());
    r < 0 ? c.fail(errno) : c.ok(0);
}

// utimensat(dirfd, path, times[2], flags). path==NULL => futimens on dirfd => CONTINUE.
static void h_utimensat(Ctx &c) {
    int flags = (int) c.arg(3);
    PathResult p;
    int e = prepare_path(c, (int) c.arg(0), 1, !(flags & AT_SYMLINK_NOFOLLOW), WRITE, true, p);
    FAIL_OR_PASS(e);
#if defined(__LP64__)
    struct timespec ts[2];
    uint64_t tp = untag(c.arg(2));
    if (tp && !read_remote(c, tp, ts, sizeof ts)) return c.fail(EFAULT);
    long r = syscall(__NR_utimensat, AT_FDCWD, p.path.c_str(), tp ? ts : nullptr,
                     AT_SYMLINK_NOFOLLOW);
    r < 0 ? c.fail(errno) : c.ok(0);
#else
    c.cont();   // 32-bit timespec/time64 layouts: authorize only
#endif
}

// This is NOT secure, an attacker can overwrite the memory before the syscall is executed.
// However, this is the best we can do on some syscalls such as execve which must be processed
// in the child. Use this method sparingly.
static void patch_and_continue(Ctx &c, int path_arg, int mode) {
    PathResult p;
    int e = prepare_path(c, AT_FDCWD, path_arg, true, mode, false, p);
    FAIL_ON(e);
    if (p.redirected) {
        if (p.path.size() > p.raw_len)
            return c.fail(ENAMETOOLONG);   // would overflow the tracee's buffer
        if (!write_remote(c, p.addr, p.path.c_str(), p.path.size() + 1)) return c.fail(EFAULT);
    }
    if (!c.valid()) return c.fail(ESRCH);
    c.cont();
}

static void h_chdir(Ctx &c) { patch_and_continue(c, 0, READ); }

static void h_execve(Ctx &c) { patch_and_continue(c, 0, READ); }

// connect(fd, addr, addrlen): only filesystem AF_UNIX sockets are path-checked.
static void h_connect(Ctx &c) { // TODO FIX
    const size_t off = offsetof(sockaddr_un, sun_path);
    uint64_t addr = untag(c.arg(1));
    auto len = (size_t) c.arg(2);
    if (!addr || len <= off || len > sizeof(sockaddr_un))
        return c.cont();   // kernel reports the error

    sockaddr_un sa{};
    memset(&sa, 0, sizeof sa);
    if (!read_remote(c, addr, &sa, len)) return c.cont();
    if (sa.sun_family != AF_UNIX || sa.sun_path[0] == '\0')
        return c.cont(); // inet / abstract / unnamed
    if (!c.valid()) return c.fail(ESRCH);

    std::string raw(sa.sun_path, strnlen(sa.sun_path, len - off));
    PathResult p;
    int e = resolve_and_authorize(c, AT_FDCWD, raw.c_str(), true, WRITE, p);
    FAIL_ON(e);
    if (p.redirected) {
        if (p.path.size() + 1 > len - off) return c.fail(ENAMETOOLONG);
        if (!write_remote(c, addr + off, p.path.c_str(), p.path.size() + 1)) return c.fail(EFAULT);
    }
    c.cont();
}

static bool isKillAllowed(pid_t target) {
    // TODO account for process children
    return target == g_client_pid;
}

static void h_kill(Ctx &c) {
    auto target = (pid_t) c.arg(0);
    if (!isKillAllowed(target)) {
        return c.fail(EPERM);
    }
    auto signal = (int) c.arg(1);
    auto response = kill(target, signal);

    if (response == -1) {
        c.fail(errno);
    } else {
        c.ok(response);
    }
}

/* ========================================================================== */
/* Function map: add new syscalls here                                        */
/* ========================================================================== */
static const std::unordered_map<int, Handler> &handler_table() {
    static const std::unordered_map<int, Handler> table = [] {
        std::unordered_map<int, Handler> m;
#ifdef __NR_open
        m[__NR_open] = h_open;        // x86_64 only (also covers __open_2)
#endif
        m[__NR_openat] = h_openat;      // also covers __openat_2
        m[__NR_fchownat] = h_fchownat;
#ifdef __NR_renameat
        m[__NR_renameat] = h_renameat;
#endif
#ifdef __NR_renameat2
        m[__NR_renameat2] = h_renameat2;   // libc renameat() may issue this on arm64
#endif
        m[NR_FSTATAT] = h_fstatat;     // libc fstatat64
#ifdef __NR_statfs
        m[__NR_statfs] = h_statfs;
#endif
#ifdef __NR_statfs64
        m[__NR_statfs64]   = h_statfs64;    // 32-bit only
#endif
        m[__NR_mkdirat] = h_mkdirat;
        m[__NR_mknodat] = h_mknodat;
        m[__NR_truncate] = h_truncate;
        m[__NR_linkat] = h_linkat;
        m[__NR_readlinkat] = h_readlinkat;
        m[__NR_unlinkat] = h_unlinkat;
        m[__NR_symlinkat] = h_symlinkat;
        m[__NR_utimensat] = h_utimensat;
        m[__NR_chdir] = h_chdir;
        m[__NR_execve] = h_execve;
        m[__NR_kill] = h_kill;
//        m[__NR_connect] = h_connect;
        return m;
    }();
    return table;
}

/* ========================================================================== */
/* Broker loop                                                                */
/* ========================================================================== */
static void broker_serve(int fd, pid_t client_pid) {
    g_client_pid = client_pid;

    seccomp_notif_sizes sizes{};
    if (static_cast<int>(syscall(__NR_seccomp, SECCOMP_GET_NOTIF_SIZES, 0, &sizes)) != 0) {
        perror("SECCOMP_GET_NOTIF_SIZES");
        return;
    }
    auto *req = static_cast<seccomp_notif *>(calloc(1, sizes.seccomp_notif));
    auto *resp = static_cast<seccomp_notif_resp *>(calloc(1, sizes.seccomp_notif_resp));
    const auto &table = handler_table();

    pthread_mutex_lock(&g_servers_mutex);
    g_policy.running = true;
    pthread_mutex_unlock(&g_servers_mutex);

    while (true) {
        memset(req, 0, sizes.seccomp_notif);
        if (ioctl(fd, SECCOMP_IOCTL_NOTIF_RECV, req) < 0) {
            if (errno == EINTR) continue;
            if (errno == ENOENT) break;
            perror("NOTIF_RECV");
            break;
        }
        if (ioctl(fd, SECCOMP_IOCTL_NOTIF_ID_VALID, &req->id) < 0) continue;

        memset(resp, 0, sizes.seccomp_notif_resp);
        resp->id = req->id;

        {
            Ctx ctx(fd, req, resp);
            if (req->data.arch != AUDIT_ARCH_CURRENT) {
                ctx.fail(
                        EPERM);           // fail closed: compat-ABI syscall numbers mean something else
            } else {
                auto it = table.find(req->data.nr);
                if (it == table.end()) {
                    ctx.cont();      // unfiltered => CONTINUE
                } else {
                    it->second(ctx);
                }
            }
        }   // Ctx closes /proc/<tid>/mem here

        if (ioctl(fd, SECCOMP_IOCTL_NOTIF_SEND, resp) < 0 && errno != ENOENT) {
            perror("NOTIF_SEND");
        }
    }
    free(req);
    free(resp);
}

/* ========================================================================== */
/* JNI entry point                                                            */
/* ========================================================================== */
extern "C"
JNIEXPORT void JNICALL
Java_com_lody_virtual_server_security_SyscallBroker_serverServe(JNIEnv *env, jobject thiz,
                                                                jint fd, jint pid,
                                                                jobject sandbox, jstring cwd) {
    jclass cls = env->GetObjectClass(sandbox);
    jmethodID check_method = env->GetMethodID(cls, "isFlagAllowed", "(Ljava/lang/String;I)Z");
    if (check_method == nullptr) {
        env->ExceptionClear();
        return;
    }
    jmethodID redirect_method = env->GetMethodID(cls, "getRedirectPath",
                                                 "(Ljava/lang/String;)Ljava/lang/String;");
    env->DeleteLocalRef(cls);
    if (redirect_method == nullptr) {
        env->ExceptionClear();
        return;
    }

    const char *c_cwd = env->GetStringUTFChars(cwd, nullptr);
    if (c_cwd == nullptr) return;
    size_t len = strlen(c_cwd);
    if (len >= PATH_MAX) {
        return;
    }
    memcpy(g_cwd, c_cwd, len + 1);
    env->ReleaseStringUTFChars(cwd, c_cwd);

    g_policy.env = env;
    g_policy.sandbox = sandbox;
    g_policy.check_method = check_method;
    g_policy.running = true;
    g_policy.redirect_method = redirect_method;

    pthread_mutex_lock(&g_servers_mutex);
    g_servers[pid] = &g_policy;
    pthread_mutex_unlock(&g_servers_mutex);

    ALOGD("Starting the syscall broker for %d on fd %d", pid, fd);
    broker_serve(fd, pid);
    g_policy = {};
}

extern "C"
JNIEXPORT void JNICALL
Java_com_lody_virtual_server_security_SyscallBroker_serverDestroy(JNIEnv *env, jobject thiz,
                                                                  jint pid) {
    pthread_mutex_lock(&g_servers_mutex);
    auto it = g_servers.find(pid);

    if (it != g_servers.end()) {
        // The server exists, safe to update
        it->second->running = false; // TODO working exit
    }

    pthread_mutex_unlock(&g_servers_mutex);
}
extern "C"
JNIEXPORT jboolean JNICALL
Java_com_lody_virtual_server_security_SyscallBroker_serverIsRunning(JNIEnv *env, jobject thiz,
                                                                    jint pid) {
    bool isRunning = false;

    pthread_mutex_lock(&g_servers_mutex);
    auto it = g_servers.find(pid);

    if (it != g_servers.end()) {
        isRunning = it->second->running;
    }

    pthread_mutex_unlock(&g_servers_mutex);

    return isRunning;
}