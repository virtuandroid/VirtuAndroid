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
#include <pthread.h>
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
#include <vector>
#include "broker_proto.h"
#include "fb/ALog.h"
#include "logger.h"

struct OpenHow {
    uint64_t flags, mode, resolve;
};   // == struct open_how (VER0)
constexpr uint64_t RESOLVE_NO_MAGICLINKS_ = 0x02;
constexpr uint64_t RESOLVE_NO_SYMLINKS_ = 0x04;
constexpr uint32_t IN_DONT_FOLLOW_ = 0x02000000;
constexpr size_t kXattrMax = 65536;
constexpr size_t kSiginfoSize = 128;                    // sizeof(siginfo_t), same on 32/64-bit
constexpr unsigned PIDFD_SIGNAL_THREAD_ = 1u << 0;
constexpr unsigned PIDFD_SIGNAL_THREAD_GROUP_ = 1u << 1;
constexpr unsigned PIDFD_SIGNAL_PROCESS_GROUP_ = 1u << 2;

struct ScopedFd {
    int fd;

    explicit ScopedFd(int f) : fd(f) {}

    ~ScopedFd() { if (fd >= 0) close(fd); }

    ScopedFd(const ScopedFd &) = delete;
};

static inline bool has_tmpfile(int flags) { return (flags & O_TMPFILE) == O_TMPFILE; }

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
    pthread_t thread;
};

// Thread-safe container for multiple server instances
pthread_mutex_t g_servers_mutex = PTHREAD_MUTEX_INITIALIZER;
std::map<pid_t, JavaPolicy *> g_servers;

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

// NewStringUTF can fail, better to use byte array and decode in kotlin
static jbyteArray makeByteArray(JNIEnv* env, const char* path) {
    if (path == nullptr) return nullptr;

    const size_t len = std::strlen(path);
    jbyteArray jbytes = env->NewByteArray(static_cast<jsize>(len));
    if (jbytes == nullptr) {            // OOM, exception pending
        env->ExceptionClear();
        return nullptr;
    }

    env->SetByteArrayRegion(jbytes, 0, static_cast<jsize>(len),
                            reinterpret_cast<const jbyte*>(path));
    if (env->ExceptionCheck()) {        // ArrayIndexOutOfBounds etc.
        env->ExceptionClear();
        env->DeleteLocalRef(jbytes);
        return nullptr;
    }
    return jbytes;
}

static bool getRedirectPath(const char *path, char out[PATH_MAX]) {
    JNIEnv *env = g_policy.env;
    if (!env) return false;

    jbyteArray jpath = makeByteArray(env, path);

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

    jbyteArray jpath = makeByteArray(env, path);

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
    if (p.empty()) {
        return ENOENT;
    }

    if (p[0] != '/') {
        char link[64], base[PATH_MAX];
        if (dirfd == AT_FDCWD) snprintf(link, sizeof link, "/proc/%d/cwd", (int) c.tid());
        else snprintf(link, sizeof link, "/proc/%d/fd/%d", (int) c.tid(), dirfd);
        ssize_t n = readlink(link, base, sizeof(base) - 1);
        if (n < 0) {
            if (dirfd == AT_FDCWD && g_cwd[0] == '/') {
                strncpy(base, g_cwd, sizeof base - 1);
                n = (ssize_t) strlen(base);
            } else {
                return dirfd == AT_FDCWD ? errno : EBADF;
            }
        }
        base[n] = 0;
        if (base[0] != '/') {
            return ENOTDIR;
        }
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
        if (special) {
            return errno;
        }
        // final component doesn't exist (create case): fall through to parent + name
    }
    std::string parent = slash == 0 ? "/" : p.substr(0, slash);
    if (!realpath(parent.c_str(), buf)) {
        // Small compatibility fix for apps which run execve.
        // Without this the forked program will try to resolve
        // /linkerconfig and print a warning when they get EACCES
        if (errno == EACCES && parent == "/linkerconfig") {
            return ENOENT;
        }
        return errno;
    }
    out = buf;
    if (out != "/") out += '/';
    out += last;
    return 0;
}

static int authorize(const std::string &resolved, int mode, PathResult &r) {
    char redirected[PATH_MAX];
    std::string target = resolved;
    bool redirect_dir = false;

    if (getRedirectPath(resolved.c_str(), redirected)) {
        target = redirected;
        redirect_dir = true;
    }

    if (!isPathAllowed(target.c_str(), mode)) return EACCES;
    r.path = std::move(target);
    r.redirected = redirect_dir;
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
    if (!c.valid()) {
        return ESRCH;                  // tracee gone / syscall interrupted
    }
    if (!raw[0]) {
        return allow_empty ? PASSTHRU : ENOENT;
    }
    r.raw_len = strlen(raw);
    return resolve_and_authorize(c, dirfd, raw, follow, mode, r);
}

// TODO Review all FAIL_OR_PASS
#define FAIL_OR_PASS(e)  do { if ((e) == PASSTHRU) return c.cont(); if (e) return c.fail(e); } while (0)
#define FAIL_ON(e)       do { if (e) return c.fail(e); } while (0)

/* ========================================================================== */
/* Handlers: open family                                                      */
/* ========================================================================== */

// Opens an already-resolved path. RESOLVE_NO_SYMLINKS|NO_MAGICLINKS makes the kernel reject
// any symlink swapped into the path between our realpath() and this open (not only the last component).
static int open_resolved(const char *path, int flags, mode_t mode) {
    if (!(flags & O_CREAT) && !has_tmpfile(flags)) mode = 0;   // openat2 rejects stray mode
    OpenHow how{(uint64_t) (unsigned) flags, (uint64_t) (mode & 07777),
                RESOLVE_NO_SYMLINKS_ | RESOLVE_NO_MAGICLINKS_};
    // __NR_openat2 seems to give SYS_SECCOMP ???

//    long fd = syscall(__NR_openat2, AT_FDCWD, path, &how, sizeof how);
//    if (fd >= 0 || errno != ENOSYS || errno != SYS_SECCOMP) return (int) fd;
    return (int) syscall(__NR_openat, AT_FDCWD, path, flags | O_NOFOLLOW, mode);  // kernel < 5.6
}

static void send_fd(Ctx &c, int fd, bool cloexec) {
    seccomp_notif_addfd add{};
    add.id = c.req->id;
    add.srcfd = (uint32_t) fd;
    add.newfd = 0;
    add.newfd_flags = cloexec ? O_CLOEXEC : 0;
    int newfd = (int) ioctl(c.notif_fd, SECCOMP_IOCTL_NOTIF_ADDFD, &add);
    int saved = errno;
    close(fd);
    if (newfd < 0) return c.fail(saved);
    c.ok(newfd);
}

static void open_core(Ctx &c, int dirfd, int path_arg, int flags, mode_t mode) {
    int acc = flags & O_ACCMODE;
    if (acc == O_ACCMODE) return c.fail(EINVAL);
    int need = (acc == O_WRONLY) ? WRITE : (acc == O_RDWR) ? (READ | WRITE) : READ;
    if ((flags & (O_CREAT | O_TRUNC | O_APPEND)) || has_tmpfile(flags)) need |= WRITE;

    if (flags & O_PATH) {
        // ioctl(ADDFD) can't transfer O_PATH fds, so open a normal fd instead.

        // "When O_PATH is specified in flags, flag bits other than
        // O_CLOEXEC, O_DIRECTORY, and O_NOFOLLOW are ignored."
        flags &= (O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
        need = READ;
    }

    PathResult p;
    int e = prepare_path(c, dirfd, path_arg, !(flags & O_NOFOLLOW), need, false, p);
    FAIL_ON(e);

    int fd = open_resolved(p.path.c_str(), flags | O_CLOEXEC, mode);
    if (fd < 0) return c.fail(errno);
    send_fd(c, fd, flags & O_CLOEXEC);
}

static void h_openat(Ctx &c) {
    open_core(c, (int) c.arg(0), 1, (int) c.arg(2), (mode_t) c.arg(3));
}

#ifdef __NR_open

static void h_open(Ctx &c) {
    open_core(c, AT_FDCWD, 0, (int) c.arg(1), (mode_t) c.arg(2));
}

#endif

#ifdef __NR_creat

static void h_creat(Ctx &c) {
    open_core(c, AT_FDCWD, 0, O_CREAT | O_WRONLY | O_TRUNC, (mode_t) c.arg(1));
}

#endif

// openat2(dirfd, path, struct open_how *how, size_t size)
static void h_openat2(Ctx &c) {
    auto size = (size_t) c.arg(3);
    if (size < sizeof(OpenHow)) return c.fail(EINVAL);
    if (size > 256) return c.fail(E2BIG);

    uint8_t buf[256] = {};
    if (!read_remote(c, untag(c.arg(2)), buf, size)) return c.fail(EFAULT);
    for (size_t i = sizeof(OpenHow); i < size; i++)        // same contract as the kernel
        if (buf[i]) return c.fail(E2BIG);

    OpenHow how{};
    memcpy(&how, buf, sizeof how);
    if ((how.flags >> 32) || (how.mode & ~07777ULL)) return c.fail(EINVAL);
    if (how.mode && !(how.flags & O_CREAT) && !has_tmpfile((int) how.flags))
        return c.fail(EINVAL);

    // BENEATH / IN_ROOT / NO_XDEV / NO_SYMLINKS are relative to dirfd, which we don't emulate
    // since we re-resolve paths ourselves. ENOSYS makes well-behaved callers fall back to openat().
    if (how.resolve) return c.fail(ENOSYS);

    open_core(c, (int) c.arg(0), 1, (int) how.flags, (mode_t) how.mode);
}

/* ========================================================================== */
/* Handlers: path operations                                                  */
/* ========================================================================== */

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

// statx(dirfd, path, flags, mask, statxbuf)
static void h_statx(Ctx &c) {
    int flags = (int) c.arg(2);
    PathResult p;
    int e = prepare_path(c, (int) c.arg(0), 1, !(flags & AT_SYMLINK_NOFOLLOW), READ,
                         flags & AT_EMPTY_PATH, p);
    FAIL_OR_PASS(e);
    alignas(8) char stx[256];                       // sizeof(struct statx)
    memset(stx, 0, sizeof stx);
    long r = syscall(__NR_statx, AT_FDCWD, p.path.c_str(),
                     (flags & ~AT_EMPTY_PATH) | AT_SYMLINK_NOFOLLOW, (unsigned) c.arg(3), stx);
    if (r < 0) return c.fail(errno);
    if (!write_remote(c, untag(c.arg(4)), stx, sizeof stx)) return c.fail(EFAULT);
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

// faccessat(dirfd, path, mode) / faccessat2(dirfd, path, mode, flags)
static void do_access(Ctx &c, int flags) {
    int amode = (int) c.arg(2);
    if ((amode & ~(R_OK | W_OK | X_OK)) ||
        (flags & ~(AT_EACCESS | AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH)))
        return c.fail(EINVAL);
    int need = (amode & W_OK) ? (READ | WRITE) : READ;

    PathResult p;
    int e = prepare_path(c, (int) c.arg(0), 1, !(flags & AT_SYMLINK_NOFOLLOW), need,
                         flags & AT_EMPTY_PATH, p);
    FAIL_OR_PASS(e);

//    long r = syscall(__NR_faccessat2, AT_FDCWD, p.path.c_str(), amode,
//                     (flags & AT_EACCESS) | AT_SYMLINK_NOFOLLOW);
//    if (r < 0 && errno == ENOSYS)   // kernel < 5.8: AT_EACCESS semantics are lost
    long r = syscall(__NR_faccessat, AT_FDCWD, p.path.c_str(), amode);
    r < 0 ? c.fail(errno) : c.ok(0);
}

static void h_faccessat(Ctx &c) { do_access(c, 0); }

static void h_faccessat2(Ctx &c) { do_access(c, (int) c.arg(3)); }

// fchmodat(dirfd, path, mode) / fchmodat2(dirfd, path, mode, flags)
// Race-free: pin the inode with an O_PATH fd, then chmod via /proc/self/fd (the broker's own proc).
static void do_chmod(Ctx &c, int flags) {
    if (flags & ~(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH)) return c.fail(EINVAL);
    PathResult p;
    int e = prepare_path(c, (int) c.arg(0), 1, !(flags & AT_SYMLINK_NOFOLLOW), WRITE,
                         flags & AT_EMPTY_PATH, p);
    FAIL_OR_PASS(e);

    ScopedFd fd(open_resolved(p.path.c_str(), O_PATH | O_NOFOLLOW | O_CLOEXEC, 0));
    if (fd.fd < 0) return c.fail(errno);
    struct stat st{};
    if (fstat(fd.fd, &st) < 0) return c.fail(errno);
    if (S_ISLNK(st.st_mode)) return c.fail(EOPNOTSUPP);   // same as the kernel for symlinks

    char link[64];
    snprintf(link, sizeof link, "/proc/self/fd/%d", fd.fd);
    long r = syscall(__NR_fchmodat, AT_FDCWD, link, (mode_t) (c.arg(2) & 07777));
    r < 0 ? c.fail(errno) : c.ok(0);
}

static void h_fchmodat(Ctx &c) { do_chmod(c, 0); }

static void h_fchmodat2(Ctx &c) { do_chmod(c, (int) c.arg(3)); }

/* ---- xattr (path variants; f*xattr is fd-based and already authorized at open) ---- */
static void do_setxattr(Ctx &c, bool follow) {   // (path, name, value, size, flags)
    auto size = (size_t) c.arg(3);
    if (size > kXattrMax) return c.fail(E2BIG);
    char name[256];
    int e = read_cstr(c, untag(c.arg(1)), name, sizeof name);
    FAIL_ON(e);
    std::vector<char> val(size ? size : 1);
    if (size && !read_remote(c, untag(c.arg(2)), val.data(), size)) return c.fail(EFAULT);

    PathResult p;
    e = prepare_path(c, AT_FDCWD, 0, follow, WRITE, false, p);
    FAIL_ON(e);
    long r = syscall(__NR_lsetxattr, p.path.c_str(), name, val.data(), size, (int) c.arg(4));
    r < 0 ? c.fail(errno) : c.ok(0);
}

static void h_setxattr(Ctx &c) { do_setxattr(c, true); }

static void h_lsetxattr(Ctx &c) { do_setxattr(c, false); }

static void do_getxattr(Ctx &c, bool follow) {   // (path, name, value, size)
    size_t size = std::min((size_t) c.arg(3), kXattrMax);
    char name[256];
    int e = read_cstr(c, untag(c.arg(1)), name, sizeof name);
    FAIL_ON(e);
    PathResult p;
    e = prepare_path(c, AT_FDCWD, 0, follow, READ, false, p);
    FAIL_ON(e);
    std::vector<char> buf(size ? size : 1);
    long r = syscall(__NR_lgetxattr, p.path.c_str(), name, size ? buf.data() : nullptr, size);
    if (r < 0) return c.fail(errno);
    if (size && r > 0 && !write_remote(c, untag(c.arg(2)), buf.data(), (size_t) r))
        return c.fail(EFAULT);
    c.ok(r);
}

static void h_getxattr(Ctx &c) { do_getxattr(c, true); }

static void h_lgetxattr(Ctx &c) { do_getxattr(c, false); }

static void do_listxattr(Ctx &c, bool follow) {  // (path, list, size)
    size_t size = std::min((size_t) c.arg(2), kXattrMax);
    PathResult p;
    int e = prepare_path(c, AT_FDCWD, 0, follow, READ, false, p);
    FAIL_ON(e);
    std::vector<char> buf(size ? size : 1);
    long r = syscall(__NR_llistxattr, p.path.c_str(), size ? buf.data() : nullptr, size);
    if (r < 0) return c.fail(errno);
    if (size && r > 0 && !write_remote(c, untag(c.arg(1)), buf.data(), (size_t) r))
        return c.fail(EFAULT);
    c.ok(r);
}

static void h_listxattr(Ctx &c) { do_listxattr(c, true); }

static void h_llistxattr(Ctx &c) { do_listxattr(c, false); }

static void do_removexattr(Ctx &c, bool follow) {  // (path, name)
    char name[256];
    int e = read_cstr(c, untag(c.arg(1)), name, sizeof name);
    FAIL_ON(e);
    PathResult p;
    e = prepare_path(c, AT_FDCWD, 0, follow, WRITE, false, p);
    FAIL_ON(e);
    long r = syscall(__NR_lremovexattr, p.path.c_str(), name);
    r < 0 ? c.fail(errno) : c.ok(0);
}

static void h_removexattr(Ctx &c) { do_removexattr(c, true); }

static void h_lremovexattr(Ctx &c) { do_removexattr(c, false); }

// inotify_add_watch(fd, path, mask). The inotify fd lives in the tracee, so borrow it with pidfd_getfd.
// The path is pinned with an O_PATH fd so the watch lands on the inode we authorized.
static void h_inotify_add_watch(Ctx &c) {
    auto mask = (uint32_t) c.arg(2);
    PathResult p;
    int e = prepare_path(c, AT_FDCWD, 1, !(mask & IN_DONT_FOLLOW_), READ, false, p);
    FAIL_ON(e);

    ScopedFd pin(open_resolved(p.path.c_str(), O_PATH | O_NOFOLLOW | O_CLOEXEC, 0));
    if (pin.fd < 0) return c.fail(errno);
    ScopedFd pidfd((int) syscall(__NR_pidfd_open, g_client_pid, 0));
    if (pidfd.fd < 0) return c.fail(EPERM);                    // fail closed
    ScopedFd ifd((int) syscall(__NR_pidfd_getfd, pidfd.fd, (int) c.arg(0), 0));
    if (ifd.fd < 0) return c.fail(EPERM);

    char link[64];
    snprintf(link, sizeof link, "/proc/self/fd/%d", pin.fd);
    long r = syscall(__NR_inotify_add_watch, ifd.fd, link, mask & ~IN_DONT_FOLLOW_);
    r < 0 ? c.fail(errno) : c.ok(r);
}

/* ========================================================================== */
/* Handlers: must run in the tracee (cont() unavoidable)                      */
/* ========================================================================== */

// This is NOT secure, an attacker can overwrite the memory before the syscall is executed.
// However, this is the best we can do on some syscalls such as execve which must be processed
// in the child. Use this method sparingly.
static void patch_and_continue(Ctx &c, int dirfd, int path_arg, bool follow, int mode,
                               bool allow_empty) {
    PathResult p;
    int e = prepare_path(c, dirfd, path_arg, follow, mode, allow_empty, p);
    FAIL_OR_PASS(e);
    if (p.redirected) {
        if (p.path.size() > p.raw_len)
            return c.fail(ENAMETOOLONG);   // would overflow tracee's buffer
        if (!write_remote(c, p.addr, p.path.c_str(), p.path.size() + 1)) return c.fail(EFAULT);
    }
    if (!c.valid()) return c.fail(ESRCH);
    c.cont();
}

static void h_chdir(Ctx &c) { patch_and_continue(c, AT_FDCWD, 0, true, READ, false); }

static void h_execve(Ctx &c) { patch_and_continue(c, AT_FDCWD, 0, true, READ, false); }

// execveat(dirfd, path, argv, envp, flags)
static void h_execveat(Ctx &c) {
    int flags = (int) c.arg(4);
    patch_and_continue(c, (int) c.arg(0), 1, !(flags & AT_SYMLINK_NOFOLLOW), READ,
                       flags & AT_EMPTY_PATH);
}

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

static bool isKillAllowed(Ctx &c, pid_t target) {
    // TODO account for process children
    return target == g_client_pid || target == c.req->pid;
}

static int read_siginfo(Ctx &c, uint64_t addr, uint8_t (&out)[kSiginfoSize]) {
    if (!addr) return EFAULT;
    return read_remote(c, addr, out, kSiginfoSize) ? 0 : EFAULT;
}

// kill(pid, sig)
static void h_kill(Ctx &c) {
    auto target = (pid_t) c.arg(0);
    if (!isKillAllowed(c, target)) return c.fail(EPERM);
    long r = syscall(__NR_kill, target, (int) c.arg(1));
    r < 0 ? c.fail(errno) : c.ok(0);
}

// tkill(tid, sig). Rewritten as tgkill(client, tid, sig): the kernel atomically verifies that
// tid belongs to the client's thread group, so there is no tid-reuse race.
static void h_tkill(Ctx &c) {
    auto tid = (pid_t) c.arg(0);
    if (tid <= 0) {
        return c.fail(EINVAL);
    }
    long r = syscall(__NR_tgkill, g_client_pid, tid, (int) c.arg(1));
    r < 0 ? c.fail(errno) : c.ok(0);
}

// tgkill(tgid, tid, sig). bionic's raise()/abort()/pthread_kill() use this.
static void h_tgkill(Ctx &c) {
    auto tgid = (pid_t) c.arg(0);
    auto tid = (pid_t) c.arg(1);
    if (tgid <= 0 || tid <= 0) return c.fail(EINVAL);
    if (!isKillAllowed(c, tgid)) return c.fail(EPERM);
    long r = syscall(__NR_tgkill, tgid, tid, (int) c.arg(2));
    r < 0 ? c.fail(errno) : c.ok(0);
}

// rt_sigqueueinfo(tgid, sig, siginfo_t *info). The kernel itself rejects si_code >= 0 and
// SI_TKILL from a different process, so the tracee can only send SI_QUEUE-style (negative) codes.
static void h_rt_sigqueueinfo(Ctx &c) {
    auto tgid = (pid_t) c.arg(0);
    if (tgid <= 0) return c.fail(EINVAL);
    if (!isKillAllowed(c, tgid)) return c.fail(EPERM);
    uint8_t info[kSiginfoSize];
    int e = read_siginfo(c, untag(c.arg(2)), info);
    FAIL_ON(e);
    long r = syscall(__NR_rt_sigqueueinfo, tgid, (int) c.arg(1), info);
    r < 0 ? c.fail(errno) : c.ok(0);
}

// rt_tgsigqueueinfo(tgid, tid, sig, siginfo_t *info)
static void h_rt_tgsigqueueinfo(Ctx &c) {
    auto tgid = (pid_t) c.arg(0);
    auto tid = (pid_t) c.arg(1);
    if (tgid <= 0 || tid <= 0) return c.fail(EINVAL);
    if (!isKillAllowed(c, tgid)) return c.fail(EPERM);
    uint8_t info[kSiginfoSize];
    int e = read_siginfo(c, untag(c.arg(3)), info);
    FAIL_ON(e);
    long r = syscall(__NR_rt_tgsigqueueinfo, tgid, tid, (int) c.arg(2), info);
    r < 0 ? c.fail(errno) : c.ok(0);
}

// Returns the pid a pidfd refers to (as seen from the broker's pid namespace),
// -1 if the target has exited, -2 if fd is not a pidfd or fdinfo is unreadable.
static int pidfd_target_pid(int fd) {
    char path[64];
    snprintf(path, sizeof path, "/proc/self/fdinfo/%d", fd);
    FILE *f = fopen(path, "re");
    if (!f) return -2;
    char line[128];
    int pid = -2;
    while (fgets(line, sizeof line, f)) {
        if (sscanf(line, "Pid: %d", &pid) == 1) break;   // "NSpid:" does not match this prefix
    }
    fclose(f);
    return pid;
}

// pidfd_send_signal(pidfd, sig, siginfo_t *info, flags)
// The pidfd lives in the tracee's fd table, so duplicate it with pidfd_getfd. A duplicated pidfd
// pins the same struct pid, so checking it and then signalling it is race-free.
static void h_pidfd_send_signal(Ctx &c) {
    auto flags = (unsigned) c.arg(3);
    if (flags & ~(PIDFD_SIGNAL_THREAD_ | PIDFD_SIGNAL_THREAD_GROUP_ | PIDFD_SIGNAL_PROCESS_GROUP_))
        return c.fail(EINVAL);
    if (flags & PIDFD_SIGNAL_PROCESS_GROUP_) {
        return c.fail(EPERM);   // would leave the sandbox
    }

    uint8_t info[kSiginfoSize];
    uint64_t info_addr = untag(c.arg(2));
    if (info_addr) {
        int e = read_siginfo(c, info_addr, info);
        FAIL_ON(e);
    }

    ScopedFd client((int) syscall(__NR_pidfd_open, g_client_pid, 0));
    if (client.fd < 0) return c.fail(EPERM);                       // fail closed
    ScopedFd mine((int) syscall(__NR_pidfd_getfd, client.fd, (int) c.arg(0), 0));
    if (mine.fd < 0) return c.fail(errno == EBADF ? EBADF : EPERM);

    int target = pidfd_target_pid(mine.fd);
    if (target == -2) return c.fail(EBADF);                        // not a pidfd
    if (target == -1) return c.fail(ESRCH);                        // process already gone
    if (!isKillAllowed(c, target)) return c.fail(EPERM);

    long r = syscall(__NR_pidfd_send_signal, mine.fd, (int) c.arg(1),
                     info_addr ? info : nullptr, flags);
    r < 0 ? c.fail(errno) : c.ok(0);
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
#ifdef __NR_creat
        m[__NR_creat] = h_creat;
#endif
        m[__NR_openat] = h_openat;      // also covers __openat_2
        m[__NR_openat2] = h_openat2;
        m[__NR_fchownat] = h_fchownat;
#ifdef __NR_renameat
        m[__NR_renameat] = h_renameat;
#endif
#ifdef __NR_renameat2
        m[__NR_renameat2] = h_renameat2;   // libc renameat() may issue this on arm64
#endif
        m[NR_FSTATAT] = h_fstatat;     // libc fstatat64
        m[__NR_statx] = h_statx;
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
        m[__NR_symlinkat] = h_symlinkat; //
        m[__NR_utimensat] = h_utimensat;
        m[__NR_faccessat] = h_faccessat;
        m[__NR_faccessat2] = h_faccessat2;
        m[__NR_fchmodat] = h_fchmodat;
        m[__NR_fchmodat2] = h_fchmodat2;
        m[__NR_setxattr] = h_setxattr;
        m[__NR_lsetxattr] = h_lsetxattr;
        m[__NR_getxattr] = h_getxattr;
        m[__NR_lgetxattr] = h_lgetxattr;
        m[__NR_listxattr] = h_listxattr;
        m[__NR_llistxattr] = h_llistxattr;
        m[__NR_removexattr] = h_removexattr;
        m[__NR_lremovexattr] = h_lremovexattr;
        m[__NR_inotify_add_watch] = h_inotify_add_watch;
        m[__NR_chdir] = h_chdir;
        m[__NR_execve] = h_execve;
        m[__NR_execveat] = h_execveat;

        m[__NR_kill] = h_kill;
        m[__NR_tkill] = h_tkill;
        m[__NR_tgkill] = h_tgkill;
        m[__NR_rt_sigqueueinfo] = h_rt_sigqueueinfo;
        m[__NR_rt_tgsigqueueinfo] = h_rt_tgsigqueueinfo;
        m[__NR_pidfd_send_signal] = h_pidfd_send_signal;
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
        pthread_mutex_lock(&g_servers_mutex);
        bool running = g_policy.running;
        pthread_mutex_unlock(&g_servers_mutex);
        if (!running) {
            break;
        }

        memset(req, 0, sizes.seccomp_notif);
        if (ioctl(fd, SECCOMP_IOCTL_NOTIF_RECV, req) < 0) {
            if (errno == EINTR) continue;
            if (errno == ENOENT) break;
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
            ALOGI("NOTIF_SEND %d", errno);
        }
    }

    close(fd);
    free(req);
    free(resp);
}

static void on_sig(int) {}

/* ========================================================================== */
/* JNI entry point                                                            */
/* ========================================================================== */
extern "C"
JNIEXPORT void JNICALL
Java_com_lody_virtual_server_security_SyscallBroker_serverServe(JNIEnv *env, jobject thiz,
                                                                jint fd, jint pid,
                                                                jobject sandbox, jstring cwd) {
    jclass cls = env->GetObjectClass(sandbox);
    jmethodID check_method = env->GetMethodID(cls, "isFlagAllowed", "([BI)Z");
    if (check_method == nullptr) {
        env->ExceptionClear();
        return;
    }
    jmethodID redirect_method = env->GetMethodID(cls, "getRedirectPath",
                                                 "([B)Ljava/lang/String;");
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
    g_policy.thread = pthread_self();

    struct sigaction sa = {0};
    sa.sa_handler = on_sig;

    // We need our own signal handler to exit the broker listener.
    // The goal is just to send EINT to ioctl, therefore the handler can be empty.
    // SIGUSR1 is seemingly already used
    sigaction(SIGUSR2, &sa, nullptr);

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
        it->second->running = false;
        auto thread = it->second->thread;
        if (thread) {
            pthread_kill(thread, SIGUSR2);
        }
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