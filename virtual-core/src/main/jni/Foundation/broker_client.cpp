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

#define ALLOW_SYSCALL(nr) \
    BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, (nr), 0, 1), \
    BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW)

#define DENY_SYSCALL(nr) \
    BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, (nr), 0, 1), \
    BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA))

int apply_seccomp_filter() {
    // 1. Prevent gaining new privileges via setuid/setgid binaries
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) {
        ALOGD("Failed to set PR_SET_NO_NEW_PRIVS");
        return -1;
    }

    // 2. Define the BPF Filter Instructions
    struct sock_filter filter[] = {
            // Load architecture number from system call data frame into accumulator
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),

            // Verify architecture matches target (prevents arch-switching exploits)
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_CURRENT, 1, 0),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),

            // Load system call number into accumulator
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),

            // Disable ptrace
            DENY_SYSCALL(__NR_ptrace),

            // These are required to send the FD back to the host process
            ALLOW_SYSCALL(__NR_mmap),
            ALLOW_SYSCALL(__NR_mprotect),
            ALLOW_SYSCALL(__NR_rt_sigprocmask),
            ALLOW_SYSCALL(__NR_ioctl),
            ALLOW_SYSCALL(__NR_writev),
            ALLOW_SYSCALL(__NR_madvise),
            ALLOW_SYSCALL(__NR_fcntl),
            ALLOW_SYSCALL(__NR_getuid),

            // Disable syscalls which open stuff from the kernel
            DENY_SYSCALL(__NR_io_uring_setup),
            DENY_SYSCALL(__NR_io_uring_enter),
            DENY_SYSCALL(__NR_io_uring_register),

            // Generally unused, but dangerous syscalls
            DENY_SYSCALL(__NR_name_to_handle_at),
            DENY_SYSCALL(__NR_open_by_handle_at),
            DENY_SYSCALL(__NR_mount),
            DENY_SYSCALL(__NR_umount2),
            DENY_SYSCALL(__NR_pivot_root),
            DENY_SYSCALL(__NR_setns),
            DENY_SYSCALL(__NR_pidfd_open),
            DENY_SYSCALL(__NR_pidfd_getfd),
            DENY_SYSCALL(__NR_bpf),
            DENY_SYSCALL(__NR_userfaultfd),
            DENY_SYSCALL(__NR_kcmp),

            // Deprecated thread killing syscall which should not be used by processes
            DENY_SYSCALL(__NR_tkill),

            // All other calls are proxied to the host process!
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
    };

    struct sock_fprog prog = {
            .len = static_cast<unsigned short>(sizeof(filter) / sizeof(filter[0])),
            .filter = filter,
    };

    int flags = SECCOMP_FILTER_FLAG_NEW_LISTENER |
                SECCOMP_FILTER_FLAG_TSYNC |
                SECCOMP_FILTER_FLAG_TSYNC_ESRCH;

    int listener = static_cast<int>(syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, flags, &prog));
    if (listener < 0) {
        ALOGD("Failed to apply Seccomp filter: %s", strerror(errno));
        return -1;
    }

    ALOGD("Applied Seccomp filter successfully");
    return listener;
}

extern "C"
JNIEXPORT jint JNICALL
Java_com_lody_virtual_server_security_SyscallBroker_clientInstall(JNIEnv *env, jobject thiz) {
    int pid = getpid();
    ALOGI("Installing client seccomp on pid: %d!", pid);

    int result = apply_seccomp_filter();
    return result;
}