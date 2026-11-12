#pragma once

#include <climits>
#include <cstdint>

#define BROKER_MAGIC    0xB975C2 // Something random
#define BROKER_MAX_BLOB 256    // sockaddr, timespec[2]
#define BROKER_MAX_OUT  4096   // stat, statfs, readlink, getcwd

// --- per-arch register access ---------------------------------------
#if defined(__aarch64__)
#define AUDIT_ARCH_CURRENT AUDIT_ARCH_AARCH64
#define UC_ARG(uc, i)  ((long)(uc)->uc_mcontext.regs[(i)])
#define UC_RET(uc)     ((uc)->uc_mcontext.regs[0])
#elif defined(__x86_64__)
static const int kArgRegs[6] = { REG_RDI, REG_RSI, REG_RDX, REG_R10, REG_R8, REG_R9 };
#define AUDIT_ARCH_CURRENT AUDIT_ARCH_X86_64
#define UC_ARG(uc, i)  ((long)(uc)->uc_mcontext.gregs[kArgRegs[(i)]])
#define UC_RET(uc)     ((uc)->uc_mcontext.gregs[REG_RAX])
#elif defined(__arm__)
#define AUDIT_ARCH_CURRENT AUDIT_ARCH_ARM
#define UC_ARG(uc, i)  ((long)(&(uc)->uc_mcontext.arm_r0)[(i)])
#define UC_RET(uc)     ((uc)->uc_mcontext.arm_r0)
#elif defined(__i386__)
static const int kArgRegs[6] = { REG_EBX, REG_ECX, REG_EDX, REG_ESI, REG_EDI, REG_EBP };
#define AUDIT_ARCH_CURRENT AUDIT_ARCH_I386
#define UC_ARG(uc, i)  ((long)(uc)->uc_mcontext.gregs[kArgRegs[(i)]])
#define UC_RET(uc)     ((uc)->uc_mcontext.gregs[REG_EAX])
#else
#error "unsupported arch"
#endif

enum broker_op {
    OP_OPENAT = 1, OP_FSTATAT, OP_STATFS, OP_FCHOWNAT, OP_RENAMEAT, OP_MKDIRAT,
    OP_MKNODAT, OP_TRUNCATE, OP_LINKAT, OP_READLINKAT, OP_UNLINKAT, OP_SYMLINKAT,
    OP_UTIMENSAT, OP_CHDIR, OP_GETCWD, OP_KILL, OP_CONNECT, OP_COUNT
};

struct broker_req_hdr {
    uint32_t magic, op;
    int64_t a[4];           // integer args, meaning depends on op
    uint32_t path_len[2];   // strlen of path0/path1 (0 = absent or empty)
    uint32_t blob_len;
    uint32_t out_cap;       // max output bytes the client can accept
    uint32_t fdmask;        // bit i: SCM_RIGHTS fd attached for slot i (else AT_FDCWD)
};  // followed on the wire by: path0, path1, blob (no NULs)

struct broker_resp_hdr {
    uint32_t magic, out_len;   // out_len bytes of output follow
    int64_t result;           // >= 0 success, < 0 -errno; fd (if any) via SCM_RIGHTS
};