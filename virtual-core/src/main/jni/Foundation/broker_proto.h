#pragma once

#include <climits>
#include <cstdint>

#define BROKER_MAGIC    0xB975C2 // Something random
#define BROKER_MAX_BLOB 256    // sockaddr, timespec[2]
#define BROKER_MAX_OUT  4096   // stat, statfs, readlink, getcwd

// --- per-arch register access ---------------------------------------
#if defined(__aarch64__)
#define AUDIT_ARCH_CURRENT AUDIT_ARCH_AARCH64
#elif defined(__x86_64__)
#define AUDIT_ARCH_CURRENT AUDIT_ARCH_X86_64
#elif defined(__arm__)
#define AUDIT_ARCH_CURRENT AUDIT_ARCH_ARM
#elif defined(__i386__)
#define AUDIT_ARCH_CURRENT AUDIT_ARCH_I386
#else
#error "unsupported arch"
#endif