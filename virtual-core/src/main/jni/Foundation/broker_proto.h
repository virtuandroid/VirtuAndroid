#pragma once

#include <climits>
#include <cstdint>

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