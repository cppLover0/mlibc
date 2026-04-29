#pragma once

#include <stddef.h>
#include <stdint.h>

#define SYS_WRITE 2
#define SYS_ARCH_PRCTL 9
#define SYS_MMAP 3
#define SYS_MUNMAP 4
#define SYS_SEEK 10
#define SYS_CLOSE 5
#define SYS_EXIT_GROUP 7
#define SYS_FUTEX 6
#define SYS_READ 1
#define SYS_EXIT 8
#define SYS_IOCTL 11
#define SYS_ACCESS 12
#define SYS_OPEN 13
#define SYS_OPENAT 14
#define SYS_UNLINKAT 15
#define SYS_UNLINK 16
#define SYS_NEWFSTATAT 17
#define SYS_FSTAT 18
#define SYS_STATX 19
#define SYS_PSELECT6 20
#define SYS_POLL 21
#define SYS_DUP 22
#define SYS_DUP2 23
#define SYS_FCNTL 24
#define SYS_GETPID 25
#define SYS_GETTID 26
#define SYS_CLONE3 27
#define SYS_CLOCK_GET 28
#define SYS_GETPGRP 29
#define SYS_GETPPID 30
#define SYS_SETPGID 31
#define SYS_GETUID 32
#define SYS_GETRESGID 33
#define SYS_GETRESUID 34
#define SYS_PIPE2 35
#define SYS_GETRANDOM 36
#define SYS_EXECVE 37
#define SYS_WAIT4 38
#define SYS_WRITEV 39
#define SYS_READLINK 40
#define SYS_READLINKAT 41
#define SYS_GETDENTS64 42
#define SYS_STATFS 43 
#define SYS_SIGPROCACTION 44
#define SYS_SIGPROCMASK 45
#define SYS_UNAME 46
#define SYS_SIGALTSTACK 47
#define SYS_CHMOD 48
#define SYS_CHDIR 49
#define SYS_FCHDIR 50
#define SYS_MKDIR 51
#define SYS_MKDIRAT 52
#define SYS_UMASK 53
#define SYS_FACCESSAT2 54
#define SYS_PREAD64 55
#define SYS_PRLIMIT64 56
#define SYS_NANOSLEEP 57
#define SYS_YIELD 58
#define SYS_CLONE 59
#define SYS_NEWTHREAD 60
#define SYS_GETPGID 61
#define SYS_GETGID 62
#define SYS_TTYNAME 63
#define SYS_SYSINFO 64
#define SYS_CPUCOUNT 65
#define SYS_SIGRETURN 66
#define SYS_KILL 67
#define SYS_PAUSE 68
#define SYS_LISTEN 69
#define SYS_ACCEPT 70
#define SYS_SOCKET 71 
#define SYS_CONNECT 72
#define SYS_BIND 73
#define SYS_RECVFROM 74
#define SYS_SENDTO 75
#define SYS_MSG_RECV 76
#define SYS_MSG_SEND 77
#define SYS_LINK 78
#define SYS_LINKAT 79
#define SYS_GETSOCKOPT 80
#define SYS_SETSOCKOPT 81
#define SYS_LIBCLOG 82

#ifndef __MLIBC_ABI_ONLY

inline static int error(long long ret) {
	auto v = static_cast<long long>(ret);
	if(static_cast<unsigned long>(v) > -4096UL)
	    return -v;
	return 0;
}


inline static long syscall(long func, uint64_t p1 = 0, uint64_t p2 = 0, uint64_t p3 = 0, uint64_t p4 = 0, uint64_t p5 = 0, uint64_t p6 = 0) {
	volatile long ret;

	register uint64_t r4 asm("r10") = p4;
	register uint64_t r5 asm("r8") = p5;
	register uint64_t r6 asm("r9") = p6;

	asm volatile("syscall"
		: "=a"(ret)
		: "a"(func), "D"(p1), "S"(p2), "d"(p3), "r"(r4),
		"r"(r5), "r"(r6)
		: "memory", "rcx", "r11");
    return ret;
}

#endif 