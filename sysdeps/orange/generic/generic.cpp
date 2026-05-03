#include <abi-bits/errno.h>
#include <bits/ensure.h>
#include <orange/syscall.h>
#include <bits/ansi/timespec.h>
#include <asm/ioctls.h>
#include <mlibc/all-sysdeps.hpp>
#include <string.h>

#include <abi-bits/fcntl.h>

namespace mlibc {

void Sysdeps<LibcPanic>::operator()() {
	sysdep<LibcLog>("!!! mlibc panic !!!");
	sysdep<Exit>(-1);
	__builtin_trap();
}

void Sysdeps<LibcLog>::operator()(const char *msg) {
	syscall(SYS_LIBCLOG, (uint64_t)msg);
}

int Sysdeps<Isatty>::operator()(int fd) {
	unsigned short winsizeHack[4];
	auto ret = syscall(SYS_IOCTL, fd, 0x5413 /* TIOCGWINSZ */, (uint64_t)&winsizeHack);
	if (int e = error(ret); e)
		return e;

	return 0;
}

int Sysdeps<Write>::operator()(int fd, void const *buf, size_t size, ssize_t *ret) {
	auto ret1 = syscall(SYS_WRITE, fd, (uint64_t)buf, size);
	if(int e = error(ret1); e)
		return e;

	*ret = ret1;
	return 0;
}

int Sysdeps<TcbSet>::operator()(void *pointer) {
	int ret = syscall(SYS_ARCH_PRCTL, 0x1002, (uint64_t)pointer);
	if(int e = error(ret); e) 
		return e;
	return 0;
}

int Sysdeps<AnonAllocate>::operator()(size_t size, void **pointer) {
	auto out = syscall(
	    SYS_MMAP, 0, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0
	);
	if(int e = error(out); e)
		return e;
	*pointer = (void*)out;
	return 0;
}

int Sysdeps<AnonFree>::operator()(void* ptr, unsigned long size) {
	auto ret = syscall(SYS_MUNMAP, (uint64_t)ptr, size);
	if(int e = error(ret); e)
		return e;
	return 0;
} // no-op

int Sysdeps<Seek>::operator()(int fd, off_t off, int whence, off_t* out) {
	auto ret = syscall(SYS_SEEK, fd, off, whence);
	if(int e = error(ret); e)
		return e;
	*out = ret;
	return 0;
}

void Sysdeps<Exit>::operator()(int status) {
	syscall(SYS_EXIT_GROUP, status);
	__builtin_unreachable();
}

void Sysdeps<ThreadExit>::operator()() {
	syscall(SYS_EXIT);
	__builtin_unreachable();
}

int Sysdeps<Close>::operator()(int fd) {
	auto ret = syscall(SYS_CLOSE, fd);
	if(int e = error(ret); e)
		return e;
	return ret;
}

int Sysdeps<FutexWake>::operator()(int * uaddr, bool all) {
	auto ret = syscall(SYS_FUTEX, (uint64_t)uaddr, 1, all ? 0xFFFFFFFF : 1);
	if(int e = error(ret); e)
		return ret;
	return 0;
}

int Sysdeps<FutexWait>::operator()(int *pointer, int expected, const struct timespec *time) {
	auto ret = syscall(SYS_FUTEX, (uint64_t)pointer, 0, expected, (uint64_t)time);
	if (int e = error(ret); e)
		return e;
	return 0;
}

int Sysdeps<Read>::operator()(int fd, void* buf, unsigned long size, long* ret) {
	auto ret1 = syscall(SYS_READ, fd, (uint64_t)buf, size);
	if(int e = error(ret1); e)
		return e;
	*ret = ret1;
	return 0;
}
int Sysdeps<Open>::operator()(const char *pathname, int flags, mode_t mode, int *fd) {
	auto ret = syscall(SYS_OPEN, (uint64_t)pathname, flags, mode);
	if(int e = error(ret); e)
		return e;
	*fd = ret;
	return 0;
}

int Sysdeps<VmMap>::operator()(void *hint, size_t size, int prot, int flags, int fd, off_t offset, void **window) {
	auto ret = syscall(SYS_MMAP, (uint64_t)hint, size, prot, flags, fd, offset);
	if(int e = error(ret); e)
		return e;
	*window = (void*)ret;
	return 0;
}

int Sysdeps<VmUnmap>::operator()(void* addr, size_t len) {
	auto ret = syscall(SYS_MUNMAP, (uint64_t)addr, len);
	if(int e = ret; e)
		return e;
	return 0;
}

int Sysdeps<ClockGet>::operator()(int clock, time_t *secs, long *nanos) {
	struct timespec ts = {};
	auto ret = syscall(SYS_CLOCK_GET, clock, (uint64_t)&ts);
	if(int e = ret; e)
		return e;

	if(secs)
		*secs = ts.tv_sec;

	if(nanos)
		*nanos = ts.tv_nsec;

	return 0;
}

int Sysdeps<GetTid>::operator()() {
	auto ret = syscall(SYS_GETTID);
	return ret;
}

int Sysdeps<GetPid>::operator()() {
	auto ret = syscall(SYS_GETPID);
	return ret;
}

uid_t Sysdeps<GetUid>::operator()() {
	auto ret = syscall(SYS_GETUID);
	return ret;
}

uid_t Sysdeps<GetEuid>::operator()() {
	auto ret = syscall(SYS_GETUID);
	return ret;
}

int Sysdeps<GetPpid>::operator()() {
	auto ret = syscall(SYS_GETPPID);
	return ret;
}

int Sysdeps<Tcgetattr>::operator()(int fd, struct termios *attr) {
	auto ret = syscall(SYS_IOCTL, fd, TCGETS, (uint64_t)attr);
	if (int e = error(ret); e)
		return e;
	return 0;
}

int Sysdeps<Tcsetattr>::operator()(int fd, int optional_action, const struct termios *attr) {
	int req;

	switch (optional_action) {
		case TCSANOW: req = TCSETS; break;
		case TCSADRAIN: req = TCSETSW; break;
		case TCSAFLUSH: req = TCSETSF; break;
		default: return EINVAL;
	}

	auto ret = syscall(SYS_IOCTL, fd, req, (uint64_t)attr);
	if (int e = error(ret); e)
		return e;
	return 0;
}

int Sysdeps<Tcsendbreak>::operator()(int fd, int) {
	auto ret = syscall(SYS_IOCTL, fd, TCSBRK, 0);
	if (int e = error(ret); e)
		return e;
	return 0;
}

int Sysdeps<Tcflow>::operator()(int fd, int action) {
	auto ret = syscall(SYS_IOCTL, fd, TCXONC, action);
	if (int e = error(ret); e)
		return e;
	return 0;
}

int Sysdeps<Tcflush>::operator()(int fd, int queue) {
	auto ret = syscall(SYS_IOCTL, fd, TCFLSH, queue);
	if (int e = error(ret); e)
		return e;
	return 0;
}

int Sysdeps<Tcdrain>::operator()(int fd) {
	auto ret = syscall(SYS_IOCTL, fd, TCSBRK, 1);
	if (int e = error(ret); e)
		return e;
	return 0;
}

int Sysdeps<Tcgetwinsize>::operator()(int fd, struct winsize *winsz) {
	auto ret = syscall(SYS_IOCTL, fd, TIOCGWINSZ, (uint64_t)winsz);
	if (int e = error(ret); e)
		return e;
	return 0;
}

int Sysdeps<Tcsetwinsize>::operator()(int fd, const struct winsize *winsz) {
	auto ret = syscall(SYS_IOCTL, fd, TIOCSWINSZ, (uint64_t)winsz);
	if (int e = error(ret); e)
		return e;
	return 0;
}

int Sysdeps<Ioctl>::operator()(int fd, unsigned long request, void *arg, int *result) {
	auto ret = syscall(SYS_IOCTL, fd, request, (uint64_t)arg);
	if(int e = error(ret); e)
		return e;
	*result = ret;
	return 0;
}

int Sysdeps<Access>::operator()(const char *path, int mode) {
	auto ret = syscall(SYS_ACCESS, (uint64_t)path, mode);
	if(int e = error(ret);e)
		return e;
	return 0;
}

int Sysdeps<Faccessat>::operator()(int dirfd, const char *pathname, int mode, int flags) {
	auto ret = syscall(SYS_FACCESSAT2, dirfd, (uint64_t)pathname, mode, flags);
	if(int e = error(ret);e)
		return e;
	return 0;
}

int Sysdeps<Writev>::operator()(int fd, const struct iovec *iovs, int iovc, ssize_t *bytes_written) {
	auto ret = syscall(SYS_WRITEV, fd, (uint64_t)iovs, iovc);
	if(int e = error(ret); e) 
		return e;
	*bytes_written = ret;
	return 0;
}

int Sysdeps<Openat>::operator()(int dirfd, const char *path, int flags, mode_t mode, int *fd) {
	auto ret = syscall(SYS_OPENAT, dirfd, (uint64_t)path, flags, mode);
	if(int e = error(ret); e)
		return e;
	*fd = ret;
	return 0;
}

int Sysdeps<Unlinkat>::operator()(int dirfd, const char *path, int flags) {
	auto ret = syscall(SYS_UNLINKAT, dirfd, (uint64_t)path, flags);
	if(int e = error(ret); e)
		return e;
	return 0;
}

int Sysdeps<Stat>::operator()(fsfd_target fsfdt, int fd, const char *path, int flags, struct stat *statbuf) {
	if (fsfdt == fsfd_target::path)
		fd = AT_FDCWD;
	else if (fsfdt == fsfd_target::fd)
		flags |= AT_EMPTY_PATH;
	else
		__ensure(fsfdt == fsfd_target::fd_path);

	auto ret = syscall(SYS_NEWFSTATAT, fd, (uint64_t)path, (uint64_t)statbuf, flags);

	if (int e = error(ret); e) {
		return e;
	}

	return 0;
}

int Sysdeps<Statx>::operator()(int dirfd, const char *pathname, int flags, unsigned int mask, struct statx *statxbuf) {
	auto ret = syscall(SYS_STATX, dirfd, (uint64_t)pathname, flags, mask, (uint64_t)statxbuf);
	if(int e = error(ret); e)
		return e;

	return 0;
}

int Sysdeps<Pselect>::operator()(int num_fds, fd_set *read_set, fd_set *write_set, fd_set *except_set, const struct timespec *timeout, const sigset_t *sigmask, int *num_events) {
	auto ret = syscall(SYS_PSELECT6, num_fds, (uint64_t)read_set, (uint64_t)write_set, (uint64_t)except_set, (uint64_t)timeout, (uint64_t)sigmask);
	if(int e = error(ret); e)
		return e;
	*num_events = ret;
	return 0;
}

int Sysdeps<Poll>::operator()(struct pollfd *fds, nfds_t count, int timeout, int *num_events) {
	auto ret = syscall(SYS_POLL, (uint64_t)fds, count, timeout);
	if(int e = error(ret); e)
		return e;
	*num_events = ret;
	return 0;
}

int Sysdeps<Dup>::operator()(int fd, int flags, int *newfd) {
	(void)flags;
	auto ret = syscall(SYS_DUP, fd);
	if(int e = error(ret); e)
		return e;
	*newfd = ret;
	return 0;
}

int Sysdeps<Dup2>::operator()(int fd, int flags, int newfd) {
	(void)flags;
	auto ret = syscall(SYS_DUP2, fd, newfd);
	if(int e = error(ret); e)
		return e;
	return 0;
}

int Sysdeps<Fcntl>::operator()(int fd, int request, va_list args, int *result) {
	auto arg = va_arg(args, unsigned long);
	auto ret = syscall(SYS_FCNTL, fd, request, arg);
	if(int e = error(ret); e)
		return e;
	*result = ret;
	return 0;
}

int Sysdeps<Fork>::operator()(pid_t *child) {
	auto ret = syscall(SYS_CLONE, SIGCHLD, 0);
	if (int e = error(ret); e)
			return e;
	*child = ret;
	return 0;
}

int Sysdeps<Waitpid>::operator()(pid_t pid, int *status, int flags, struct rusage *ru, pid_t *ret_pid) {
	auto ret = syscall(SYS_WAIT4, pid, (uint64_t)status, flags, (uint64_t)ru);
	if (int e = error(ret); e)
			return e;
	*ret_pid = ret;
	return 0;
}

int Sysdeps<Execve>::operator()(const char *path, char *const argv[], char *const envp[]) {
	auto ret = syscall(SYS_EXECVE, (uint64_t)path, (uint64_t)argv, (uint64_t)envp);
	if (int e = error(ret); e)
		return e;
	return 0;
}

void Sysdeps<Yield>::operator()() {
	syscall(SYS_YIELD);
}

#ifndef MLIBC_BUILDING_RTLD	

extern "C" void __mlibc_thread_entry();

int Sysdeps<Clone>::operator()(void *tcb, pid_t *pid_out, void *stack) {
	auto ret = syscall(SYS_NEWTHREAD, (uint64_t)__mlibc_thread_entry, (uint64_t)stack);
	if(int e = error(ret); e)
		return e;
	*pid_out = ret;
	return 0;
}

#endif

int Sysdeps<GetPgid>::operator()(pid_t pid, pid_t *pgid) {
	auto ret = syscall(SYS_GETPGID, pid);
	if(int e = error(ret); e)
		return e;
	*pgid = ret;
	return 0;
}

int Sysdeps<SetPgid>::operator()(pid_t pid, pid_t pgid) {
	auto ret = syscall(SYS_SETPGID, pid, pgid);
	if(int e  = error(ret); e)
		return e;
	return 0;
}

int Sysdeps<GetResgid>::operator()(gid_t *rgid, gid_t *egid, gid_t *sgid) {
	auto ret = syscall(SYS_GETRESGID, (uint64_t)rgid, (uint64_t)egid, (uint64_t)sgid);
	if(int e = error(ret); e)
		return e;
	return 0;
}

int Sysdeps<GetResuid>::operator()(uid_t *ruid, uid_t *euid, uid_t *suid) {
	auto ret = syscall(SYS_GETRESUID, (uint64_t)ruid, (uint64_t)euid, (uint64_t)suid);
	if(int e = error(ret); e)
		return e;
	return 0;
}

int Sysdeps<Pipe>::operator()(int *fds, int flags) {
	auto ret = syscall(SYS_PIPE2, (uint64_t)fds, flags);
	if(int e = error(ret); e)
		return e;
	return 0;
}

int Sysdeps<GetEntropy>::operator()(void *buffer, size_t length) {
	auto ret = syscall(SYS_GETRANDOM, (uint64_t)buffer, length);
	if(int e = error(ret); e)
		return e;
	return 0;
}

int Sysdeps<Readlink>::operator()(const char *path, void *buffer, size_t max_size, ssize_t *length) {
	auto ret = syscall(SYS_READLINK, (uint64_t)path, (uint64_t)buffer, max_size);
	if(int e = error(ret); e)
		return e;
	*length = ret;
	return 0;
}

int Sysdeps<Readlinkat>::operator()(int dirfd, const char *path, void *buffer, size_t max_size, ssize_t *length) {
	auto ret = syscall(SYS_READLINKAT, dirfd, (uint64_t)path, (uint64_t)buffer, max_size);
	if(int e = error(ret); e)
		return e;
	*length = ret;
	return 0;
}

int Sysdeps<OpenDir>::operator()(const char *path, int *fd) {
	return sysdep<Open>(path, O_DIRECTORY, 0, fd);
}

int Sysdeps<ReadEntries>::operator()(int handle, void *buffer, size_t max_size, size_t *bytes_read) {
	auto ret = syscall(SYS_GETDENTS64, handle, (uint64_t)buffer, max_size);
	if(int e = error(ret); e)
		return e;
	*bytes_read = ret;
	return 0;
}

int Sysdeps<Statfs>::operator()(const char *path, struct statfs *buf) {
	auto ret = syscall(SYS_STATFS, (uint64_t)path, (uint64_t)buf);
	if(int e = error(ret); e)
		return e;
	return 0;
}

#if !MLIBC_BUILDING_RTLD
#include <string.h>

void _mlibc_restorer() {
	syscall(SYS_SIGRETURN);
	sysdep<LibcPanic>();
}

int Sysdeps<Sigaction>::operator()(int signum, const struct sigaction *act,
		struct sigaction *oldact) {
	struct ksigaction {
		void (*handler)(int);
		unsigned long flags;
		void (*restorer)(void);
		uint32_t mask[2];
	};

	struct ksigaction kernel_act, kernel_oldact;
	if (act) {
		kernel_act.handler = act->sa_handler;
		kernel_act.flags = act->sa_flags;
		kernel_act.restorer = (void (*)(void))_mlibc_restorer;
		memcpy(&kernel_act.mask, &act->sa_mask, sizeof(kernel_act.mask));
	}

	static_assert(sizeof(kernel_act.mask) == 8);

	auto ret = syscall(SYS_SIGPROCACTION, signum, (uint64_t)(act ?
		&kernel_act : nullptr), (uint64_t)(oldact ?
		&kernel_oldact : nullptr), sizeof(kernel_act.mask));
	if (int e = error(ret); e)
		return e;

	if (oldact) {
		oldact->sa_handler = kernel_oldact.handler;
		oldact->sa_flags = kernel_oldact.flags;
		oldact->sa_restorer = kernel_oldact.restorer;
		memcpy(&oldact->sa_mask, &kernel_oldact.mask, sizeof(kernel_oldact.mask));
	}
	return 0;
}
#endif // !MLIBC_BUILDING_RTLD

int Sysdeps<Sigprocmask>::operator()(int how, const sigset_t *set, sigset_t *old) {
	auto ret = syscall(SYS_SIGPROCMASK, how, (uint64_t)set, (uint64_t)old, 8);
	if(int e = error(ret); e)
		return e;
	return 0;
}

int Sysdeps<Uname>::operator()(struct utsname *buf) {
	auto ret = syscall(SYS_UNAME, (uint64_t)buf);
	if(int e = error(ret); e)
		return e;
	return 0;
}

int Sysdeps<Sigaltstack>::operator()(const stack_t *ss, stack_t *oss) {
	auto ret = syscall(SYS_SIGALTSTACK, (uint64_t)ss, (uint64_t)oss);
	if(int e = error(ret); e)
		return e;
	return 0;
}

int Sysdeps<Chmod>::operator()(const char *pathname, mode_t mode) {
	auto ret = syscall(SYS_CHMOD, (uint64_t)pathname, mode);
	if(int e = error(ret); e)
		return e;
	return 0;
}

int Sysdeps<Chdir>::operator()(const char *path) {
	auto ret = syscall(SYS_CHDIR, (uint64_t)path);
	if(int e = error(ret); e)
		return e;
	return 0;
}

int Sysdeps<Fchdir>::operator()(int fd) {
	auto ret = syscall(SYS_FCHDIR, fd);
	if(int e = error(ret); e)
		return e;
	return 0;
}

int Sysdeps<Mkdir>::operator()(const char *path, mode_t mode) {
	auto ret = syscall(SYS_MKDIR, (uint64_t)path, mode);
	if(int e = error(ret); e)
		return e;
	return 0;
}

int Sysdeps<Mkdirat>::operator()(int dirfd, const char *path, mode_t mode) {
	auto ret = syscall(SYS_MKDIRAT, dirfd, (uint64_t)path, mode);
	if(int e = error(ret); e)
		return e;
	return 0;
}

int Sysdeps<Umask>::operator()(mode_t mode, mode_t *old) {
	auto ret = syscall(SYS_UMASK, mode);
	if(int e = error(ret); e)
		return e;
	*old = ret;
	return 0;
}

int Sysdeps<Pread>::operator()(int fd, void *buf, size_t n, off_t off, ssize_t *bytes_read) {
	auto ret = syscall(SYS_PREAD64, fd, (uint64_t)buf, n, off);
	if(int e = error(ret); e)
		return e;
	*bytes_read = ret;
	return 0;
}

int Sysdeps<Sleep>::operator()(time_t *secs, long *nanos) {
	__ensure(*nanos < 1'000'000'000);

	struct timespec req = {
		.tv_sec = *secs,
		.tv_nsec = *nanos
	};
	struct timespec rem = {};

	auto ret = syscall(SYS_NANOSLEEP, 1, 0, (uint64_t)&req, (uint64_t)&rem);
	if (int e = error(ret); e)
		return e;

	*secs = rem.tv_sec;
	*nanos = rem.tv_nsec;
	return 0;
}

gid_t Sysdeps<GetGid>::operator()() {
	auto ret = syscall(SYS_GETGID);
	return ret;
}

gid_t Sysdeps<GetEgid>::operator()() {
	auto ret = syscall(SYS_GETGID);
	return ret;
}

int Sysdeps<Ttyname>::operator()(int fd, char *buf, size_t size) {
	auto ret = syscall(SYS_TTYNAME, fd, (uint64_t)buf, size);
	if(int e = error(ret);e)
		return e;
	return 0;
}

int Sysdeps<GetRlimit>::operator()(int resource, struct rlimit *limit) {
	auto ret = syscall(SYS_PRLIMIT64, 0, resource, 0, (uint64_t)limit);
	if (int e = error(ret); e)
		return e;
	return 0;
}

int Sysdeps<Sysinfo>::operator()(struct sysinfo *info) {
	auto ret = syscall(SYS_SYSINFO, (uint64_t)info);
	if (int e = error(ret); e)
		return e;
	return 0;
}


int Sysdeps<Sysconf>::operator()(int num, long *ret) {
	switch(num) {
		case _SC_OPEN_MAX: {
			struct rlimit ru;
			if(int e = sysdep<GetRlimit>(RLIMIT_NOFILE, &ru); e) {
				return e;
			}
			*ret = (ru.rlim_cur == RLIM_INFINITY) ? -1 : ru.rlim_cur;
			break;
		}
		case _SC_NPROCESSORS_CONF:
		case _SC_NPROCESSORS_ONLN: {
			*ret = syscall(SYS_CPUCOUNT);
			break;
		}
		case _SC_PHYS_PAGES: {
			struct sysinfo info;
			if(int e = sysdep<Sysinfo>(&info); e) {
				return e;
			}
			unsigned unit = (info.mem_unit) ? info.mem_unit : 1;
			*ret = (info.totalram * unit) / 4096;
			break;
		}
		case _SC_CHILD_MAX: {
			struct rlimit ru;
			if(int e = sysdep<GetRlimit>(RLIMIT_NPROC, &ru); e) {
				return e;
			}
			*ret = (ru.rlim_cur == RLIM_INFINITY) ? -1 : ru.rlim_cur;
			break;
		}
		case _SC_LINE_MAX: {
			*ret = -1;
			break;
		}
		default: {
			return EINVAL;
		}
	}

	return 0;
}

int Sysdeps<GetHostname>::operator()(char *buf, size_t bufsize) {
	struct utsname uname_buf;
	if (auto e = sysdep<Uname>(&uname_buf); e)
		return e;

	auto node_len = strlen(uname_buf.nodename);
	if (node_len >= bufsize)
		return ENAMETOOLONG;

	memcpy(buf, uname_buf.nodename, node_len);
	buf[node_len] = '\0';
	return 0;
}

int Sysdeps<Kill>::operator()(pid_t pid, int sig) {
	auto ret = syscall(SYS_KILL, pid, sig);
	if(int e = error(ret); e)
		return e;
	return ret;
}

int Sysdeps<Pause>::operator()() {
	auto ret = syscall(SYS_PAUSE);
	return ret;
}

int Sysdeps<Fsync>::operator()(int fd) {
	(void)fd;
	return 0;
}

int Sysdeps<Listen>::operator()(int fd, int backlog) {
	auto ret = syscall(SYS_LISTEN, fd, backlog);
	if(int e = error(ret); e)
		return e;
	return 0;
}

int Sysdeps<Accept>::operator()(int fd, int *newfd, struct sockaddr *addr_ptr, socklen_t *addr_length, int flags) {
	auto ret = syscall(SYS_ACCEPT, fd, (uint64_t)addr_ptr, (uint64_t)addr_length, flags);
	if(int e = error(ret); e)
		return e;
	*newfd = ret;
	return 0;
}

int Sysdeps<Socket>::operator()(int family, int type, int protocol, int *fd) {
	auto ret = syscall(SYS_SOCKET, family, type, protocol);
	if(int e = error(ret); e)
		return e;
	*fd = ret;
	return 0;
}

int Sysdeps<Connect>::operator()(int fd, const struct sockaddr *addr_ptr, socklen_t addr_length) {
	auto ret = syscall(SYS_CONNECT, fd, (uint64_t)addr_ptr, addr_length);
	if(int e = error(ret); e)
		return e;
	return 0;
}

int Sysdeps<Bind>::operator()(int fd, const struct sockaddr *addr_ptr, socklen_t addr_length) {
	auto ret = syscall(SYS_BIND, fd, (uint64_t)addr_ptr, addr_length);
	if(int e = error(ret); e)
		return e;
	return 0;
}

int Sysdeps<Sendto>::operator()(int fd, const void *buffer, size_t size, int flags, const struct sockaddr *sock_addr, socklen_t addr_length, ssize_t *length) {
	auto ret = syscall(SYS_SENDTO, fd, (uint64_t)buffer, size, flags, (uint64_t)sock_addr, (uint64_t)addr_length);
	if(int e = error(ret); e)
		return e;
	*length = ret;
	return 0;
}

int Sysdeps<Recvfrom>::operator()(int fd, void *buffer, size_t size, int flags, struct sockaddr *sock_addr, socklen_t *addr_length, ssize_t *length) {
	auto ret = syscall(SYS_RECVFROM, fd, (uint64_t)buffer, size, flags, (uint64_t)sock_addr, (uint64_t)addr_length);
	if(int e = error(ret); e)
		return e;
	*length = ret;
	return 0;
}

int Sysdeps<MsgRecv>::operator()(int fd, struct msghdr *hdr, int flags, ssize_t *length) {
	auto ret = syscall(SYS_MSG_RECV, fd, (uint64_t)hdr, flags);
	if(int e = error(ret);e)
		return e;
	*length =ret;
	return 0;
}

int Sysdeps<MsgSend>::operator()(int fd, const struct msghdr *hdr, int flags, ssize_t *length) {
	auto ret = syscall(SYS_MSG_SEND, fd, (uint64_t)hdr, flags);
	if(int e = error(ret);e)
		return e;
	*length =ret;
	return 0;
}

int Sysdeps<Link>::operator()(const char *old_path, const char *new_path) {
	auto ret = syscall(SYS_LINK, (uint64_t)old_path, (uint64_t)new_path);
	if(int e = error(ret); e)
		return e;
	return 0;
}

int Sysdeps<Linkat>::operator()(int olddirfd, const char *old_path, int newdirfd, const char *new_path, int flags) {
	auto ret = syscall(SYS_LINKAT, olddirfd, (uint64_t)old_path, newdirfd, (uint64_t)new_path, flags);
	if(int e = error(ret); e)
		return e;
	return 0;
}

int Sysdeps<Fadvise>::operator()(int fd, off_t offset, off_t length, int advice) {
	(void)fd;
	(void)offset;
	(void)length;
	(void)advice;
	return 0;
}

int Sysdeps<SetGid>::operator()(gid_t new_gid) {
	(void)new_gid;
	return 0;
}

int Sysdeps<SetUid>::operator()(uid_t uid) {
	return 0;
}

int Sysdeps<ThreadSetname>::operator()(void *tcb, const char *name) {
	return 0;
}

int Sysdeps<GetSockopt>::operator()(int fd, int layer, int number, void *__restrict buffer, socklen_t *__restrict size) { 
	auto ret = syscall(SYS_GETSOCKOPT, fd, layer, number, (uint64_t)buffer, (uint64_t)size);
	if(int e = error(ret); e)
		return e;
	return 0;
}

int Sysdeps<SetSockopt>::operator()(int fd, int layer, int number, const void *buffer, socklen_t size) {
	auto ret = syscall(SYS_SETSOCKOPT, fd, layer, number, (uint64_t)buffer, size, 0);
	if (int e = error(ret); e)
		return e;
	return 0;
}

int Sysdeps<Ptsname>::operator()(int fd, char *buffer, size_t length) {
	auto ret = syscall(SYS_PTSNAME, fd, (uint64_t)buffer, length);
	if(int e = error(ret); e)
		return e;
	return 0;
}

int Sysdeps<Unlockpt>::operator()(int fd) {
	return 0;
}

} // namespace mlibc
