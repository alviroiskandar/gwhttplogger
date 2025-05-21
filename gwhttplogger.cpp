#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <cerrno>

#include <unordered_map>
#include <mutex>

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <unistd.h>
#include <sys/syscall.h>

#define likely(x)	__builtin_expect(!!(x), 1)

enum {
	SK_IS_HTTP		= (1ull << 10ull),
	SK_IS_HTTP_KEEPALIVE	= (1ull << 11ull),
	SK_IS_HTTP_PIPELINE	= (1ull << 12ull),

	SK_HTTP_STATE_HDR	= (1ull << 30ull),
	SK_HTTP_STATE_BODY	= (1ull << 31ull),
};

struct addr {
	union {
		struct sockaddr sa;
		struct sockaddr_in in;
		struct sockaddr_in6 in6;
	};
};

struct socket {
	uint64_t	flags;
	int		fd;
	bool		has_dst_addr;
	struct addr	dst_addr;

	char		*recv_buf;
	size_t		recv_len;
	char		*send_buf;
	size_t		send_len;
};

struct ghttpl_ctx {
	std::unordered_map<int, struct socket> sockets;
	std::mutex sockets_lock;
};

static struct ghttpl_ctx *g_ctx = nullptr;
static std::mutex g_init_lock;

static void init_gwhttplogger(void)
{
	if (likely(g_ctx))
		return;

	std::lock_guard<std::mutex> lock(g_init_lock);
	g_ctx = new ghttpl_ctx();
}

static void trace_socket(int fd, int domain, int type)
{
	if (likely(!g_ctx))
		return;

	/* Only trace TCP sockets. */
	if (!(type & SOCK_STREAM))
		return;

	std::lock_guard<std::mutex> lock(g_ctx->sockets_lock);
	auto it = g_ctx->sockets.find(fd);
	if (it != g_ctx->sockets.end()) {
		/* Something went wrong. Maybe the program called dup2()? */
		return;
	}

	struct socket sock;

	sock.fd = fd;
	sock.has_dst_addr = false;
	sock.recv_buf = nullptr;
	sock.recv_len = 0;
	sock.send_buf = nullptr;
	sock.send_len = 0;
	sock.dst_addr.sa.sa_family = domain;
	g_ctx->sockets[fd] = sock;
}

static void trace_connect(int fd, const struct sockaddr *addr)
{
	if (likely(!g_ctx))
		return;

	std::lock_guard<std::mutex> lock(g_ctx->sockets_lock);
	auto it = g_ctx->sockets.find(fd);
	if (it == g_ctx->sockets.end()) {
		/* We do not know this socket. */
		return;
	}

	struct socket &sock = it->second;
	sock.dst_addr.sa = *addr;
	sock.has_dst_addr = true;
}

static void trace_close(int fd)
{
	if (likely(!g_ctx))
		return;

	std::lock_guard<std::mutex> lock(g_ctx->sockets_lock);
	auto it = g_ctx->sockets.find(fd);
	if (it == g_ctx->sockets.end()) {
		/* We do not know this socket. */
		return;
	}

	struct socket &sock = it->second;
	if (sock.recv_buf) {
		free(sock.recv_buf);
		sock.recv_buf = nullptr;
	}
	if (sock.send_buf) {
		free(sock.send_buf);
		sock.send_buf = nullptr;
	}
	g_ctx->sockets.erase(it);
}

int socket(int domain, int type, int protocol)
{
	int ret;

	__asm__ volatile (
		"syscall"
		: "=a" (ret)
		: "a" (__NR_socket), "D" (domain), "S" (type), "d" (protocol)
		: "rcx", "r11", "memory"
	);

	if (ret < 0) {
		errno = -ret;
		ret = -1;
	}

	init_gwhttplogger();
	trace_socket(ret, domain, type);
	return ret;
}

int connect(int fd, const struct sockaddr *addr, socklen_t addrlen)
{
	int ret;

	__asm__ volatile (
		"syscall"
		: "=a" (ret)
		: "a" (__NR_connect), "D" (fd), "S" (addr), "d" (addrlen)
		: "rcx", "r11", "memory"
	);

	if (ret < 0) {
		errno = -ret;
		ret = -1;
	}

	trace_connect(fd, addr);
	return ret;
}

ssize_t recvfrom(int fd, void *buf, size_t len, int flags,
		 struct sockaddr *src_addr, socklen_t *addrlen)
{
	register int __flags __asm__ ("%r10") = flags;
	register struct sockaddr *__src_addr __asm__ ("%r8") = src_addr;
	register socklen_t *__addrlen __asm__ ("%r9") = addrlen;
	ssize_t ret;

	__asm__ volatile (
		"syscall"
		: "=a" (ret)
		: "a" (__NR_recvfrom), "D" (fd), "S" (buf), "d" (len),
		  "r" (__flags), "r" (__src_addr), "r" (__addrlen)
		: "rcx", "r11", "memory"
	);

	if (ret < 0) {
		errno = -ret;
		ret = -1;
	}

	return ret;
}

ssize_t sendto(int fd, const void *buf, size_t len, int flags,
	       const struct sockaddr *dst_addr, socklen_t addrlen)
{
	register int __flags __asm__ ("%r10") = flags;
	register const struct sockaddr *__dst_addr __asm__ ("%r8") = dst_addr;
	register socklen_t __addrlen __asm__ ("%r9") = addrlen;
	ssize_t ret;

	__asm__ volatile (
		"syscall"
		: "=a" (ret)
		: "a" (__NR_sendto), "D" (fd), "S" (buf), "d" (len),
		  "r" (__flags), "r" (__dst_addr), "r" (__addrlen)
		: "rcx", "r11", "memory"
	);

	if (ret < 0) {
		errno = -ret;
		ret = -1;
	}

	return ret;
}

int close(int fd)
{
	int ret;

	trace_close(fd);
	__asm__ volatile (
		"syscall"
		: "=a" (ret)
		: "a" (__NR_close), "D" (fd)
		: "rcx", "r11", "memory"
	);

	if (ret < 0) {
		errno = -ret;
		ret = -1;
	}

	return ret;
}
