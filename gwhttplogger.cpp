#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <cerrno>
#include <cassert>
#include <cstddef>
#include <cctype>
#include <ctime>

#include <unordered_map>
#include <memory>
#include <queue>
#include <mutex>
#include <new>

#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/syscall.h>

#define noinline		__attribute__((__noinline__))
#define likely(x)		__builtin_expect(!!(x), 1)
#define unlikely(x)		__builtin_expect(!!(x), 0)
#define ADDRPORT_STRLEN		(INET6_ADDRSTRLEN + (sizeof(":65535[]") - 1))
#define MAX_HTTP_METHOD_LEN	16
#define pr_debug(fmt, ...)	fprintf(stderr, fmt "\n", ##__VA_ARGS__)

struct ghl_buf {
	size_t	len;
	size_t	cap;
	char	*buf;

	ghl_buf(void):
		len(0),
		cap(0),
		buf(nullptr)
	{
	}

	void reset(void)
	{
		if (this->buf) {
			free(this->buf);
			buf = nullptr;
		}
		this->len = 0;
		this->cap = 0;
	}

	void advance(size_t len)
	{
		if (len > this->len)
			this->len = 0;
		else
			this->len -= len;

		if (this->len > 0)
			memmove(this->buf, this->buf + len, this->len);
	}

	void append(const char *data, size_t data_len)
	{
		if (this->len + data_len > this->cap) {
			size_t new_cap = this->cap == 0 ? 4096 : this->cap * 2;
			char *new_buf;

			while (this->len + data_len > new_cap)
				new_cap *= 2;

			new_buf = static_cast<char *>(realloc(this->buf, new_cap + 1ul));
			if (!new_buf)
				throw std::bad_alloc();

			this->buf = new_buf;
			this->cap = new_cap;
		}

		memcpy(this->buf + this->len, data, data_len);
		this->buf[this->len + data_len] = '\0';
		this->len += data_len;
	}

	~ghl_buf(void)
	{
		this->reset();
	}
};

enum {
	SK_STATE_INIT		= 0,
	SK_STATE_CONNECT	= 1,

	SK_STATE_HTTP_REQ_HDR	= 2,
	SK_STATE_HTTP_REQ_BODY	= 3,
	SK_STATE_HTTP_REQ_DONE	= 4,

	SK_STATE_HTTP_RES_HDR	= 5,
	SK_STATE_HTTP_RES_BODY	= 6,
	SK_STATE_HTTP_RES_DONE	= 7,

	SK_STATE_CLOSE		= 8,
};

struct http_res {
	int		status;
	uint64_t	content_length;
};

struct http_req {
	char		method[MAX_HTTP_METHOD_LEN];
	std::string	uri;
	char		host[512];
	uint64_t	content_length;
	struct http_res	res;
	time_t		time;
};

struct ghl_sock {
	int		state;
	int		fd;
	char		dst_addr[ADDRPORT_STRLEN];
	struct ghl_buf	send_buf;
	struct ghl_buf	recv_buf;

	std::queue<struct http_req> req_queue;
};

struct ghl_ctx {
	std::unordered_map<int, std::unique_ptr<struct ghl_sock>> sockets;
	std::mutex sockets_lock;
	FILE *log_handle;
};

alignas(64) static char __g_ctx[sizeof(ghl_ctx)];
static struct ghl_ctx *g_ctx = nullptr;
static volatile bool g_ghl_stop = false;
static std::mutex g_init_lock;

static void strtolower(char *str)
{
	char *p;
	for (p = str; *p; p++)
		*p = tolower((unsigned char)*p);
}

static int sockaddr_to_str(const struct sockaddr *addr, char buf[ADDRPORT_STRLEN])
{
	uint16_t port;
	size_t len;

	if (addr->sa_family == AF_INET) {
		const struct sockaddr_in *addr4 = reinterpret_cast<const struct sockaddr_in *>(addr);
		port = ntohs(addr4->sin_port);
		inet_ntop(AF_INET, &addr4->sin_addr, buf, INET_ADDRSTRLEN);
		len = strlen(buf);
	} else if (addr->sa_family == AF_INET6) {
		const struct sockaddr_in6 *addr6 = reinterpret_cast<const struct sockaddr_in6 *>(addr);
		port = ntohs(addr6->sin6_port);
		buf[0] = '[';
		inet_ntop(AF_INET6, &addr6->sin6_addr, buf + 1, INET6_ADDRSTRLEN);
		len = strlen(buf);
		buf[len] = ']';
		buf[len + 1] = '\0';
		len++;
	} else {
		return -1;
	}

	if (len + 1 + sizeof(":65535[]") - 1 > ADDRPORT_STRLEN)
		return -1;

	buf[len] = ':';
	snprintf(buf + len + 1, ADDRPORT_STRLEN - len - 1, "%u", port);
	return 0;
}

static void __ghl_kill_sock_trace(struct ghl_ctx *ctx, int fd)
{
	auto it = ctx->sockets.find(fd);
	if (it != ctx->sockets.end())
		ctx->sockets.erase(it);
}

static void __ghl_trace_socket(struct ghl_ctx *ctx, int fd, int domain, int type)
{
	/*
	 * Only trace IPv4 and IPv6.
	 */
	if (domain != AF_INET && domain != AF_INET6)
		return;

	/*
	 * Only trace TCP sockets.
	 */
	if (!(type & SOCK_STREAM))
		return;

	std::unique_ptr<struct ghl_sock> sk = std::make_unique<struct ghl_sock>();
	sk->fd = fd;

	std::lock_guard<std::mutex> lock(ctx->sockets_lock);
	auto it = ctx->sockets.find(fd);
	if (it == ctx->sockets.end())
		ctx->sockets[fd] = std::move(sk);
}

static void __ghl_trace_connect(struct ghl_ctx *ctx, int fd, int ret,
				const struct sockaddr *addr)
{
	struct ghl_sock *sk;

	/*
	 * Successful connect() either returns 0 or -EINPROGRESS.
	 */
	if (ret != 0 && ret != -EINPROGRESS)
		return;

	std::lock_guard<std::mutex> lock(ctx->sockets_lock);
	auto it = ctx->sockets.find(fd);
	if (it == ctx->sockets.end())
		return;

	if (addr->sa_family != AF_INET && addr->sa_family != AF_INET6) {
		/*
		 * Weird, the socket must've been confirmed that it's either
		 * IPv4 or IPv6 in __ghl_trace_socket(), but the address it's
		 * trying to connect to is not {IPv4 or IPv6}.
		 *
		 * Stop tracing this socket, something is wrong.
		 */
		__ghl_kill_sock_trace(ctx, fd);
		return;
	}

	sk = it->second.get();
	if (sk->state != SK_STATE_INIT) {
		/*
		 * What? They call connect() twice on the same socket?
		 *
		 * Stop tracing this socket, something is wrong.
		 */
		__ghl_kill_sock_trace(ctx, fd);
		return;
	}

	sk->state = SK_STATE_CONNECT;
	sockaddr_to_str(addr, sk->dst_addr);
}

static void __ghl_trace_recv(struct ghl_ctx *ctx, int fd, const char *buf,
			     ssize_t len)
{
	std::lock_guard<std::mutex> lock(ctx->sockets_lock);
	struct ghl_sock *sk;

	auto it = ctx->sockets.find(fd);
	if (it == ctx->sockets.end())
		return;

	sk = it->second.get();
	sk->recv_buf.append(buf, len);
}

static void init_http_req(struct http_req *req)
{
	req->method[0] = '\0';
	req->uri.clear();
	req->host[0] = '\0';
	req->content_length = 0;
}

struct http_hdr_parse_st {
	size_t	i;
	char	*start;
	char	*end;
	char	*line;
	char	*next_line;
	char	*key;
	char	*val;
};

static int ghl_parse_http_hdr(struct http_hdr_parse_st *s)
{
	s->i++;

	if (!s->end) {
		s->end = strstr(s->start, "\r\n\r\n");
		if (!s->end)
			return -EAGAIN;

		s->end += 4;
		s->line = s->start;
	} else {
		s->line = s->next_line;
		if (!s->line)
			return -EINVAL;
	}

	s->next_line = strstr(s->line, "\r\n");
	if (!s->next_line)
		return -EINVAL;

	if (s->next_line + 2 == s->end)
		return 0;

	*s->next_line = '\0';
	s->next_line += 2;

	s->key = s->line;
	s->val = strchr(s->line, ':');
	if (!s->val) {
		s->key = s->val = nullptr;
		return 1;
	}

	*s->val = '\0';
	s->val++;
	while (isspace(*s->val))
		s->val++;
	strtolower(s->key);
	return 1;
}

static int ghl_http_hdr_parse_proc(struct http_hdr_parse_st &hst,
				   struct http_req &req)
{
	if (hst.i == 1 && !hst.key) {
		/* Parse method and URI. */
		char *method = hst.line;
		char *uri = strchr(hst.line, ' ');
		char *end;

		if (!uri)
			return -EINVAL;

		*uri = '\0';
		uri++;
		if (*uri != '/')
			return -EINVAL;

		end = strstr(uri, " HTTP/1.");
		if (!end)
			return -EINVAL;
		*end = '\0';

		strncpy(req.method, method, sizeof(req.method) - 1);
		req.method[sizeof(req.method) - 1] = '\0';
		req.uri = std::string(uri);
		return 0;
	}

	if (!hst.key || !hst.val)
		return -EINVAL;

	if (!strcmp(hst.key, "host")) {
		strncpy(req.host, hst.val, sizeof(req.host) - 1);
		req.host[sizeof(req.host) - 1] = '\0';
	} else if (!strncmp(hst.key, "content-length", 14)) {
		char *endptr;
		errno = 0;
		req.content_length = strtoull(hst.val, &endptr, 10);
		if (errno || *endptr != '\0')
			return -EINVAL;
	}

	return 0;
}

static int ghl_handle_state_req_connect(struct ghl_sock *sk)
{
	static const char *http_patterns[] = {
		"GET /",
		"POST /",
		"PUT /",
		"DELETE /",
		"HEAD /",
		"OPTIONS /",
		"PATCH /",
	};
	size_t glen, len = sk->send_buf.len, i, c = sizeof(http_patterns) / sizeof(http_patterns[0]);
	char *buf = sk->send_buf.buf;
	struct http_hdr_parse_st hst;
	bool possible_http = false;
	struct http_req req;

	init_http_req(&req);

	/*
	 * Make sure it's an HTTP request.
	 */
	for (i = 0; i < c; i++) {
		glen = strlen(http_patterns[i]);
		if (strncmp(buf, http_patterns[i], len > glen ? glen : len) == 0) {
			sk->state = SK_STATE_HTTP_REQ_HDR;
			possible_http = true;
			break;
		}
	}

	if (!possible_http)
		return -EINVAL;

	memset(&hst, 0, sizeof(hst));
	hst.start = buf;
	while (1) {
		int ret = ghl_parse_http_hdr(&hst);
		if (ret == -EAGAIN) {
			/*
			 * We don't have a complete HTTP request header yet.
			 * Wait for more data.
			 */
			sk->state = SK_STATE_HTTP_REQ_HDR;
			return ret;
		}

		if (ret < 0)
			return ret;
		if (!ret)
			break;

		if (ghl_http_hdr_parse_proc(hst, req) < 0)
			return -EINVAL;
	}

	req.time = time(nullptr);
	sk->state = SK_STATE_HTTP_REQ_BODY;
	sk->req_queue.push(req);
	sk->send_buf.advance(hst.end - sk->send_buf.buf);

	if (!req.content_length)
		sk->state = SK_STATE_HTTP_REQ_DONE;
	else
		sk->state = SK_STATE_HTTP_REQ_BODY;

	return 0;
}

static int ghl_handle_state_req_body(struct ghl_sock *sk)
{
	struct http_req *req = &sk->req_queue.back();
	size_t sub_len = req->content_length;

	if (sub_len <= sk->send_buf.len) {
		/* Either we have the whole body or more... */
		sk->send_buf.advance(sub_len);
		sk->state = SK_STATE_HTTP_REQ_DONE;
		req->content_length = 0;
		return 0;
	} else {
		/* We don't have the whole body yet. */
		sk->state = SK_STATE_HTTP_REQ_BODY;
		return -EAGAIN;
	}
}

static void __ghl_trace_send(struct ghl_ctx *ctx, int fd, const char *buf,
			     ssize_t len)
{
	std::lock_guard<std::mutex> lock(ctx->sockets_lock);
	struct ghl_sock *sk;
	int ret = -EINVAL;

	auto it = ctx->sockets.find(fd);
	if (it == ctx->sockets.end())
		return;

	sk = it->second.get();
	sk->send_buf.append(buf, len);

repeat:
	switch (sk->state) {
	case SK_STATE_CONNECT:
	case SK_STATE_HTTP_REQ_HDR:
	case SK_STATE_HTTP_REQ_DONE:
		ret = ghl_handle_state_req_connect(sk);
		break;
	case SK_STATE_HTTP_REQ_BODY:
		ret = ghl_handle_state_req_body(sk);
		break;
	case SK_STATE_INIT:
	default:
		/* Shouldn't happen, but just in case... */
		goto kill;
	}
	if (ret == -EAGAIN)
		return;
	if (ret < 0)
		goto kill;
	if (sk->send_buf.len > 0)
		goto repeat;

	return;
kill:
	__ghl_kill_sock_trace(ctx, fd);
}

static void __ghl_trace_close(struct ghl_ctx *ctx, int fd)
{
	std::lock_guard<std::mutex> lock(ctx->sockets_lock);
	auto it = ctx->sockets.find(fd);
	if (it != ctx->sockets.end())
		__ghl_kill_sock_trace(ctx, fd);
}

noinline
static void ghl_stop(void)
{
	struct ghl_ctx *c = g_ctx;

	g_ghl_stop = true;
	g_ctx = nullptr;

	if (c) {
		if (c->log_handle) {
			fclose(c->log_handle);
			c->log_handle = nullptr;
		}
		c->~ghl_ctx();
	}
}

noinline
static void ghl_init(void)
{
	try {
		std::lock_guard<std::mutex> lock(g_init_lock);
		char *log_file;

		if (g_ctx)
			return;

		log_file = getenv("GWLOG_PATH");
		if (!log_file) {
			ghl_stop();
			return;
		}

		g_ctx = new(__g_ctx) ghl_ctx();
		g_ctx->log_handle = fopen(log_file, "a");
		if (!g_ctx->log_handle) {
			ghl_stop();
			return;
		}

		setvbuf(g_ctx->log_handle, nullptr, _IOLBF, 0);
	} catch (...) {
		ghl_stop();
	}
}

noinline
static void ghl_trace_socket(int fd, int domain, int type) noexcept
{
	if (!g_ctx || g_ghl_stop)
		return;

	try {
		__ghl_trace_socket(g_ctx, fd, domain, type);
	} catch (...) {
		ghl_stop();
	}
}

noinline
static void ghl_trace_connect(int fd, int ret, const struct sockaddr *addr) noexcept
{
	if (!g_ctx || g_ghl_stop)
		return;

	try {
		__ghl_trace_connect(g_ctx, fd, ret, addr);
	} catch (...) {
		ghl_stop();
	}
}

noinline
static void ghl_trace_recv(int fd, const char *buf, ssize_t len) noexcept
{
	if (!g_ctx || g_ghl_stop)
		return;

	try {
		__ghl_trace_recv(g_ctx, fd, buf, len);
	} catch (...) {
		ghl_stop();
	}
}

noinline
static void ghl_trace_send(int fd, const char *buf, ssize_t len) noexcept
{
	if (!g_ctx || g_ghl_stop)
		return;

	try {
		__ghl_trace_send(g_ctx, fd, buf, len);
	} catch (...) {
		ghl_stop();
	}
}

noinline
static void ghl_trace_close(int fd) noexcept
{
	if (!g_ctx || g_ghl_stop)
		return;

	try {
		__ghl_trace_close(g_ctx, fd);
	} catch (...) {
		ghl_stop();
	}
}

extern "C" {

int socket(int domain, int type, int protocol)
{
	int ret;

	__asm__ volatile (
		"syscall"
		: "=a" (ret)
		: "a" (__NR_socket), "D" (domain), "S" (type), "d" (protocol)
		: "rcx", "r11", "memory"
	);

	if (likely(ret >= 0)) {
		if (unlikely(!g_ctx))
			ghl_init();
		ghl_trace_socket(ret, domain, type);
	} else {
		errno = -ret;
		ret = -1;
	}

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

	ghl_trace_connect(fd, ret, addr);

	if (ret < 0) {
		errno = -ret;
		ret = -1;
	}

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

	if (likely(ret >= 0)) {
		ghl_trace_recv(fd, static_cast<const char *>(buf), ret);
	} else {
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

	if (likely(ret >= 0)) {
		ghl_trace_send(fd, static_cast<const char *>(buf), ret);
	} else {
		errno = -ret;
		ret = -1;
	}

	return ret;
}

ssize_t recv(int fd, void *buf, size_t len, int flags)
{
	return recvfrom(fd, buf, len, flags, nullptr, nullptr);
}

ssize_t send(int fd, const void *buf, size_t len, int flags)
{
	return sendto(fd, buf, len, flags, nullptr, 0);
}

ssize_t read(int fd, void *buf, size_t len)
{
	ssize_t ret;

	__asm__ volatile (
		"syscall"
		: "=a" (ret)
		: "a" (__NR_read), "D" (fd), "S" (buf), "d" (len)
		: "rcx", "r11", "memory"
	);

	if (likely(ret >= 0)) {
		ghl_trace_recv(fd, static_cast<const char *>(buf), ret);
	} else {
		errno = -ret;
		ret = -1;
	}

	return ret;
}

ssize_t write(int fd, const void *buf, size_t len)
{
	ssize_t ret;

	__asm__ volatile (
		"syscall"
		: "=a" (ret)
		: "a" (__NR_write), "D" (fd), "S" (buf), "d" (len)
		: "rcx", "r11", "memory"
	);

	if (likely(ret >= 0)) {
		ghl_trace_send(fd, static_cast<const char *>(buf), len);
	} else {
		errno = -ret;
		ret = -1;
	}

	return ret;
}

int close(int fd)
{
	int ret;

	ghl_trace_close(fd);
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

} /* extern "C" */
