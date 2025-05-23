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

#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/syscall.h>

#include <unordered_map>
#include <memory>
#include <queue>
#include <mutex>
#include <new>

#define noinline		__attribute__((__noinline__))
#define likely(x)		__builtin_expect(!!(x), 1)
#define unlikely(x)		__builtin_expect(!!(x), 0)
#define ADDRPORT_STRLEN		(INET6_ADDRSTRLEN + (sizeof(":65535[]") - 1))
#define MAX_HTTP_METHOD_LEN	16

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

struct ghl_addr {
	union {
		struct sockaddr sa;
		struct sockaddr_in in;
		struct sockaddr_in6 in6;
	};
};

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
};

struct ghl_sock {
	uint8_t		state;
	int		fd;
	struct ghl_buf	send_buf;
	struct ghl_buf	recv_buf;
	struct ghl_addr addr;

	std::queue<struct http_req> req_queue;

	ghl_sock(void):
		state(SK_STATE_INIT),
		fd(-1)
	{
		memset(&addr, 0, sizeof(addr));
	}
};

struct ghl_ctx {
	std::unordered_map<int, std::unique_ptr<struct ghl_sock>> sockets;
	std::mutex sockets_lock;
	FILE *log_handle;
};

alignas(64) static char __ghl_ctx_alloc[sizeof(ghl_ctx)];
static struct ghl_ctx *g_ctx = nullptr;
static volatile bool g_ghl_stop = false;
static std::mutex g_init_lock;

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
static void ghl_init(void) noexcept
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

		g_ctx = new(__ghl_ctx_alloc) ghl_ctx();
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

static void __ghl_kill_sock_trace(struct ghl_ctx *ctx, int fd)
{
	auto it = ctx->sockets.find(fd);
	if (it != ctx->sockets.end())
		ctx->sockets.erase(it);
}

static void ghl_kill_sock_trace(struct ghl_ctx *ctx, int fd)
{
	std::lock_guard<std::mutex> lock(ctx->sockets_lock);
	__ghl_kill_sock_trace(ctx, fd);
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

	std::unique_ptr<struct ghl_sock> sk;
	sk = std::make_unique<struct ghl_sock>();
	sk->fd = fd;

	std::lock_guard<std::mutex> lock(ctx->sockets_lock);
	auto it = ctx->sockets.find(fd);
	if (it == ctx->sockets.end())
		ctx->sockets[fd] = std::move(sk);
}

static void __ghl_trace_connect(struct ghl_ctx *ctx, int fd, const struct sockaddr *addr)
{
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

	struct ghl_sock *sk = it->second.get();
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
	if (addr->sa_family == AF_INET)
		sk->addr.in = *reinterpret_cast<const struct sockaddr_in *>(addr);
	else
		sk->addr.in6 = *reinterpret_cast<const struct sockaddr_in6 *>(addr);
}

static void strtolower(char *str)
{
	char *p;
	for (p = str; *p; p++)
		*p = tolower((unsigned char)*p);
}

static int ghl_parse_http_res_hdr_line(char *line, struct http_res *res)
{
	char *key, *val, *val_end;

	key = line;
	val = strchr(line, ':');
	if (!val)
		return -EINVAL;

	*val = '\0';
	val += 1;
	while (*val && isspace((unsigned char)*val))
		val++;

	val_end = strchr(val, '\r');
	if (val_end)
		*val_end = '\0';

	strtolower(key);
	if (strcmp(key, "content-length") == 0)
		res->content_length = strtoull(val, nullptr, 10);

	return 0;
}

static int __ghl_parse_http_res_hdr(struct ghl_sock *sk, struct http_res *res)
{
	char *buf = sk->recv_buf.buf;
	char *line, *next_line;
	size_t i = 0;

	/*
	 * Check if we have a complete HTTP response header.
	 */
	char *end = strstr(buf, "\r\n\r\n");

	if (!end) {
		/*
		 * We don't have a complete HTTP response header yet.
		 * Wait for more data.
		 */
		return -EAGAIN;
	}

	/*
	 * We have a complete HTTP response header.
	 * Parse the HTTP response header.
	 */
	line = buf;
	while (1) {
		next_line = strstr(line, "\r\n");
		if (!next_line)
			break;

		*next_line = '\0';

		if (i > 0) {
			if (ghl_parse_http_res_hdr_line(line, res) < 0)
				return -EINVAL;
		} else {
			char *status = strchr(line, ' ');
			if (!status)
				return -EINVAL;

			*status = '\0';
			status += 1;
			res->status = atoi(status);
			if (res->status < 100 || res->status > 599)
				return -EINVAL;
		}

		line = next_line + 2;
		if (line >= end)
			break;

		i++;
	}

	sk->recv_buf.advance(end - buf + 4);

	if (sk->recv_buf.len < res->content_length)
		return -EAGAIN;

	return 0;
}

static int ghl_parse_http_res_hdr(struct ghl_sock *sk)
{
	struct http_res res;

	if (sk->state != SK_STATE_HTTP_REQ_DONE)
		return -EINVAL;

	memset(&res, 0, sizeof(res));
	int ret = __ghl_parse_http_res_hdr(sk, &res);
	if (ret < 0)
		return ret;

	sk->req_queue.front().res = res;
	if (res.content_length > 0)
		sk->state = SK_STATE_HTTP_RES_BODY;
	else
		sk->state = SK_STATE_HTTP_RES_DONE;

	return 0;
}

static int ghl_parse_http_res_body(struct ghl_sock *sk)
{
	size_t len = sk->recv_buf.len;
	struct http_res *res;

	if (sk->req_queue.empty())
		return -EINVAL;

	res = &sk->req_queue.front().res;
	if (res->content_length < len)
		len = res->content_length;

	sk->recv_buf.advance(len);
	res->content_length -= len;
	if (!res->content_length)
		sk->state = SK_STATE_HTTP_RES_DONE;
	return 0;
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

static void ghl_save_log(struct ghl_ctx *ctx, struct ghl_sock *sk, struct http_req *req)
{
	char addr_buf[ADDRPORT_STRLEN];
	char time_buf[64];
	time_t now = time(nullptr);
	struct tm tm;

	localtime_r(&now, &tm);
	strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", &tm);
	sockaddr_to_str(&sk->addr.sa, addr_buf);
	fprintf(ctx->log_handle, "%s: DST=%s; HOST=%s; REQ=\"%s %s\"; RES_CODE=%d;\n",
		time_buf, addr_buf, req->host, req->method, req->uri.c_str(), req->res.status);
}

static int ghl_handle_http_res_done(struct ghl_ctx *ctx, struct ghl_sock *sk)
{
	if (sk->state != SK_STATE_HTTP_RES_DONE)
		return -EINVAL;

	ghl_save_log(ctx, sk, &sk->req_queue.front());
	sk->req_queue.pop();
	if (sk->req_queue.empty())
		sk->state = SK_STATE_HTTP_REQ_DONE;
	else
		sk->state = SK_STATE_HTTP_RES_HDR;

	return 0;
}

static void __ghl_trace_recv(struct ghl_ctx *ctx, int fd, const char *buf, ssize_t len)
{
	std::lock_guard<std::mutex> lock(ctx->sockets_lock);
	int ret;

	auto it = ctx->sockets.find(fd);
	if (it == ctx->sockets.end())
		return;

	struct ghl_sock *sk = it->second.get();
	sk->recv_buf.append(buf, len);

	if (sk->state <= SK_STATE_CONNECT) {
		/*
		 * Apparently, this is not an HTTP connection because we receive
		 * the data before the HTTP request is sent.
		 */
		__ghl_kill_sock_trace(ctx, fd);
		return;
	}

repeat:
	switch (sk->state) {
	case SK_STATE_HTTP_REQ_DONE:
	case SK_STATE_HTTP_RES_HDR:
		ret = ghl_parse_http_res_hdr(sk);
		break;
	case SK_STATE_HTTP_RES_BODY:
		ret = ghl_parse_http_res_body(sk);
		break;
	default:
		ret = -EINVAL;
		break;
	}

	if (ret && ret != -EAGAIN) {
		/*
		 * We have an error, stop tracing this socket.
		 */
		__ghl_kill_sock_trace(ctx, fd);
		return;
	}

	if (ret == -EAGAIN)
		return;

	if (sk->state == SK_STATE_HTTP_RES_DONE) {
		ret = ghl_handle_http_res_done(ctx, sk);
		if (ret < 0) {
			__ghl_kill_sock_trace(ctx, fd);
			return;
		}
	}

	if (sk->recv_buf.len > 0)
		goto repeat;
}

static int ghl_parse_http_req_hdr_line(char *line, struct http_req *req)
{
	char *key, *val, *val_end;

	key = line;
	val = strchr(line, ':');
	if (!val)
		return -EINVAL;

	*val = '\0';
	val += 1;
	while (*val && isspace((unsigned char)*val))
		val++;

	val_end = strchr(val, '\r');
	if (val_end)
		*val_end = '\0';

	strtolower(key);
	if (strcmp(key, "host") == 0) {
		strncpy(req->host, val, sizeof(req->host));
		req->host[sizeof(req->host) - 1] = '\0';
	} else if (strcmp(key, "content-length") == 0) {
		req->content_length = strtoull(val, nullptr, 10);
	}

	return 0;
}


static int parse_method_and_uri(char *line, struct http_req *req)
{
	char *start, *end;

	start = strchr(line, ' ');
	if (!start)
		return -EINVAL;

	end = strchr(start + 1, ' ');
	if (!end)
		return -EINVAL;

	*end = '\0';
	*start = '\0';

	strncpy(req->method, line, sizeof(req->method));
	req->method[sizeof(req->method) - 1] = '\0';

	req->uri = std::string(start + 1);
	if (req->uri.empty())
		return -EINVAL;

	return 0;
}

static int __ghl_parse_http_req_hdr(struct ghl_sock *sk, struct http_req *req)
{
	char *buf = sk->send_buf.buf;
	char *line, *next_line;
	size_t i = 0;

	/*
	 * Check if we have a complete HTTP request header.
	 */
	char *end = strstr(buf, "\r\n\r\n");

	if (!end) {
		/*
		 * We don't have a complete HTTP request header yet.
		 * Wait for more data.
		 */
		return -EAGAIN;
	}

	/*
	 * We have a complete HTTP request header.
	 * Parse the HTTP request header.
	 */
	line = buf;
	while (1) {
		next_line = strstr(line, "\r\n");
		if (!next_line)
			break;

		*next_line = '\0';

		if (i > 0) {
			if (ghl_parse_http_req_hdr_line(line, req) < 0)
				return -EINVAL;
		} else {
			if (parse_method_and_uri(line, req) < 0)
				return -EINVAL;
		}

		line = next_line + 2;
		if (line >= end)
			break;

		i++;
	}

	sk->req_queue.push(*req);
	if (req->content_length > 0)
		sk->state = SK_STATE_HTTP_REQ_BODY;
	else
		sk->state = SK_STATE_HTTP_REQ_DONE;

	sk->send_buf.advance(end - buf + 4);

	if (sk->send_buf.len < req->content_length)
		return -EAGAIN;

	return 0;
}

static void init_http_req(struct http_req *req)
{
	req->method[0] = '\0';
	req->uri.clear();
	req->host[0] = '\0';
	req->content_length = 0;
}

static int ghl_parse_http_req_hdr(struct ghl_sock *sk)
{
	static const char *http_patterns[] = {
		"GET /",
		"POST /",
		"PUT /",
		"DELETE /",
		"HEAD /",
		"OPTIONS /",
		"PATCH /",
		"CONNECT /",
	};
	size_t glen, len = sk->send_buf.len, i, c = sizeof(http_patterns) / sizeof(http_patterns[0]);
	char *buf = sk->send_buf.buf;
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

	return __ghl_parse_http_req_hdr(sk, &req);
}

static int ghl_parse_http_req_body(struct ghl_sock *sk)
{
	size_t len = sk->send_buf.len;
	struct http_req *req;

	if (sk->req_queue.empty())
		return -EINVAL;

	req = &sk->req_queue.front();
	if (req->content_length < len)
		len = req->content_length;

	sk->send_buf.advance(len);
	req->content_length -= len;
	if (!req->content_length)
		sk->state = SK_STATE_HTTP_REQ_DONE;
	return 0;
}

static void __ghl_trace_send(struct ghl_ctx *ctx, int fd, const char *buf, ssize_t len)
{
	std::lock_guard<std::mutex> lock(ctx->sockets_lock);
	int ret;

	auto it = ctx->sockets.find(fd);
	if (it == ctx->sockets.end())
		return;

	struct ghl_sock *sk = it->second.get();
	sk->send_buf.append(buf, len);

repeat:
	switch (sk->state) {
	case SK_STATE_CONNECT:
	case SK_STATE_HTTP_REQ_HDR:
	case SK_STATE_HTTP_REQ_DONE:
		ret = ghl_parse_http_req_hdr(sk);
		break;
	case SK_STATE_HTTP_REQ_BODY:
		ret = ghl_parse_http_req_body(sk);
		break;
	default:
		ret = -EINVAL;
		break;
	}

	if (ret && ret != -EAGAIN) {
		__ghl_kill_sock_trace(ctx, fd);
		return;
	}

	if (ret == -EAGAIN)
		return;

	if (sk->send_buf.len > 0)
		goto repeat;
}

static void __ghl_trace_close(struct ghl_ctx *ctx, int fd)
{
	std::lock_guard<std::mutex> lock(ctx->sockets_lock);
	__ghl_kill_sock_trace(ctx, fd);
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
static void ghl_trace_connect(int fd, const struct sockaddr *addr) noexcept
{
	if (!g_ctx || g_ghl_stop)
		return;

	try {
		__ghl_trace_connect(g_ctx, fd, addr);
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

	if (ret < 0) {
		errno = -ret;
		ret = -1;
	} else {
		if (unlikely(!g_ctx))
			ghl_init();
		ghl_trace_socket(ret, domain, type);
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

	if (ret < 0) {
		errno = -ret;
		ret = -1;
	}

	ghl_trace_connect(fd, addr);
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
	} else {
		ghl_trace_recv(fd, static_cast<const char *>(buf), ret);
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
	} else {
		ghl_trace_send(fd, static_cast<const char *>(buf), len);
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

ssize_t read(int fd, void *buf, size_t len, int flags)
{
	__asm__ volatile (
		"syscall"
		: "=a" (len)
		: "a" (__NR_read), "D" (fd), "S" (buf), "d" (len)
		: "rcx", "r11", "memory"
	);

	if (len < 0) {
		errno = -len;
		len = -1;
	} else {
		ghl_trace_recv(fd, static_cast<const char *>(buf), len);
	}

	return len;
}

ssize_t write(int fd, const void *buf, size_t len, int flags)
{
	__asm__ volatile (
		"syscall"
		: "=a" (len)
		: "a" (__NR_write), "D" (fd), "S" (buf), "d" (len)
		: "rcx", "r11", "memory"
	);

	if (len < 0) {
		errno = -len;
		len = -1;
	} else {
		ghl_trace_send(fd, static_cast<const char *>(buf), len);
	}

	return len;
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
