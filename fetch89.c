/*
 * fetch89 - fetch a URL over HTTP/HTTPS. C89 + POSIX sockets (+ OpenSSL).
 *
 * Build with HTTPS:
 *   cc -std=c89 -pedantic -D_POSIX_C_SOURCE=200112L -o fetch89 fetch89.c -lssl -lcrypto
 *
 * Build without any SSL dependency (HTTP only):
 *   cc -std=c89 -pedantic -D_POSIX_C_SOURCE=200112L -DFETCH89_NO_SSL -o fetch89 fetch89.c
 *
 * Environment (command line options win over environment):
 *   FETCH89_PORT           override port of the requested URL
 *   FETCH89_SCHEME         default scheme for URLs without one: http | https
 *   FETCH89_OUTPUT         default output file (same as -o)
 *   FETCH89_VERBOSE        1 = same as -v
 *   FETCH89_USER_AGENT     User-Agent header (default fetch89/1.0)
 *   FETCH89_HEADER         one extra header line, e.g. "Authorization: Bearer x"
 *   FETCH89_CONTENT_TYPE   Content-Type for --post/--put
 *   FETCH89_TIMEOUT        socket timeout in seconds (default 30, 0 = none)
 *   FETCH89_MAX_REDIRECTS  max redirects to follow (default 5, 0 = none)
 *   FETCH89_INSECURE       1 = do not verify TLS certificates   (SSL build)
 *   FETCH89_CA_FILE        CA bundle file                       (SSL build)
 *   FETCH89_CA_DIR         CA directory                         (SSL build)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netdb.h>
#ifndef FETCH89_NO_SSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif

struct url {
    int tls;
    char host[256];
    char port[8];
    char path[2048];
};

struct conn {
    int fd;
#ifndef FETCH89_NO_SSL
    SSL_CTX *ctx;
    SSL *ssl;
#endif
};

struct config {
    const char *port;
    const char *scheme;
    const char *output;
    const char *user_agent;
    const char *header;
    const char *content_type;
    const char *ca_file;
    const char *ca_dir;
    int verbose;
    int timeout;
    int max_redirects;
    int insecure;
};

static struct config cfg;

static const char *env(const char *name)
{
    const char *v = getenv(name);
    return (v != NULL && *v != '\0') ? v : NULL;
}

static int env_int(const char *name, int def)
{
    const char *v = env(name);
    return v ? atoi(v) : def;
}

static int lower(int c)
{
    return (c >= 'A' && c <= 'Z') ? c + ('a' - 'A') : c;
}

static void load_env(void)
{
    cfg.port = env("FETCH89_PORT");
    cfg.scheme = env("FETCH89_SCHEME");
    cfg.output = env("FETCH89_OUTPUT");
    cfg.user_agent = env("FETCH89_USER_AGENT");
    cfg.header = env("FETCH89_HEADER");
    cfg.content_type = env("FETCH89_CONTENT_TYPE");
    cfg.ca_file = env("FETCH89_CA_FILE");
    cfg.ca_dir = env("FETCH89_CA_DIR");
    cfg.verbose = env_int("FETCH89_VERBOSE", 0);
    cfg.timeout = env_int("FETCH89_TIMEOUT", 30);
    cfg.max_redirects = env_int("FETCH89_MAX_REDIRECTS", 5);
    cfg.insecure = env_int("FETCH89_INSECURE", 0);

    if (cfg.user_agent == NULL)
        cfg.user_agent = "fetch89/1.0";
    if (cfg.content_type == NULL)
        cfg.content_type = "application/x-www-form-urlencoded";
    if (cfg.header != NULL &&
        (strchr(cfg.header, '\r') != NULL || strchr(cfg.header, '\n') != NULL)) {
        fprintf(stderr, "fetch89: FETCH89_HEADER must be a single line, ignored\n");
        cfg.header = NULL;
    }
    if (cfg.user_agent != NULL &&
        (strchr(cfg.user_agent, '\r') != NULL || strchr(cfg.user_agent, '\n') != NULL))
        cfg.user_agent = "fetch89/1.0";
    if (cfg.content_type != NULL &&
        (strchr(cfg.content_type, '\r') != NULL || strchr(cfg.content_type, '\n') != NULL))
        cfg.content_type = "application/x-www-form-urlencoded";
}

static void usage(FILE *f)
{
    fprintf(f,
        "usage: fetch89 [options] url\n"
        "  -o FILE       write body to FILE instead of stdout\n"
        "  --post DATA   send POST with DATA as body\n"
        "  --put DATA    send PUT with DATA as body\n"
        "  -v            verbose: print request/response headers to stderr\n"
        "  -h            this help\n"
        "url without a scheme defaults to https:// (http:// if built without SSL)\n"
        "env: FETCH89_PORT FETCH89_SCHEME FETCH89_OUTPUT FETCH89_VERBOSE\n"
        "     FETCH89_USER_AGENT FETCH89_HEADER FETCH89_CONTENT_TYPE\n"
        "     FETCH89_TIMEOUT FETCH89_MAX_REDIRECTS\n"
#ifndef FETCH89_NO_SSL
        "     FETCH89_INSECURE FETCH89_CA_FILE FETCH89_CA_DIR\n"
#endif
        );
}

static int parse_url(const char *s, struct url *u)
{
    size_t n;
    const char *p;

#ifdef FETCH89_NO_SSL
    u->tls = 0;
#else
    u->tls = !(cfg.scheme != NULL && strcmp(cfg.scheme, "http") == 0);
#endif
    if (strncmp(s, "http://", 7) == 0) {
        u->tls = 0;
        s += 7;
    } else if (strncmp(s, "https://", 8) == 0) {
#ifdef FETCH89_NO_SSL
        fprintf(stderr, "fetch89: built without SSL, https not supported\n");
        return -1;
#else
        u->tls = 1;
        s += 8;
#endif
    }
    strcpy(u->port, u->tls ? "443" : "80");

    p = s;
    while (*p && *p != ':' && *p != '/')
        p++;
    n = (size_t)(p - s);
    if (n == 0 || n >= sizeof(u->host))
        return -1;
    memcpy(u->host, s, n);
    u->host[n] = '\0';

    if (*p == ':') {
        s = ++p;
        while (*p && *p != '/')
            p++;
        n = (size_t)(p - s);
        if (n == 0 || n >= sizeof(u->port))
            return -1;
        memcpy(u->port, s, n);
        u->port[n] = '\0';
    }

    if (*p == '\0') {
        strcpy(u->path, "/");
    } else {
        if (strlen(p) >= sizeof(u->path))
            return -1;
        strcpy(u->path, p);
    }
    return 0;
}

static int open_tcp(const char *host, const char *port)
{
    struct addrinfo hints, *res, *p;
    struct timeval tv;
    int fd = -1;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, port, &hints, &res) != 0)
        return -1;
    for (p = res; p != NULL; p = p->ai_next) {
        fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0)
            continue;
        if (cfg.timeout > 0) {
            tv.tv_sec = cfg.timeout;
            tv.tv_usec = 0;
            setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        }
        if (connect(fd, p->ai_addr, p->ai_addrlen) == 0)
            break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

static void conn_close(struct conn *c)
{
#ifndef FETCH89_NO_SSL
    if (c->ssl) {
        SSL_shutdown(c->ssl);
        SSL_free(c->ssl);
    }
    if (c->ctx)
        SSL_CTX_free(c->ctx);
    c->ssl = NULL;
    c->ctx = NULL;
#endif
    if (c->fd >= 0)
        close(c->fd);
    c->fd = -1;
}

static int conn_open(struct conn *c, const struct url *u)
{
    c->fd = -1;
#ifndef FETCH89_NO_SSL
    c->ctx = NULL;
    c->ssl = NULL;
#endif

    c->fd = open_tcp(u->host, u->port);
    if (c->fd < 0) {
        fprintf(stderr, "fetch89: cannot connect to %s:%s\n", u->host, u->port);
        return -1;
    }
    if (!u->tls)
        return 0;

#ifndef FETCH89_NO_SSL
    c->ctx = SSL_CTX_new(TLS_client_method());
    if (c->ctx == NULL) {
        fprintf(stderr, "fetch89: SSL_CTX_new failed\n");
        conn_close(c);
        return -1;
    }
    if (cfg.ca_file != NULL || cfg.ca_dir != NULL) {
        if (SSL_CTX_load_verify_locations(c->ctx, cfg.ca_file, cfg.ca_dir) != 1) {
            fprintf(stderr, "fetch89: cannot load CA file/dir\n");
            conn_close(c);
            return -1;
        }
    } else {
        SSL_CTX_set_default_verify_paths(c->ctx);
    }
    SSL_CTX_set_verify(c->ctx, cfg.insecure ? SSL_VERIFY_NONE : SSL_VERIFY_PEER, NULL);
    c->ssl = SSL_new(c->ctx);
    if (c->ssl == NULL) {
        conn_close(c);
        return -1;
    }
    SSL_set_fd(c->ssl, c->fd);
    SSL_set_tlsext_host_name(c->ssl, u->host);
    if (!cfg.insecure)
        SSL_set1_host(c->ssl, u->host);
    if (SSL_connect(c->ssl) <= 0) {
        fprintf(stderr, "fetch89: TLS handshake failed\n");
        ERR_print_errors_fp(stderr);
        conn_close(c);
        return -1;
    }
#endif
    return 0;
}

static int conn_write(struct conn *c, const char *buf, size_t len)
{
    int r;
    while (len > 0) {
#ifndef FETCH89_NO_SSL
        if (c->ssl)
            r = SSL_write(c->ssl, buf, (int)len);
        else
#endif
            r = (int)write(c->fd, buf, len);
        if (r <= 0)
            return -1;
        buf += r;
        len -= (size_t)r;
    }
    return 0;
}

static int conn_read(struct conn *c, char *buf, size_t len)
{
#ifndef FETCH89_NO_SSL
    if (c->ssl)
        return SSL_read(c->ssl, buf, (int)len);
#endif
    return (int)read(c->fd, buf, len);
}

static int read_all(struct conn *c, char **out, size_t *outlen)
{
    size_t cap = 65536, n = 0;
    char *b = (char *)malloc(cap);
    char *nb;
    int r;

    if (b == NULL)
        return -1;
    for (;;) {
        if (cap - n < 4097) {
            cap *= 2;
            nb = (char *)realloc(b, cap);
            if (nb == NULL) {
                free(b);
                return -1;
            }
            b = nb;
        }
        r = conn_read(c, b + n, cap - n - 1);
        if (r <= 0)
            break;
        n += (size_t)r;
    }
    b[n] = '\0';
    *out = b;
    *outlen = n;
    return 0;
}

static int get_header(const char *hdr, const char *name, char *out, size_t outsz)
{
    const char *p = hdr, *e, *q;
    size_t nl = strlen(name), i, n;

    while (*p) {
        e = strstr(p, "\r\n");
        if (e == NULL)
            e = p + strlen(p);
        if ((size_t)(e - p) > nl && p[nl] == ':') {
            for (i = 0; i < nl; i++)
                if (lower((unsigned char)p[i]) != lower((unsigned char)name[i]))
                    break;
            if (i == nl) {
                q = p + nl + 1;
                while (*q == ' ' || *q == '\t')
                    q++;
                n = (size_t)(e - q);
                if (n >= outsz)
                    n = outsz - 1;
                memcpy(out, q, n);
                out[n] = '\0';
                return 1;
            }
        }
        if (*e == '\0')
            break;
        p = e + 2;
    }
    return 0;
}

/*
 * One request. On success *resp holds the malloc'd response with the
 * header/body separator replaced by NUL: headers start at *resp,
 * body starts at *body.
 */
static int do_request(const struct url *u, const char *method, const char *data,
                      char **resp, char **body, size_t *resplen)
{
    struct conn c;
    char *req, *sep;
    size_t datalen = data ? strlen(data) : 0;
    size_t reqcap = strlen(u->path) + strlen(u->host) + strlen(cfg.user_agent)
                    + strlen(cfg.content_type) + (cfg.header ? strlen(cfg.header) : 0)
                    + 512;
    int hdrlen;

    req = (char *)malloc(reqcap);
    if (req == NULL)
        return -1;

    hdrlen = sprintf(req,
        "%s %s HTTP/1.0\r\n"
        "Host: %s\r\n"
        "User-Agent: %s\r\n"
        "Accept: */*\r\n"
        "Connection: close\r\n",
        method, u->path, u->host, cfg.user_agent);
    if (cfg.header)
        hdrlen += sprintf(req + hdrlen, "%s\r\n", cfg.header);
    if (data) {
        hdrlen += sprintf(req + hdrlen,
            "Content-Type: %s\r\n"
            "Content-Length: %lu\r\n", cfg.content_type, (unsigned long)datalen);
    }
    hdrlen += sprintf(req + hdrlen, "\r\n");

    if (cfg.verbose)
        fprintf(stderr, "%s", req);

    if (conn_open(&c, u) != 0) {
        free(req);
        return -1;
    }
    if (conn_write(&c, req, (size_t)hdrlen) != 0 ||
        (data && conn_write(&c, data, datalen) != 0)) {
        fprintf(stderr, "fetch89: write failed\n");
        conn_close(&c);
        free(req);
        return -1;
    }
    free(req);

    if (read_all(&c, resp, resplen) != 0) {
        conn_close(&c);
        return -1;
    }
    conn_close(&c);

    sep = strstr(*resp, "\r\n\r\n");
    if (sep == NULL) {
        fprintf(stderr, "fetch89: malformed response\n");
        free(*resp);
        return -1;
    }
    *sep = '\0';
    *body = sep + 4;
    if (cfg.verbose)
        fprintf(stderr, "%s\r\n\r\n", *resp);
    return 0;
}

int main(int argc, char **argv)
{
    const char *target = NULL, *method = "GET", *data = NULL;
    int i, hop, status;
    struct url u;
    char *resp, *body, loc[2048];
    size_t resplen;
    FILE *out;

    signal(SIGPIPE, SIG_IGN);
    load_env();

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0) {
            usage(stdout);
            return 0;
        } else if (strcmp(argv[i], "-v") == 0) {
            cfg.verbose = 1;
        } else if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            cfg.output = argv[++i];
        } else if (strcmp(argv[i], "--post") == 0 && i + 1 < argc) {
            method = "POST";
            data = argv[++i];
        } else if (strcmp(argv[i], "--put") == 0 && i + 1 < argc) {
            method = "PUT";
            data = argv[++i];
        } else if (argv[i][0] == '-' && argv[i][1] != '\0') {
            fprintf(stderr, "fetch89: bad option: %s\n", argv[i]);
            usage(stderr);
            return 1;
        } else if (target == NULL) {
            target = argv[i];
        } else {
            usage(stderr);
            return 1;
        }
    }
    if (target == NULL) {
        usage(stderr);
        return 1;
    }
    if (parse_url(target, &u) != 0) {
        fprintf(stderr, "fetch89: bad url\n");
        return 1;
    }
    if (cfg.port != NULL) {
        if (strlen(cfg.port) >= sizeof(u.port)) {
            fprintf(stderr, "fetch89: bad FETCH89_PORT\n");
            return 1;
        }
        strcpy(u.port, cfg.port);
    }

    for (hop = 0; ; hop++) {
        if (do_request(&u, method, data, &resp, &body, &resplen) != 0)
            return 1;

        status = 0;
        sscanf(resp, "HTTP/%*s %d", &status);

        if ((status == 301 || status == 302 || status == 303 ||
             status == 307 || status == 308) &&
            hop < cfg.max_redirects &&
            get_header(resp, "Location", loc, sizeof(loc))) {
            struct url nu = u;
            int ok = 0;
            if (strncmp(loc, "http://", 7) == 0 || strncmp(loc, "https://", 8) == 0) {
                ok = (parse_url(loc, &nu) == 0);
            } else if (loc[0] == '/') {
                strcpy(nu.path, loc);
                ok = 1;
            }
            if (ok) {
                u = nu;
                if (status != 307 && status != 308) {
                    method = "GET";
                    data = NULL;
                }
                free(resp);
                continue;
            }
        }
        break;
    }

    if (cfg.output) {
        out = fopen(cfg.output, "wb");
        if (out == NULL) {
            fprintf(stderr, "fetch89: cannot open %s\n", cfg.output);
            free(resp);
            return 1;
        }
    } else {
        out = stdout;
    }
    fwrite(body, 1, resplen - (size_t)(body - resp), out);
    if (cfg.output)
        fclose(out);
    free(resp);
    return 0;
}
