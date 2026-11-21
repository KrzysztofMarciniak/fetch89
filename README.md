# fetch89

Fetch a URL over HTTP or HTTPS and print the body. One C89 file, no curl, no wget.

[web](https://github.com/krzysztofMarciniak/web) - A small terminal HTML reader in one C89 file. 


[rss89](https://github.com/KrzysztofMarciniak/rss89) - Minimal RSS/Atom reader in C89 (+ POSIX). Two commands, plain files, no libraries.


[see89](https://github.com/KrzysztofMarciniak/see89) - Search wiby.me and DuckDuckGo (html version) from the terminal. 

## Build

With HTTPS (needs OpenSSL 1.1.0 or newer, e.g. `libssl-dev`):

    cc -std=c89 -pedantic -D_POSIX_C_SOURCE=200112L -o fetch89 fetch89.c -lssl -lcrypto

HTTP only (no OpenSSL needed):

    cc -std=c89 -pedantic -D_POSIX_C_SOURCE=200112L -DFETCH89_NO_SSL -o fetch89 fetch89.c

Requires a POSIX system (sockets, `getaddrinfo`).

## Usage

    fetch89 example.org
    fetch89 example.org -o example.html
    fetch89 example.org --post "a=1&b=2"
    fetch89 example.org --put "data"
    fetch89 -v http://localhost:8080/

| Option        | Meaning                                              |
|---------------|------------------------------------------------------|
| `-o FILE`     | Write body to FILE instead of stdout                 |
| `--post DATA` | Send a POST with DATA as the body                    |
| `--put DATA`  | Send a PUT with DATA as the body                     |
| `-v`          | Print request and response headers to stderr         |
| `-h`          | Print help                                           |

A URL without a scheme defaults to `https://` (`http://` in the no-SSL build).
Redirects (301, 302, 303, 307, 308) are followed. 301, 302 and 303 switch to GET.

## Environment

Command line options override environment variables.

| Variable                | Meaning                                          | Default                              |
|-------------------------|--------------------------------------------------|--------------------------------------|
| `FETCH89_PORT`          | Override the port of the requested URL           | from URL / scheme                    |
| `FETCH89_SCHEME`        | Scheme for URLs without one: `http` or `https`   | `https`                              |
| `FETCH89_OUTPUT`        | Output file (same as `-o`)                       | stdout                               |
| `FETCH89_VERBOSE`       | `1` = same as `-v`                               | `0`                                  |
| `FETCH89_USER_AGENT`    | User-Agent header                                | `fetch89/1.0`                        |
| `FETCH89_HEADER`        | One extra header line, e.g. `Authorization: Bearer x` | none                            |
| `FETCH89_CONTENT_TYPE`  | Content-Type for `--post` / `--put`              | `application/x-www-form-urlencoded`  |
| `FETCH89_TIMEOUT`       | Socket timeout in seconds, `0` = none            | `30`                                 |
| `FETCH89_MAX_REDIRECTS` | Max redirects to follow, `0` = none              | `5`                                  |
| `FETCH89_INSECURE`      | `1` = skip TLS certificate verification (SSL build) | `0`                               |
| `FETCH89_CA_FILE`       | CA bundle file (SSL build)                       | system default                       |
| `FETCH89_CA_DIR`        | CA directory (SSL build)                         | system default                       |

Examples:

    FETCH89_PORT=8080 fetch89 localhost
    FETCH89_HEADER="Authorization: Bearer TOKEN" fetch89 api.example.org
    FETCH89_CONTENT_TYPE=application/json fetch89 api.example.org --post '{"a":1}'
    FETCH89_TIMEOUT=5 FETCH89_MAX_REDIRECTS=0 fetch89 example.org

## Exit codes

- `0`: a response was received and written (including HTTP 4xx/5xx, check with `-v`).
- `1`: bad arguments, connection failure, TLS failure, or malformed response.

## Notes and limits

- Requests use HTTP/1.0 with `Connection: close`, so servers do not send chunked bodies.
- TLS certificates and hostnames are verified unless `FETCH89_INSECURE=1`.
- `--post` and `--put` send DATA exactly as given; there is no `@file` syntax.
- IPv6 literal URLs (`http://[::1]/`) are not supported.
- Environment values containing newlines are rejected, to prevent header injection.
