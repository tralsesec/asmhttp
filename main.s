.intel_syntax noprefix

# ==============================================================================
# GLOBAL CONSTANTS
# ==============================================================================

# Connection
.equ INADDR_ANY,            0
.equ SOCK_STREAM,           1
.equ AF_INET,               2

# Operation
.equ SOL_SOCKET,            1
.equ SO_REUSEADDR,          2
.equ WORKER_CORES,          4
.equ BACKLOG,            1024

# HTTP
.equ MAX_OTHER_HDRS,       16       # More than 16 custom headers: REQ_F_ERR_HDR_LIMIT
.equ READ_TIMEOUT,        500       # 500 ms
.equ MAX_HEADER_SIZE,    1024       # 1 KB limit
.equ MAX_BODY_SIZE,      1024       # 1 KB limit

# Max size: 2 KB. Remember: req_buffers is 128 KB by default!
.equ MAX_REQUEST_SIZE, MAX_HEADER_SIZE + MAX_BODY_SIZE

# ==============================================================================
# BSS DATA
# ==============================================================================

.section .bss
.align 64
active_mask: .quad 0                # 64-bit slot tracker (0 = free, 1 = busy)

.align 64
req_structs: .zero (64 * 64)        # 4 KB: 64 cache-line aligned structs

.align 64
req_buffers: .zero (64 * 2048)      # 128 KB: 64 raw request buffers (2 KB each)

# ==============================================================================
# STRUCTS
# ==============================================================================

# ==============================================================================
# HTTP REQUEST STRUCT
# ==============================================================================

# ==============================================================================
# HTTP REQUEST STRUCT
# ==============================================================================

# ==============================================================================
# STRUCT: http_request (Exactly 64 bytes / 1 Full CPU Cache Line)
# Natural alignment preserved. Zero bytes wasted.
# ==============================================================================
# Offset | Size | Field            | Description
# -------+------+------------------+--------------------------------------------
# +0     | 8    | flags            | 64-bit Bitmask (Method, HTTP ver, VIP flags)
# +8     | 2    | uri_off          | 16-bit offset to Path start
# +10    | 2    | uri_len          | 16-bit length of Path (stops before '?')
# +12    | 2    | query_off        | 16-bit offset to Query params (after '?')
# +14    | 2    | query_len        | 16-bit length of Query params
# +16    | 2    | host_off         | 16-bit offset to Host value
# +18    | 2    | host_len         | 16-bit length of Host value
# +20    | 2    | auth_off         | 16-bit offset to Authorization value
# +22    | 2    | auth_len         | 16-bit length of Authorization value
# +24    | 2    | cookie_off       | 16-bit offset to Cookie value
# +26    | 2    | cookie_len       | 16-bit length of Cookie value
# +28    | 2    | ua_off           | 16-bit offset to User-Agent value
# +30    | 2    | ua_len           | 16-bit length of User-Agent value
# +32    | 2    | content_type_off | 16-bit offset to Content-Type string
# +34    | 2    | content_type_len | 16-bit length of Content-Type string
# +36    | 2    | referer_off      | 16-bit offset to Referer value
# +38    | 2    | referer_len      | 16-bit length of Referer value
# +40    | 4    | body_len         | 32-bit byte count of Body (aligned to 4)
# +44    | 2    | body_off         | 16-bit offset to Body start (aligned to 2)
# +46    | 1    | route_id         | 8-bit Target endpoint ID (0..255)
# +47    | 1    | status_enum      | 8-bit Compact HTTP status enum (0..255)
# +48    | 8    | other_hdrs_ptr   | 64-bit pointer to unknown headers array
# +56    | 4    | client_fd        | 32-bit client socket descriptor
# +60    | 2    | other_count      | Number of unknown headers parsed
# +62    | 2    | client_port      | 16-bit client port (little endian)
# ------------------------------------------------------------------------------

.equ REQ_OFF_FLAGS,        0
.equ REQ_OFF_URI_OFF,      8
.equ REQ_OFF_URI_LEN,     10
.equ REQ_OFF_QUERY_OFF,   12
.equ REQ_OFF_QUERY_LEN,   14
.equ REQ_OFF_HOST_OFF,    16
.equ REQ_OFF_HOST_LEN,    18
.equ REQ_OFF_AUTH_OFF,    20
.equ REQ_OFF_AUTH_LEN,    22
.equ REQ_OFF_COOKIE_OFF,  24
.equ REQ_OFF_COOKIE_LEN,  26
.equ REQ_OFF_UA_OFF,      28
.equ REQ_OFF_UA_LEN,      30
.equ REQ_OFF_CT_OFF,      32
.equ REQ_OFF_CT_LEN,      34
.equ REQ_OFF_REF_OFF,     36
.equ REQ_OFF_REF_LEN,     38
.equ REQ_OFF_BODY_LEN,    40
.equ REQ_OFF_BODY_OFF,    44
.equ REQ_OFF_ROUTE_ID,    46
.equ REQ_OFF_STATUS_ENUM, 47
.equ REQ_OFF_OTHER_PTR,   48
.equ REQ_OFF_CLIENT_FD,   56
.equ REQ_OFF_OTHER_CNT,   60
.equ REQ_OFF_CLIENT_PORT, 62
.equ HTTP_REQ_SIZE,       64

# ==============================================================================
# COMPACT HTTP STATUS ENUMS (8-bit)
# ==============================================================================
.equ STATUS_200_OK,                  0
.equ STATUS_201_CREATED,             1
.equ STATUS_204_NO_CONTENT,          2
.equ STATUS_206_PARTIAL_CONTENT,     3
.equ STATUS_301_MOVED_PERMANENTLY,   4
.equ STATUS_302_FOUND,               5
.equ STATUS_304_NOT_MODIFIED,        6
.equ STATUS_400_BAD_REQUEST,         7
.equ STATUS_401_UNAUTHORIZED,        8
.equ STATUS_403_FORBIDDEN,           9
.equ STATUS_404_NOT_FOUND,          10
.equ STATUS_405_METHOD_NOT_ALLOWED, 11
.equ STATUS_413_PAYLOAD_TOO_LARGE,  12
.equ STATUS_415_UNSUPPORTED_MEDIA,  13
.equ STATUS_416_RANGE_NOT_SATISFIED,14
.equ STATUS_429_TOO_MANY_REQUESTS,  15
.equ STATUS_431_HEADERS_TOO_LARGE,  16
.equ STATUS_500_INTERNAL_ERROR,     17
.equ STATUS_501_NOT_IMPLEMENTED,    18
.equ STATUS_502_BAD_GATEWAY,        19
.equ STATUS_503_SERVICE_UNAVAILABLE,20
.equ STATUS_504_GATEWAY_TIMEOUT,    21

# ==============================================================================
# HTTP REQUEST FLAGS (64-bit Bitmask)
# ==============================================================================

# ------------------------------------------------------------------------------
# HTTP Methods (Bits 0-7)
# ------------------------------------------------------------------------------
.equ REQ_METHOD_UNKNOWN,    0
.equ REQ_METHOD_GET,        (1 << 0)
.equ REQ_METHOD_POST,       (1 << 1)
.equ REQ_METHOD_PUT,        (1 << 2)
.equ REQ_METHOD_DELETE,     (1 << 3)
.equ REQ_METHOD_HEAD,       (1 << 4)
.equ REQ_METHOD_OPTIONS,    (1 << 5)
.equ REQ_METHOD_PATCH,      (1 << 6)
.equ REQ_METHOD_CONNECT,    (1 << 7)

# Mask to isolate method bits (0-7)
.equ REQ_METHOD_MASK,       0xFF

# ------------------------------------------------------------------------------
# HTTP Protocol Versions (Bits 8-11)
# ------------------------------------------------------------------------------
.equ REQ_VER_10,            (1 << 8)
.equ REQ_VER_11,            (1 << 9)
.equ REQ_VER_20,            (1 << 10)
.equ REQ_VER_30,            (1 << 11)

.equ REQ_VER_MASK,          (0xF << 8)

# ------------------------------------------------------------------------------
# VIP Header Presence Indicators (Bits 12-19)
# Lets your router skip parsing if a header was never supplied
# ------------------------------------------------------------------------------
.equ REQ_F_HAS_HOST,        (1 << 12)
.equ REQ_F_HAS_AUTH,        (1 << 13)
.equ REQ_F_HAS_COOKIE,      (1 << 14)
.equ REQ_F_HAS_UA,          (1 << 15)
.equ REQ_F_HAS_REFERER,     (1 << 16)
.equ REQ_F_HAS_CT,          (1 << 17)   # Content-Type provided
.equ REQ_F_HAS_ACCEPT,      (1 << 18)
.equ REQ_F_HAS_ORIGIN,      (1 << 19)   # CORS origin header present

# ------------------------------------------------------------------------------
# Connection & Transport State (Bits 20-27)
# ------------------------------------------------------------------------------
.equ REQ_F_KEEPALIVE,       (1 << 20)   # Connection: keep-alive (or default in 1.1)
.equ REQ_F_CLOSE,           (1 << 21)   # Connection: close
.equ REQ_F_CHUNKED,         (1 << 22)   # Transfer-Encoding: chunked
.equ REQ_F_UPGRADE,         (1 << 23)   # Connection: Upgrade (e.g. WebSocket)
.equ REQ_F_GZIP_ACCEPTED,   (1 << 24)   # Accept-Encoding includes gzip
.equ REQ_F_TLS,             (1 << 25)   # Set if request arrived over TLS/HTTPS

# ------------------------------------------------------------------------------
# Body & Content-Type Enums (Bits 28-35)
# Classifies payload instantly so routes don't run string checks
# ------------------------------------------------------------------------------
.equ REQ_F_HAS_BODY,        (1 << 28)   # Content-Length > 0 or Chunked
.equ REQ_F_CT_JSON,         (1 << 29)   # application/json
.equ REQ_F_CT_URLENCODED,   (1 << 30)   # application/x-www-form-urlencoded
.equ REQ_F_CT_MULTIPART,    (1 << 31)   # multipart/form-data
.equ REQ_F_CT_OCTET,        (1 << 32)   # application/octet-stream
.equ REQ_F_CT_TEXT,         (1 << 33)   # text/plain or text/html

# ------------------------------------------------------------------------------
# Security Violations & Attack Detection (Bits 36-43)
# Reject malicious requests immediately before routing
# ------------------------------------------------------------------------------
.equ REQ_F_ERR_BAD_URI,     (1 << 36)   # Path traversal (../) or invalid chars
.equ REQ_F_ERR_BODY_LARGE,  (1 << 37)   # Content-Length exceeds MAX_BODY_LIMIT
.equ REQ_F_ERR_BAD_VERSION, (1 << 38)   # Unsupported protocol version
.equ REQ_F_ERR_SMUGGLING,   (1 << 39)   # Both Content-Length AND chunked present (RFC 9112)
.equ REQ_F_ERR_HDR_LIMIT,   (1 << 40)   # Too many headers (exceeded other_cap)
.equ REQ_F_ERR_MULTI_HOST,  (1 << 41)   # Multiple Host headers sent (Host injection)
.equ REQ_F_ERR_INVALID_CHR, (1 << 42)   # Control characters in header values (\0, bare LF)
.equ REQ_F_ERR_MASK,        (0x7F << 36) # Fast branch: test flags, REQ_F_ERR_MASK -> jnz 4xx

# ------------------------------------------------------------------------------
# Flow Control & Body Protocol (Bits 44-46)
# ------------------------------------------------------------------------------
.equ REQ_F_EXPECT_100,      (1 << 44)   # "Expect: 100-continue" (must send 100 before body)
.equ REQ_F_TRAILERS,        (1 << 45)   # "TE: trailers" (chunked trailers expected)
.equ REQ_F_HAS_QUERY,       (1 << 46)   # Query string exists (query_len > 0)

# ------------------------------------------------------------------------------
# Caching & Range Requests (Bits 47-50)
# Enables instant 304 Not Modified and 206 Partial Content
# ------------------------------------------------------------------------------
.equ REQ_F_HAS_IF_MODIFIED, (1 << 47)   # If-Modified-Since present
.equ REQ_F_HAS_IF_NONE_MAT, (1 << 48)   # If-None-Match present (ETag check)
.equ REQ_F_HAS_RANGE,       (1 << 49)   # Range: bytes=... (video streaming / resumption)
.equ REQ_F_CACHE_NO_STORE,  (1 << 50)   # Cache-Control: no-store / no-cache

# ------------------------------------------------------------------------------
# Modern Compression Negotiation (Bits 51-54)
# Lets sendfile serve pre-compressed .br / .gz / .zst directly off disk
# ------------------------------------------------------------------------------
.equ REQ_F_BR_ACCEPTED,     (1 << 51)   # Accept-Encoding: br (Brotli)
.equ REQ_F_ZSTD_ACCEPTED,   (1 << 52)   # Accept-Encoding: zstd (Zstandard)
.equ REQ_F_ACCEPT_JSON,     (1 << 53)   # Accept: application/json
.equ REQ_F_ACCEPT_HTML,     (1 << 54)   # Accept: text/html

# ------------------------------------------------------------------------------
# Route Engine Fast-Paths (Bits 55-58)
# Pre-computed by parser to eliminate branch chains in the router
# ------------------------------------------------------------------------------
.equ REQ_F_PATH_IS_ROOT,    (1 << 55)   # URI is exactly "/"
.equ REQ_F_PATH_IS_STATIC,  (1 << 56)   # Path begins with "/static/" or has file extension
.equ REQ_F_PATH_IS_API,     (1 << 57)   # Path begins with "/api/"
.equ REQ_F_WS_HANDSHAKE,    (1 << 58)   # Upgrade: websocket + Sec-WebSocket-Key

# ------------------------------------------------------------------------------
# Application & Middleware State (Bits 59-63)
# ------------------------------------------------------------------------------
.equ REQ_F_AUTH_VALID,      (1 << 59)   # Auth middleware passed (token/cookie verified)
.equ REQ_F_ROLE_ADMIN,      (1 << 60)   # Client has elevated/admin role
.equ REQ_F_RATE_LIMITED,    (1 << 61)   # Rate limiter tripped (divert to 429 Too Many Requests)
.equ REQ_F_RESP_STREAMING,  (1 << 62)   # Body is chunked stream / SSE (skip Content-Length)
.equ REQ_F_INTERNAL_ERR,    (1 << 63)   # Handler crashed or faulted (divert to 500 handler)

# ==============================================================================
# STRUCT OFFSETS: http_response
# ==============================================================================
.equ RESP_OFF_BUF,     0
.equ RESP_OFF_LEN,     8
.equ RESP_OFF_STATUS, 12
.equ HTTP_RESP_SIZE,  16

# ------------------------------------------------------------------------------
# MACRO: SET_REQ_FLAG flag, base=r12, scr_reg=r10
# Sets \flag in REQ_OFF_FLAGS on the specified http_request struct.
#
# Emits a single, direct 32-bit immediate 'or' if bits fit in 0..30 (positive simm32).
# Routes through \scr_reg for higher bits to bypass x86-64's missing 'or m64, imm64'.
#
# Arguments:
#   flag:    64-bit flag bitmask or expression to set
#   base:    Register pointing to http_request base (defaults to r12)
#   scr_reg: Scratch register for high bits (defaults to r10)
#
# Clobbers:
#   \scr_reg (ONLY when flag exceeds bit 30; untouched on low bits)
# ------------------------------------------------------------------------------
.macro SET_REQ_FLAG flag, base=r12, scr_reg=r10
    .if ((\flag) & ~0x7FFFFFFF)
        # Bits 31 through 63: load full 64-bit inverted mask into scratch register
        mov r10, (\flag)
        or qword ptr [\base + REQ_OFF_FLAGS], \scr_reg
    .else
        # Bits 0 through 30: safe to emit direct end
        or qword ptr [\base + REQ_OFF_FLAGS], (\flag)
    .endif
.endm

# ------------------------------------------------------------------------------
# MACRO: CLEAR_REQ_FLAG flag, base=r12, scr_reg=r10
# Clears \flag in REQ_OFF_FLAGS on the specified http_request struct.
#
# Emits a direct 'and' if the sign-extended 32-bit immediate safely matches.
# Otherwise routes through \scr_reg to avoid immediate truncation or sign bugs.
# ------------------------------------------------------------------------------
.macro CLEAR_REQ_FLAG flag, base=r12, scr_reg=r10
    .if ((\flag) >= (1 << 31))
        # Bits 31 through 63: load full 64-bit inverted mask into scratch register
        mov \scr_reg, ~(\flag)
        and qword ptr [\base + REQ_OFF_FLAGS], \scr_reg
    .else
        # Bits 0 through 30: safe to emit direct end
        and qword ptr [\base + REQ_OFF_FLAGS], ~(\flag)
    .endif
.endm

# ------------------------------------------------------------------------------
# MACRO: TEST_REQ_FLAG flag, base=r12, scr_reg=r10
# Tests \flag against REQ_OFF_FLAGS on the specified http_request struct.
#
# Emits a direct 32-bit immediate 'test' if the mask fits in bits 0..30 (positive simm32).
# Routes through \scr_reg for higher bits (>= 31) to bypass x86-64's missing 'test m64, imm64'.
#
# Arguments:
#   flag:    64-bit flag bitmask or expression to test
#   base:    Register pointing to http_request base (defaults to r12)
#   scr_reg: Scratch register for high bits (defaults to r10)
#
# CPU Flags Set:
#   ZF (Zero Flag) is set to 1 if no bits match (use jz)
#   ZF (Zero Flag) is cleared to 0 if any bit matches (use jnz)
#
# Clobbers:
#   \scr_reg (ONLY when flag exceeds bit 30; untouched on low bits)
# ------------------------------------------------------------------------------
.macro TEST_REQ_FLAG flag, base=r12, scr_reg=r10
    .if ((\flag) & ~0x7FFFFFFF)
        # Bits 31 through 63: load full 64-bit inverted mask into scratch register
        mov \scr_reg, (\flag)
        test qword ptr [\base + REQ_OFF_FLAGS], \scr_reg
    .else
        # Bits 0 through 30: safe to emit direct end
        test qword ptr [\base + REQ_OFF_FLAGS], (\flag)
    .endif
.endm

# ------------------------------------------------------------------------------
# MACRO: DEF_HTTP_RESP name, buf_label, buf_len, status=200
# Emits a 16-byte http_response struct.
# ------------------------------------------------------------------------------
.macro DEF_HTTP_RESP name, buf_label, buf_len, status=200
\name:
    .quad \buf_label                    # +0: Pointer to Response buffer
    .long \buf_len                      # +8: Length (32-Bit Integer)
    .word \status                       # +12: Status code (16-Bit Integer; e.g., 200)
    .word 0                             # +14: Padding to 16 bytes
.equ \name\()_len, 16
.endm

# ==============================================================================
# HTTP RESPONSE FLAGS (Bitmask: Bits 0-15)
# ==============================================================================
.equ FLAG_NONE,         0
.equ FLAG_KEEPALIVE,    (1 << 0)   # 1: "Connection: keep-alive", 0: "close"
.equ FLAG_SENDFILE,     (1 << 1)   # body_buf is not a buffer, but a fd!
.equ FLAG_NO_BODY,      (1 << 2)   # 204 No Content, 304 Not Modified, or HEAD-Request
.equ FLAG_CHUNKED,      (1 << 3)   # "Transfer-Encoding: chunked" (no Content-Length; is removed)
.equ FLAG_CORS,         (1 << 4)   # "Access-Control-Allow-Origin: *\r\n"
.equ FLAG_NOCACHE,      (1 << 5)   # "Cache-Control: no-store\r\n"

# ==============================================================================
# CONTENT-TYPE ENUMS (Bits 16-23)
# No string-lookups: Builder finds Header-String via Jump Table!
# ==============================================================================
.equ CT_SHIFT,          16
.equ CT_NONE,           (0 << CT_SHIFT)
.equ CT_HTML,           (1 << CT_SHIFT)   # "Content-Type: text/html; charset=utf-8\r\n"
.equ CT_PLAIN,          (2 << CT_SHIFT)   # "Content-Type: text/plain; charset=utf-8\r\n"
.equ CT_JSON,           (3 << CT_SHIFT)   # "Content-Type: application/json\r\n"
.equ CT_OCTET,          (4 << CT_SHIFT)   # "Content-Type: application/octet-stream\r\n"

# ------------------------------------------------------------------------------
# MACRO: HTTP_ALLOC size=256
# Reserves an aligned scratchpad on the stack and sets rdi as the write head.
# size MUST be a multiple of 16 to preserve ABI stack alignment!
#
# For request:  use size=64
# For response: use size=256
# ------------------------------------------------------------------------------
.macro HTTP_ALLOC size=256
    sub rsp, \size
    mov rdi, rsp
.endm

# ------------------------------------------------------------------------------
# MACRO: HTTP_DEALLOC size=256
# Reserves an aligned scratchpad on the stack and sets rdi as the write head.
# size MUST be a multiple of 16 to preserve ABI stack alignment!
#
# For request:  use size=64
# For response: use size=256
# ------------------------------------------------------------------------------
.macro HTTP_DEALLOC size=256
    add rsp, \size
    mov rdi, rsp
.endm

# ------------------------------------------------------------------------------
# MACRO: HTTP_SEND_RESP fd, body_ptr, body_len, alloc_size=256
# Computes header length, binds pointers to sys_writev, calls the sender.
# ------------------------------------------------------------------------------
.macro HTTP_SEND_RESP fd, body_ptr, body_len
    # 1. Compute header length before touching rdi
    mov rdx, rdi
    sub rdx, rsp                        # rdx = header length (bytes written)

    # 2. Setup arguments for http_send_response
    mov rsi, rsp                        # rsi = header buffer
    mov rdi, \fd                        # rdi = client socket fd
    mov rcx, \body_ptr                  # rcx = body pointer
    mov r8, \body_len                   # r8 = body length

    call http_send_response
.endm

# ------------------------------------------------------------------------------
# MACRO: HTTP_WRITE str
# Writes arbitrary ASCII strings directly to [rdi] and advances rdi.
# Clobbers: rsi, rcx
# ------------------------------------------------------------------------------
.macro HTTP_WRITE str
    .pushsection .rodata
.Lhw_\@:
    .ascii "\str"
.Lhw_end_\@:
    .popsection

    LOAD_ADDR rsi, .Lhw_\@
    mov ecx, (.Lhw_end_\@ - .Lhw_\@)
    rep movsb
.endm

# ------------------------------------------------------------------------------
# MACRO: HTTP_WRITE_STATUS_LINE status=200, ver=11
# Generates the status line at compile-time in .rodata and copies it to [rdi].
# Clobbers: rsi, rcx
# ------------------------------------------------------------------------------
.macro HTTP_WRITE_STATUS_LINE status=200, ver=11
    .pushsection .rodata
.Lsl_\@:
    .if \ver == 10
        .ascii "HTTP/1.0 "
    .elseif \ver == 11
        .ascii "HTTP/1.1 "
    .else
        .ascii "HTTP/2 "
    .endif

    .if \status == 201
        .ascii "201 Created\r\n"
    .elseif \status == 204
        .ascii "204 No Content\r\n"
    .elseif \status == 400
        .ascii "400 Bad Request\r\n"
    .elseif \status == 404
        .ascii "404 Not Found\r\n"
    .elseif \status == 500
        .ascii "500 Internal Server Error\r\n"
    .else
        .ascii "200 OK\r\n"
    .endif
.Lsl_end_\@:
    .popsection

    LOAD_ADDR rsi, .Lsl_\@
    mov ecx, (.Lsl_end_\@ - .Lsl_\@)
    rep movsb
.endm

# ------------------------------------------------------------------------------
# MACRO: HTTP_WRITE_HEADER_KV key, val
# Formats and writes "<key>: <val>\r\n" directly to [rdi] and advances rdi.
# Clobbers: rsi, rcx
# ------------------------------------------------------------------------------
.macro HTTP_WRITE_HEADER_KV key, val
    .pushsection .rodata
.Lhkv_\@:
    .ascii "\key"
    .ascii ": "
    .ascii "\val"
    .ascii "\r\n"
.Lhkv_end_\@:
    .popsection

    LOAD_ADDR rsi, .Lhkv_\@
    mov ecx, (.Lhkv_end_\@ - .Lhkv_\@)
    rep movsb
.endm

# ------------------------------------------------------------------------------
# MACRO: HTTP_WRITE_CONTENT_LENGTH len
# Writes "Content-Length: <len>\r\n" to [rdi] and advances rdi.
# len can be a constant (e.g. 42) or a register (e.g. r15d).
# Clobbers: rcx
# ------------------------------------------------------------------------------
.macro HTTP_WRITE_CONTENT_LENGTH len
    # 1. Write "Content-" (8 bytes)
    mov rax, 0x2d746e65746e6f43
    mov [rdi], rax
    add rdi, 8

    # 2. Write "Length: " (8 bytes)
    mov rax, 0x203a6874676e654c
    mov [rdi], rax
    add rdi, 8

    # 3. Convert length to ASCII and append (assumes positive length)
    mov rsi, \len
    call itoa

    # 4. Write CRLF
    mov word ptr [rdi], 0x0a0d
    add rdi, 2
.endm

# ------------------------------------------------------------------------------
# MACRO: HTTP_WRITE_HEADER_END
# Appends the final "\r\n" (2 bytes) to terminate the HTTP header block.
# Clobbers: None
# ------------------------------------------------------------------------------
.macro HTTP_WRITE_HEADER_END
    mov word ptr [rdi], 0x0a0d
    add rdi, 2
.endm

# ------------------------------------------------------------------------------
# MACRO: HTTP_WRITE_BODY fd, body, len, alloc_size=256
# Automatically writes Content-Length, appends \r\n, and dispatches via writev.
#
# Arguments:
#   fd:         Client socket descriptor (e.g. r13)
#   body:       Quoted string literal ("hello") OR pointer to dynamic buffer
#   len:        [Optional] Length of dynamic buffer (omitted for static strings)
#
# Register Safety:
#   Stashes dynamic arguments in r9/r10 across itoa to avoid clobbering.
# ------------------------------------------------------------------------------
.macro HTTP_SEND_BODY fd, body, len
    .ifb \len
        # ======================================================================
        # Branch 1: Static String Literal (Compile-Time Length)
        # ======================================================================
        .pushsection .rodata
    .Lbody_\@:
        .ascii "\body"
    .Lbody_end_\@:
        .equ .Lbody_len_\@, (.Lbody_end_\@ - .Lbody_\@)
        .popsection

        # 1. Write Content-Length: <len>\r\n using compile-time constant
        HTTP_WRITE_CONTENT_LENGTH .Lbody_len_\@

        # 2. Terminate HTTP headers with final \r\n
        HTTP_WRITE_HEADER_END

        # 3. Stream headers + rodata body via writev
        LOAD_ADDR rax, .Lbody_\@
        HTTP_SEND_RESP \fd, rax, .Lbody_len_\@

    .else
        # ======================================================================
        # Branch 2: Dynamic Buffer (Runtime Pointer + Runtime Length)
        # ======================================================================
        # Preserve pointer and length in r9 and r10 across itoa
        mov r9, \body
        mov r10, \len

        # 1. Write Content-Length: <len>\r\n using runtime integer
        HTTP_WRITE_CONTENT_LENGTH r10

        # 2. Terminate HTTP headers with final \r\n
        HTTP_WRITE_HEADER_END

        # 3. Stream headers + dynamic buffer via writev
        HTTP_SEND_RESP \fd, r9, r10
    .endif
.endm

# ------------------------------------------------------------------------------
# MACRO: HTTP_SEND_FILE sock_fd, file_fd, file_size, alloc_size=256
# Writes headers, flushes via sys_write, then streams file via sys_sendfile64.
# ------------------------------------------------------------------------------
.macro HTTP_SEND_FILE sock_fd, file_fd, file_size, alloc_size=256
    mov r9, \file_fd
    mov r10, \file_size

    # 1. Write Content-Length: <file_size>\r\n
    HTTP_WRITE_CONTENT_LENGTH r10
    HTTP_WRITE_HEADER_END

    # 2. itoa is finished; stash sock_fd in r8
    mov r8, \sock_fd

    # 3. Flush headers to client
    mov rdx, rdi
    sub rdx, rsp
    WRITE r8, rsp, rdx
    add rsp, \alloc_size

    # 4. sys_sendfile64(out_fd=r8, in_fd=r9, *offset=NULL, count=r10)
    mov rdi, r8                         # arg1: out_fd (socket)
    mov rsi, r9                         # arg2: in_fd (disk file)
    xor edx, edx                        # arg3: NULL offset (sequential stream)
    # arg4: r10 already holds file_size
    mov eax, 40                         # SYS_SENDFILE
    syscall
.endm

# ==============================================================================
# OPERATIONAL MACROS
# ==============================================================================

# ------------------------------------------------------------------------------
# MACRO: PRINT_STR "string\n"
# Automatically places text into .rodata, saves registers, and writes to stdout.
# Clobbers: None (all modified registers are preserved on stack)
# ------------------------------------------------------------------------------
.macro PRINT_STR str
    .pushsection .rodata
.Lpstr_\@:
    .ascii "\str"
.Lpstr_end_\@:
    .popsection

    # Preserve all registers syscalls or args touch
    push rax
    push rdi
    push rsi
    push rdx
    push rcx
    push r11

    mov eax, SYS_WRITE                   # Syscall 1
    mov edi, 1                           # stdout
    lea rsi, [rip + .Lpstr_\@]           # Pointer to .rodata string
    mov edx, (.Lpstr_end_\@ - .Lpstr_\@) # String length
    syscall

    pop r11
    pop rcx
    pop rdx
    pop rsi
    pop rdi
    pop rax
.endm

# ------------------------------------------------------------------------------
# MACRO: DEF_SOCKADDR_IN name, port, ip1, ip2, ip3, ip4
# Emits a 16-byte sockaddr_in struct into the current section.
# Port is converted to network byte order (Big Endian) at compile time.
#
# Arguments:
#   name:  Label identifier for the struct
#   port:  Port number in host byte order (0 - 65535)
#   ipN:   IPv4 octets (e.g. 127, 0, 0, 1)
#
# Emits:
#   <name>     : struct start label
#   <name>_len : compile-time constant equal to 16
#
# Example:
#   DEF_SOCKADDR_IN local_addr, 8080, 127, 0, 0, 1
# ------------------------------------------------------------------------------
.macro DEF_SOCKADDR_IN name, port, ip1, ip2, ip3, ip4
\name:
    .word 2                                         # AF_INET = 2 (sin_family)
    .byte ((\port >> 8) & 0xFF), (\port & 0xFF)     # sin_port in Big Endian
    .byte \ip1, \ip2, \ip3, \ip4                    # sin_addr (e.g., 127, 0, 0, 1)
    .zero 8                                         # sin_zero (8 byte padding)
.equ \name\()_len, . - \name
.endm

# Loads global label pointer to register.
.macro LOAD_ADDR register, label
    lea \register, [rip + \label]
.endm

# ==============================================================================
# READ-ONLY DATA
# ==============================================================================
.section .rodata
.align 16

DEF_SOCKADDR_IN sockaddr_any, 80, 0, 0, 0, 0

# Macro to generate packed status descriptor entries
.macro STATUS_ENTRY str
    .quad .Lse_\@
    .long (.Lse_end_\@ - .Lse_\@)
    .long 0                             # 4 bytes padding to make each entry 16 bytes
    .pushsection .rodata.str
.Lse_\@:
    .ascii "HTTP/1.1 \str\r\n"
.Lse_end_\@:
    .popsection
.endm

status_lookup_table:
    STATUS_ENTRY "200 OK"
    STATUS_ENTRY "201 Created"
    STATUS_ENTRY "204 No Content"
    STATUS_ENTRY "206 Partial Content"
    STATUS_ENTRY "301 Moved Permanently"
    STATUS_ENTRY "302 Found"
    STATUS_ENTRY "304 Not Modified"
    STATUS_ENTRY "400 Bad Request"
    STATUS_ENTRY "401 Unauthorized"
    STATUS_ENTRY "403 Forbidden"
    STATUS_ENTRY "404 Not Found"
    STATUS_ENTRY "405 Method Not Allowed"
    STATUS_ENTRY "413 Payload Too Large"
    STATUS_ENTRY "415 Unsupported Media Type"
    STATUS_ENTRY "416 Range Not Satisfiable"
    STATUS_ENTRY "429 Too Many Requests"
    STATUS_ENTRY "431 Request Header Fields Too Large"
    STATUS_ENTRY "500 Internal Server Error"
    STATUS_ENTRY "501 Not Implemented"
    STATUS_ENTRY "502 Bad Gateway"
    STATUS_ENTRY "503 Service Unavailable"
    STATUS_ENTRY "504 Gateway Timeout"

# ==============================================================================
# SYSCALL DEFINITIONS
# ==============================================================================
.equ SYS_READ,        0
.equ SYS_WRITE,       1
.equ SYS_CLOSE,       3
.equ SYS_FSTAT,       5
.equ SYS_WRITEV,     20
.equ SYS_SENDFILE,   40
.equ SYS_SOCKET,     41
.equ SYS_ACCEPT,     43
.equ SYS_BIND,       49
.equ SYS_LISTEN,     50
.equ SYS_SETSOCKOPT, 54
.equ SYS_FORK,       57
.equ SYS_EXIT,       60
.equ SYS_SCHED_SETAFFINITY, 203

# ==============================================================================
# CORE SYSCALL MACROS
# ==============================================================================

.macro SYS nr
    mov rax, \nr
    syscall
.endm

.macro SYS1 nr, a1
    mov rdi, \a1
    mov rax, \nr
    syscall
.endm

.macro SYS2 nr, a1, a2
    mov rdi, \a1
    mov rsi, \a2
    mov rax, \nr
    syscall
.endm

.macro SYS3 nr, a1, a2, a3
    mov rdi, \a1
    mov rsi, \a2
    mov rdx, \a3
    mov rax, \nr
    syscall
.endm

# ==============================================================================
# CONVENIENCE WRAPPERS
# ==============================================================================
.macro READ fd, buf, count
    SYS3 SYS_READ, \fd, \buf, \count
.endm

.macro WRITE fd, buf, count
    SYS3 SYS_WRITE, \fd, \buf, \count
.endm

.macro WRITEV fd, iov, iovcnt
    SYS3 SYS_WRITEV, \fd, \iov, \iovcnt
.endm

.macro FSTAT fd, stat_buf
    mov edi, \fd
    mov rsi, \stat_buf
    mov rax, SYS_FSTAT
    syscall
.endm

.macro CLOSE fd
    SYS1 SYS_CLOSE, \fd
.endm

# ------------------------------------------------------------------------------
# SETSOCKOPT_REUSEADDR sockfd
# Clobbers: rax, rdi, rsi, rdx, r10, r8, rcx, r11
# ------------------------------------------------------------------------------
.macro SETSOCKOPT_REUSEADDR sockfd
    push 1                              # Value = 1 (enable) on stack
    mov rdi, \sockfd                    # arg1: sockfd
    mov rsi, SOL_SOCKET                 # arg2: level (1)
    mov rdx, SO_REUSEADDR               # arg3: optname (2)
    mov r10, rsp                        # arg4: optval pointer (&1)
    mov r8, 4                           # arg5: optlen (sizeof(int) = 4)
    mov rax, SYS_SETSOCKOPT             # syscall 54
    syscall
    pop r8                              # Restore stack
.endm

.macro SOCKET domain, type, protocol
    SYS3 SYS_SOCKET, \domain, \type, \protocol
.endm

.macro ACCEPT sockfd, sockaddr_ptr=0, sockaddr_len_ptr=0
    SYS3 SYS_ACCEPT, \sockfd, \sockaddr_ptr, \sockaddr_len_ptr
.endm

# Use DEF_SOCKADDR_IN to define sockaddr_obj
.macro BIND sockfd, sockaddr_obj
    LOAD_ADDR r8, \sockaddr_obj
    SYS3 SYS_BIND, \sockfd, r8, \sockaddr_obj\()_len
.endm

.macro LISTEN sockfd
    SYS2 SYS_LISTEN, \sockfd, BACKLOG
.endm

.macro FORK
    SYS SYS_FORK
.endm

.macro SCHED_SETAFFINITY pid, cpusetsize, mask
    # sys_sched_setaffinity(pid=0, cpusetsize=128, mask=rsp)
    SYS3 SYS_SCHED_SETAFFINITY, \pid, \cpusetsize, \mask
.endm

.macro EXIT status
    SYS1 SYS_EXIT, \status
.endm

# ==============================================================================
# HTTP MACROS
# ==============================================================================

# ==============================================================================
# HTTP ROUTING ENGINE
# Dispatches incoming requests based on HTTP method and URI path.
# ==============================================================================

.section .text
.global _start
.global http_init

_start:
    call worker_event_loop

worker_event_loop:
    # Clear r15 (64-bit free-list for ring buffer)
    xor r15d, r15d

    # Create socket (r12 = server fd)
    SOCKET AF_INET, SOCK_STREAM, 0
    mov r12, rax

    # Allow immediate rebinding even if in TIME_WAIT
    SETSOCKOPT_REUSEADDR r12

    # Bind & listen to 0.0.0.0
    BIND r12, sockaddr_any
    LISTEN r12

    # 1. Accept connection (r13 = client fd)
    ACCEPT r12
    mov r13, rax

    # 2. Claim slot (0..63)
    call claim_slot
    cmp rax, -1
    je .Lfailed
    mov r14d, eax

    # 3. Resolve struct and wire buffer from slot_id
    call get_slot_ptrs                  # rax = req_struct, rdx = wire_buf
    mov r15, rdx                        # Stash wire_buf in r15 across calls

    # 4. Read HTTP request
    mov rdi, rax                        # rdi = struct pointer
    mov rsi, rdx                        # rsi = wire buffer
    mov edx, r13d                       # edx = client socket fd
    call http_read_request

    # Stash URI offset and length into callee-preserved registers
    movzx ebx, word ptr [rdi + REQ_OFF_URI_OFF] # URI start offset
    movzx r14d, word ptr [rdi + REQ_OFF_URI_LEN] # URI length

    # Open file: open(r15 + uri_off, O_RDONLY)
    # (Use [r15 + rbx + 1] if you want relative paths like 'etc/passwd')
    # 1. Point rdi to start of URI in the wire buffer
    lea rdi, [r15 + rbx]

    # 2. In-place null-terminate using two registers ([base + index])
    mov byte ptr [rdi + r14], 0

    # 3. open(rdi, O_RDONLY)
    xor esi, esi
    mov eax, 2
    syscall

    test eax, eax
    js .Lfailed
    mov r12d, eax                       # r12d = file fd

    # 4. sys_fstat(fd, statbuf) to obtain exact byte size
    sub rsp, 144                        # struct stat is 144 bytes on x86-64
    FSTAT r12d, rsp

    mov r14, [rsp + 48]                 # st_size is located at offset 48
    add rsp, 144                        # Clean up stat buffer

    # 5. Send headers with exact Content-Length, then stream the file
    HTTP_ALLOC
    HTTP_WRITE_STATUS_LINE 200, 11
    HTTP_WRITE_HEADER_KV "Server", "asmhttp"
    HTTP_WRITE_HEADER_KV "Content-Type", "text/plain"
    HTTP_SEND_FILE r13, r12, r14
    HTTP_DEALLOC

    # 6. Close both sock_fd and file_fd then exit
    CLOSE r12
    CLOSE r13
    EXIT 0

.Lfailed:
    # Quick 404 response
    HTTP_ALLOC
    HTTP_WRITE_STATUS_LINE 404, 11
    HTTP_SEND_BODY r13, "404 Not Found\n"
    HTTP_DEALLOC
    CLOSE r13
    EXIT 0

http_init:
    xor r14d, r14d                      # r14 = current core index (0..3)

.Lfork_workers:
    # If we already reached the last core, parent becomes that worker
    cmp r14d, WORKER_CORES - 1
    jge .Lworker_init

    FORK                               # Syscall 57
    test rax, rax
    jz .Lworker_init                   # Child runs as worker r14

    # Parent advances to next core and continues spawning
    inc r14d
    jmp .Lfork_workers

.Lworker_init:
    # 1. Pin worker process to CPU core r14
    # Create 128-byte cpu_set_t bitmask on stack
    sub rsp, 128
    # Zero out the mask
    xor eax, eax
    mov ecx, 16
    mov rdi, rsp
    rep stosq

    # Set the bit corresponding to our core (1 << r14)
    bts [rsp], r14

    # sys_sched_setaffinity(pid=0, cpusetsize=128, mask=rsp)
    SCHED_SETAFFINITY 0, 128, rsp
    add rsp, 128

    # 2. Worker now runs its own private network setup
    # Open socket, set SO_REUSEPORT, bind to port 80, and run the accept loop
    jmp worker_event_loop

# ------------------------------------------------------------------------------
# itoa(u64 val)
# Writes ASCII representation of rsi directly into [rdi] and advances rdi.
# In:
#   rsi = unsigned 64-bit integer
#   rdi = write head pointer
# Out:
#   rdi = updated write head (pointing to next free byte)
# Clobbers: rax, rcx, rdx, r8
# ------------------------------------------------------------------------------
itoa:
    mov rax, rsi                        # Value to convert
    mov r8, rsp                         # Anchor stack pointer
    mov ecx, 10

.Lextract_loop:
    xor edx, edx
    div rcx                             # TODO: div too slow!
    add dl, '0'                         # Convert to ASCII
    dec rsp
    mov [rsp], dl                       # Push signle byte to stack
    test rax, rax
    jnz .Lextract_loop

.Lflush_loop:
    mov al, [rsp]
    mov [rdi], al                       # Read bytes in correct forward order
    inc rdi                             # Write to buffer
    inc rsp                             # Advance write head
    cmp rsp, r8
    jne .Lflush_loop

    ret

# ------------------------------------------------------------------------------
# http_send_response(fd, header_buf, header_len, body_buf, body_len)
# In:
#   rdi = client_fd
#   rsi = header buffer pointer
#   rdx = header length
#   rcx = body buffer pointer
#   r8  = body length
# Clobbers: rax, rcx, r11 (syscall)
# ------------------------------------------------------------------------------
http_send_response:
    sub rsp, 32                         # 32 bytes for struct iovec[2]

    # iov[0] = Header
    mov [rsp + 0], rsi
    mov [rsp + 8], rdx

    # iov[1] = Body
    mov [rsp + 16], rcx
    mov [rsp + 24], r8

    # sys_writev(fd, iov, 2)
    WRITEV rdi, rsp, 2

    add rsp, 32
    ret

# ------------------------------------------------------------------------------
# claim_slot -> rax (slot_id: 0..63, or -1 if full)
# Clobbers: rdx
# ------------------------------------------------------------------------------
claim_slot:
    mov rax, [rip + active_mask]
    not rax                             # Invert: 1s are now FREE slots
    test rax, rax
    jz .Lserver_busy                    # All 64 slots are occupied (HTTP 503)

    tzcnt rdx, rax                      # rdx = index of first available free bit (0..63)

    # Because asmhttp runs multi-core and not multi-threaded,
    # we don't need any atomic operations!

    bts rax, rdx                        # 1 cycle: mark slot busy in register
    mov [rip + active_mask], rax        # Store updated mask to .bss

    mov rax, rdx                        # rax = claimed slot_id (0..63)
    ret

# ------------------------------------------------------------------------------
# release_slot(slot_id)
# In: rdi = slot_id (0..63)
# ------------------------------------------------------------------------------
release_slot:
    mov rax, [rip + active_mask]
    btr rax, rdi                                 # Reset bit to 0 (mark free)
    mov [rip + active_mask], rax
    ret

# ------------------------------------------------------------------------------
# get_slot_ptrs(slot_id) -> rax (req_struct*), rdx (wire_buf*)
# In:  rax = slot_id (0..63)
# Out: rax = pointer to http_request struct
#      rdx = pointer to 2 KB wire buffer
# Clobbers: rax, rdx
# ------------------------------------------------------------------------------
get_slot_ptrs:
    mov rdx, rax

    # 1. Struct pointer: base + (slot_id * 64)
    shl rax, 6
    lea r8, [rip + req_structs]
    add r8, rax

    # 2. Wire buffer pointer: base + (slot_id * 2048)
    shl rdx, 11
    lea r9, [rip + req_buffers]
    add r9, rdx

    mov rax, r8
    mov rdx, r9

    ret

.Lserver_busy:
    mov rax, -1
    ret

# ------------------------------------------------------------------------------
# http_read_request(http_request *req, char *wire_buf, int client_fd)
# In:
#   rdi = pointer to 64-byte http_request struct target
#   rsi = pointer to wire buffer receiving raw network data
#   edx = client socket file descriptor (client_fd)
# Out:
#   rax = 64-bit parsed flags mask (or -1 on disconnect / socket fault)
#   rdi = restored pointer to http_request struct base
# Preserves:
#   rbx, r12, r13, r14, r15
# ------------------------------------------------------------------------------
http_read_request:
    push rbx
    push r12
    push r13
    push r14
    push r15

    mov r12, rdi                        # r12 = struct base pointer
    mov r13, rsi                        # r13 = wire buffer base pointer
    mov r14d, edx                       # r14d = client_fd

    # --------------------------------------------------------------------------
    # 1. Read wire data from client socket
    # --------------------------------------------------------------------------
    READ r14, r13, MAX_REQUEST_SIZE

    test rax, rax
    jle .Lread_error                    # <= 0: client disconnect or socket fault
    mov r15, rax                        # r15 = total bytes read

    # --------------------------------------------------------------------------
    # 2. Fast Zero the 64-byte struct (1 cache line)
    # --------------------------------------------------------------------------
    xor eax, eax
    mov qword ptr [r12 + 0],  rax
    mov qword ptr [r12 + 8],  rax
    mov qword ptr [r12 + 16], rax
    mov qword ptr [r12 + 24], rax
    mov qword ptr [r12 + 32], rax
    mov qword ptr [r12 + 40], rax
    mov qword ptr [r12 + 48], rax
    mov qword ptr [r12 + 56], rax

    # Store client_fd directly into struct
    mov dword ptr [r12 + REQ_OFF_CLIENT_FD], r14d

    # Setup parser cursors
    mov rsi, r13                        # rsi = current scan cursor
    lea r14, [r13 + r15]                # r14 = buffer end boundary (r13 + bytes)

    # --------------------------------------------------------------------------
    # 3. Parse HTTP Method
    # --------------------------------------------------------------------------
    mov eax, [rsi]

.Lcheck_get:
    # "GET " (0x20544547)
    cmp eax, 0x20544547
    jne .Lcheck_post
    or qword ptr [r12 + REQ_OFF_FLAGS], REQ_METHOD_GET
    add rsi, 4
    jmp .Lparse_uri

.Lcheck_post:
    # "POST" (0x54534f50) + ' '
    cmp eax, 0x54534f50
    jne .Lcheck_head
    cmp byte ptr [rsi + 4], ' '
    jne .Lcheck_head
    or qword ptr [r12 + REQ_OFF_FLAGS], REQ_METHOD_POST
    add rsi, 5
    jmp .Lparse_uri

.Lcheck_head:
    # "HEAD" (0x44414548) + ' '
    cmp eax, 0x44414548
    jne .Lcheck_put
    cmp byte ptr [rsi + 4], ' '
    jne .Lcheck_put
    or qword ptr [r12 + REQ_OFF_FLAGS], REQ_METHOD_HEAD
    add rsi, 5
    jmp .Lparse_uri

.Lcheck_put:
    # "PUT " (0x20545550)
    cmp eax, 0x20545550
    jne .Lcheck_delete
    or qword ptr [r12 + REQ_OFF_FLAGS], REQ_METHOD_PUT
    add rsi, 4
    jmp .Lparse_uri

.Lcheck_delete:
    # "DELE" (0x454c4544) + "TE "
    cmp eax, 0x454c4544
    jne .Lcheck_options
    cmp word ptr [rsi + 4], 0x4554       # 'T', 'E'
    jne .Lcheck_options
    cmp byte ptr [rsi + 6], ' '
    jne .Lcheck_options
    or qword ptr [r12 + REQ_OFF_FLAGS], REQ_METHOD_DELETE
    add rsi, 7
    jmp .Lparse_uri

.Lcheck_options:
    # "OPTI" (0x4954504f) + "ONS "
    cmp eax, 0x4954504f
    jne .Lcheck_patch
    cmp dword ptr [rsi + 4], 0x20534e4f  # 'O', 'N', 'S', ' '
    jne .Lcheck_patch
    or qword ptr [r12 + REQ_OFF_FLAGS], REQ_METHOD_OPTIONS
    add rsi, 8
    jmp .Lparse_uri

.Lcheck_patch:
    # "PATC" (0x43544150) + "H "
    cmp eax, 0x43544150
    jne .Lunknown_method
    cmp word ptr [rsi + 4], 0x2048       # 'H', ' '
    jne .Lunknown_method
    or qword ptr [r12 + REQ_OFF_FLAGS], REQ_METHOD_PATCH
    add rsi, 6
    jmp .Lparse_uri

.Lunknown_method:
    or qword ptr [r12 + REQ_OFF_FLAGS], REQ_METHOD_UNKNOWN
.Lskip_unknown_method:
    cmp rsi, r14
    jae .Lparse_abort
    lodsb                               # TODO: mov al, [rsi]; inc rsi might be faster
    cmp al, ' '
    jne .Lskip_unknown_method

    # --------------------------------------------------------------------------
    # 4. Parse URI & Query Strings
    # --------------------------------------------------------------------------
.Lparse_uri:
    # rsi points to start of URI
    mov rax, rsi
    sub rax, r13                        # rax = 16-bit uri_off
    mov [r12 + REQ_OFF_URI_OFF], ax

    mov rbx, rsi                        # rbx = anchor for URI start
    xor edx, edx                        # edx tracks query start (0 if none)

.Lscan_uri_loop:
    cmp rsi, r14
    jae .Lparse_abort
    mov al, [rsi]

    cmp al, ' '
    je .Luri_end
    cmp al, '?'
    jne .Lcheck_dot_traversal

    # Hit '?' query delimiter
    # TODO: probably even store as error instead of ignoring duplicate '?'
    test edx, edx
    jnz .Lskip_char                     # Ignore duplicate '?'

    # Calculate and store path length (stops right before '?')
    mov rcx, rsi
    sub rcx, rbx
    mov [r12 + REQ_OFF_URI_LEN], cx

    lea rdx, [rsi + 1]                  # rdx = query start address
    sub rdx, r13                        # 16-bit offset from buffer start
    mov [r12 + REQ_OFF_QUERY_OFF], dx
    SET_REQ_FLAG REQ_F_HAS_QUERY
    jmp .Lskip_char

.Lcheck_dot_traversal:
    # Path traversal check: check for "../"
    cmp al, '.'
    jne .Lskip_char
    cmp byte ptr [rsi + 1], '.'
    jne .Lskip_char
    cmp byte ptr [rsi + 2], '/'
    jne .Lskip_char
    SET_REQ_FLAG REQ_F_ERR_BAD_URI

.Lskip_char:
    inc rsi
    jmp .Lscan_uri_loop

.Luri_end:
    # If no '?' was found, calculate uri_len up to the space
    test edx, edx
    jnz .Lrecord_query_len
    mov rcx, rsi
    sub rcx, rbx
    mov [r12 + REQ_OFF_URI_LEN], cx
    jmp .Lfast_path_routes

.Lrecord_query_len:
    # Calculate query length: cursor - (r13 + query_off)
    mov rcx, rsi
    sub rcx, r13
    sub cx, [r12 + REQ_OFF_QUERY_OFF]
    mov [r12 + REQ_OFF_QUERY_LEN], cx

.Lfast_path_routes:
    # Fast path: check if path is root "/"
    movzx ecx, word ptr [r12 + REQ_OFF_URI_LEN]
    cmp ecx, 1
    jne .Lcheck_api_prefix
    cmp byte ptr [rbx], '/'
    jne .Lcheck_version
    SET_REQ_FLAG REQ_F_PATH_IS_ROOT
    jmp .Lcheck_version

.Lcheck_api_prefix:
    cmp ecx, 5
    jl .Lcheck_static_prefix
    cmp dword ptr [rbx], 0x6970612f     # "/api"
    jne .Lcheck_static_prefix
    cmp byte ptr [rbx + 4], '/'
    jne .Lcheck_static_prefix
    SET_REQ_FLAG REQ_F_PATH_IS_API

.Lcheck_static_prefix:
    cmp ecx, 8
    jl .Lcheck_version
    # Check for "/static/"
    mov rax, 0x2f6369746174732f
    cmp [rbx], rax
    jne .Lcheck_version
    SET_REQ_FLAG REQ_F_PATH_IS_STATIC

    # --------------------------------------------------------------------------
    # 5. Parse HTTP Protocol Version
    # --------------------------------------------------------------------------
.Lcheck_version:
    inc rsi                             # Skip space
    cmp rsi, r14
    jae .Lparse_abort

    mov rax, [rsi]
    # "HTTP/1.1" (0x312e312f50545448)
    mov rbx, 0x312e312f50545448
    cmp rax, rbx
    jne .Lcheck_http_10
    SET_REQ_FLAG (REQ_VER_11 | REQ_F_KEEPALIVE)
    add rsi, 8
    jmp .Lfind_first_crlf

.Lcheck_http_10:
    # "HTTP/1.0" (0x302e312f50545448)
    mov rbx, 0x302e312f50545448
    cmp rax, rbx
    jne .Lcheck_http_20
    or qword ptr [r12 + REQ_OFF_FLAGS], REQ_VER_10
    add rsi, 8
    jmp .Lfind_first_crlf

.Lcheck_http_20:
    # "HTTP/2.0" or "HTTP/2 "
    cmp dword ptr [rsi], 0x50545448     # "HTTP"
    jne .Lbad_version
    or qword ptr [r12 + REQ_OFF_FLAGS], REQ_VER_20
    jmp .Lfind_first_crlf

.Lbad_version:
    SET_REQ_FLAG REQ_F_ERR_BAD_VERSION

.Lfind_first_crlf:
    cmp rsi, r14
    jae .Lparse_abort
    cmp word ptr [rsi], 0x0a0d          # Find \r\n
    je .Lfirst_line_done
    inc rsi
    jmp .Lfind_first_crlf

.Lfirst_line_done:
    add rsi, 2                          # Skip \r\n

    # --------------------------------------------------------------------------
    # 6. Parse Header Lines Loop
    # --------------------------------------------------------------------------
.Lheader_loop:
    cmp rsi, r14
    jae .Lheaders_finished

    # Check for empty line (\r\n) indicating end of headers
    cmp word ptr [rsi], 0x0a0d
    je .Lheaders_finished

    # Read first 4 bytes for magic matching
    mov eax, [rsi]

    # --- Match "Host:" / "host:" ---
    cmp eax, 0x74736f48                 # "Host"
    je .Lmatch_host
    cmp eax, 0x74736f68                 # "host"
    je .Lmatch_host

    # --- Match "Conn" (Connection) ---
    cmp eax, 0x6e6e6f43                 # "Conn"
    je .Lmatch_connection
    cmp eax, 0x6e6e6f63                 # "conn"
    je .Lmatch_connection

    # --- Match "Cont" (Content-Length / Content-Type) ---
    cmp eax, 0x746e6543                 # "Cont"
    je .Lmatch_content
    cmp eax, 0x746e6563                 # "cont"
    je .Lmatch_content

    # --- Match "User" (User-Agent) ---
    cmp eax, 0x72657355                 # "User"
    je .Lmatch_ua
    cmp eax, 0x72657375                 # "user"
    je .Lmatch_ua

    # --- Match "Cook" (Cookie) ---
    cmp eax, 0x6b6f6f43                 # "Cook"
    je .Lmatch_cookie
    cmp eax, 0x6b6f6f63                 # "cook"
    je .Lmatch_cookie

    # --- Match "Auth" (Authorization) ---
    cmp eax, 0x68747541                 # "Auth"
    je .Lmatch_auth
    cmp eax, 0x68747561                 # "auth"
    je .Lmatch_auth

    # --- Match "Refe" (Referer) ---
    cmp eax, 0x65666552                 # "Refe"
    je .Lmatch_referer
    cmp eax, 0x65666572                 # "refe"
    je .Lmatch_referer

    # --- Match "Acce" (Accept / Accept-Encoding) ---
    cmp eax, 0x65636341                 # "Acce"
    je .Lmatch_accept
    cmp eax, 0x65636361                 # "acce"
    je .Lmatch_accept

    # --- Match "Tran" (Transfer-Encoding) ---
    cmp eax, 0x6e617254                 # "Tran"
    je .Lmatch_transfer_encoding

    # --- Fallback: Unknown Header ---
    jmp .Lhandle_other_header

# ------------------------------------------------------------------------------
# Header Extractors
# ------------------------------------------------------------------------------
.Lmatch_host:
    cmp byte ptr [rsi + 4], ':'
    jne .Lhandle_other_header
    TEST_REQ_FLAG REQ_F_HAS_HOST
    jnz .Lerr_multi_host
    SET_REQ_FLAG REQ_F_HAS_HOST
    add rsi, 5
    call .Lextract_val
    mov [r12 + REQ_OFF_HOST_OFF], ax
    mov [r12 + REQ_OFF_HOST_LEN], dx
    jmp .Lheader_loop

.Lerr_multi_host:
    SET_REQ_FLAG REQ_F_ERR_MULTI_HOST
    jmp .Lskip_to_crlf

.Lmatch_connection:
    # Skip past "Connection:"
    add rsi, 11
    call .Lextract_val
    # Inspect first 4 bytes of value
    mov eax, [r13 + rax]
    cmp eax, 0x736f6c63                 # "clos" (close)
    jne .Lcheck_upgrade
    SET_REQ_FLAG REQ_F_CLOSE
    CLEAR_REQ_FLAG REQ_F_KEEPALIVE
    jmp .Lheader_loop

.Lcheck_upgrade:
    cmp eax, 0x72677055                 # "Upgr" (Upgrade)
    jne .Lheader_loop
    SET_REQ_FLAG REQ_F_UPGRADE
    jmp .Lheader_loop

.Lmatch_content:
    # Differentiate Content-Length vs Content-Type
    # "ent-Length:" = 11 bytes past "Cont"
    cmp dword ptr [rsi + 4], 0x2d746e65 # "ent-"
    jne .Lhandle_other_header

    cmp dword ptr [rsi + 8], 0x676e654c # "Leng"
    je .Lis_content_length
    cmp dword ptr [rsi + 8], 0x65707954 # "Type"
    je .Lis_content_type
    jmp .Lhandle_other_header

.Lis_content_length:
    add rsi, 15                         # Skip "Content-Length:"
    call .Lextract_val
    # Parse decimal ASCII string at [r13 + rax] into integer
    lea rbx, [r13 + rax]
    movzx ecx, dx
    call .Lparse_int
    mov [r12 + REQ_OFF_BODY_LEN], eax
    SET_REQ_FLAG REQ_F_HAS_BODY

    cmp eax, MAX_BODY_SIZE
    jbe .Lheader_loop
    SET_REQ_FLAG REQ_F_ERR_BODY_LARGE
    jmp .Lheader_loop

.Lis_content_type:
    add rsi, 13                         # Skip "Content-Type:"
    call .Lextract_val
    mov [r12 + REQ_OFF_CT_OFF], ax
    mov [r12 + REQ_OFF_CT_LEN], dx
    SET_REQ_FLAG REQ_F_HAS_CT

    # Check for application/json ("appl")
    mov eax, [r13 + rax]
    cmp eax, 0x6c707061
    jne .Lheader_loop
    SET_REQ_FLAG REQ_F_CT_JSON
    jmp .Lheader_loop

.Lmatch_ua:
    add rsi, 11                         # Skip "User-Agent:"
    call .Lextract_val
    mov [r12 + REQ_OFF_UA_OFF], ax
    mov [r12 + REQ_OFF_UA_LEN], dx
    SET_REQ_FLAG REQ_F_HAS_UA
    jmp .Lheader_loop

.Lmatch_cookie:
    add rsi, 7                          # Skip "Cookie:"
    call .Lextract_val
    mov [r12 + REQ_OFF_COOKIE_OFF], ax
    mov [r12 + REQ_OFF_COOKIE_LEN], dx
    SET_REQ_FLAG REQ_F_HAS_COOKIE
    jmp .Lheader_loop

.Lmatch_auth:
    add rsi, 14                         # Skip "Authorization:"
    call .Lextract_val
    mov [r12 + REQ_OFF_AUTH_OFF], ax
    mov [r12 + REQ_OFF_AUTH_LEN], dx
    SET_REQ_FLAG REQ_F_HAS_AUTH
    jmp .Lheader_loop

.Lmatch_referer:
    add rsi, 8                          # Skip "Referer:"
    call .Lextract_val
    mov [r12 + REQ_OFF_REF_OFF], ax
    mov [r12 + REQ_OFF_REF_LEN], dx
    SET_REQ_FLAG REQ_F_HAS_REFERER
    jmp .Lheader_loop

.Lmatch_accept:
    add rsi, 7                          # Skip "Accept:"
    call .Lextract_val
    SET_REQ_FLAG REQ_F_HAS_ACCEPT
    jmp .Lheader_loop

.Lmatch_transfer_encoding:
    add rsi, 18                         # Skip "Transfer-Encoding:"
    call .Lextract_val
    mov eax, [r13 + rax]
    cmp eax, 0x6e756863                 # "chun" (chunked)
    jne .Lheader_loop
    SET_REQ_FLAG REQ_F_CHUNKED
    jmp .Lheader_loop

.Lhandle_other_header:
    # Bounds check against compile-time cap
    movzx eax, word ptr [r12 + REQ_OFF_OTHER_CNT]
    cmp eax, MAX_OTHER_HDRS
    jae .Lhdr_limit_exceeded

    # Check if other_hdrs_ptr was configured
    mov rdi, [r12 + REQ_OFF_OTHER_PTR]
    test rdi, rdi
    jz .Lskip_to_crlf

    # Record 4-byte slice: [offset: 16-bit, len: 16-bit]
    mov rbx, rsi
    sub rbx, r13                        # 16-bit line offset
    call .Lskip_to_crlf_len             # Returns line len in ecx

    shl ecx, 16
    or ecx, ebx                         # Pack: (len << 16) | offset
    mov [rdi + rax * 4], ecx
    inc word ptr [r12 + REQ_OFF_OTHER_CNT]
    jmp .Lheader_loop

.Lhdr_limit_exceeded:
    SET_REQ_FLAG REQ_F_ERR_HDR_LIMIT

.Lskip_to_crlf:
    cmp rsi, r14
    jae .Lheaders_finished
    cmp word ptr [rsi], 0x0a0d
    je .Ladvance_crlf
    inc rsi
    jmp .Lskip_to_crlf
.Ladvance_crlf:
    add rsi, 2
    jmp .Lheader_loop

# ------------------------------------------------------------------------------
# 7. Finalize & RFC 9112 Validation
# ------------------------------------------------------------------------------
.Lheaders_finished:
    add rsi, 2                          # Skip final \r\n

    # Record body offset
    mov rax, rsi
    sub rax, r13
    mov [r12 + REQ_OFF_BODY_OFF], eax

    # RFC 9112 Section 6.1: Reject request smuggling
    # If BOTH Chunked and Content-Length exist, trip error flag
    TEST_REQ_FLAG REQ_F_CHUNKED
    jz .Lfinalize_return
    TEST_REQ_FLAG REQ_F_HAS_BODY
    jz .Lfinalize_return
    SET_REQ_FLAG REQ_F_ERR_SMUGGLING

.Lfinalize_return:
    mov rax, [r12 + REQ_OFF_FLAGS]      # Return flags in rax

.Lparse_abort:
    mov rdi, r12                        # Restore pointer to struct base
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

.Lread_error:
    mov rdi, r12                        # Restore pointer to struct base
    mov rax, -1
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

# ------------------------------------------------------------------------------
# Helper: .Lextract_val
# Skips leading spaces, finds \r\n, returns:
#   rax = 16-bit value offset
#   rdx = 16-bit value length
# Advances rsi past \r\n
# ------------------------------------------------------------------------------
.Lextract_val:
    # Skip spaces
.Lskip_sp:
    cmp byte ptr [rsi], ' '
    jne .Lstart_val
    inc rsi
    jmp .Lskip_sp

.Lstart_val:
    mov rax, rsi
    sub rax, r13                        # rax = offset

    mov rbx, rsi
.Lfind_end:
    cmp rsi, r14
    jae .Lval_at_end
    cmp word ptr [rsi], 0x0a0d
    je .Lfound_end
    inc rsi
    jmp .Lfind_end

.Lfound_end:
    mov rdx, rsi
    sub rdx, rbx                        # rdx = length
    add rsi, 2                          # Advance past \r\n
    ret

.Lval_at_end:
    mov rdx, rsi
    sub rdx, rbx
    ret

# ------------------------------------------------------------------------------
# Helper: .Lskip_to_crlf_len
# Advances rsi to next \r\n, returns line length in ecx
# ------------------------------------------------------------------------------
.Lskip_to_crlf_len:
    mov rbx, rsi
.Llen_loop:
    cmp rsi, r14
    jae .Llen_done
    cmp word ptr [rsi], 0x0a0d
    je .Llen_found
    inc rsi
    jmp .Llen_loop
.Llen_found:
    mov rcx, rsi
    sub rcx, rbx
    add rsi, 2
    ret
.Llen_done:
    mov rcx, rsi
    sub rcx, rbx
    ret

# ------------------------------------------------------------------------------
# Helper: .Lparse_int (Fast Base-10 ATOI)
# In:  rbx = pointer to ASCII string, ecx = length
# Out: eax = unsigned integer value
# ------------------------------------------------------------------------------
.Lparse_int:
    xor eax, eax
.Latoi_loop:
    test ecx, ecx
    jz .Latoi_done
    movzx edx, byte ptr [rbx]
    sub edx, '0'
    cmp edx, 9
    ja .Latoi_done
    imul eax, eax, 10
    add eax, edx
    inc rbx
    dec ecx
    jmp .Latoi_loop
.Latoi_done:
    ret
