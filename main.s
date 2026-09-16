.intel_syntax noprefix

# ==============================================================================
# SYSCALL DEFINITIONS
# ==============================================================================
.equ SYS_READ,       0
.equ SYS_WRITE,      1
.equ SYS_CLOSE,      3
.equ SYS_WRITEV,    20
.equ SYS_SOCKET,    41
.equ SYS_ACCEPT,    43
.equ SYS_BIND,      49
.equ SYS_LISTEN,    50
.equ SYS_FORK,      57
.equ SYS_EXIT,      60

.equ AF_INET,        2
.equ SOCK_STREAM,    1
.equ INADDR_ANY,     0

# ==============================================================================
# GLOBAL CONSTANTS
# ==============================================================================
.equ BACKLOG,        0

# ==============================================================================
# STRUCTS
# ==============================================================================

# ------------------------------------------------------------------------------
# STRUCT: http_request_pair (24 bytes, natural alignment)
# Tuple containing k/v pair.
# ------------------------------------------------------------------------------
# Offset | Size | Field       | Description
# -------+------+-------------+-------------------------------------------------
# +0     | 8    | key         | 64-bit Pointer to key buf (.quad)
# +8     | 8    | value       | 64-bit Pointer to value buf (.quad)
# +16    | 4    | key_len     | 32-bit Integer for key length (.long)
# +20    | 4    | value_len   | 32-bit Integer for value length (.long)
# ------------------------------------------------------------------------------

# ==============================================================================
# STRUCT OFFSETS: http_request_pair
# ==============================================================================
.equ PAIR_OFF_KEY,       0
.equ PAIR_OFF_VALUE,     8
.equ HEAD_PAIR_SIZE,    16

# ------------------------------------------------------------------------------
# MACRO: DEF_HTTP_HEAD_PAIR name, key, key_len, value, value_len
# Emits a 24-byte http_request_pair struct.
# ------------------------------------------------------------------------------
.macro DEF_HTTP_HEAD_PAIR name, key, key_len, value, value_len
\name:
    .quad \key                          # +0: 64-bit Pointer to key buf
    .quad \value                        # +8: 64-bit Pointer to value buf
    .long \key_len                      # +16: 32-bit Integer for key length
    .long \value_len                    # +20: 32-bit Integer for value length
.equ \name\()_len, 24
.endm

# ------------------------------------------------------------------------------
# STRUCT: http_response (32 bytes, natural alignment)
# Offset | Size | Field       | Description
# -------+------+-------------+-------------------------------------------------
# +0     | 8    | header_buf  | 64-bit Pointer to response header buf (.quad)
# +8     | 8    | resp_buf    | 64-bit Pointer to response buffer (.quad)
# +16    | 4    | header_len  | 32-bit length of header buf (.long)
# +20    | 4    | resp_len    | 32-bit length of buffer in bytes (.long)
# +24    | 2    | status_code | 16-bit HTTP status code (e.g. 200) (.word)
# +26    | 2    | http_ver    | 16-bit HTTP version (e.g., 11 or 21) (.word)
# +28    | 4    | flags       | 32-bit Bitmask (Keep-Alive, Sendfile, etc.) (.long)
# ------------------------------------------------------------------------------

# ==============================================================================
# STRUCT OFFSETS: http_response
# ==============================================================================
.equ RESP_OFF_HEADER,   0
.equ RESP_OFF_BUF,      8
.equ RESP_OFF_HEADLEN, 16
.equ RESP_OFF_LEN,     20
.equ RESP_OFF_STATUS,  24
.equ RESP_OFF_HTTPV,   26
.equ RESP_OFF_FLAGS,   28
.equ HTTP_RESP_SIZE,   32

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
# MACRO: DEF_HTTP_RESP
# Arguments:
#   name:        Label for the 32-Byte Struct
#   header_buf:  Pointer to header buf
#   header_len:  Length of header buffer
#   body_buf:    Pointer to body (or fd for FLAG_SENDFILE)
#   body_len:    Length of body buffer (0 for FLAG_SENDFILE / ignored)
#   status:      HTTP Status Code (Default: 200)
#   flags:       Combined Bitmaske (Default: CT_HTML | FLAG_KEEPALIVE)
#   ver:         HTTP Version (Default: 11 for HTTP/1.1, 10 for 1.0)
# ------------------------------------------------------------------------------
.macro DEF_HTTP_RESP name, header_buf, header_len, body_buf=0, body_len=0, status=200, flags=(CT_HTML | FLAG_KEEPALIVE), ver=11
\name:
    .quad \header_buf                   # +0:  Pointer to header_buf
    .quad \body_buf                     # +8:  Pointer to body_buf OR fd (on FLAG_SENDFILE)
    .long \header_len                   # +16: header_len
    .long \body_len                     # +20: body_len
    .word \status                       # +24: status_code (e.g., 200, 404)
    .word \ver                          # +26: http_ver (e.g., 10, 11, 21)
    .long \flags                        # +28: flags bitmask
.equ \name\()_len, 32
.endm

# ==============================================================================
# OPERATIONAL MACROS
# ==============================================================================

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

# Default Response (200 OK)
DEF_HTTP_HEADER raw_200_header, 0
BUILD_HTTP_RESP resp_200, 200, raw_200_header, 0
DEF_HTTP_RESP resp_ok, raw_200, raw_200_len, 200

# ==============================================================================
# BSS DATA
# ==============================================================================

# Ring buffer: divided into 64 1024-byte-sized blocks.
# Free-list tracked in r15 (check out _start)
.section .bss
.align 64                           # Cache alignment prevents false sharing!
spsc_head:   .quad 0                # Head of ring buffer (producer-offset)
.align 64
spsc_tail:   .quad 0                # Tail of ring buffer (consumer-offset)
.align 16
ring_buffer: .zero 65536            # 64 KB ring-buffer for requests

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

.macro CLOSE fd
    SYS1 SYS_CLOSE, \fd
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

.macro EXIT status
    SYS1 SYS_EXIT, \status
.endm

# ==============================================================================
# HTTP MACROS
# ==============================================================================

# ------------------------------------------------------------------------------
# MACRO: WRITE_RESP fd, http_response_reg
# Writes resp_buf to client fd using length from http_response struct.
#
# Arguments:
#   fd:                 Client socket FD (e.g. r13)
#   http_response_reg:  Register holding pointer to http_response struct
# ------------------------------------------------------------------------------
.macro WRITE_RESP fd, http_response_reg
    LOAD_ADDR rax, \http_response_reg
    mov rdi, \fd
    mov rsi, [rax + RESP_OFF_BUF]
    mov edx, [rax + RESP_OFF_LEN]
    mov rax, SYS_WRITE
    syscall
.endm

# ==============================================================================
# HTTP ROUTING ENGINE
# Dispatches incoming requests based on HTTP method and URI path.
# ==============================================================================

.section .text
.global _start

_start:
    # Clear r15 (64-bit free-list for ring buffer)
    xor r15d, r15d

    # Create socket (r12 = server fd)
    SOCKET AF_INET, SOCK_STREAM, 0
    mov r12, rax

    # Bind & listen to 0.0.0.0
    BIND r12, sockaddr_any
    LISTEN r12

    # Accept connection (r13 = client fd)
    ACCEPT r12
    mov r13, rax

    # Read request into scratchpad
    LOAD_ADDR rsi, scratchpad
    READ r13, rsi, 1024

    # Write 200 OK
    WRITE_RESP r13, resp_ok

    # Close connection
    CLOSE r13

    # Exit program
    EXIT 0

# ------------------------------------------------------------------------------
# http_parse_method
# Extracts the HTTP verb (GET, POST, etc.) from the raw request buffer.
#
# In:
#   rdi = pointer to start of raw request buffer
#   rsi = length of buffer in bytes
#
# Out:
#   rax = method enum (1=GET, 2=POST, -1=UNKNOWN)
#   rdx = offset to first character of request path
#
# Clobbers:
#   rcx, r8, r9
#
# Preserves:
#   r12 - r15, rbx (SysV ABI compliant)
# ------------------------------------------------------------------------------
http_parse_method:
    ret
