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

# TODO: remove? Actually useless.
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
.macro DEF_HTTP_RESP_OLD name, header_buf, header_len, body_buf=0, body_len=0, status=200, flags=(CT_HTML | FLAG_KEEPALIVE), ver=11
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

# ------------------------------------------------------------------------------
# MACRO: HTTP_INIT_RESP size=256
# Reserves an aligned scratchpad on the stack and sets rdi as the write head.
# size MUST be a multiple of 16 to preserve ABI stack alignment!
# ------------------------------------------------------------------------------
.macro HTTP_INIT_RESP size=256
    sub rsp, \size
    mov rdi, rsp
.endm

# ------------------------------------------------------------------------------
# MACRO: HTTP_SEND_RESP fd, body_ptr, body_len, alloc_size=256
# Computes header length, binds pointers to sys_writev, calls the sender,
# and cleans up the stack scratchpad immediately after sending.
# ------------------------------------------------------------------------------
.macro HTTP_SEND_RESP fd, body_ptr, body_len, alloc_size=256
    # 1. Compute header length before touching rdi
    mov rdx, rdi
    sub rdx, rsp                        # rdx = header length (bytes written)

    # 2. Setup arguments for http_send_response
    mov rsi, rsp                        # rsi = header buffer
    mov rdi, \fd                        # rdi = client socket fd
    mov rcx, \body_ptr                  # rcx = body pointer
    mov r8, \body_len                   # r8 = body length

    call http_send_response

    # 3. Release scratchpad from stack AFTER sending
    add rsp, \alloc_size
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

msg_hello: .ascii "hello"
.equ msg_hello_len, . - msg_hello

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
scratchpad:  .zero 65536            # 64 KB ring-buffer for requests

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

    # --------------------------------------------------------------------------
    # Clean Response Lifecycle
    # --------------------------------------------------------------------------
    # 1. Allocate 256-byte scratchpad & set rdi = rsp
    HTTP_INIT_RESP 256

    # 2. Stream headers lineraly to [rdi]
    HTTP_WRITE_STATUS_LINE 200, 11
    HTTP_WRITE_HEADER_KV "Server", "asm-core"
    HTTP_WRITE_HEADER_KV "Content-Type", "text/plain"
    HTTP_WRITE_CONTENT_LENGTH msg_hello_len
    HTTP_WRITE_HEADER_END

    # 3. Fire writev and immediately release the 256-byte stack frame
    LOAD_ADDR rax, msg_hello
    HTTP_SEND_RESP r13, rax, msg_hello_len, 256

    # 4. Close connection
    CLOSE r13

    # Exit program
    EXIT 0

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
    mov [rsp], al                       # Push signle byte to stack
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
# ------------------------------------------------------------------------------
http_parse_method:
    ret
