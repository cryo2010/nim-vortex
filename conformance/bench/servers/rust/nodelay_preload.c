/* LD_PRELOAD shim: set TCP_NODELAY on every accepted socket.
 *
 * salvo 0.77 doesn't set TCP_NODELAY and seals its Acceptor trait, so it can't be
 * done in-code (see src/main.rs). Without it, an HTTP/2 response's HEADERS + DATA
 * frames get held ~40ms by Nagle + delayed-ACK. Intercepting accept/accept4 sets
 * nodelay on the raw fd right after accept, before rustls wraps it -- so it applies
 * to h2 too. Only affects TCP accepts; the QUIC/h3 UDP path is untouched.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

static void set_nodelay(int fd) {
    if (fd >= 0) {
        int one = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    }
}

int accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags) {
    static int (*real)(int, struct sockaddr *, socklen_t *, int) = 0;
    if (!real) real = dlsym(RTLD_NEXT, "accept4");
    int fd = real(sockfd, addr, addrlen, flags);
    set_nodelay(fd);
    return fd;
}

int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
    static int (*real)(int, struct sockaddr *, socklen_t *) = 0;
    if (!real) real = dlsym(RTLD_NEXT, "accept");
    int fd = real(sockfd, addr, addrlen);
    set_nodelay(fd);
    return fd;
}
