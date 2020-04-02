/*
 * uxfdsick.c: implementation of Socket that just talks to two
 * existing input and output file descriptors.
 */

#include <stdio.h>
#include <assert.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

#include "tree234.h"
#include "putty.h"
#include "network.h"

typedef struct FdSocket {
    int outfd, infd, inerrfd;

    bufchain pending_output_data;
    bufchain pending_input_data;
    ProxyStderrBuf psb;
    enum { EOF_NO, EOF_PENDING, EOF_SENT } outgoingeof;

    int pending_error;

    Plug *plug;

    Socket sock;
} FdSocket;

static void fdsocket_select_result_input(int fd, int event);
static void fdsocket_select_result_output(int fd, int event);
static void fdsocket_select_result_input_error(int fd, int event);

/*
 * Trees to look up the fds in.
 */
static tree234 *fdsocket_by_outfd;
static tree234 *fdsocket_by_infd;
static tree234 *fdsocket_by_inerrfd;

static int fdsocket_infd_cmp(void *av, void *bv)
{
    FdSocket *a = (FdSocket *)av;
    FdSocket *b = (FdSocket *)bv;
    if (a->infd < b->infd)
        return -1;
    if (a->infd > b->infd)
        return +1;
    return 0;
}
static int fdsocket_infd_find(void *av, void *bv)
{
    int a = *(int *)av;
    FdSocket *b = (FdSocket *)bv;
    if (a < b->infd)
        return -1;
    if (a > b->infd)
        return +1;
    return 0;
}
static int fdsocket_inerrfd_cmp(void *av, void *bv)
{
    FdSocket *a = (FdSocket *)av;
    FdSocket *b = (FdSocket *)bv;
    if (a->inerrfd < b->inerrfd)
        return -1;
    if (a->inerrfd > b->inerrfd)
        return +1;
    return 0;
}
static int fdsocket_inerrfd_find(void *av, void *bv)
{
    int a = *(int *)av;
    FdSocket *b = (FdSocket *)bv;
    if (a < b->inerrfd)
        return -1;
    if (a > b->inerrfd)
        return +1;
    return 0;
}
static int fdsocket_outfd_cmp(void *av, void *bv)
{
    FdSocket *a = (FdSocket *)av;
    FdSocket *b = (FdSocket *)bv;
    if (a->outfd < b->outfd)
        return -1;
    if (a->outfd > b->outfd)
        return +1;
    return 0;
}
static int fdsocket_outfd_find(void *av, void *bv)
{
    int a = *(int *)av;
    FdSocket *b = (FdSocket *)bv;
    if (a < b->outfd)
        return -1;
    if (a > b->outfd)
        return +1;
    return 0;
}

static Plug *fdsocket_plug(Socket *s, Plug *p)
{
    FdSocket *fds = container_of(s, FdSocket, sock);
    Plug *ret = fds->plug;
    if (p)
        fds->plug = p;
    return ret;
}

static void fdsocket_close(Socket *s)
{
    FdSocket *fds = container_of(s, FdSocket, sock);

    if (fds->outfd >= 0) {
        del234(fdsocket_by_outfd, fds);
        uxsel_del(fds->outfd);
        close(fds->outfd);
    }

    if (fds->infd >= 0) {
        del234(fdsocket_by_infd, fds);
        uxsel_del(fds->infd);
        close(fds->infd);
    }

    if (fds->inerrfd >= 0) {
        del234(fdsocket_by_inerrfd, fds);
        uxsel_del(fds->inerrfd);
        close(fds->inerrfd);
    }

    bufchain_clear(&fds->pending_input_data);
    bufchain_clear(&fds->pending_output_data);

    delete_callbacks_for_context(fds);

    sfree(fds);
}

static void fdsocket_error_callback(void *vs)
{
    FdSocket *fds = (FdSocket *)vs;

    /*
     * Just in case other socket work has caused this socket to vanish
     * or become somehow non-erroneous before this callback arrived...
     */
    if (!fds->pending_error)
        return;

    /*
     * An error has occurred on this socket. Pass it to the plug.
     */
    plug_closing(fds->plug, strerror(fds->pending_error),
                 fds->pending_error, 0);
}

static int fdsocket_try_send(FdSocket *fds)
{
    int sent = 0;

    while (bufchain_size(&fds->pending_output_data) > 0) {
        ssize_t ret;

        ptrlen data = bufchain_prefix(&fds->pending_output_data);
        ret = write(fds->outfd, data.ptr, data.len);
        noise_ultralight(NOISE_SOURCE_IOID, ret);
        if (ret < 0 && errno != EWOULDBLOCK) {
            if (!fds->pending_error) {
                fds->pending_error = errno;
                queue_toplevel_callback(fdsocket_error_callback, fds);
            }
            return 0;
        } else if (ret <= 0) {
            break;
        } else {
            bufchain_consume(&fds->pending_output_data, ret);
            sent += ret;
        }
    }

    if (fds->outgoingeof == EOF_PENDING) {
        del234(fdsocket_by_outfd, fds);
        close(fds->outfd);
        uxsel_del(fds->outfd);
        fds->outfd = -1;
        fds->outgoingeof = EOF_SENT;
    }

    if (bufchain_size(&fds->pending_output_data) == 0)
        uxsel_del(fds->outfd);
    else
        uxsel_set(fds->outfd, SELECT_W, fdsocket_select_result_output);

    return sent;
}

static size_t fdsocket_write(Socket *s, const void *data, size_t len)
{
    FdSocket *fds = container_of(s, FdSocket, sock);

    assert(fds->outgoingeof == EOF_NO);

    bufchain_add(&fds->pending_output_data, data, len);

    fdsocket_try_send(fds);

    return bufchain_size(&fds->pending_output_data);
}

static size_t fdsocket_write_oob(Socket *s, const void *data, size_t len)
{
    /*
     * oob data is treated as inband; nasty, but nothing really
     * better we can do
     */
    return fdsocket_write(s, data, len);
}

static void fdsocket_write_eof(Socket *s)
{
    FdSocket *fds = container_of(s, FdSocket, sock);

    assert(fds->outgoingeof == EOF_NO);
    fds->outgoingeof = EOF_PENDING;

    fdsocket_try_send(fds);
}

static void fdsocket_set_frozen(Socket *s, bool is_frozen)
{
    FdSocket *fds = container_of(s, FdSocket, sock);

    if (fds->infd < 0)
        return;

    if (is_frozen)
        uxsel_del(fds->infd);
    else
        uxsel_set(fds->infd, SELECT_R, fdsocket_select_result_input);
}

static const char *fdsocket_socket_error(Socket *s)
{
    return NULL;
}

static void fdsocket_select_result_input(int fd, int event)
{
    FdSocket *fds;
    char buf[20480];
    int retd;

    if (!(fds = find234(fdsocket_by_infd, &fd, fdsocket_infd_find)))
        return;

    retd = read(fds->infd, buf, sizeof(buf));
    if (retd > 0) {
        plug_receive(fds->plug, 0, buf, retd);
    } else {
        if (retd < 0) {
            plug_closing(fds->plug, strerror(errno), errno, 0);
        } else {
            plug_closing(fds->plug, NULL, 0, 0);
        }
        del234(fdsocket_by_infd, fds);
        uxsel_del(fds->infd);
        close(fds->infd);
        fds->infd = -1;
    }
}

static void fdsocket_select_result_output(int fd, int event)
{
    FdSocket *fds;

    if (!(fds = find234(fdsocket_by_outfd, &fd, fdsocket_outfd_find)))
        return;

    if (fdsocket_try_send(fds))
        plug_sent(fds->plug, bufchain_size(&fds->pending_output_data));
}

static void fdsocket_select_result_input_error(int fd, int event)
{
    FdSocket *fds;
    char buf[20480];
    int retd;

    if (!(fds = find234(fdsocket_by_inerrfd, &fd, fdsocket_inerrfd_find)))
        return;

    retd = read(fd, buf, sizeof(buf));
    if (retd > 0) {
        log_proxy_stderr(fds->plug, &fds->psb, buf, retd);
    } else {
        del234(fdsocket_by_inerrfd, fds);
        uxsel_del(fds->inerrfd);
        close(fds->inerrfd);
        fds->inerrfd = -1;
    }
}

static const SocketVtable FdSocket_sockvt = {
    fdsocket_plug,
    fdsocket_close,
    fdsocket_write,
    fdsocket_write_oob,
    fdsocket_write_eof,
    fdsocket_set_frozen,
    fdsocket_socket_error,
    NULL, /* peer_info */
};

Socket *make_fd_socket(int infd, int outfd, int inerrfd, Plug *plug)
{
    FdSocket *fds;

    fds = snew(FdSocket);
    fds->sock.vt = &FdSocket_sockvt;
    fds->plug = plug;
    fds->outgoingeof = EOF_NO;
    fds->pending_error = 0;

    fds->infd = infd;
    fds->outfd = outfd;
    fds->inerrfd = inerrfd;

    bufchain_init(&fds->pending_input_data);
    bufchain_init(&fds->pending_output_data);
    psb_init(&fds->psb);

    if (fds->outfd >= 0) {
        if (!fdsocket_by_outfd)
            fdsocket_by_outfd = newtree234(fdsocket_outfd_cmp);
        add234(fdsocket_by_outfd, fds);
    }

    if (fds->infd >= 0) {
        if (!fdsocket_by_infd)
            fdsocket_by_infd = newtree234(fdsocket_infd_cmp);
        add234(fdsocket_by_infd, fds);
        uxsel_set(fds->infd, SELECT_R, fdsocket_select_result_input);
    }

    if (fds->inerrfd >= 0) {
        assert(fds->inerrfd != fds->infd);
        if (!fdsocket_by_inerrfd)
            fdsocket_by_inerrfd = newtree234(fdsocket_inerrfd_cmp);
        add234(fdsocket_by_inerrfd, fds);
        uxsel_set(fds->inerrfd, SELECT_R, fdsocket_select_result_input_error);
    }

    return &fds->sock;
}
