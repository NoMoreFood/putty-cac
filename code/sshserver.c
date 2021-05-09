/*
 * Top-level code for SSH server implementation.
 */

#include <assert.h>
#include <stddef.h>

#include "putty.h"
#include "ssh.h"
#include "sshbpp.h"
#include "sshppl.h"
#include "sshchan.h"
#include "sshserver.h"
#ifndef NO_GSSAPI
#include "sshgssc.h"
#include "sshgss.h"
#endif

struct Ssh { int dummy; };

typedef struct server server;
struct server {
    bufchain in_raw, out_raw;
    IdempotentCallback ic_out_raw;
    bool pending_close;

    bufchain dummy_user_input;     /* we never put anything on this */

    PacketLogSettings pls;
    LogContext *logctx;
    struct DataTransferStats stats;

    int remote_bugs;

    Socket *socket;
    Plug plug;
    int conn_throttle_count;
    bool frozen;

    Conf *conf;
    const SshServerConfig *ssc;
    ssh_key *const *hostkeys;
    int nhostkeys;
    RSAKey *hostkey1;
    AuthPolicy *authpolicy;
    LogPolicy *logpolicy;
    const SftpServerVtable *sftpserver_vt;

    agentfwd *stunt_agentfwd;

    Seat seat;
    Ssh ssh;
    struct ssh_version_receiver version_receiver;

    BinaryPacketProtocol *bpp;
    PacketProtocolLayer *base_layer;
    ConnectionLayer *cl;

#ifndef NO_GSSAPI
    struct ssh_connection_shared_gss_state gss_state;
#endif
};

static void ssh_server_free_callback(void *vsrv);
static void server_got_ssh_version(struct ssh_version_receiver *rcv,
                                   int major_version);
static void server_connect_bpp(server *srv);
static void server_bpp_output_raw_data_callback(void *vctx);

void share_activate(ssh_sharing_state *sharestate,
                    const char *server_verstring) {}
void ssh_connshare_provide_connlayer(ssh_sharing_state *sharestate,
                                     ConnectionLayer *cl) {}
int share_ndownstreams(ssh_sharing_state *sharestate) { return 0; }
void share_got_pkt_from_server(ssh_sharing_connstate *cs, int type,
                               const void *vpkt, int pktlen) {}
void share_setup_x11_channel(ssh_sharing_connstate *cs, share_channel *chan,
                             unsigned upstream_id, unsigned server_id,
                             unsigned server_currwin, unsigned server_maxpkt,
                             unsigned client_adjusted_window,
                             const char *peer_addr, int peer_port, int endian,
                             int protomajor, int protominor,
                             const void *initial_data, int initial_len) {}
Channel *agentf_new(SshChannel *c) { return NULL; }
bool agent_exists(void) { return false; }
void ssh_got_exitcode(Ssh *ssh, int exitcode) {}
void ssh_check_frozen(Ssh *ssh) {}

mainchan *mainchan_new(
    PacketProtocolLayer *ppl, ConnectionLayer *cl, Conf *conf,
    int term_width, int term_height, bool is_simple, SshChannel **sc_out)
{ return NULL; }
void mainchan_get_specials(
    mainchan *mc, add_special_fn_t add_special, void *ctx) {}
void mainchan_special_cmd(mainchan *mc, SessionSpecialCode code, int arg) {}
void mainchan_terminal_size(mainchan *mc, int width, int height) {}

/* Seat functions to ensure we don't get choosy about crypto - as the
 * server, it's not up to us to give user warnings */
static int server_confirm_weak_crypto_primitive(
    Seat *seat, const char *algtype, const char *algname,
    void (*callback)(void *ctx, int result), void *ctx) { return 1; }
static int server_confirm_weak_cached_hostkey(
    Seat *seat, const char *algname, const char *betteralgs,
    void (*callback)(void *ctx, int result), void *ctx) { return 1; }

static const SeatVtable server_seat_vt = {
    .output = nullseat_output,
    .eof = nullseat_eof,
    .get_userpass_input = nullseat_get_userpass_input,
    .notify_remote_exit = nullseat_notify_remote_exit,
    .connection_fatal = nullseat_connection_fatal,
    .update_specials_menu = nullseat_update_specials_menu,
    .get_ttymode = nullseat_get_ttymode,
    .set_busy_status = nullseat_set_busy_status,
    .verify_ssh_host_key = nullseat_verify_ssh_host_key,
    .confirm_weak_crypto_primitive = server_confirm_weak_crypto_primitive,
    .confirm_weak_cached_hostkey = server_confirm_weak_cached_hostkey,
    .is_utf8 = nullseat_is_never_utf8,
    .echoedit_update = nullseat_echoedit_update,
    .get_x_display = nullseat_get_x_display,
    .get_windowid = nullseat_get_windowid,
    .get_window_pixel_size = nullseat_get_window_pixel_size,
    .stripctrl_new = nullseat_stripctrl_new,
    .set_trust_status = nullseat_set_trust_status,
    .verbose = nullseat_verbose_no,
    .interactive = nullseat_interactive_no,
    .get_cursor_position = nullseat_get_cursor_position,
};

static void server_socket_log(Plug *plug, PlugLogType type, SockAddr *addr,
                              int port, const char *error_msg, int error_code)
{
    /* server *srv = container_of(plug, server, plug); */
    /* FIXME */
}

static void server_closing(Plug *plug, const char *error_msg, int error_code,
                           bool calling_back)
{
    server *srv = container_of(plug, server, plug);
    if (error_msg) {
        ssh_remote_error(&srv->ssh, "%s", error_msg);
    } else if (srv->bpp) {
        srv->bpp->input_eof = true;
        queue_idempotent_callback(&srv->bpp->ic_in_raw);
    }
}

static void server_receive(
    Plug *plug, int urgent, const char *data, size_t len)
{
    server *srv = container_of(plug, server, plug);

    /* Log raw data, if we're in that mode. */
    if (srv->logctx)
        log_packet(srv->logctx, PKT_INCOMING, -1, NULL, data, len,
                   0, NULL, NULL, 0, NULL);

    bufchain_add(&srv->in_raw, data, len);
    if (!srv->frozen && srv->bpp)
        queue_idempotent_callback(&srv->bpp->ic_in_raw);
}

static void server_sent(Plug *plug, size_t bufsize)
{
#ifdef FIXME
    server *srv = container_of(plug, server, plug);

    /*
     * If the send backlog on the SSH socket itself clears, we should
     * unthrottle the whole world if it was throttled. Also trigger an
     * extra call to the consumer of the BPP's output, to try to send
     * some more data off its bufchain.
     */
    if (bufsize < SSH_MAX_BACKLOG) {
        srv_throttle_all(srv, 0, bufsize);
        queue_idempotent_callback(&srv->ic_out_raw);
    }
#endif
}

LogContext *ssh_get_logctx(Ssh *ssh)
{
    server *srv = container_of(ssh, server, ssh);
    return srv->logctx;
}

void ssh_throttle_conn(Ssh *ssh, int adjust)
{
    server *srv = container_of(ssh, server, ssh);
    int old_count = srv->conn_throttle_count;
    bool frozen;

    srv->conn_throttle_count += adjust;
    assert(srv->conn_throttle_count >= 0);

    if (srv->conn_throttle_count && !old_count) {
        frozen = true;
    } else if (!srv->conn_throttle_count && old_count) {
        frozen = false;
    } else {
        return;                /* don't change current frozen state */
    }

    srv->frozen = frozen;

    if (srv->socket) {
        sk_set_frozen(srv->socket, frozen);

        /*
         * Now process any SSH connection data that was stashed in our
         * queue while we were frozen.
         */
        queue_idempotent_callback(&srv->bpp->ic_in_raw);
    }
}

void ssh_conn_processed_data(Ssh *ssh)
{
    /* FIXME: we could add the same check_frozen_state system as we
     * have in ssh.c, but because that was originally added to work
     * around a peculiarity of the GUI event loop, I haven't yet. */
}

Conf *make_ssh_server_conf(void)
{
    Conf *conf = conf_new();
    load_open_settings(NULL, conf);
    /* In Uppity, we support even the legacy des-cbc cipher by
     * default, so that it will be available if the user forces it by
     * overriding the KEXINIT strings. If the user wants it _not_
     * supported, of course, they can override KEXINIT in the other
     * direction. */
    conf_set_bool(conf, CONF_ssh2_des_cbc, true);
    return conf;
}

static const PlugVtable ssh_server_plugvt = {
    .log = server_socket_log,
    .closing = server_closing,
    .receive = server_receive,
    .sent = server_sent,
};

Plug *ssh_server_plug(
    Conf *conf, const SshServerConfig *ssc,
    ssh_key *const *hostkeys, int nhostkeys,
    RSAKey *hostkey1, AuthPolicy *authpolicy, LogPolicy *logpolicy,
    const SftpServerVtable *sftpserver_vt)
{
    server *srv = snew(server);

    memset(srv, 0, sizeof(server));

    srv->plug.vt = &ssh_server_plugvt;
    srv->conf = conf_copy(conf);
    srv->ssc = ssc;
    srv->logctx = log_init(logpolicy, conf);
    conf_set_bool(srv->conf, CONF_ssh_no_shell, true);
    srv->nhostkeys = nhostkeys;
    srv->hostkeys = hostkeys;
    srv->hostkey1 = hostkey1;
    srv->authpolicy = authpolicy;
    srv->logpolicy = logpolicy;
    srv->sftpserver_vt = sftpserver_vt;

    srv->seat.vt = &server_seat_vt;

    bufchain_init(&srv->in_raw);
    bufchain_init(&srv->out_raw);
    bufchain_init(&srv->dummy_user_input);

#ifndef NO_GSSAPI
    /* FIXME: replace with sensible */
    srv->gss_state.libs = snew(struct ssh_gss_liblist);
    srv->gss_state.libs->nlibraries = 0;
#endif

    return &srv->plug;
}

void ssh_server_start(Plug *plug, Socket *socket)
{
    server *srv = container_of(plug, server, plug);
    const char *our_protoversion;

    if (srv->ssc->bare_connection) {
        our_protoversion = "2.0";     /* SSH-2 only */
    } else if (srv->hostkey1 && srv->nhostkeys) {
        our_protoversion = "1.99";    /* offer both SSH-1 and SSH-2 */
    } else if (srv->hostkey1) {
        our_protoversion = "1.5";     /* SSH-1 only */
    } else {
        assert(srv->nhostkeys);
        our_protoversion = "2.0";     /* SSH-2 only */
    }

    srv->socket = socket;

    srv->ic_out_raw.fn = server_bpp_output_raw_data_callback;
    srv->ic_out_raw.ctx = srv;
    srv->version_receiver.got_ssh_version = server_got_ssh_version;
    srv->bpp = ssh_verstring_new(
        srv->conf, srv->logctx, srv->ssc->bare_connection,
        our_protoversion, &srv->version_receiver,
        true, srv->ssc->application_name);
    server_connect_bpp(srv);
    queue_idempotent_callback(&srv->bpp->ic_in_raw);
}

static void ssh_server_free_callback(void *vsrv)
{
    server *srv = (server *)vsrv;

    logeventf(srv->logctx, "freeing server instance");

    bufchain_clear(&srv->in_raw);
    bufchain_clear(&srv->out_raw);
    bufchain_clear(&srv->dummy_user_input);

    if (srv->socket)
        sk_close(srv->socket);

    if (srv->stunt_agentfwd)
        agentfwd_free(srv->stunt_agentfwd);

    if (srv->base_layer)
        ssh_ppl_free(srv->base_layer);
    if (srv->bpp)
        ssh_bpp_free(srv->bpp);

    delete_callbacks_for_context(srv);

    conf_free(srv->conf);
    log_free(srv->logctx);

#ifndef NO_GSSAPI
    sfree(srv->gss_state.libs);        /* FIXME: replace with sensible */
#endif

    LogPolicy *lp = srv->logpolicy;
    sfree(srv);

    server_instance_terminated(lp);
}

static void server_connect_bpp(server *srv)
{
    srv->bpp->ssh = &srv->ssh;
    srv->bpp->in_raw = &srv->in_raw;
    srv->bpp->out_raw = &srv->out_raw;
    bufchain_set_callback(srv->bpp->out_raw, &srv->ic_out_raw);
    srv->bpp->pls = &srv->pls;
    srv->bpp->logctx = srv->logctx;
    srv->bpp->remote_bugs = srv->remote_bugs;
    /* Servers don't really have a notion of 'unexpected' connection
     * closure. The client is free to close if it likes. */
    srv->bpp->expect_close = true;
}

static void server_connect_ppl(server *srv, PacketProtocolLayer *ppl)
{
    ppl->bpp = srv->bpp;
    ppl->user_input = &srv->dummy_user_input;
    ppl->logctx = srv->logctx;
    ppl->ssh = &srv->ssh;
    ppl->seat = &srv->seat;
    ppl->remote_bugs = srv->remote_bugs;
}

static void server_bpp_output_raw_data_callback(void *vctx)
{
    server *srv = (server *)vctx;

    if (!srv->socket)
        return;

    while (bufchain_size(&srv->out_raw) > 0) {
        size_t backlog;

        ptrlen data = bufchain_prefix(&srv->out_raw);

        if (srv->logctx)
            log_packet(srv->logctx, PKT_OUTGOING, -1, NULL, data.ptr, data.len,
                       0, NULL, NULL, 0, NULL);
        backlog = sk_write(srv->socket, data.ptr, data.len);

        bufchain_consume(&srv->out_raw, data.len);

        if (backlog > SSH_MAX_BACKLOG) {
#ifdef FIXME
            ssh_throttle_all(ssh, 1, backlog);
#endif
            return;
        }
    }

    if (srv->pending_close) {
        sk_close(srv->socket);
        srv->socket = NULL;
        queue_toplevel_callback(ssh_server_free_callback, srv);
    }
}

static void server_shutdown_internal(server *srv)
{
    /*
     * We only need to free the base PPL, which will free the others
     * (if any) transitively.
     */
    if (srv->base_layer) {
        ssh_ppl_free(srv->base_layer);
        srv->base_layer = NULL;
    }

    srv->cl = NULL;
}

static void server_initiate_connection_close(server *srv)
{
    /* Wind up everything above the BPP. */
    server_shutdown_internal(srv);

    /* Force any remaining queued SSH packets through the BPP, and
     * schedule closing the network socket after they go out. */
    ssh_bpp_handle_output(srv->bpp);
    srv->pending_close = true;
    queue_idempotent_callback(&srv->ic_out_raw);

    /* Now we expect the other end to close the connection too in
     * response, so arrange that we'll receive notification of that
     * via ssh_remote_eof. */
    srv->bpp->expect_close = true;
}

#define GET_FORMATTED_MSG(fmt)                  \
    char *msg;                                  \
    va_list ap;                                 \
    va_start(ap, fmt);                          \
    msg = dupvprintf(fmt, ap);                  \
    va_end(ap);

#define LOG_FORMATTED_MSG(logctx, fmt) do       \
    {                                           \
        va_list ap;                             \
        va_start(ap, fmt);                      \
        logeventvf(logctx, fmt, ap);            \
        va_end(ap);                             \
    } while (0)

void ssh_remote_error(Ssh *ssh, const char *fmt, ...)
{
    server *srv = container_of(ssh, server, ssh);
    LOG_FORMATTED_MSG(srv->logctx, fmt);
    queue_toplevel_callback(ssh_server_free_callback, srv);
}

void ssh_remote_eof(Ssh *ssh, const char *fmt, ...)
{
    server *srv = container_of(ssh, server, ssh);
    LOG_FORMATTED_MSG(srv->logctx, fmt);
    queue_toplevel_callback(ssh_server_free_callback, srv);
}

void ssh_proto_error(Ssh *ssh, const char *fmt, ...)
{
    server *srv = container_of(ssh, server, ssh);
    if (srv->base_layer) {
        GET_FORMATTED_MSG(fmt);
        ssh_bpp_queue_disconnect(srv->bpp, msg,
                                 SSH2_DISCONNECT_PROTOCOL_ERROR);
        server_initiate_connection_close(srv);
        logeventf(srv->logctx, "Protocol error: %s", msg);
        sfree(msg);
    }
}

void ssh_sw_abort(Ssh *ssh, const char *fmt, ...)
{
    server *srv = container_of(ssh, server, ssh);
    LOG_FORMATTED_MSG(srv->logctx, fmt);
    queue_toplevel_callback(ssh_server_free_callback, srv);
}

void ssh_user_close(Ssh *ssh, const char *fmt, ...)
{
    server *srv = container_of(ssh, server, ssh);
    LOG_FORMATTED_MSG(srv->logctx, fmt);
    queue_toplevel_callback(ssh_server_free_callback, srv);
}

static void server_got_ssh_version(struct ssh_version_receiver *rcv,
                                   int major_version)
{
    server *srv = container_of(rcv, server, version_receiver);
    BinaryPacketProtocol *old_bpp;
    PacketProtocolLayer *connection_layer;

    old_bpp = srv->bpp;
    srv->remote_bugs = ssh_verstring_get_bugs(old_bpp);

    if (srv->ssc->bare_connection) {
        srv->bpp = ssh2_bare_bpp_new(srv->logctx);
        server_connect_bpp(srv);

        connection_layer = ssh2_connection_new(
            &srv->ssh, NULL, false, srv->conf,
            ssh_verstring_get_local(old_bpp), &srv->cl);
        ssh2connection_server_configure(connection_layer,
                                        srv->sftpserver_vt, srv->ssc);
        server_connect_ppl(srv, connection_layer);

        srv->base_layer = connection_layer;
    } else if (major_version == 2) {
        PacketProtocolLayer *userauth_layer, *transport_child_layer;

        srv->bpp = ssh2_bpp_new(srv->logctx, &srv->stats, true);
        server_connect_bpp(srv);

        connection_layer = ssh2_connection_new(
            &srv->ssh, NULL, false, srv->conf,
            ssh_verstring_get_local(old_bpp), &srv->cl);
        ssh2connection_server_configure(connection_layer,
                                        srv->sftpserver_vt, srv->ssc);
        server_connect_ppl(srv, connection_layer);

        if (conf_get_bool(srv->conf, CONF_ssh_no_userauth)) {
            userauth_layer = NULL;
            transport_child_layer = connection_layer;
        } else {
            userauth_layer = ssh2_userauth_server_new(
                connection_layer, srv->authpolicy, srv->ssc);
            server_connect_ppl(srv, userauth_layer);
            transport_child_layer = userauth_layer;
        }

        srv->base_layer = ssh2_transport_new(
            srv->conf, NULL, 0, NULL,
            ssh_verstring_get_remote(old_bpp),
            ssh_verstring_get_local(old_bpp),
#ifndef NO_GSSAPI
            &srv->gss_state,
#else
            NULL,
#endif
            &srv->stats, transport_child_layer, srv->ssc);
        ssh2_transport_provide_hostkeys(
            srv->base_layer, srv->hostkeys, srv->nhostkeys);
        if (userauth_layer)
            ssh2_userauth_server_set_transport_layer(
                userauth_layer, srv->base_layer);
        server_connect_ppl(srv, srv->base_layer);

    } else {
        srv->bpp = ssh1_bpp_new(srv->logctx);
        server_connect_bpp(srv);

        connection_layer = ssh1_connection_new(&srv->ssh, srv->conf, &srv->cl);
        ssh1connection_server_configure(connection_layer, srv->ssc);
        server_connect_ppl(srv, connection_layer);

        srv->base_layer = ssh1_login_server_new(
            connection_layer, srv->hostkey1, srv->authpolicy, srv->ssc);
        server_connect_ppl(srv, srv->base_layer);
    }

    /* Connect the base layer - whichever it is - to the BPP, and set
     * up its selfptr. */
    srv->base_layer->selfptr = &srv->base_layer;
    ssh_ppl_setup_queues(srv->base_layer, &srv->bpp->in_pq, &srv->bpp->out_pq);

#ifdef FIXME // we probably will want one of these, in the end
    srv->pinger = pinger_new(srv->conf, &srv->backend);
#endif

    if (srv->ssc->stunt_open_unconditional_agent_socket) {
        char *socketname;
        srv->stunt_agentfwd = agentfwd_new(srv->cl, &socketname);
        if (srv->stunt_agentfwd) {
            logeventf(srv->logctx, "opened unconditional agent socket at %s\n",
                      socketname);
            sfree(socketname);
        }
    }

    queue_idempotent_callback(&srv->bpp->ic_in_raw);
    ssh_ppl_process_queue(srv->base_layer);

    ssh_bpp_free(old_bpp);
}
