#include "putty.h"
#include "ssh.h"
#include "ssh/bpp.h"
#include "test.h"

void modalfatalbox(const char *p, ...)
{
    va_list ap;
    fprintf(stderr, "FATAL ERROR: ");
    va_start(ap, p);
    vfprintf(stderr, p, ap);
    va_end(ap);
    fputc('\n', stderr);
    exit(1);
}

const char *const appname = "test_bpp";

char *platform_default_s(const char *name)
{ return NULL; }
bool platform_default_b(const char *name, bool def)
{ return def; }
int platform_default_i(const char *name, int def)
{ return def; }
FontSpec *platform_default_fontspec(const char *name)
{ return fontspec_new_default(); }
Filename *platform_default_filename(const char *name)
{ return filename_from_str(""); }
char *platform_get_x_display(void) { return NULL; }

void old_keyfile_warning(void) { }

/* Catch error reports via ssh_proto_error, ssh_sw_abort etc */
static bool error_reported;

void ssh_check_frozen(Ssh *ssh) {}
void ssh_conn_processed_data(Ssh *ssh) {}
void ssh_sendbuffer_changed(Ssh *ssh) {}
void ssh_remote_error(Ssh *ssh, const char *fmt, ...) {error_reported = true;}
void ssh_proto_error(Ssh *ssh, const char *fmt, ...) {error_reported = true;}
void ssh_remote_eof(Ssh *ssh, const char *fmt, ...) {error_reported = true;}
void ssh_sw_abort(Ssh *ssh, const char *fmt, ...) {error_reported = true;}
void ssh_user_close(Ssh *ssh, const char *fmt, ...) {error_reported = true;}

char *get_remote_username(Conf *conf) { return NULL; }
const bool share_can_be_upstream = false;
const bool share_can_be_downstream = false;

bool failed = false;

static bool test_bpp2_large_packet_once(
    LogContext *logctx, const ssh_cipheralg *cipher,
    bool etm_mode, uint32_t payload_len)
{
    struct DataTransferStats stats;
    memset(&stats, 0, sizeof(stats));
    bufchain wire;

    error_reported = false;

    bufchain_init(&wire);
    BinaryPacketProtocol *bpp_out = ssh2_bpp_new(logctx, &stats, false);
    BinaryPacketProtocol *bpp_in = ssh2_bpp_new(logctx, &stats, false);
    bpp_out->out_raw = &wire;
    bpp_in->in_raw = &wire;

    testrandom_seed("bpp2");
    const char cipherkey[16] = "128bit cipherkey";
    const char iv[16] = "initialisationve";
    const char mackey[32] = "key for HMAC-SHA-256 MAC sdfsdfs";
    ssh2_bpp_new_outgoing_crypto(bpp_out, cipher, cipherkey, iv,
                                 &ssh_hmac_sha256, etm_mode, mackey,
                                 &ssh_comp_none, false, false);
    ssh2_bpp_new_incoming_crypto(bpp_in, cipher, cipherkey, iv,
                                 &ssh_hmac_sha256, etm_mode, mackey,
                                 &ssh_comp_none, false, false);

    PktOut *pkt = ssh_bpp_new_pktout(bpp_out, 100);
    put_padding(pkt, payload_len, 'x');
    pq_push(&bpp_out->out_pq, pkt);
    ssh_bpp_handle_output(bpp_out);
    ssh_bpp_handle_input(bpp_in);

    pq_in_clear(&bpp_in->in_pq);
    ssh_bpp_free(bpp_out);
    ssh_bpp_free(bpp_in);
    bufchain_clear(&wire);

    return error_reported;
}

static bool test_bpp1_large_packet_once(
    LogContext *logctx, uint32_t payload_len)
{
    bufchain wire;

    error_reported = false;

    bufchain_init(&wire);
    BinaryPacketProtocol *bpp_out = ssh1_bpp_new(logctx);
    BinaryPacketProtocol *bpp_in = ssh1_bpp_new(logctx);
    bpp_out->out_raw = &wire;
    bpp_in->in_raw = &wire;

    testrandom_seed("bpp1");
    const ssh_cipheralg *cipher = &ssh_blowfish_ssh1;
    const char cipherkey[32] = "32-byte test cipher key material";
    ssh1_bpp_new_cipher(bpp_out, cipher, cipherkey);
    ssh1_bpp_new_cipher(bpp_in, cipher, cipherkey);

    PktOut *pkt = ssh_bpp_new_pktout(bpp_out, 100);
    put_padding(pkt, payload_len, 'x');
    pq_push(&bpp_out->out_pq, pkt);
    ssh_bpp_handle_output(bpp_out);
    ssh_bpp_handle_input(bpp_in);

    pq_in_clear(&bpp_in->in_pq);
    ssh_bpp_free(bpp_out);
    ssh_bpp_free(bpp_in);
    bufchain_clear(&wire);

    return error_reported;
}

static void test_bpp2_large_packet(
    LogContext *logctx, const ssh_cipheralg *cipher, bool etm_mode)
{
    uint32_t payload_len = OUR_V2_PACKETLIMIT + 1;
    bool err = test_bpp2_large_packet_once(
        logctx, cipher, etm_mode, payload_len);
    assert(err && "That packet should definitely be too large");
    do {
        payload_len--;
    } while (test_bpp2_large_packet_once(
                 logctx, cipher, etm_mode, payload_len));
}

static void test_bpp1_large_packet(LogContext *logctx)
{
    uint32_t payload_len = 262145;     /* > SSH-1 mandated max packet size */
    bool err = test_bpp1_large_packet_once(logctx, payload_len);
    assert(err && "That packet should definitely be too large");
    do {
        payload_len--;
    } while (test_bpp1_large_packet_once(logctx, payload_len));
}

int main(void)
{
    testrandom_init();

    /* We're using the stub logging system, which doesn't need these
     * parameters to be real */
    LogContext *logctx = log_init(NULL, NULL);

    test_bpp2_large_packet(logctx, &ssh_aes128_sdctr, false);
    test_bpp2_large_packet(logctx, &ssh_aes128_sdctr, true);
    test_bpp2_large_packet(logctx, &ssh_aes128_cbc, false);
    test_bpp1_large_packet(logctx);

    if (failed) {
        printf("Test suite FAILED!\n");
        return 1;
    } else {
        printf("Test suite passed\n");
        return 0;
    }
}
