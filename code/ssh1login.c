/*
 * Packet protocol layer for the SSH-1 login phase (combining what
 * SSH-2 would think of as key exchange and user authentication).
 */

#include <assert.h>

#include "putty.h"
#include "ssh.h"
#include "mpint.h"
#include "sshbpp.h"
#include "sshppl.h"
#include "sshcr.h"

typedef struct agent_key {
    RSAKey key;
    strbuf *comment;
    ptrlen blob; /* only used during initial parsing of agent response */
} agent_key;

struct ssh1_login_state {
    int crState;

    PacketProtocolLayer *successor_layer;

    Conf *conf;

    char *savedhost;
    int savedport;
    bool try_agent_auth, is_trivial_auth;

    int remote_protoflags;
    int local_protoflags;
    unsigned char session_key[32];
    char *username;
    agent_pending_query *auth_agent_query;

    int len;
    unsigned char *rsabuf;
    unsigned long supported_ciphers_mask, supported_auths_mask;
    bool tried_publickey, tried_agent;
    bool tis_auth_refused, ccard_auth_refused;
    unsigned char cookie[8];
    unsigned char session_id[16];
    int cipher_type;
    strbuf *publickey_blob;
    char *publickey_comment;
    bool privatekey_available, privatekey_encrypted;
    prompts_t *cur_prompt;
    int userpass_ret;
    char c;
    int pwpkt_type;
    void *agent_response_to_free;
    ptrlen agent_response;
    BinarySource asrc[1];          /* response from SSH agent */
    size_t agent_keys_len;
    agent_key *agent_keys;
    size_t agent_key_index, agent_key_limit;
    bool authed;
    RSAKey key;
    int dlgret;
    Filename *keyfile;
    RSAKey servkey, hostkey;
    bool want_user_input;

    StripCtrlChars *tis_scc;
    bool tis_scc_initialised;

    PacketProtocolLayer ppl;
};

static void ssh1_login_free(PacketProtocolLayer *);
static void ssh1_login_process_queue(PacketProtocolLayer *);
static void ssh1_login_dialog_callback(void *, int);
static void ssh1_login_special_cmd(PacketProtocolLayer *ppl,
                                   SessionSpecialCode code, int arg);
static bool ssh1_login_want_user_input(PacketProtocolLayer *ppl);
static void ssh1_login_got_user_input(PacketProtocolLayer *ppl);
static void ssh1_login_reconfigure(PacketProtocolLayer *ppl, Conf *conf);

static const PacketProtocolLayerVtable ssh1_login_vtable = {
    .free = ssh1_login_free,
    .process_queue = ssh1_login_process_queue,
    .get_specials = ssh1_common_get_specials,
    .special_cmd = ssh1_login_special_cmd,
    .want_user_input = ssh1_login_want_user_input,
    .got_user_input = ssh1_login_got_user_input,
    .reconfigure = ssh1_login_reconfigure,
    .queued_data_size = ssh_ppl_default_queued_data_size,
    .name = NULL, /* no layer names in SSH-1 */
};

static void ssh1_login_agent_query(struct ssh1_login_state *s, strbuf *req);
static void ssh1_login_agent_callback(void *loginv, void *reply, int replylen);

PacketProtocolLayer *ssh1_login_new(
    Conf *conf, const char *host, int port,
    PacketProtocolLayer *successor_layer)
{
    struct ssh1_login_state *s = snew(struct ssh1_login_state);
    memset(s, 0, sizeof(*s));
    s->ppl.vt = &ssh1_login_vtable;

    s->conf = conf_copy(conf);
    s->savedhost = dupstr(host);
    s->savedport = port;
    s->successor_layer = successor_layer;
    s->is_trivial_auth = true;

    return &s->ppl;
}

static void ssh1_login_free(PacketProtocolLayer *ppl)
{
    struct ssh1_login_state *s =
        container_of(ppl, struct ssh1_login_state, ppl);

    if (s->successor_layer)
        ssh_ppl_free(s->successor_layer);

    conf_free(s->conf);
    sfree(s->savedhost);
    sfree(s->rsabuf);
    sfree(s->username);
    if (s->publickey_blob)
        strbuf_free(s->publickey_blob);
    sfree(s->publickey_comment);
    if (s->cur_prompt)
        free_prompts(s->cur_prompt);
    if (s->agent_keys) {
        for (size_t i = 0; i < s->agent_keys_len; i++) {
            freersakey(&s->agent_keys[i].key);
            strbuf_free(s->agent_keys[i].comment);
        }
        sfree(s->agent_keys);
    }
    sfree(s->agent_response_to_free);
    if (s->auth_agent_query)
        agent_cancel_query(s->auth_agent_query);
    sfree(s);
}

static bool ssh1_login_filter_queue(struct ssh1_login_state *s)
{
    return ssh1_common_filter_queue(&s->ppl);
}

static PktIn *ssh1_login_pop(struct ssh1_login_state *s)
{
    if (ssh1_login_filter_queue(s))
        return NULL;
    return pq_pop(s->ppl.in_pq);
}

static void ssh1_login_setup_tis_scc(struct ssh1_login_state *s);

static void ssh1_login_process_queue(PacketProtocolLayer *ppl)
{
    struct ssh1_login_state *s =
        container_of(ppl, struct ssh1_login_state, ppl);
    PktIn *pktin;
    PktOut *pkt;
    int i;

    /* Filter centrally handled messages off the front of the queue on
     * every entry to this coroutine, no matter where we're resuming
     * from, even if we're _not_ looping on pq_pop. That way we can
     * still proactively handle those messages even if we're waiting
     * for a user response. */
    if (ssh1_login_filter_queue(s))
        return;

    crBegin(s->crState);

    crMaybeWaitUntilV((pktin = ssh1_login_pop(s)) != NULL);

    if (pktin->type != SSH1_SMSG_PUBLIC_KEY) {
        ssh_proto_error(s->ppl.ssh, "Public key packet not received");
        return;
    }

    ppl_logevent("Received public keys");

    {
        ptrlen pl = get_data(pktin, 8);
        memcpy(s->cookie, pl.ptr, pl.len);
    }

    get_rsa_ssh1_pub(pktin, &s->servkey, RSA_SSH1_EXPONENT_FIRST);
    get_rsa_ssh1_pub(pktin, &s->hostkey, RSA_SSH1_EXPONENT_FIRST);

    s->hostkey.comment = NULL; /* avoid confusing rsa_ssh1_fingerprint */

    /*
     * Log the host key fingerprint.
     */
    if (!get_err(pktin)) {
        char *fingerprint = rsa_ssh1_fingerprint(&s->hostkey);
        ppl_logevent("Host key fingerprint is:");
        ppl_logevent("      %s", fingerprint);
        sfree(fingerprint);
    }

    s->remote_protoflags = get_uint32(pktin);
    s->supported_ciphers_mask = get_uint32(pktin);
    s->supported_auths_mask = get_uint32(pktin);

    if (get_err(pktin)) {
        ssh_proto_error(s->ppl.ssh, "Bad SSH-1 public key packet");
        return;
    }

    if ((s->ppl.remote_bugs & BUG_CHOKES_ON_RSA))
        s->supported_auths_mask &= ~(1 << SSH1_AUTH_RSA);

    s->local_protoflags =
        s->remote_protoflags & SSH1_PROTOFLAGS_SUPPORTED;
    s->local_protoflags |= SSH1_PROTOFLAG_SCREEN_NUMBER;

    ssh1_compute_session_id(s->session_id, s->cookie,
                            &s->hostkey, &s->servkey);

    random_read(s->session_key, 32);

    /*
     * Verify that the `bits' and `bytes' parameters match.
     */
    if (s->hostkey.bits > s->hostkey.bytes * 8 ||
        s->servkey.bits > s->servkey.bytes * 8) {
        ssh_proto_error(s->ppl.ssh, "SSH-1 public keys were badly formatted");
        return;
    }

    s->len = 32;
    if (s->len < s->hostkey.bytes)
        s->len = s->hostkey.bytes;
    if (s->len < s->servkey.bytes)
        s->len = s->servkey.bytes;

    s->rsabuf = snewn(s->len, unsigned char);

    /*
     * Verify the host key.
     */
    {
        /*
         * First format the key into a string.
         */
        char *keystr = rsastr_fmt(&s->hostkey);
        char **fingerprints = rsa_ssh1_fake_all_fingerprints(&s->hostkey);

        /* First check against manually configured host keys. */
        s->dlgret = verify_ssh_manual_host_key(s->conf, fingerprints, NULL);
        if (s->dlgret == 0) {          /* did not match */
            ssh2_free_all_fingerprints(fingerprints);
            sfree(keystr);
            ssh_proto_error(s->ppl.ssh, "Host key did not appear in manually "
                            "configured list");
            return;
        } else if (s->dlgret < 0) { /* none configured; use standard handling */
            char *keydisp = ssh1_pubkey_str(&s->hostkey);
            s->dlgret = seat_verify_ssh_host_key(
                s->ppl.seat, s->savedhost, s->savedport, "rsa", keystr,
                keydisp, fingerprints, ssh1_login_dialog_callback, s);
            sfree(keydisp);
            ssh2_free_all_fingerprints(fingerprints);
            sfree(keystr);
#ifdef FUZZING
            s->dlgret = 1;
#endif
            crMaybeWaitUntilV(s->dlgret >= 0);

            if (s->dlgret == 0) {
                ssh_user_close(s->ppl.ssh,
                               "User aborted at host key verification");
                return;
            }
        } else {
            ssh2_free_all_fingerprints(fingerprints);
            sfree(keystr);
        }
    }

    for (i = 0; i < 32; i++) {
        s->rsabuf[i] = s->session_key[i];
        if (i < 16)
            s->rsabuf[i] ^= s->session_id[i];
    }

    {
        RSAKey *smaller = (s->hostkey.bytes > s->servkey.bytes ?
                           &s->servkey : &s->hostkey);
        RSAKey *larger = (s->hostkey.bytes > s->servkey.bytes ?
                          &s->hostkey : &s->servkey);

        if (!rsa_ssh1_encrypt(s->rsabuf, 32, smaller) ||
            !rsa_ssh1_encrypt(s->rsabuf, smaller->bytes, larger)) {
            ssh_proto_error(s->ppl.ssh, "SSH-1 public key encryptions failed "
                            "due to bad formatting");
            return;
        }
    }

    ppl_logevent("Encrypted session key");

    {
        bool cipher_chosen = false, warn = false;
        const char *cipher_string = NULL;
        int i;
        for (i = 0; !cipher_chosen && i < CIPHER_MAX; i++) {
            int next_cipher = conf_get_int_int(
                s->conf, CONF_ssh_cipherlist, i);
            if (next_cipher == CIPHER_WARN) {
                /* If/when we choose a cipher, warn about it */
                warn = true;
            } else if (next_cipher == CIPHER_AES) {
                /* XXX Probably don't need to mention this. */
                ppl_logevent("AES not supported in SSH-1, skipping");
            } else {
                switch (next_cipher) {
                  case CIPHER_3DES:     s->cipher_type = SSH1_CIPHER_3DES;
                    cipher_string = "3DES"; break;
                  case CIPHER_BLOWFISH: s->cipher_type = SSH1_CIPHER_BLOWFISH;
                    cipher_string = "Blowfish"; break;
                  case CIPHER_DES:      s->cipher_type = SSH1_CIPHER_DES;
                    cipher_string = "single-DES"; break;
                }
                if (s->supported_ciphers_mask & (1 << s->cipher_type))
                    cipher_chosen = true;
            }
        }
        if (!cipher_chosen) {
            if ((s->supported_ciphers_mask & (1 << SSH1_CIPHER_3DES)) == 0) {
                ssh_proto_error(s->ppl.ssh, "Server violates SSH-1 protocol "
                                "by not supporting 3DES encryption");
            } else {
                /* shouldn't happen */
                ssh_sw_abort(s->ppl.ssh, "No supported ciphers found");
            }
            return;
        }

        /* Warn about chosen cipher if necessary. */
        if (warn) {
            s->dlgret = seat_confirm_weak_crypto_primitive(
                s->ppl.seat, "cipher", cipher_string,
                ssh1_login_dialog_callback, s);
            crMaybeWaitUntilV(s->dlgret >= 0);
            if (s->dlgret == 0) {
                ssh_user_close(s->ppl.ssh, "User aborted at cipher warning");
                return;
            }
        }
    }

    switch (s->cipher_type) {
      case SSH1_CIPHER_3DES:
        ppl_logevent("Using 3DES encryption");
        break;
      case SSH1_CIPHER_DES:
        ppl_logevent("Using single-DES encryption");
        break;
      case SSH1_CIPHER_BLOWFISH:
        ppl_logevent("Using Blowfish encryption");
        break;
    }

    pkt = ssh_bpp_new_pktout(s->ppl.bpp, SSH1_CMSG_SESSION_KEY);
    put_byte(pkt, s->cipher_type);
    put_data(pkt, s->cookie, 8);
    put_uint16(pkt, s->len * 8);
    put_data(pkt, s->rsabuf, s->len);
    put_uint32(pkt, s->local_protoflags);
    pq_push(s->ppl.out_pq, pkt);

    ppl_logevent("Trying to enable encryption...");

    sfree(s->rsabuf);
    s->rsabuf = NULL;

    /*
     * Force the BPP to synchronously marshal all packets up to and
     * including the SESSION_KEY into wire format, before we turn on
     * crypto.
     */
    ssh_bpp_handle_output(s->ppl.bpp);

    {
        const ssh_cipheralg *cipher =
            (s->cipher_type == SSH1_CIPHER_BLOWFISH ? &ssh_blowfish_ssh1 :
             s->cipher_type == SSH1_CIPHER_DES ? &ssh_des : &ssh_3des_ssh1);
        ssh1_bpp_new_cipher(s->ppl.bpp, cipher, s->session_key);
    }

    freersakey(&s->servkey);
    freersakey(&s->hostkey);
    crMaybeWaitUntilV((pktin = ssh1_login_pop(s)) != NULL);

    if (pktin->type != SSH1_SMSG_SUCCESS) {
        ssh_proto_error(s->ppl.ssh, "Encryption not successfully enabled");
        return;
    }

    ppl_logevent("Successfully started encryption");

    if ((s->username = get_remote_username(s->conf)) == NULL) {
        s->cur_prompt = new_prompts();
        s->cur_prompt->to_server = true;
        s->cur_prompt->from_server = false;
        s->cur_prompt->name = dupstr("SSH login name");
        add_prompt(s->cur_prompt, dupstr("login as: "), true);
        s->userpass_ret = seat_get_userpass_input(
            s->ppl.seat, s->cur_prompt, NULL);
        while (1) {
            while (s->userpass_ret < 0 &&
                   bufchain_size(s->ppl.user_input) > 0)
                s->userpass_ret = seat_get_userpass_input(
                    s->ppl.seat, s->cur_prompt, s->ppl.user_input);

            if (s->userpass_ret >= 0)
                break;

            s->want_user_input = true;
            crReturnV;
            s->want_user_input = false;
        }
        if (!s->userpass_ret) {
            /*
             * Failed to get a username. Terminate.
             */
            ssh_user_close(s->ppl.ssh, "No username provided");
            return;
        }
        s->username = prompt_get_result(s->cur_prompt->prompts[0]);
        free_prompts(s->cur_prompt);
        s->cur_prompt = NULL;
    }

    pkt = ssh_bpp_new_pktout(s->ppl.bpp, SSH1_CMSG_USER);
    put_stringz(pkt, s->username);
    pq_push(s->ppl.out_pq, pkt);

    ppl_logevent("Sent username \"%s\"", s->username);
    if (seat_verbose(s->ppl.seat) || seat_interactive(s->ppl.seat))
        ppl_printf("Sent username \"%s\"\r\n", s->username);

    crMaybeWaitUntilV((pktin = ssh1_login_pop(s)) != NULL);

    if (!(s->supported_auths_mask & (1 << SSH1_AUTH_RSA))) {
        /* We must not attempt PK auth. Pretend we've already tried it. */
        s->tried_publickey = s->tried_agent = true;
    } else {
        s->tried_publickey = s->tried_agent = false;
    }
    s->tis_auth_refused = s->ccard_auth_refused = false;

    /*
     * Load the public half of any configured keyfile for later use.
     */
    s->keyfile = conf_get_filename(s->conf, CONF_keyfile);
    if (!filename_is_null(s->keyfile)) {
        int keytype;
        ppl_logevent("Reading key file \"%s\"", filename_to_str(s->keyfile));
        keytype = key_type(s->keyfile);
        if (keytype == SSH_KEYTYPE_SSH1 ||
            keytype == SSH_KEYTYPE_SSH1_PUBLIC) {
            const char *error;
            s->publickey_blob = strbuf_new();
            if (rsa1_loadpub_f(s->keyfile,
                               BinarySink_UPCAST(s->publickey_blob),
                               &s->publickey_comment, &error)) {
                s->privatekey_available = (keytype == SSH_KEYTYPE_SSH1);
                if (!s->privatekey_available)
                    ppl_logevent("Key file contains public key only");
                s->privatekey_encrypted = rsa1_encrypted_f(s->keyfile, NULL);
            } else {
                ppl_logevent("Unable to load key (%s)", error);
                ppl_printf("Unable to load key file \"%s\" (%s)\r\n",
                           filename_to_str(s->keyfile), error);

                strbuf_free(s->publickey_blob);
                s->publickey_blob = NULL;
            }
        } else {
            ppl_logevent("Unable to use this key file (%s)",
                         key_type_to_str(keytype));
            ppl_printf("Unable to use key file \"%s\" (%s)\r\n",
                       filename_to_str(s->keyfile),
                       key_type_to_str(keytype));
        }
    }

    /* Check whether we're configured to try Pageant, and also whether
     * it's available. */
    s->try_agent_auth = (conf_get_bool(s->conf, CONF_tryagent) &&
                         agent_exists());

    while (pktin->type == SSH1_SMSG_FAILURE) {
        s->pwpkt_type = SSH1_CMSG_AUTH_PASSWORD;

        if (s->try_agent_auth && !s->tried_agent) {
            /*
             * Attempt RSA authentication using Pageant.
             */
            s->authed = false;
            s->tried_agent = true;
            ppl_logevent("Pageant is running. Requesting keys.");

            /* Request the keys held by the agent. */
            {
                strbuf *request = strbuf_new_for_agent_query();
                put_byte(request, SSH1_AGENTC_REQUEST_RSA_IDENTITIES);
                ssh1_login_agent_query(s, request);
                strbuf_free(request);
                crMaybeWaitUntilV(!s->auth_agent_query);
            }
            BinarySource_BARE_INIT_PL(s->asrc, s->agent_response);

            get_uint32(s->asrc); /* skip length field */
            if (get_byte(s->asrc) == SSH1_AGENT_RSA_IDENTITIES_ANSWER) {
                size_t nkeys = get_uint32(s->asrc);
                size_t origpos = s->asrc->pos;

                /*
                 * Check that the agent response is well formed.
                 */
                for (size_t i = 0; i < nkeys; i++) {
                    get_rsa_ssh1_pub(s->asrc, NULL, RSA_SSH1_EXPONENT_FIRST);
                    get_string(s->asrc); /* comment */
                    if (get_err(s->asrc)) {
                        ppl_logevent("Pageant's response was truncated");
                        goto parsed_agent_query;
                    }
                }

                /*
                 * Copy the list of public-key blobs out of the Pageant
                 * response.
                 */
                BinarySource_REWIND_TO(s->asrc, origpos);
                s->agent_keys_len = nkeys;
                s->agent_keys = snewn(s->agent_keys_len, agent_key);
                for (size_t i = 0; i < nkeys; i++) {
                    memset(&s->agent_keys[i].key, 0,
                           sizeof(s->agent_keys[i].key));

                    const char *blobstart = get_ptr(s->asrc);
                    get_rsa_ssh1_pub(s->asrc, &s->agent_keys[i].key,
                                     RSA_SSH1_EXPONENT_FIRST);
                    const char *blobend = get_ptr(s->asrc);

                    s->agent_keys[i].comment = strbuf_new();
                    put_datapl(s->agent_keys[i].comment, get_string(s->asrc));

                    s->agent_keys[i].blob = make_ptrlen(
                        blobstart, blobend - blobstart);
                }

                ppl_logevent("Pageant has %"SIZEu" SSH-1 keys", nkeys);

                if (s->publickey_blob) {
                    /*
                     * If we've been given a specific public key blob,
                     * filter the list of keys to try from the agent
                     * down to only that one, or none if it's not
                     * there.
                     */
                    ptrlen our_blob = ptrlen_from_strbuf(s->publickey_blob);
                    size_t i;

                    for (i = 0; i < nkeys; i++) {
                        if (ptrlen_eq_ptrlen(our_blob, s->agent_keys[i].blob))
                            break;
                    }

                    if (i < nkeys) {
                        ppl_logevent("Pageant key #%"SIZEu" matches "
                                     "configured key file", i);
                        s->agent_key_index = i;
                        s->agent_key_limit = i+1;
                    } else {
                        ppl_logevent("Configured key file not in Pageant");
                        s->agent_key_index = 0;
                        s->agent_key_limit = 0;
                    }
                } else {
                    /*
                     * Otherwise, try them all.
                     */
                    s->agent_key_index = 0;
                    s->agent_key_limit = nkeys;
                }
            } else {
                ppl_logevent("Failed to get reply from Pageant");
            }
          parsed_agent_query:;

            for (; s->agent_key_index < s->agent_key_limit;
                 s->agent_key_index++) {
                ppl_logevent("Trying Pageant key #%"SIZEu, s->agent_key_index);
                pkt = ssh_bpp_new_pktout(s->ppl.bpp, SSH1_CMSG_AUTH_RSA);
                put_mp_ssh1(pkt,
                            s->agent_keys[s->agent_key_index].key.modulus);
                pq_push(s->ppl.out_pq, pkt);
                crMaybeWaitUntilV((pktin = ssh1_login_pop(s))
                                  != NULL);
                if (pktin->type != SSH1_SMSG_AUTH_RSA_CHALLENGE) {
                    ppl_logevent("Key refused");
                    continue;
                }
                ppl_logevent("Received RSA challenge");

                {
                    mp_int *challenge = get_mp_ssh1(pktin);
                    if (get_err(pktin)) {
                        mp_free(challenge);
                        ssh_proto_error(s->ppl.ssh, "Server's RSA challenge "
                                        "was badly formatted");
                        return;
                    }

                    strbuf *agentreq = strbuf_new_for_agent_query();
                    put_byte(agentreq, SSH1_AGENTC_RSA_CHALLENGE);

                    rsa_ssh1_public_blob(
                        BinarySink_UPCAST(agentreq),
                        &s->agent_keys[s->agent_key_index].key,
                        RSA_SSH1_EXPONENT_FIRST);

                    put_mp_ssh1(agentreq, challenge);
                    mp_free(challenge);

                    put_data(agentreq, s->session_id, 16);
                    put_uint32(agentreq, 1);    /* response format */
                    ssh1_login_agent_query(s, agentreq);
                    strbuf_free(agentreq);
                    crMaybeWaitUntilV(!s->auth_agent_query);
                }

                {
                    const unsigned char *ret = s->agent_response.ptr;
                    if (ret) {
                        if (s->agent_response.len >= 5+16 &&
                            ret[4] == SSH1_AGENT_RSA_RESPONSE) {
                            ppl_logevent("Sending Pageant's response");
                            pkt = ssh_bpp_new_pktout(
                                s->ppl.bpp, SSH1_CMSG_AUTH_RSA_RESPONSE);
                            put_data(pkt, ret + 5, 16);
                            pq_push(s->ppl.out_pq, pkt);
                            s->is_trivial_auth = false;
                            crMaybeWaitUntilV(
                                (pktin = ssh1_login_pop(s))
                                != NULL);
                            if (pktin->type == SSH1_SMSG_SUCCESS) {
                                ppl_logevent("Pageant's response "
                                             "accepted");
                                if (seat_verbose(s->ppl.seat)) {
                                    ptrlen comment = ptrlen_from_strbuf(
                                        s->agent_keys[s->agent_key_index].
                                        comment);
                                    ppl_printf("Authenticated using RSA "
                                               "key \"%.*s\" from "
                                               "agent\r\n",
                                               PTRLEN_PRINTF(comment));
                                }
                                s->authed = true;
                            } else
                                ppl_logevent("Pageant's response not "
                                             "accepted");
                        } else {
                            ppl_logevent("Pageant failed to answer "
                                         "challenge");
                            sfree((char *)ret);
                        }
                    } else {
                        ppl_logevent("No reply received from Pageant");
                    }
                }
                if (s->authed)
                    break;
            }
            if (s->authed)
                break;
        }
        if (s->publickey_blob && s->privatekey_available &&
            !s->tried_publickey) {
            /*
             * Try public key authentication with the specified
             * key file.
             */
            bool got_passphrase; /* need not be kept over crReturn */
            if (seat_verbose(s->ppl.seat))
                ppl_printf("Trying public key authentication.\r\n");
            ppl_logevent("Trying public key \"%s\"",
                         filename_to_str(s->keyfile));
            s->tried_publickey = true;
            got_passphrase = false;
            while (!got_passphrase) {
                /*
                 * Get a passphrase, if necessary.
                 */
                int retd;
                char *passphrase = NULL;    /* only written after crReturn */
                const char *error;
                if (!s->privatekey_encrypted) {
                    if (seat_verbose(s->ppl.seat))
                        ppl_printf("No passphrase required.\r\n");
                    passphrase = NULL;
                } else {
                    s->cur_prompt = new_prompts();
                    s->cur_prompt->to_server = false;
                    s->cur_prompt->from_server = false;
                    s->cur_prompt->name = dupstr("SSH key passphrase");
                    add_prompt(s->cur_prompt,
                               dupprintf("Passphrase for key \"%s\": ",
                                         s->publickey_comment), false);
                    s->userpass_ret = seat_get_userpass_input(
                        s->ppl.seat, s->cur_prompt, NULL);
                    while (1) {
                        while (s->userpass_ret < 0 &&
                               bufchain_size(s->ppl.user_input) > 0)
                            s->userpass_ret = seat_get_userpass_input(
                                s->ppl.seat, s->cur_prompt, s->ppl.user_input);

                        if (s->userpass_ret >= 0)
                            break;

                        s->want_user_input = true;
                        crReturnV;
                        s->want_user_input = false;
                    }
                    if (!s->userpass_ret) {
                        /* Failed to get a passphrase. Terminate. */
                        ssh_user_close(s->ppl.ssh,
                                       "User aborted at passphrase prompt");
                        return;
                    }
                    passphrase = prompt_get_result(s->cur_prompt->prompts[0]);
                    free_prompts(s->cur_prompt);
                    s->cur_prompt = NULL;
                }
                /*
                 * Try decrypting key with passphrase.
                 */
                retd = rsa1_load_f(s->keyfile, &s->key, passphrase, &error);
                if (passphrase) {
                    smemclr(passphrase, strlen(passphrase));
                    sfree(passphrase);
                }
                if (retd == 1) {
                    /* Correct passphrase. */
                    got_passphrase = true;
                } else if (retd == 0) {
                    ppl_printf("Couldn't load private key from %s (%s).\r\n",
                               filename_to_str(s->keyfile), error);
                    got_passphrase = false;
                    break;             /* go and try something else */
                } else if (retd == -1) {
                    ppl_printf("Wrong passphrase.\r\n");
                    got_passphrase = false;
                    /* and try again */
                } else {
                    unreachable("unexpected return from rsa1_load_f()");
                }
            }

            if (got_passphrase) {

                /*
                 * Send a public key attempt.
                 */
                pkt = ssh_bpp_new_pktout(s->ppl.bpp, SSH1_CMSG_AUTH_RSA);
                put_mp_ssh1(pkt, s->key.modulus);
                pq_push(s->ppl.out_pq, pkt);

                crMaybeWaitUntilV((pktin = ssh1_login_pop(s))
                                  != NULL);
                if (pktin->type == SSH1_SMSG_FAILURE) {
                    ppl_printf("Server refused our public key.\r\n");
                    continue;          /* go and try something else */
                }
                if (pktin->type != SSH1_SMSG_AUTH_RSA_CHALLENGE) {
                    ssh_proto_error(s->ppl.ssh, "Received unexpected packet"
                                    " in response to offer of public key, "
                                    "type %d (%s)", pktin->type,
                                    ssh1_pkt_type(pktin->type));
                    return;
                }

                {
                    int i;
                    unsigned char buffer[32];
                    mp_int *challenge, *response;

                    challenge = get_mp_ssh1(pktin);
                    if (get_err(pktin)) {
                        mp_free(challenge);
                        ssh_proto_error(s->ppl.ssh, "Server's RSA challenge "
                                        "was badly formatted");
                        return;
                    }
                    response = rsa_ssh1_decrypt(challenge, &s->key);
                    freersapriv(&s->key);   /* burn the evidence */

                    for (i = 0; i < 32; i++) {
                        buffer[i] = mp_get_byte(response, 31 - i);
                    }

                    {
                        ssh_hash *h = ssh_hash_new(&ssh_md5);
                        put_data(h, buffer, 32);
                        put_data(h, s->session_id, 16);
                        ssh_hash_final(h, buffer);
                    }

                    pkt = ssh_bpp_new_pktout(
                        s->ppl.bpp, SSH1_CMSG_AUTH_RSA_RESPONSE);
                    put_data(pkt, buffer, 16);
                    pq_push(s->ppl.out_pq, pkt);
                    s->is_trivial_auth = false;

                    mp_free(challenge);
                    mp_free(response);
                }

                crMaybeWaitUntilV((pktin = ssh1_login_pop(s))
                                  != NULL);
                if (pktin->type == SSH1_SMSG_FAILURE) {
                    if (seat_verbose(s->ppl.seat))
                        ppl_printf("Failed to authenticate with"
                                   " our public key.\r\n");
                    continue;          /* go and try something else */
                } else if (pktin->type != SSH1_SMSG_SUCCESS) {
                    ssh_proto_error(s->ppl.ssh, "Received unexpected packet"
                                    " in response to RSA authentication, "
                                    "type %d (%s)", pktin->type,
                                    ssh1_pkt_type(pktin->type));
                    return;
                }

                break;                 /* we're through! */
            }

        }

        /*
         * Otherwise, try various forms of password-like authentication.
         */
        s->cur_prompt = new_prompts();

        if (conf_get_bool(s->conf, CONF_try_tis_auth) &&
            (s->supported_auths_mask & (1 << SSH1_AUTH_TIS)) &&
            !s->tis_auth_refused) {
            ssh1_login_setup_tis_scc(s);
            s->pwpkt_type = SSH1_CMSG_AUTH_TIS_RESPONSE;
            ppl_logevent("Requested TIS authentication");
            pkt = ssh_bpp_new_pktout(s->ppl.bpp, SSH1_CMSG_AUTH_TIS);
            pq_push(s->ppl.out_pq, pkt);
            crMaybeWaitUntilV((pktin = ssh1_login_pop(s)) != NULL);
            if (pktin->type == SSH1_SMSG_FAILURE) {
                ppl_logevent("TIS authentication declined");
                if (seat_interactive(s->ppl.seat))
                    ppl_printf("TIS authentication refused.\r\n");
                s->tis_auth_refused = true;
                continue;
            } else if (pktin->type == SSH1_SMSG_AUTH_TIS_CHALLENGE) {
                ptrlen challenge = get_string(pktin);
                if (get_err(pktin)) {
                    ssh_proto_error(s->ppl.ssh, "TIS challenge packet was "
                                    "badly formed");
                    return;
                }
                ppl_logevent("Received TIS challenge");
                s->cur_prompt->to_server = true;
                s->cur_prompt->from_server = true;
                s->cur_prompt->name = dupstr("SSH TIS authentication");

                strbuf *sb = strbuf_new();
                put_datapl(sb, PTRLEN_LITERAL("\
-- TIS authentication challenge from server: ---------------------------------\
\r\n"));
                if (s->tis_scc) {
                    stripctrl_retarget(s->tis_scc, BinarySink_UPCAST(sb));
                    put_datapl(s->tis_scc, challenge);
                    stripctrl_retarget(s->tis_scc, NULL);
                } else {
                    put_datapl(sb, challenge);
                }
                if (!ptrlen_endswith(challenge, PTRLEN_LITERAL("\n"), NULL))
                    put_datapl(sb, PTRLEN_LITERAL("\r\n"));
                put_datapl(sb, PTRLEN_LITERAL("\
-- End of TIS authentication challenge from server: --------------------------\
\r\n"));

                s->cur_prompt->instruction = strbuf_to_str(sb);
                s->cur_prompt->instr_reqd = true;
                add_prompt(s->cur_prompt, dupstr(
                               "TIS authentication response: "), false);
            } else {
                ssh_proto_error(s->ppl.ssh, "Received unexpected packet"
                                " in response to TIS authentication, "
                                "type %d (%s)", pktin->type,
                                ssh1_pkt_type(pktin->type));
                return;
            }
        } else if (conf_get_bool(s->conf, CONF_try_tis_auth) &&
            (s->supported_auths_mask & (1 << SSH1_AUTH_CCARD)) &&
            !s->ccard_auth_refused) {
            ssh1_login_setup_tis_scc(s);
            s->pwpkt_type = SSH1_CMSG_AUTH_CCARD_RESPONSE;
            ppl_logevent("Requested CryptoCard authentication");
            pkt = ssh_bpp_new_pktout(s->ppl.bpp, SSH1_CMSG_AUTH_CCARD);
            pq_push(s->ppl.out_pq, pkt);
            crMaybeWaitUntilV((pktin = ssh1_login_pop(s)) != NULL);
            if (pktin->type == SSH1_SMSG_FAILURE) {
                ppl_logevent("CryptoCard authentication declined");
                ppl_printf("CryptoCard authentication refused.\r\n");
                s->ccard_auth_refused = true;
                continue;
            } else if (pktin->type == SSH1_SMSG_AUTH_CCARD_CHALLENGE) {
                ptrlen challenge = get_string(pktin);
                if (get_err(pktin)) {
                    ssh_proto_error(s->ppl.ssh, "CryptoCard challenge packet "
                                    "was badly formed");
                    return;
                }
                ppl_logevent("Received CryptoCard challenge");
                s->cur_prompt->to_server = true;
                s->cur_prompt->from_server = true;
                s->cur_prompt->name = dupstr("SSH CryptoCard authentication");

                strbuf *sb = strbuf_new();
                put_datapl(sb, PTRLEN_LITERAL("\
-- CryptoCard authentication challenge from server: --------------------------\
\r\n"));
                if (s->tis_scc) {
                    stripctrl_retarget(s->tis_scc, BinarySink_UPCAST(sb));
                    put_datapl(s->tis_scc, challenge);
                    stripctrl_retarget(s->tis_scc, NULL);
                } else {
                    put_datapl(sb, challenge);
                }
                if (!ptrlen_endswith(challenge, PTRLEN_LITERAL("\n"), NULL))
                    put_datapl(sb, PTRLEN_LITERAL("\r\n"));
                put_datapl(sb, PTRLEN_LITERAL("\
-- End of CryptoCard authentication challenge from server: -------------------\
\r\n"));

                s->cur_prompt->instruction = strbuf_to_str(sb);
                s->cur_prompt->instr_reqd = true;
                add_prompt(s->cur_prompt, dupstr(
                               "CryptoCard authentication response: "), false);
            } else {
                ssh_proto_error(s->ppl.ssh, "Received unexpected packet"
                                " in response to TIS authentication, "
                                "type %d (%s)", pktin->type,
                                ssh1_pkt_type(pktin->type));
                return;
            }
        }
        if (s->pwpkt_type == SSH1_CMSG_AUTH_PASSWORD) {
            if ((s->supported_auths_mask & (1 << SSH1_AUTH_PASSWORD)) == 0) {
                ssh_sw_abort(s->ppl.ssh, "No supported authentication methods "
                             "available");
                return;
            }
            s->cur_prompt->to_server = true;
            s->cur_prompt->from_server = false;
            s->cur_prompt->name = dupstr("SSH password");
            add_prompt(s->cur_prompt, dupprintf("%s@%s's password: ",
                                                s->username, s->savedhost),
                       false);
        }

        /*
         * Show password prompt, having first obtained it via a TIS
         * or CryptoCard exchange if we're doing TIS or CryptoCard
         * authentication.
         */
        s->userpass_ret = seat_get_userpass_input(
            s->ppl.seat, s->cur_prompt, NULL);
        while (1) {
            while (s->userpass_ret < 0 &&
                   bufchain_size(s->ppl.user_input) > 0)
                s->userpass_ret = seat_get_userpass_input(
                    s->ppl.seat, s->cur_prompt, s->ppl.user_input);

            if (s->userpass_ret >= 0)
                break;

            s->want_user_input = true;
            crReturnV;
            s->want_user_input = false;
        }
        if (!s->userpass_ret) {
            /*
             * Failed to get a password (for example
             * because one was supplied on the command line
             * which has already failed to work). Terminate.
             */
            ssh_user_close(s->ppl.ssh, "User aborted at password prompt");
            return;
        }

        if (s->pwpkt_type == SSH1_CMSG_AUTH_PASSWORD) {
            /*
             * Defence against traffic analysis: we send a
             * whole bunch of packets containing strings of
             * different lengths. One of these strings is the
             * password, in a SSH1_CMSG_AUTH_PASSWORD packet.
             * The others are all random data in
             * SSH1_MSG_IGNORE packets. This way a passive
             * listener can't tell which is the password, and
             * hence can't deduce the password length.
             *
             * Anybody with a password length greater than 16
             * bytes is going to have enough entropy in their
             * password that a listener won't find it _that_
             * much help to know how long it is. So what we'll
             * do is:
             *
             *  - if password length < 16, we send 15 packets
             *    containing string lengths 1 through 15
             *
             *  - otherwise, we let N be the nearest multiple
             *    of 8 below the password length, and send 8
             *    packets containing string lengths N through
             *    N+7. This won't obscure the order of
             *    magnitude of the password length, but it will
             *    introduce a bit of extra uncertainty.
             *
             * A few servers can't deal with SSH1_MSG_IGNORE, at
             * least in this context. For these servers, we need
             * an alternative defence. We make use of the fact
             * that the password is interpreted as a C string:
             * so we can append a NUL, then some random data.
             *
             * A few servers can deal with neither SSH1_MSG_IGNORE
             * here _nor_ a padded password string.
             * For these servers we are left with no defences
             * against password length sniffing.
             */
            if (!(s->ppl.remote_bugs & BUG_CHOKES_ON_SSH1_IGNORE) &&
                !(s->ppl.remote_bugs & BUG_NEEDS_SSH1_PLAIN_PASSWORD)) {
                /*
                 * The server can deal with SSH1_MSG_IGNORE, so
                 * we can use the primary defence.
                 */
                int bottom, top, pwlen, i;
                const char *pw = prompt_get_result_ref(
                    s->cur_prompt->prompts[0]);

                pwlen = strlen(pw);
                if (pwlen < 16) {
                    bottom = 0;    /* zero length passwords are OK! :-) */
                    top = 15;
                } else {
                    bottom = pwlen & ~7;
                    top = bottom + 7;
                }

                assert(pwlen >= bottom && pwlen <= top);

                for (i = bottom; i <= top; i++) {
                    if (i == pwlen) {
                        pkt = ssh_bpp_new_pktout(s->ppl.bpp, s->pwpkt_type);
                        put_stringz(pkt, pw);
                        pq_push(s->ppl.out_pq, pkt);
                    } else {
                        strbuf *random_data = strbuf_new_nm();
                        random_read(strbuf_append(random_data, i), i);

                        pkt = ssh_bpp_new_pktout(s->ppl.bpp, SSH1_MSG_IGNORE);
                        put_stringsb(pkt, random_data);
                        pq_push(s->ppl.out_pq, pkt);
                    }
                }
                ppl_logevent("Sending password with camouflage packets");
            }
            else if (!(s->ppl.remote_bugs & BUG_NEEDS_SSH1_PLAIN_PASSWORD)) {
                /*
                 * The server can't deal with SSH1_MSG_IGNORE
                 * but can deal with padded passwords, so we
                 * can use the secondary defence.
                 */
                strbuf *padded_pw = strbuf_new_nm();

                ppl_logevent("Sending length-padded password");
                pkt = ssh_bpp_new_pktout(s->ppl.bpp, s->pwpkt_type);
                put_asciz(padded_pw, prompt_get_result_ref(
                              s->cur_prompt->prompts[0]));
                size_t pad = 63 & -padded_pw->len;
                random_read(strbuf_append(padded_pw, pad), pad);
                put_stringsb(pkt, padded_pw);
                pq_push(s->ppl.out_pq, pkt);
            } else {
                /*
                 * The server is believed unable to cope with
                 * any of our password camouflage methods.
                 */
                ppl_logevent("Sending unpadded password");
                pkt = ssh_bpp_new_pktout(s->ppl.bpp, s->pwpkt_type);
                put_stringz(pkt, prompt_get_result_ref(
                                s->cur_prompt->prompts[0]));
                pq_push(s->ppl.out_pq, pkt);
            }
        } else {
            pkt = ssh_bpp_new_pktout(s->ppl.bpp, s->pwpkt_type);
            put_stringz(pkt, prompt_get_result_ref(s->cur_prompt->prompts[0]));
            pq_push(s->ppl.out_pq, pkt);
        }
        s->is_trivial_auth = false;
        ppl_logevent("Sent password");
        free_prompts(s->cur_prompt);
        s->cur_prompt = NULL;
        crMaybeWaitUntilV((pktin = ssh1_login_pop(s)) != NULL);
        if (pktin->type == SSH1_SMSG_FAILURE) {
            if (seat_verbose(s->ppl.seat))
                ppl_printf("Access denied\r\n");
            ppl_logevent("Authentication refused");
        } else if (pktin->type != SSH1_SMSG_SUCCESS) {
            ssh_proto_error(s->ppl.ssh, "Received unexpected packet"
                            " in response to password authentication, type %d "
                            "(%s)", pktin->type, ssh1_pkt_type(pktin->type));
            return;
        }
    }

    if (conf_get_bool(s->conf, CONF_ssh_no_trivial_userauth) &&
        s->is_trivial_auth) {
        ssh_proto_error(s->ppl.ssh, "Authentication was trivial! "
                        "Abandoning session as specified in configuration.");
        return;
    }

    ppl_logevent("Authentication successful");

    if (conf_get_bool(s->conf, CONF_compression)) {
        ppl_logevent("Requesting compression");
        pkt = ssh_bpp_new_pktout(s->ppl.bpp, SSH1_CMSG_REQUEST_COMPRESSION);
        put_uint32(pkt, 6);         /* gzip compression level */
        pq_push(s->ppl.out_pq, pkt);
        crMaybeWaitUntilV((pktin = ssh1_login_pop(s)) != NULL);
        if (pktin->type == SSH1_SMSG_SUCCESS) {
            /*
             * We don't have to actually do anything here: the SSH-1
             * BPP will take care of automatically starting the
             * compression, by recognising our outgoing request packet
             * and the success response. (Horrible, but it's the
             * easiest way to avoid race conditions if other packets
             * cross in transit.)
             */
        } else if (pktin->type == SSH1_SMSG_FAILURE) {
            ppl_logevent("Server refused to enable compression");
            ppl_printf("Server refused to compress\r\n");
        } else {
            ssh_proto_error(s->ppl.ssh, "Received unexpected packet"
                            " in response to compression request, type %d "
                            "(%s)", pktin->type, ssh1_pkt_type(pktin->type));
            return;
        }
    }

    ssh1_connection_set_protoflags(
        s->successor_layer, s->local_protoflags, s->remote_protoflags);
    {
        PacketProtocolLayer *successor = s->successor_layer;
        s->successor_layer = NULL;     /* avoid freeing it ourself */
        ssh_ppl_replace(&s->ppl, successor);
        return;   /* we've just freed s, so avoid even touching s->crState */
    }

    crFinishV;
}

static void ssh1_login_setup_tis_scc(struct ssh1_login_state *s)
{
    if (s->tis_scc_initialised)
        return;
    s->tis_scc = seat_stripctrl_new(s->ppl.seat, NULL, SIC_KI_PROMPTS);
    if (s->tis_scc)
        stripctrl_enable_line_limiting(s->tis_scc);
    s->tis_scc_initialised = true;
}

static void ssh1_login_dialog_callback(void *loginv, int ret)
{
    struct ssh1_login_state *s = (struct ssh1_login_state *)loginv;
    s->dlgret = ret;
    ssh_ppl_process_queue(&s->ppl);
}

static void ssh1_login_agent_query(struct ssh1_login_state *s, strbuf *req)
{
    void *response;
    int response_len;

    sfree(s->agent_response_to_free);
    s->agent_response_to_free = NULL;

    s->auth_agent_query = agent_query(req, &response, &response_len,
                                      ssh1_login_agent_callback, s);
    if (!s->auth_agent_query)
        ssh1_login_agent_callback(s, response, response_len);
}

static void ssh1_login_agent_callback(void *loginv, void *reply, int replylen)
{
    struct ssh1_login_state *s = (struct ssh1_login_state *)loginv;

    s->auth_agent_query = NULL;
    s->agent_response_to_free = reply;
    s->agent_response = make_ptrlen(reply, replylen);

    queue_idempotent_callback(&s->ppl.ic_process_queue);
}

static void ssh1_login_special_cmd(PacketProtocolLayer *ppl,
                                   SessionSpecialCode code, int arg)
{
    struct ssh1_login_state *s =
        container_of(ppl, struct ssh1_login_state, ppl);
    PktOut *pktout;

    if (code == SS_PING || code == SS_NOP) {
        if (!(s->ppl.remote_bugs & BUG_CHOKES_ON_SSH1_IGNORE)) {
            pktout = ssh_bpp_new_pktout(s->ppl.bpp, SSH1_MSG_IGNORE);
            put_stringz(pktout, "");
            pq_push(s->ppl.out_pq, pktout);
        }
    }
}

static bool ssh1_login_want_user_input(PacketProtocolLayer *ppl)
{
    struct ssh1_login_state *s =
        container_of(ppl, struct ssh1_login_state, ppl);
    return s->want_user_input;
}

static void ssh1_login_got_user_input(PacketProtocolLayer *ppl)
{
    struct ssh1_login_state *s =
        container_of(ppl, struct ssh1_login_state, ppl);
    if (s->want_user_input)
        queue_idempotent_callback(&s->ppl.ic_process_queue);
}

static void ssh1_login_reconfigure(PacketProtocolLayer *ppl, Conf *conf)
{
    struct ssh1_login_state *s =
        container_of(ppl, struct ssh1_login_state, ppl);
    ssh_ppl_reconfigure(s->successor_layer, conf);
}
