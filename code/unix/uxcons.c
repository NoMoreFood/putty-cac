/*
 * uxcons.c: various interactive-prompt routines shared between the
 * Unix console PuTTY tools
 */

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>

#include <termios.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>

#include "putty.h"
#include "storage.h"
#include "ssh.h"
#include "console.h"

static struct termios orig_termios_stderr;
static bool stderr_is_a_tty;

void stderr_tty_init()
{
    /* Ensure that if stderr is a tty, we can get it back to a sane state. */
    if (isatty(STDERR_FILENO)) {
        stderr_is_a_tty = true;
        tcgetattr(STDERR_FILENO, &orig_termios_stderr);
    }
}

void premsg(struct termios *cf)
{
    if (stderr_is_a_tty) {
        tcgetattr(STDERR_FILENO, cf);
        tcsetattr(STDERR_FILENO, TCSADRAIN, &orig_termios_stderr);
    }
}
void postmsg(struct termios *cf)
{
    if (stderr_is_a_tty)
        tcsetattr(STDERR_FILENO, TCSADRAIN, cf);
}

void cleanup_exit(int code)
{
    /*
     * Clean up.
     */
    sk_cleanup();
    random_save_seed();
    exit(code);
}

void console_print_error_msg(const char *prefix, const char *msg)
{
    struct termios cf;
    premsg(&cf);
    fputs(prefix, stderr);
    fputs(": ", stderr);
    fputs(msg, stderr);
    fputc('\n', stderr);
    fflush(stderr);
    postmsg(&cf);
}

/*
 * Wrapper around Unix read(2), suitable for use on a file descriptor
 * that's been set into nonblocking mode. Handles EAGAIN/EWOULDBLOCK
 * by means of doing a one-fd poll and then trying again; all other
 * errors (including errors from poll) are returned to the caller.
 */
static int block_and_read(int fd, void *buf, size_t len)
{
    int ret;
    pollwrapper *pw = pollwrap_new();

    while ((ret = read(fd, buf, len)) < 0 && (
#ifdef EAGAIN
               (errno == EAGAIN) ||
#endif
#ifdef EWOULDBLOCK
               (errno == EWOULDBLOCK) ||
#endif
               false)) {

        pollwrap_clear(pw);
        pollwrap_add_fd_rwx(pw, fd, SELECT_R);
        do {
            ret = pollwrap_poll_endless(pw);
        } while (ret < 0 && errno == EINTR);
        assert(ret != 0);
        if (ret < 0) {
            pollwrap_free(pw);
            return ret;
        }
        assert(pollwrap_check_fd_rwx(pw, fd, SELECT_R));
    }

    pollwrap_free(pw);
    return ret;
}

int console_verify_ssh_host_key(
    Seat *seat, const char *host, int port, const char *keytype,
    char *keystr, const char *keydisp, char **fingerprints,
    void (*callback)(void *ctx, int result), void *ctx)
{
    int ret;

    char line[32];
    struct termios cf;
    const char *common_fmt, *intro, *prompt;

    /*
     * Verify the key.
     */
    ret = verify_host_key(host, port, keytype, keystr);

    if (ret == 0)                      /* success - key matched OK */
        return 1;

    premsg(&cf);
    if (ret == 2) {                    /* key was different */
        common_fmt = hk_wrongmsg_common_fmt;
        intro = hk_wrongmsg_interactive_intro;
        prompt = hk_wrongmsg_interactive_prompt;
    } else {                           /* key was absent */
        common_fmt = hk_absentmsg_common_fmt;
        intro = hk_absentmsg_interactive_intro;
        prompt = hk_absentmsg_interactive_prompt;
    }

    FingerprintType fptype_default =
        ssh2_pick_default_fingerprint(fingerprints);

    fprintf(stderr, common_fmt, keytype, fingerprints[fptype_default]);
    if (console_batch_mode) {
        fputs(console_abandoned_msg, stderr);
        return 0;
    }

    fputs(intro, stderr);
    fflush(stderr);
    while (true) {
        fputs(prompt, stderr);
        fflush(stderr);

        struct termios oldmode, newmode;
        tcgetattr(0, &oldmode);
        newmode = oldmode;
        newmode.c_lflag |= ECHO | ISIG | ICANON;
        tcsetattr(0, TCSANOW, &newmode);
        line[0] = '\0';
        if (block_and_read(0, line, sizeof(line) - 1) <= 0)
            /* handled below */;
        tcsetattr(0, TCSANOW, &oldmode);

        if (line[0] == 'i' || line[0] == 'I') {
            fprintf(stderr, "Full public key:\n%s\n", keydisp);
            if (fingerprints[SSH_FPTYPE_SHA256])
                fprintf(stderr, "SHA256 key fingerprint:\n%s\n",
                        fingerprints[SSH_FPTYPE_SHA256]);
            if (fingerprints[SSH_FPTYPE_MD5])
                fprintf(stderr, "MD5 key fingerprint:\n%s\n",
                        fingerprints[SSH_FPTYPE_MD5]);
        } else {
            break;
        }
    }

    /* In case of misplaced reflexes from another program, also recognise 'q'
     * as 'abandon connection rather than trust this key' */
    if (line[0] != '\0' && line[0] != '\r' && line[0] != '\n' &&
        line[0] != 'q' && line[0] != 'Q') {
        if (line[0] == 'y' || line[0] == 'Y')
            store_host_key(host, port, keytype, keystr);
        postmsg(&cf);
        return 1;
    } else {
        fputs(console_abandoned_msg, stderr);
        postmsg(&cf);
        return 0;
    }
}

int console_confirm_weak_crypto_primitive(
    Seat *seat, const char *algtype, const char *algname,
    void (*callback)(void *ctx, int result), void *ctx)
{
    char line[32];
    struct termios cf;

    premsg(&cf);
    fprintf(stderr, weakcrypto_msg_common_fmt, algtype, algname);

    if (console_batch_mode) {
        fputs(console_abandoned_msg, stderr);
        postmsg(&cf);
        return 0;
    }

    fputs(console_continue_prompt, stderr);
    fflush(stderr);

    {
        struct termios oldmode, newmode;
        tcgetattr(0, &oldmode);
        newmode = oldmode;
        newmode.c_lflag |= ECHO | ISIG | ICANON;
        tcsetattr(0, TCSANOW, &newmode);
        line[0] = '\0';
        if (block_and_read(0, line, sizeof(line) - 1) <= 0)
            /* handled below */;
        tcsetattr(0, TCSANOW, &oldmode);
    }

    if (line[0] == 'y' || line[0] == 'Y') {
        postmsg(&cf);
        return 1;
    } else {
        fputs(console_abandoned_msg, stderr);
        postmsg(&cf);
        return 0;
    }
}

int console_confirm_weak_cached_hostkey(
    Seat *seat, const char *algname, const char *betteralgs,
    void (*callback)(void *ctx, int result), void *ctx)
{
    char line[32];
    struct termios cf;

    premsg(&cf);
    fprintf(stderr, weakhk_msg_common_fmt, algname, betteralgs);

    if (console_batch_mode) {
        fputs(console_abandoned_msg, stderr);
        postmsg(&cf);
        return 0;
    }

    fputs(console_continue_prompt, stderr);
    fflush(stderr);

    {
        struct termios oldmode, newmode;
        tcgetattr(0, &oldmode);
        newmode = oldmode;
        newmode.c_lflag |= ECHO | ISIG | ICANON;
        tcsetattr(0, TCSANOW, &newmode);
        line[0] = '\0';
        if (block_and_read(0, line, sizeof(line) - 1) <= 0)
            /* handled below */;
        tcsetattr(0, TCSANOW, &oldmode);
    }

    if (line[0] == 'y' || line[0] == 'Y') {
        postmsg(&cf);
        return 1;
    } else {
        fputs(console_abandoned_msg, stderr);
        postmsg(&cf);
        return 0;
    }
}

/*
 * Ask whether to wipe a session log file before writing to it.
 * Returns 2 for wipe, 1 for append, 0 for cancel (don't log).
 */
int console_askappend(LogPolicy *lp, Filename *filename,
                      void (*callback)(void *ctx, int result), void *ctx)
{
    static const char msgtemplate[] =
        "The session log file \"%.*s\" already exists.\n"
        "You can overwrite it with a new session log,\n"
        "append your session log to the end of it,\n"
        "or disable session logging for this session.\n"
        "Enter \"y\" to wipe the file, \"n\" to append to it,\n"
        "or just press Return to disable logging.\n"
        "Wipe the log file? (y/n, Return cancels logging) ";

    static const char msgtemplate_batch[] =
        "The session log file \"%.*s\" already exists.\n"
        "Logging will not be enabled.\n";

    char line[32];
    struct termios cf;

    premsg(&cf);
    if (console_batch_mode) {
        fprintf(stderr, msgtemplate_batch, FILENAME_MAX, filename->path);
        fflush(stderr);
        return 0;
    }
    fprintf(stderr, msgtemplate, FILENAME_MAX, filename->path);
    fflush(stderr);

    {
        struct termios oldmode, newmode;
        tcgetattr(0, &oldmode);
        newmode = oldmode;
        newmode.c_lflag |= ECHO | ISIG | ICANON;
        tcsetattr(0, TCSANOW, &newmode);
        line[0] = '\0';
        if (block_and_read(0, line, sizeof(line) - 1) <= 0)
            /* handled below */;
        tcsetattr(0, TCSANOW, &oldmode);
    }

    postmsg(&cf);
    if (line[0] == 'y' || line[0] == 'Y')
        return 2;
    else if (line[0] == 'n' || line[0] == 'N')
        return 1;
    else
        return 0;
}

bool console_antispoof_prompt = true;
bool console_set_trust_status(Seat *seat, bool trusted)
{
    if (console_batch_mode || !is_interactive() || !console_antispoof_prompt) {
        /*
         * In batch mode, we don't need to worry about the server
         * mimicking our interactive authentication, because the user
         * already knows not to expect any.
         *
         * If standard input isn't connected to a terminal, likewise,
         * because even if the server did send a spoof authentication
         * prompt, the user couldn't respond to it via the terminal
         * anyway.
         *
         * We also vacuously return success if the user has purposely
         * disabled the antispoof prompt.
         */
        return true;
    }

    return false;
}

/*
 * Warn about the obsolescent key file format.
 *
 * Uniquely among these functions, this one does _not_ expect a
 * frontend handle. This means that if PuTTY is ported to a
 * platform which requires frontend handles, this function will be
 * an anomaly. Fortunately, the problem it addresses will not have
 * been present on that platform, so it can plausibly be
 * implemented as an empty function.
 */
void old_keyfile_warning(void)
{
    static const char message[] =
        "You are loading an SSH-2 private key which has an\n"
        "old version of the file format. This means your key\n"
        "file is not fully tamperproof. Future versions of\n"
        "PuTTY may stop supporting this private key format,\n"
        "so we recommend you convert your key to the new\n"
        "format.\n"
        "\n"
        "Once the key is loaded into PuTTYgen, you can perform\n"
        "this conversion simply by saving it again.\n";

    struct termios cf;
    premsg(&cf);
    fputs(message, stderr);
    postmsg(&cf);
}

void console_logging_error(LogPolicy *lp, const char *string)
{
    /* Errors setting up logging are considered important, so they're
     * displayed to standard error even when not in verbose mode */
    struct termios cf;
    premsg(&cf);
    fprintf(stderr, "%s\n", string);
    fflush(stderr);
    postmsg(&cf);
}


void console_eventlog(LogPolicy *lp, const char *string)
{
    /* Ordinary Event Log entries are displayed in the same way as
     * logging errors, but only in verbose mode */
    if (lp_verbose(lp))
        console_logging_error(lp, string);
}

StripCtrlChars *console_stripctrl_new(
    Seat *seat, BinarySink *bs_out, SeatInteractionContext sic)
{
    return stripctrl_new(bs_out, false, 0);
}

/*
 * Special functions to read and print to the console for password
 * prompts and the like. Uses /dev/tty or stdin/stderr, in that order
 * of preference; also sanitises escape sequences out of the text, on
 * the basis that it might have been sent by a hostile SSH server
 * doing malicious keyboard-interactive.
 */
static void console_open(FILE **outfp, int *infd)
{
    int fd;

    if ((fd = open("/dev/tty", O_RDWR)) >= 0) {
        *infd = fd;
        *outfp = fdopen(*infd, "w");
    } else {
        *infd = 0;
        *outfp = stderr;
    }
}
static void console_close(FILE *outfp, int infd)
{
    if (outfp != stderr)
        fclose(outfp);             /* will automatically close infd too */
}

static void console_write(FILE *outfp, ptrlen data)
{
    fwrite(data.ptr, 1, data.len, outfp);
    fflush(outfp);
}

int console_get_userpass_input(prompts_t *p)
{
    size_t curr_prompt;
    FILE *outfp = NULL;
    int infd;

    /*
     * Zero all the results, in case we abort half-way through.
     */
    {
        int i;
        for (i = 0; i < p->n_prompts; i++)
            prompt_set_result(p->prompts[i], "");
    }

    if (p->n_prompts && console_batch_mode)
        return 0;

    console_open(&outfp, &infd);

    /*
     * Preamble.
     */
    /* We only print the `name' caption if we have to... */
    if (p->name_reqd && p->name) {
        ptrlen plname = ptrlen_from_asciz(p->name);
        console_write(outfp, plname);
        if (!ptrlen_endswith(plname, PTRLEN_LITERAL("\n"), NULL))
            console_write(outfp, PTRLEN_LITERAL("\n"));
    }
    /* ...but we always print any `instruction'. */
    if (p->instruction) {
        ptrlen plinst = ptrlen_from_asciz(p->instruction);
        console_write(outfp, plinst);
        if (!ptrlen_endswith(plinst, PTRLEN_LITERAL("\n"), NULL))
            console_write(outfp, PTRLEN_LITERAL("\n"));
    }

    for (curr_prompt = 0; curr_prompt < p->n_prompts; curr_prompt++) {

        struct termios oldmode, newmode;
        prompt_t *pr = p->prompts[curr_prompt];

        tcgetattr(infd, &oldmode);
        newmode = oldmode;
        newmode.c_lflag |= ISIG | ICANON;
        if (!pr->echo)
            newmode.c_lflag &= ~ECHO;
        else
            newmode.c_lflag |= ECHO;
        tcsetattr(infd, TCSANOW, &newmode);

        console_write(outfp, ptrlen_from_asciz(pr->prompt));

        bool failed = false;
        while (1) {
            size_t toread = 65536;
            size_t prev_result_len = pr->result->len;
            void *ptr = strbuf_append(pr->result, toread);
            int ret = read(infd, ptr, toread);

            if (ret <= 0) {
                failed = true;
                break;
            }

            strbuf_shrink_to(pr->result, prev_result_len + ret);
            if (strbuf_chomp(pr->result, '\n'))
                break;
        }

        tcsetattr(infd, TCSANOW, &oldmode);

        if (!pr->echo)
            console_write(outfp, PTRLEN_LITERAL("\n"));

        if (failed) {
            console_close(outfp, infd);
            return 0;                  /* failure due to read error */
        }
    }

    console_close(outfp, infd);

    return 1; /* success */
}

bool is_interactive(void)
{
    return isatty(0);
}

/*
 * X11-forwarding-related things suitable for console.
 */

char *platform_get_x_display(void) {
    return dupstr(getenv("DISPLAY"));
}
