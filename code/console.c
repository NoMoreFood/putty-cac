/*
 * Common pieces between the platform console frontend modules.
 */

#include <stdbool.h>
#include <stdarg.h>

#include "putty.h"
#include "misc.h"
#include "console.h"

const char weakcrypto_msg_common_fmt[] =
    "The first %s supported by the server is\n"
    "%s, which is below the configured warning threshold.\n";

const char weakhk_msg_common_fmt[] =
    "The first host key type we have stored for this server\n"
    "is %s, which is below the configured warning threshold.\n"
    "The server also provides the following types of host key\n"
    "above the threshold, which we do not have stored:\n"
    "%s\n";

const char console_continue_prompt[] = "Continue with connection? (y/n) ";
const char console_abandoned_msg[] = "Connection abandoned.\n";

const SeatDialogPromptDescriptions *console_prompt_descriptions(Seat *seat)
{
    static const SeatDialogPromptDescriptions descs = {
        .hk_accept_action = "enter \"y\"",
        .hk_connect_once_action = "enter \"n\"",
        .hk_cancel_action = "press Return",
        .hk_cancel_action_Participle = "Pressing Return",
    };
    return &descs;
}

bool console_batch_mode = false;

/*
 * Error message and/or fatal exit functions, all based on
 * console_print_error_msg which the platform front end provides.
 */
void console_print_error_msg_fmt_v(
    const char *prefix, const char *fmt, va_list ap)
{
    char *msg = dupvprintf(fmt, ap);
    console_print_error_msg(prefix, msg);
    sfree(msg);
}

void console_print_error_msg_fmt(const char *prefix, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    console_print_error_msg_fmt_v(prefix, fmt, ap);
    va_end(ap);
}

void modalfatalbox(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    console_print_error_msg_fmt_v("FATAL ERROR", fmt, ap);
    va_end(ap);
    cleanup_exit(1);
}

void nonfatal(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    console_print_error_msg_fmt_v("ERROR", fmt, ap);
    va_end(ap);
}

void console_connection_fatal(Seat *seat, const char *msg)
{
    console_print_error_msg("FATAL ERROR", msg);
    cleanup_exit(1);
}

/*
 * Console front ends redo their select() or equivalent every time, so
 * they don't need separate timer handling.
 */
void timer_change_notify(unsigned long next)
{
}
