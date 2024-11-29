#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>

#include "putty.h"
#include "dialog.h"
#include "terminal.h"

static const TermWinVtable fuzz_termwin_vt;

int main(int argc, char **argv)
{
    char blk[512];
    size_t len;
    Terminal *term;
    Conf *conf;
    struct unicode_data ucsdata;
    TermWin termwin;

    termwin.vt = &fuzz_termwin_vt;

    conf = conf_new();
    do_defaults(NULL, conf);
    init_ucs_generic(conf, &ucsdata);

    term = term_init(conf, &ucsdata, &termwin);
    term_size(term, 24, 80, 10000);
    term->ldisc = NULL;
    /* Tell american fuzzy lop that this is a good place to fork. */
#ifdef __AFL_HAVE_MANUAL_CONTROL
    __AFL_INIT();
#endif
    while (!feof(stdin)) {
        len = fread(blk, 1, sizeof(blk), stdin);
        term_data(term, blk, len);
    }
    term_update(term);
    return 0;
}

/* functions required by terminal.c */
static bool fuzz_setup_draw_ctx(TermWin *tw) { return true; }
static void fuzz_draw_text(
    TermWin *tw, int x, int y, wchar_t *text, int len,
    unsigned long attr, int lattr, truecolour tc)
{
    int i;

    printf("TEXT[attr=%08lx,lattr=%02x]@(%d,%d):", attr, lattr, x, y);
    for (i = 0; i < len; i++) {
        printf(" %x", (unsigned)text[i]);
    }
    printf("\n");
}
static void fuzz_draw_cursor(
    TermWin *tw, int x, int y, wchar_t *text, int len,
    unsigned long attr, int lattr, truecolour tc)
{
    int i;

    printf("CURS[attr=%08lx,lattr=%02x]@(%d,%d):", attr, lattr, x, y);
    for (i = 0; i < len; i++) {
        printf(" %x", (unsigned)text[i]);
    }
    printf("\n");
}
static void fuzz_draw_trust_sigil(TermWin *tw, int x, int y)
{
    printf("TRUST@(%d,%d)\n", x, y);
}
static int fuzz_char_width(TermWin *tw, int uc) { return 1; }
static void fuzz_free_draw_ctx(TermWin *tw) {}
static void fuzz_set_cursor_pos(TermWin *tw, int x, int y) {}
static void fuzz_set_raw_mouse_mode(TermWin *tw, bool enable) {}
static void fuzz_set_scrollbar(TermWin *tw, int total, int start, int page) {}
static void fuzz_bell(TermWin *tw, int mode) {}
static void fuzz_clip_write(
    TermWin *tw, int clipboard, wchar_t *text, int *attrs,
    truecolour *colours, int len, bool must_deselect) {}
static void fuzz_clip_request_paste(TermWin *tw, int clipboard) {}
static void fuzz_refresh(TermWin *tw) {}
static void fuzz_request_resize(TermWin *tw, int w, int h) {}
static void fuzz_set_title(TermWin *tw, const char *title, int codepage) {}
static void fuzz_set_icon_title(TermWin *tw, const char *icontitle, int cp) {}
static void fuzz_set_minimised(TermWin *tw, bool minimised) {}
static void fuzz_set_maximised(TermWin *tw, bool maximised) {}
static void fuzz_move(TermWin *tw, int x, int y) {}
static void fuzz_set_zorder(TermWin *tw, bool top) {}
static void fuzz_palette_set(TermWin *tw, unsigned start, unsigned ncolours,
                             const rgb *colours) {}
static void fuzz_palette_get_overrides(TermWin *tw, Terminal *term) {}
static void fuzz_unthrottle(TermWin *tw, size_t size) {}

static const TermWinVtable fuzz_termwin_vt = {
    .setup_draw_ctx = fuzz_setup_draw_ctx,
    .draw_text = fuzz_draw_text,
    .draw_cursor = fuzz_draw_cursor,
    .draw_trust_sigil = fuzz_draw_trust_sigil,
    .char_width = fuzz_char_width,
    .free_draw_ctx = fuzz_free_draw_ctx,
    .set_cursor_pos = fuzz_set_cursor_pos,
    .set_raw_mouse_mode = fuzz_set_raw_mouse_mode,
    .set_scrollbar = fuzz_set_scrollbar,
    .bell = fuzz_bell,
    .clip_write = fuzz_clip_write,
    .clip_request_paste = fuzz_clip_request_paste,
    .refresh = fuzz_refresh,
    .request_resize = fuzz_request_resize,
    .set_title = fuzz_set_title,
    .set_icon_title = fuzz_set_icon_title,
    .set_minimised = fuzz_set_minimised,
    .set_maximised = fuzz_set_maximised,
    .move = fuzz_move,
    .set_zorder = fuzz_set_zorder,
    .palette_set = fuzz_palette_set,
    .palette_get_overrides = fuzz_palette_get_overrides,
    .unthrottle = fuzz_unthrottle,
};

void ldisc_send(Ldisc *ldisc, const void *buf, int len, bool interactive) {}
void ldisc_echoedit_update(Ldisc *ldisc) {}
void ldisc_provide_userpass_le(Ldisc *ldisc, TermLineEditor *le)
{ unreachable("This fake ldisc should never be used for user/pass prompts"); }
void modalfatalbox(const char *fmt, ...) { exit(0); }
void nonfatal(const char *fmt, ...) { }

/* needed by timing.c */
void timer_change_notify(unsigned long next) { }

/* needed by config.c */

void dlg_radiobutton_set(dlgcontrol *ctrl, dlgparam *dp, int whichbutton) { }
int dlg_radiobutton_get(dlgcontrol *ctrl, dlgparam *dp) { return 0; }
void dlg_checkbox_set(dlgcontrol *ctrl, dlgparam *dp, bool checked) { }
bool dlg_checkbox_get(dlgcontrol *ctrl, dlgparam *dp) { return false; }
void dlg_editbox_set(dlgcontrol *ctrl, dlgparam *dp, char const *text) { }
char *dlg_editbox_get(dlgcontrol *ctrl, dlgparam *dp)
{ return dupstr("moo"); }
void dlg_listbox_clear(dlgcontrol *ctrl, dlgparam *dp) { }
void dlg_listbox_del(dlgcontrol *ctrl, dlgparam *dp, int index) { }
void dlg_listbox_add(dlgcontrol *ctrl, dlgparam *dp, char const *text) { }
void dlg_listbox_addwithid(dlgcontrol *ctrl, dlgparam *dp,
                           char const *text, int id) { }
int dlg_listbox_getid(dlgcontrol *ctrl, dlgparam *dp, int index)
{ return 0; }
int dlg_listbox_index(dlgcontrol *ctrl, dlgparam *dp) { return -1; }
bool dlg_listbox_issel(dlgcontrol *ctrl, dlgparam *dp, int index)
{ return false; }
void dlg_listbox_select(dlgcontrol *ctrl, dlgparam *dp, int index) { }
void dlg_text_set(dlgcontrol *ctrl, dlgparam *dp, char const *text) { }
void dlg_filesel_set(dlgcontrol *ctrl, dlgparam *dp, Filename *fn) { }
Filename *dlg_filesel_get(dlgcontrol *ctrl, dlgparam *dp) { return NULL; }
void dlg_fontsel_set(dlgcontrol *ctrl, dlgparam *dp, FontSpec *fn) { }
FontSpec *dlg_fontsel_get(dlgcontrol *ctrl, dlgparam *dp) { return NULL; }
void dlg_update_start(dlgcontrol *ctrl, dlgparam *dp) { }
void dlg_update_done(dlgcontrol *ctrl, dlgparam *dp) { }
void dlg_set_focus(dlgcontrol *ctrl, dlgparam *dp) { }
void dlg_label_change(dlgcontrol *ctrl, dlgparam *dp, char const *text) { }
dlgcontrol *dlg_last_focused(dlgcontrol *ctrl, dlgparam *dp)
{ return NULL; }
void dlg_beep(dlgparam *dp) { }
void dlg_error_msg(dlgparam *dp, const char *msg) { }
void dlg_end(dlgparam *dp, int value) { }
void dlg_coloursel_start(dlgcontrol *ctrl, dlgparam *dp,
                         int r, int g, int b) { }
bool dlg_coloursel_results(dlgcontrol *ctrl, dlgparam *dp,
                           int *r, int *g, int *b) { return false; }
void dlg_refresh(dlgcontrol *ctrl, dlgparam *dp) { }
bool dlg_is_visible(dlgcontrol *ctrl, dlgparam *dp) { return false; }

const int ngsslibs = 0;
const char *const gsslibnames[0] = { };
const struct keyvalwhere gsslibkeywords[0] = { };

/*
 * Default settings that are specific to Unix plink.
 */
char *platform_default_s(const char *name)
{
    if (!strcmp(name, "TermType"))
        return dupstr(getenv("TERM"));
    if (!strcmp(name, "SerialLine"))
        return dupstr("/dev/ttyS0");
    return NULL;
}

bool platform_default_b(const char *name, bool def)
{
    return def;
}

int platform_default_i(const char *name, int def)
{
    return def;
}

FontSpec *platform_default_fontspec(const char *name)
{
    return fontspec_new_default();
}

Filename *platform_default_filename(const char *name)
{
    if (!strcmp(name, "LogFileName"))
        return filename_from_str("putty.log");
    else
        return filename_from_str("");
}

char *x_get_default(const char *key)
{
    return NULL;                       /* this is a stub */
}
