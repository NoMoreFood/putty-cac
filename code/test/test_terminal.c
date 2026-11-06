#include "putty.h"
#include "terminal.h"

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

const char *const appname = "test_terminal";

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

const struct BackendVtable *const backends[] = { NULL };

typedef struct Mock {
    Terminal *term;
    Conf *conf;
    struct unicode_data ucsdata[1];
    strbuf *title;

    strbuf *context;

    bool any_test_failed;

    /* OSC 52 clipboard tracking */
    int nclipwrites;
    int last_clip;
    strbuf *clip_text;          /* UTF-8 of last clip_write */
    bool clip_text_nul_terminated;
    int nclipreads;
    int last_clip_read;
    strbuf *to_backend;

    TermWin tw;
    Seat seat;
    Backend backend;
} Mock;

static bool mock_setup_draw_ctx(TermWin *win) { return false; }
static void mock_draw_text(TermWin *win, int x, int y, wchar_t *text, int len,
                           unsigned long attrs, int lattrs, truecolour tc) {}
static void mock_draw_cursor(TermWin *win, int x, int y, wchar_t *text,
                             int len, unsigned long attrs, int lattrs,
                             truecolour tc) {}
static void mock_set_raw_mouse_mode(TermWin *win, bool enable) {}
static void mock_set_raw_mouse_mode_pointer(TermWin *win, bool enable) {}
static void mock_palette_set(TermWin *win, unsigned start, unsigned ncolours,
                             const rgb *colours) {}
static void mock_palette_get_overrides(TermWin *tw, Terminal *term) {}
static void mock_set_title(TermWin *win, const char *title, int codepage);
static void mock_set_icon_title(TermWin *win, const char *title, int cp) {}
static void mock_clip_write(TermWin *win, int clipboard, wchar_t *text,
                            int *attrs, truecolour *colours, int len,
                            bool must_deselect);
static void mock_clip_request_read(TermWin *win, int clipboard);
static void mock_bell(TermWin *win, int mode) {}

static const TermWinVtable mock_termwin_vt = {
    .setup_draw_ctx = mock_setup_draw_ctx,
    .draw_text = mock_draw_text,
    .draw_cursor = mock_draw_cursor,
    .set_title = mock_set_title,
    .set_icon_title = mock_set_icon_title,
    .set_raw_mouse_mode = mock_set_raw_mouse_mode,
    .set_raw_mouse_mode_pointer = mock_set_raw_mouse_mode_pointer,
    .palette_set = mock_palette_set,
    .palette_get_overrides = mock_palette_get_overrides,
    .clip_write = mock_clip_write,
    .bell = mock_bell,
    .clip_request_read = mock_clip_request_read,
};

static void mock_clip_write(TermWin *win, int clipboard, wchar_t *text,
                            int *attrs, truecolour *colours, int len,
                            bool must_deselect)
{
    Mock *mk = container_of(win, Mock, tw);
    mk->nclipwrites++;
    mk->last_clip = clipboard;
    mk->clip_text_nul_terminated = (len > 0 && text[len-1] == 0);
    /* Touch every attr/colour, so ASan/valgrind catch a short array */
    for (int i = 0; i < len; i++)
        (void)attrs[i], (void)colours[i];
    strbuf_clear(mk->clip_text);
    wchar_t *copy = snewn(len + 1, wchar_t);
    memcpy(copy, text, len * sizeof(wchar_t));
    copy[len] = 0;
    char *utf8 = encode_wide_string_as_utf8(copy);
    put_dataz(mk->clip_text, utf8);
    sfree(utf8);
    sfree(copy);
}

static void mock_clip_request_read(TermWin *win, int clipboard)
{
    Mock *mk = container_of(win, Mock, tw);
    mk->nclipreads++;
    mk->last_clip_read = clipboard;
}

static void mock_backend_send(Backend *be, const char *buf, size_t len)
{
    Mock *mk = container_of(be, Mock, backend);
    put_data(mk->to_backend, buf, len);
}
static bool mock_backend_sendok(Backend *be) { return true; }
static bool mock_ldisc_option_state(Backend *be, int option)
{ return false; }
static void mock_provide_ldisc(Backend *be, Ldisc *ldisc) {}

static const BackendVtable mock_backend_vt = {
    .sendok = mock_backend_sendok,
    .send = mock_backend_send,
    .ldisc_option_state = mock_ldisc_option_state,
    .provide_ldisc = mock_provide_ldisc,
    .id = "mock",
};

static const SeatVtable mock_seat_vt = {
    .echoedit_update = nullseat_echoedit_update,
};

static Mock *mock_new(void)
{
    Mock *mk = snew(Mock);
    memset(mk, 0, sizeof(*mk));

    mk->conf = conf_new();
    do_defaults(NULL, mk->conf);

    init_ucs_generic(mk->conf, mk->ucsdata);
    mk->ucsdata->line_codepage = CP_ISO8859_1;

    mk->context = strbuf_new();
    mk->title = strbuf_new();

    mk->tw.vt = &mock_termwin_vt;
    mk->seat.vt = &mock_seat_vt;
    mk->backend.vt = &mock_backend_vt;
    mk->clip_text = strbuf_new();
    mk->to_backend = strbuf_new();

    return mk;
}

static void mock_free(Mock *mk)
{
    strbuf_free(mk->context);
    strbuf_free(mk->clip_text);
    strbuf_free(mk->to_backend);
    conf_free(mk->conf);
    term_free(mk->term);
    strbuf_free(mk->title);
    sfree(mk);
}

static void mock_set_title(TermWin *win, const char *title, int codepage)
{
    Mock *mk = container_of(win, Mock, tw);
    strbuf_clear(mk->title);
    put_dataz(mk->title, title);
}

static void reset(Mock *mk)
{
    term_pwron(mk->term, true);
    term_size(mk->term, 24, 80, 0);
    term_set_trust_status(mk->term, false);
    strbuf_clear(mk->context);
    strbuf_clear(mk->title);
}

#if 0

static void test_context(Mock *mk, const char *fmt, ...)
{
    strbuf_clear(mk->context);
    va_list ap;
    va_start(ap, fmt);
    put_fmtv(mk->context, fmt, ap);
    va_end(ap);
}

#endif

static void report_fail(Mock *mk, const char *file, int line,
                        const char *fmt, ...)
{
    printf("%s:%d", file, line);
    if (mk->context->len)
        printf(" (%s)", mk->context->s);
    printf(": ");
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    printf("\n");
    mk->any_test_failed = true;
}

static inline void check_iequal(Mock *mk, const char *file, int line,
                                long long lhs, long long rhs)
{
    if (lhs != rhs)
        report_fail(mk, file, line, "%lld != %lld / %#llx != %#llx",
                    lhs, rhs, lhs, rhs);
}

static inline void check_sequal(Mock *mk, const char *file, int line,
                                const char *lhs, const char *rhs)
{
    if (strcmp(lhs, rhs) != 0)
        report_fail(mk, file, line, "'%s' != '%s'", lhs, rhs);
}

#define IEQUAL(lhs, rhs) check_iequal(mk, __FILE__, __LINE__, lhs, rhs)
#define SEQUAL(lhs, rhs) check_sequal(mk, __FILE__, __LINE__, lhs, rhs)

static inline void term_datapl(Terminal *term, ptrlen pl)
{
    term_data(term, pl.ptr, pl.len);
}

static struct termchar get_termchar(Terminal *term, int x, int y)
{
    termline *tl = term_get_line(term, y);
    termchar tc;
    if (0 <= x && x < tl->cols)
        tc = tl->chars[x];
    else
        tc = term->erase_char;
    term_release_line(tl);
    return tc;
}

static unsigned short get_lineattr(Terminal *term, int y)
{
    termline *tl = term_get_line(term, y);
    unsigned short lattr = tl->lattr;
    term_release_line(tl);
    return lattr;
}

static void test_hello_world(Mock *mk)
{
    /* A trivial test just to kick off this test framework */
    mk->ucsdata->line_codepage = CP_ISO8859_1;

    reset(mk);
    term_datapl(mk->term, PTRLEN_LITERAL("hello, world"));
    IEQUAL(mk->term->curs.x, 12);
    IEQUAL(mk->term->curs.y, 0);
    IEQUAL(get_termchar(mk->term, 0, 0).chr, CSET_ASCII | 'h');
    IEQUAL(get_termchar(mk->term, 1, 0).chr, CSET_ASCII | 'e');
    IEQUAL(get_termchar(mk->term, 2, 0).chr, CSET_ASCII | 'l');
    IEQUAL(get_termchar(mk->term, 3, 0).chr, CSET_ASCII | 'l');
    IEQUAL(get_termchar(mk->term, 4, 0).chr, CSET_ASCII | 'o');
    IEQUAL(get_termchar(mk->term, 5, 0).chr, CSET_ASCII | ',');
    IEQUAL(get_termchar(mk->term, 6, 0).chr, CSET_ASCII | ' ');
    IEQUAL(get_termchar(mk->term, 7, 0).chr, CSET_ASCII | 'w');
    IEQUAL(get_termchar(mk->term, 8, 0).chr, CSET_ASCII | 'o');
    IEQUAL(get_termchar(mk->term, 9, 0).chr, CSET_ASCII | 'r');
    IEQUAL(get_termchar(mk->term, 10, 0).chr, CSET_ASCII | 'l');
    IEQUAL(get_termchar(mk->term, 11, 0).chr, CSET_ASCII | 'd');
}

static void test_wrap(Mock *mk)
{
    /* Test behaviour when printing characters wrap to the next line */
    mk->ucsdata->line_codepage = CP_UTF8;

    /* Print 'abc' without enough space for the c, in wrapping mode */
    reset(mk);
    mk->term->curs.x = 78;
    mk->term->curs.y = 0;
    mk->term->wrap = true;
    /* The 'a' prints without anything unusual happening */
    term_datapl(mk->term, PTRLEN_LITERAL("a"));
    IEQUAL(mk->term->curs.x, 79);
    IEQUAL(mk->term->curs.y, 0);
    IEQUAL(mk->term->wrapnext, 0);
    IEQUAL(get_termchar(mk->term, 78, 0).chr, CSET_ASCII | 'a');
    /* The 'b' prints, leaving the cursor where it is with wrapnext set */
    term_datapl(mk->term, PTRLEN_LITERAL("b"));
    IEQUAL(mk->term->curs.x, 79);
    IEQUAL(mk->term->curs.y, 0);
    IEQUAL(mk->term->wrapnext, 1);
    IEQUAL(get_lineattr(mk->term, 0), 0);
    IEQUAL(get_termchar(mk->term, 79, 0).chr, CSET_ASCII | 'b');
    /* And now the 'c' causes a deferred wrap and goes to the next line */
    term_datapl(mk->term, PTRLEN_LITERAL("c"));
    IEQUAL(mk->term->curs.x, 1);
    IEQUAL(mk->term->curs.y, 1);
    IEQUAL(mk->term->wrapnext, 0);
    IEQUAL(get_lineattr(mk->term, 0), LATTR_WRAPPED);
    IEQUAL(get_termchar(mk->term, 79, 0).chr, CSET_ASCII | 'b');
    IEQUAL(get_termchar(mk->term, 0, 1).chr, CSET_ASCII | 'c');
    /* If we backspace once, the cursor moves back on to the c */
    term_datapl(mk->term, PTRLEN_LITERAL("\b"));
    IEQUAL(mk->term->curs.x, 0);
    IEQUAL(mk->term->curs.y, 1);
    IEQUAL(mk->term->wrapnext, 0);
    /* Now backspace again, and the cursor returns to the b */
    term_datapl(mk->term, PTRLEN_LITERAL("\b"));
    IEQUAL(mk->term->curs.x, 79);
    IEQUAL(mk->term->curs.y, 0);
    IEQUAL(mk->term->wrapnext, 0);

    /* Now try it with a double-width character in place of ab */
    mk->term->curs.x = 78;
    mk->term->curs.y = 0;
    mk->term->wrap = true;
    /* The DW character goes directly to the wrapnext state */
    term_datapl(mk->term, PTRLEN_LITERAL("\xEA\xB0\x80"));
    IEQUAL(mk->term->curs.x, 79);
    IEQUAL(mk->term->curs.y, 0);
    IEQUAL(mk->term->wrapnext, 1);
    IEQUAL(get_termchar(mk->term, 78, 0).chr, 0xAC00);
    IEQUAL(get_termchar(mk->term, 79, 0).chr, UCSWIDE);
    /* And the 'c' causes a deferred wrap as before */
    term_datapl(mk->term, PTRLEN_LITERAL("c"));
    IEQUAL(mk->term->curs.x, 1);
    IEQUAL(mk->term->curs.y, 1);
    IEQUAL(mk->term->wrapnext, 0);
    IEQUAL(get_lineattr(mk->term, 0), LATTR_WRAPPED);
    IEQUAL(get_termchar(mk->term, 78, 0).chr, 0xAC00);
    IEQUAL(get_termchar(mk->term, 79, 0).chr, UCSWIDE);
    IEQUAL(get_termchar(mk->term, 0, 1).chr, CSET_ASCII | 'c');
    /* If we backspace once, the cursor moves back on to the c */
    term_datapl(mk->term, PTRLEN_LITERAL("\b"));
    IEQUAL(mk->term->curs.x, 0);
    IEQUAL(mk->term->curs.y, 1);
    IEQUAL(mk->term->wrapnext, 0);
    /* Now backspace again, and the cursor goes to the RHS of the DW char */
    term_datapl(mk->term, PTRLEN_LITERAL("\b"));
    IEQUAL(mk->term->curs.x, 79);
    IEQUAL(mk->term->curs.y, 0);
    IEQUAL(mk->term->wrapnext, 0);

    /* Now put the DW character in place of bc */
    reset(mk);
    mk->term->curs.x = 78;
    mk->term->curs.y = 0;
    mk->term->wrap = true;
    /* The 'a' prints as before */
    term_datapl(mk->term, PTRLEN_LITERAL("a"));
    IEQUAL(mk->term->curs.x, 79);
    IEQUAL(mk->term->curs.y, 0);
    IEQUAL(mk->term->wrapnext, 0);
    IEQUAL(get_termchar(mk->term, 78, 0).chr, CSET_ASCII | 'a');
    /* The DW character wraps, setting LATTR_WRAPPED2 */
    term_datapl(mk->term, PTRLEN_LITERAL("\xEA\xB0\x80"));
    IEQUAL(mk->term->curs.x, 2);
    IEQUAL(mk->term->curs.y, 1);
    IEQUAL(mk->term->wrapnext, 0);
    IEQUAL(get_lineattr(mk->term, 0), LATTR_WRAPPED | LATTR_WRAPPED2);
    IEQUAL(get_termchar(mk->term, 78, 0).chr, CSET_ASCII | 'a');
    IEQUAL(get_termchar(mk->term, 79, 0).chr, CSET_ASCII | ' ');
    IEQUAL(get_termchar(mk->term, 0, 1).chr, 0xAC00);
    IEQUAL(get_termchar(mk->term, 1, 1).chr, UCSWIDE);
    /* If we backspace once, cursor moves to the RHS of the DW char */
    term_datapl(mk->term, PTRLEN_LITERAL("\b"));
    IEQUAL(mk->term->curs.x, 1);
    IEQUAL(mk->term->curs.y, 1);
    IEQUAL(mk->term->wrapnext, 0);
    /* Backspace again, and cursor moves from RHS to LHS of that char */
    term_datapl(mk->term, PTRLEN_LITERAL("\b"));
    IEQUAL(mk->term->curs.x, 0);
    IEQUAL(mk->term->curs.y, 1);
    IEQUAL(mk->term->wrapnext, 0);
    /* Now backspace again, and the cursor skips the empty column so
     * that it can return to the previous logical character, to wit, the a */
    term_datapl(mk->term, PTRLEN_LITERAL("\b"));
    IEQUAL(mk->term->curs.x, 78);
    IEQUAL(mk->term->curs.y, 0);
    IEQUAL(mk->term->wrapnext, 0);

    /* Print 'ab' up to the rightmost column, and then backspace */
    reset(mk);
    mk->term->curs.x = 78;
    mk->term->curs.y = 0;
    mk->term->wrap = true;
    /* As before, the 'ab' put us in the rightmost column with wrapnext set */
    term_datapl(mk->term, PTRLEN_LITERAL("ab"));
    IEQUAL(mk->term->curs.x, 79);
    IEQUAL(mk->term->curs.y, 0);
    IEQUAL(mk->term->wrapnext, 1);
    IEQUAL(get_lineattr(mk->term, 0), 0);
    IEQUAL(get_termchar(mk->term, 78, 0).chr, CSET_ASCII | 'a');
    IEQUAL(get_termchar(mk->term, 79, 0).chr, CSET_ASCII | 'b');
    /* Backspacing just clears the wrapnext flag, so we're logically
     * back on the b again */
    term_datapl(mk->term, PTRLEN_LITERAL("\b"));
    IEQUAL(mk->term->curs.x, 79);
    IEQUAL(mk->term->curs.y, 0);
    IEQUAL(mk->term->wrapnext, 0);

    /* For completeness, the easy case: just print 'a' then backspace */
    reset(mk);
    mk->term->curs.x = 78;
    mk->term->curs.y = 0;
    mk->term->wrap = true;
    /* 'a' printed in column n-1 takes us to column n */
    term_datapl(mk->term, PTRLEN_LITERAL("a"));
    IEQUAL(mk->term->curs.x, 79);
    IEQUAL(mk->term->curs.y, 0);
    IEQUAL(mk->term->wrapnext, 0);
    IEQUAL(get_lineattr(mk->term, 0), 0);
    IEQUAL(get_termchar(mk->term, 78, 0).chr, CSET_ASCII | 'a');
    /* Backspacing moves us back a space on to the a */
    term_datapl(mk->term, PTRLEN_LITERAL("\b"));
    IEQUAL(mk->term->curs.x, 78);
    IEQUAL(mk->term->curs.y, 0);
    IEQUAL(mk->term->wrapnext, 0);

    /*
     * Now test the special cases that arise when the terminal is only
     * one column wide!
     */

    reset(mk);
    term_size(mk->term, 24, 1, 0);
    mk->term->curs.x = 0;
    mk->term->curs.y = 0;
    mk->term->wrap = true;
    /* Printing a single-width character takes us into wrapnext immediately */
    term_datapl(mk->term, PTRLEN_LITERAL("a"));
    IEQUAL(mk->term->curs.x, 0);
    IEQUAL(mk->term->curs.y, 0);
    IEQUAL(mk->term->wrapnext, 1);
    IEQUAL(get_lineattr(mk->term, 0), 0);
    IEQUAL(get_termchar(mk->term, 0, 0).chr, CSET_ASCII | 'a');
    /* Printing a second one wraps, and takes us _back_ to wrapnext */
    term_datapl(mk->term, PTRLEN_LITERAL("b"));
    IEQUAL(mk->term->curs.x, 0);
    IEQUAL(mk->term->curs.y, 1);
    IEQUAL(mk->term->wrapnext, 1);
    IEQUAL(get_lineattr(mk->term, 0), LATTR_WRAPPED);
    IEQUAL(get_termchar(mk->term, 0, 0).chr, CSET_ASCII | 'a');
    IEQUAL(get_termchar(mk->term, 0, 1).chr, CSET_ASCII | 'b');
    /* Backspacing once clears the wrapnext flag, putting us on the b */
    term_datapl(mk->term, PTRLEN_LITERAL("\b"));
    IEQUAL(mk->term->curs.x, 0);
    IEQUAL(mk->term->curs.y, 1);
    IEQUAL(mk->term->wrapnext, 0);
    /* Backspacing again returns to the previous line, putting us on the a */
    term_datapl(mk->term, PTRLEN_LITERAL("\b"));
    IEQUAL(mk->term->curs.x, 0);
    IEQUAL(mk->term->curs.y, 0);
    IEQUAL(mk->term->wrapnext, 0);

    /* And now try with a double-width character */
    reset(mk);
    term_size(mk->term, 24, 1, 0);
    mk->term->curs.x = 0;
    mk->term->curs.y = 0;
    mk->term->wrap = true;
    /* DW character won't fit at all, so it transforms into U+FFFD
     * REPLACEMENT CHARACTER and then behaves like a SW char */
    term_datapl(mk->term, PTRLEN_LITERAL("\xEA\xB0\x80"));
    IEQUAL(mk->term->curs.x, 0);
    IEQUAL(mk->term->curs.y, 0);
    IEQUAL(mk->term->wrapnext, 1);
    IEQUAL(get_lineattr(mk->term, 0), 0);
    IEQUAL(get_termchar(mk->term, 0, 0).chr, 0xFFFD);
}

static void test_nonwrap(Mock *mk)
{
    /* Test behaviour when printing characters hit end of line without wrap.
     * The wrapnext flag is never set in this mode. */
    mk->ucsdata->line_codepage = CP_UTF8;

    /* Print 'abc' without enough space for the c */
    reset(mk);
    mk->term->curs.x = 78;
    mk->term->curs.y = 0;
    mk->term->wrap = false;
    /* The 'a' prints without anything unusual happening */
    term_datapl(mk->term, PTRLEN_LITERAL("a"));
    IEQUAL(mk->term->curs.x, 79);
    IEQUAL(mk->term->curs.y, 0);
    IEQUAL(mk->term->wrapnext, 0);
    IEQUAL(get_termchar(mk->term, 78, 0).chr, CSET_ASCII | 'a');
    /* The 'b' prints, leaving the cursor where it is */
    term_datapl(mk->term, PTRLEN_LITERAL("b"));
    IEQUAL(mk->term->curs.x, 79);
    IEQUAL(mk->term->curs.y, 0);
    IEQUAL(mk->term->wrapnext, 0);
    IEQUAL(get_lineattr(mk->term, 0), 0);
    IEQUAL(get_termchar(mk->term, 79, 0).chr, CSET_ASCII | 'b');
    /* The 'c' overwrites the b */
    term_datapl(mk->term, PTRLEN_LITERAL("c"));
    IEQUAL(mk->term->curs.x, 79);
    IEQUAL(mk->term->curs.y, 0);
    IEQUAL(mk->term->wrapnext, 0);
    IEQUAL(get_lineattr(mk->term, 0), 0);
    IEQUAL(get_termchar(mk->term, 78, 0).chr, CSET_ASCII | 'a');
    IEQUAL(get_termchar(mk->term, 79, 0).chr, CSET_ASCII | 'c');
    /* Since wrapnext was never set, backspacing returns us to the a */
    term_datapl(mk->term, PTRLEN_LITERAL("\b"));
    IEQUAL(mk->term->curs.x, 78);
    IEQUAL(mk->term->curs.y, 0);
    IEQUAL(mk->term->wrapnext, 0);

    /* Now try it with a double-width character in place of ab */
    mk->term->curs.x = 78;
    mk->term->curs.y = 0;
    mk->term->wrap = false;
    /* The DW character occupies the rightmost two columns */
    term_datapl(mk->term, PTRLEN_LITERAL("\xEA\xB0\x80"));
    IEQUAL(mk->term->curs.x, 79);
    IEQUAL(mk->term->curs.y, 0);
    IEQUAL(mk->term->wrapnext, 0);
    IEQUAL(get_termchar(mk->term, 78, 0).chr, 0xAC00);
    IEQUAL(get_termchar(mk->term, 79, 0).chr, UCSWIDE);
    /* The 'c' must overprint the RHS of the DW char, clearing the LHS */
    term_datapl(mk->term, PTRLEN_LITERAL("c"));
    IEQUAL(mk->term->curs.x, 79);
    IEQUAL(mk->term->curs.y, 0);
    IEQUAL(mk->term->wrapnext, 0);
    IEQUAL(get_lineattr(mk->term, 0), 0);
    IEQUAL(get_termchar(mk->term, 78, 0).chr, CSET_ASCII | ' ');
    IEQUAL(get_termchar(mk->term, 79, 0).chr, CSET_ASCII | 'c');

    /* Now put the DW char in place of the bc */
    reset(mk);
    mk->term->curs.x = 78;
    mk->term->curs.y = 0;
    mk->term->wrap = false;
    /* The 'a' prints as before */
    term_datapl(mk->term, PTRLEN_LITERAL("a"));
    IEQUAL(mk->term->curs.x, 79);
    IEQUAL(mk->term->curs.y, 0);
    IEQUAL(mk->term->wrapnext, 0);
    IEQUAL(get_termchar(mk->term, 78, 0).chr, CSET_ASCII | 'a');
    /* The DW char won't fit, so turns into U+FFFD REPLACEMENT CHARACTER */
    term_datapl(mk->term, PTRLEN_LITERAL("\xEA\xB0\x80"));
    IEQUAL(mk->term->curs.x, 79);
    IEQUAL(mk->term->curs.y, 0);
    IEQUAL(mk->term->wrapnext, 0);
    IEQUAL(get_lineattr(mk->term, 0), 0);
    IEQUAL(get_termchar(mk->term, 78, 0).chr, CSET_ASCII | 'a');
    IEQUAL(get_termchar(mk->term, 79, 0).chr, 0xFFFD);

    /* Just for completeness, try both of those together */
    reset(mk);
    mk->term->curs.x = 78;
    mk->term->curs.y = 0;
    mk->term->wrap = false;
    /* First DW character occupies the rightmost columns */
    term_datapl(mk->term, PTRLEN_LITERAL("\xEA\xB0\x80"));
    IEQUAL(mk->term->curs.x, 79);
    IEQUAL(mk->term->curs.y, 0);
    IEQUAL(mk->term->wrapnext, 0);
    IEQUAL(get_termchar(mk->term, 78, 0).chr, 0xAC00);
    IEQUAL(get_termchar(mk->term, 79, 0).chr, UCSWIDE);
    /* Second DW char becomes U+FFFD, overwriting RHS of the first one */
    term_datapl(mk->term, PTRLEN_LITERAL("\xEA\xB0\x81"));
    IEQUAL(mk->term->curs.x, 79);
    IEQUAL(mk->term->curs.y, 0);
    IEQUAL(mk->term->wrapnext, 0);
    IEQUAL(get_lineattr(mk->term, 0), 0);
    IEQUAL(get_termchar(mk->term, 78, 0).chr, CSET_ASCII | ' ');
    IEQUAL(get_termchar(mk->term, 79, 0).chr, 0xFFFD);
}

static void test_wintitle(Mock *mk)
{
    reset(mk);
    term_datapl(mk->term, PTRLEN_LITERAL("\033]0;foo\033\\"));
    term_update(mk->term);
    SEQUAL(mk->title->s, "foo");
    term_datapl(mk->term, PTRLEN_LITERAL("\033]0;bar\007"));
    term_update(mk->term);
    SEQUAL(mk->title->s, "bar");

    /* Regression test for a bug in which a DCS string was
     * accidentally treated as a title-setting OSC 0. We expect that
     * this is not a window-title setting sequence, and leaves the
     * title unchanged. */
    term_datapl(mk->term, PTRLEN_LITERAL("\033Pzz\033\\"));
    term_update(mk->term);
    SEQUAL(mk->title->s, "bar");
}


/* ----------------------------------------------------------------------
 * OSC 52 clipboard tests.
 */

#if SELECTION_NUL_TERMINATED
#define EXPECT_NUL true
#else
#define EXPECT_NUL false
#endif

static void osc52_setup(Mock *mk, bool write, bool read)
{
    conf_set_bool(mk->conf, CONF_allow_osc52_write, write);
    conf_set_bool(mk->conf, CONF_allow_osc52_read, read);
    term_reconfig(mk->term, mk->conf);
    reset(mk);
    mk->nclipwrites = mk->nclipreads = 0;
    mk->last_clip = mk->last_clip_read = -1;
    strbuf_clear(mk->clip_text);
    strbuf_clear(mk->to_backend);
    mk->term->osc52_read_pending = false;
}

/* Flush anything the terminal sent through the ldisc */
static void osc52_flush(Mock *mk)
{
    run_toplevel_callbacks();
}

static void test_osc52_disabled_by_default(Mock *mk)
{
    Conf *conf = conf_new();
    do_defaults(NULL, conf);
    IEQUAL(conf_get_bool(conf, CONF_allow_osc52_write), false);
    IEQUAL(conf_get_bool(conf, CONF_allow_osc52_read), false);
    conf_free(conf);

    osc52_setup(mk, false, false);
    term_datapl(mk->term, PTRLEN_LITERAL("\033]52;c;aGVsbG8=\007"));
    term_datapl(mk->term, PTRLEN_LITERAL("\033]52;c;!\007"));
    term_datapl(mk->term, PTRLEN_LITERAL("\033]52;c;?\007"));
    osc52_flush(mk);
    IEQUAL(mk->nclipwrites, 0);
    IEQUAL(mk->nclipreads, 0);
    IEQUAL(mk->to_backend->len, 0);
    /* Nothing was buffered either */
    IEQUAL(mk->term->osc52_buf == NULL, true);
    /* And the terminal is back to normal afterwards */
    term_datapl(mk->term, PTRLEN_LITERAL("x"));
    IEQUAL(get_termchar(mk->term, 0, 0).chr, CSET_ASCII | 'x');
}

static void test_osc52_write(Mock *mk)
{
    osc52_setup(mk, true, false);

    /* BEL-terminated */
    term_datapl(mk->term, PTRLEN_LITERAL("\033]52;c;aGVsbG8=\007"));
    IEQUAL(mk->nclipwrites, 1);
    IEQUAL(mk->last_clip, OSC52_CLIPBOARD);
    SEQUAL(mk->clip_text->s, "hello");
    IEQUAL(mk->clip_text_nul_terminated, EXPECT_NUL);

    /* ST-terminated (7-bit) */
    term_datapl(mk->term, PTRLEN_LITERAL("\033]52;c;d29ybGQ=\033\\"));
    IEQUAL(mk->nclipwrites, 2);
    SEQUAL(mk->clip_text->s, "world");

    /* Empty selection parameter (as sent by tmux) means clipboard */
    term_datapl(mk->term, PTRLEN_LITERAL("\033]52;;aGk=\007"));
    IEQUAL(mk->nclipwrites, 3);
    IEQUAL(mk->last_clip, OSC52_CLIPBOARD);
    SEQUAL(mk->clip_text->s, "hi");

    /* Missing base64 padding is tolerated */
    term_datapl(mk->term, PTRLEN_LITERAL("\033]52;c;aGk\007"));
    IEQUAL(mk->nclipwrites, 4);
    SEQUAL(mk->clip_text->s, "hi");

    /* Primary selection */
    term_datapl(mk->term, PTRLEN_LITERAL("\033]52;p;cHJp\007"));
    if (OSC52_PRIMARY != CLIP_NULL) {
        IEQUAL(mk->last_clip, OSC52_PRIMARY);
        SEQUAL(mk->clip_text->s, "pri");
    }

    /* Newlines are converted to the platform clipboard convention */
    mk->nclipwrites = 0;
    term_datapl(mk->term, PTRLEN_LITERAL("\033]52;c;YQpiDQpj\007"));
    IEQUAL(mk->nclipwrites, 1);
#if SELECTION_NUL_TERMINATED
    SEQUAL(mk->clip_text->s, "a\r\nb\r\nc");
#else
    SEQUAL(mk->clip_text->s, "a\nb\r\nc");
#endif

    /* Text after the sequence still displays normally */
    term_datapl(mk->term, PTRLEN_LITERAL("\033[H\033]52;c;aGk=\007ok"));
    IEQUAL(get_termchar(mk->term, 0, 0).chr, CSET_ASCII | 'o');
    IEQUAL(get_termchar(mk->term, 1, 0).chr, CSET_ASCII | 'k');
}

static void test_osc52_write_utf8(Mock *mk)
{
    osc52_setup(mk, true, false);
    int old_cp = mk->ucsdata->line_codepage;
    mk->ucsdata->line_codepage = CP_UTF8;
    /* "héllo ✓" in UTF-8 */
    term_datapl(mk->term,
                PTRLEN_LITERAL("\033]52;c;aMOpbGxvIOKckw==\007"));
    IEQUAL(mk->nclipwrites, 1);
    SEQUAL(mk->clip_text->s, "h\xC3\xA9llo \xE2\x9C\x93");
    /* C1 ST in UTF-8 (C2 9C) terminates it too */
    term_datapl(mk->term, PTRLEN_LITERAL("\033]52;c;aGk=\xC2\x9C"));
    IEQUAL(mk->nclipwrites, 2);
    SEQUAL(mk->clip_text->s, "hi");
    mk->ucsdata->line_codepage = old_cp;
}

static void test_osc52_clear(Mock *mk)
{
    osc52_setup(mk, true, false);

    term_datapl(mk->term, PTRLEN_LITERAL("\033]52;c;aGk=\007"));
    SEQUAL(mk->clip_text->s, "hi");
    /* "!" clears */
    term_datapl(mk->term, PTRLEN_LITERAL("\033]52;c;!\007"));
    IEQUAL(mk->nclipwrites, 2);
    SEQUAL(mk->clip_text->s, "");
    IEQUAL(mk->clip_text_nul_terminated, EXPECT_NUL);

    /* Invalid base64 clears */
    static const char *const bad[] = {
        "\033]52;c;@@@@\007",       /* bad alphabet */
        "\033]52;c;aGk=aGk=\007",   /* padding in the middle */
        "\033]52;c;a\007",          /* impossible length */
        "\033]52;c;aG k=\007",      /* whitespace */
        "\033]52;c;aGk===\007",     /* excess padding */
    };
    for (size_t i = 0; i < lenof(bad); i++) {
        term_datapl(mk->term, PTRLEN_LITERAL("\033]52;c;aGk=\007"));
        SEQUAL(mk->clip_text->s, "hi");
        term_datapl(mk->term, ptrlen_from_asciz(bad[i]));
        SEQUAL(mk->clip_text->s, "");
    }

    /* Empty data clears, too */
    term_datapl(mk->term, PTRLEN_LITERAL("\033]52;c;aGk=\007"));
    term_datapl(mk->term, PTRLEN_LITERAL("\033]52;c;\007"));
    SEQUAL(mk->clip_text->s, "");
}

static void test_osc52_rejects(Mock *mk)
{
    osc52_setup(mk, true, false);

    /* Malformed: no ';' after the selection */
    term_datapl(mk->term, PTRLEN_LITERAL("\033]52;aGk=\007"));
    /* Invalid selection characters */
    term_datapl(mk->term, PTRLEN_LITERAL("\033]52;x;aGk=\007"));
    term_datapl(mk->term, PTRLEN_LITERAL("\033]52;c\033;aGk=\007"));
    /* Overlong selection parameter */
    term_datapl(mk->term,
                PTRLEN_LITERAL("\033]52;ccccccccccccccccccccc;aGk=\007"));
    /* Cut buffers only: nothing we support */
    term_datapl(mk->term, PTRLEN_LITERAL("\033]52;0;aGk=\007"));
    /* Aborted by CR / LF / CAN-style ESC */
    term_datapl(mk->term, PTRLEN_LITERAL("\033]52;c;aG\rk=\007"));
    term_datapl(mk->term, PTRLEN_LITERAL("\033]52;c;aG\nk=\007"));
    term_datapl(mk->term, PTRLEN_LITERAL("\033]52;c;aG\033[0m"));
    IEQUAL(mk->nclipwrites, 0);

    /* With write disabled but read enabled, writes are still refused */
    osc52_setup(mk, false, true);
    term_datapl(mk->term, PTRLEN_LITERAL("\033]52;c;aGk=\007"));
    term_datapl(mk->term, PTRLEN_LITERAL("\033]52;c;!\007"));
    IEQUAL(mk->nclipwrites, 0);
}

static void test_osc52_large(Mock *mk)
{
    osc52_setup(mk, true, false);

    /* Much larger than OSC_STR_MAX: 96KiB of 'A' -> 128KiB base64 */
    size_t rawlen = 96 * 1024;
    strbuf *raw = strbuf_new();
    for (size_t i = 0; i < rawlen; i++)
        put_byte(raw, 'A' + i % 26);
    strbuf *seq = strbuf_new();
    put_datapl(seq, PTRLEN_LITERAL("\033]52;c;"));
    base64_encode_bs(BinarySink_UPCAST(seq), ptrlen_from_strbuf(raw), 0);
    put_byte(seq, '\007');
    term_datapl(mk->term, ptrlen_from_strbuf(seq));
    IEQUAL(mk->nclipwrites, 1);
    IEQUAL(mk->clip_text->len, rawlen);
    IEQUAL(memcmp(mk->clip_text->s, raw->s, rawlen), 0);

    /* Delivered in small pieces, as from a network connection */
    mk->nclipwrites = 0;
    strbuf_clear(mk->clip_text);
    for (size_t i = 0; i < seq->len; i += 1000)
        term_data(mk->term, seq->s + i,
                  seq->len - i < 1000 ? seq->len - i : 1000);
    IEQUAL(mk->nclipwrites, 1);
    IEQUAL(mk->clip_text->len, rawlen);

    /* Over the limit: ignored entirely, never truncated */
    mk->nclipwrites = 0;
    strbuf_clear(seq);
    put_datapl(seq, PTRLEN_LITERAL("\033]52;c;"));
    for (size_t i = 0; i < OSC52_MAX_PAYLOAD + 4; i++)
        put_byte(seq, 'Q');
    put_byte(seq, '\007');
    term_datapl(mk->term, ptrlen_from_strbuf(seq));
    IEQUAL(mk->nclipwrites, 0);
    IEQUAL(mk->term->osc52_buf == NULL, true);

    /* And the next sequence works normally */
    term_datapl(mk->term, PTRLEN_LITERAL("\033]52;c;aGk=\007"));
    IEQUAL(mk->nclipwrites, 1);
    SEQUAL(mk->clip_text->s, "hi");

    /* Other OSC strings keep their existing limit and behaviour */
    term_datapl(mk->term, PTRLEN_LITERAL("\033]2;title\007"));
    term_update(mk->term);
    SEQUAL(mk->title->s, "title");

    strbuf_free(seq);
    strbuf_free(raw);
}

static void test_osc52_read(Mock *mk)
{
    /* Disabled: no request, no reply */
    osc52_setup(mk, true, false);
    term_datapl(mk->term, PTRLEN_LITERAL("\033]52;c;?\007"));
    osc52_flush(mk);
    IEQUAL(mk->nclipreads, 0);
    IEQUAL(mk->to_backend->len, 0);
    /* An unsolicited result is dropped */
    term_clip_read_result(mk->term, L"secret", 6);
    osc52_flush(mk);
    IEQUAL(mk->to_backend->len, 0);

    /* Enabled */
    osc52_setup(mk, false, true);
    term_datapl(mk->term, PTRLEN_LITERAL("\033]52;c;?\007"));
    IEQUAL(mk->nclipreads, 1);
    IEQUAL(mk->last_clip_read, OSC52_CLIPBOARD);
    /* A second request while one is outstanding is ignored */
    term_datapl(mk->term, PTRLEN_LITERAL("\033]52;c;?\007"));
    IEQUAL(mk->nclipreads, 1);
    term_clip_read_result(mk->term, L"secret", 6);
    osc52_flush(mk);
    SEQUAL(mk->to_backend->s, "\033]52;c;c2VjcmV0\007");
    /* Only one reply per request */
    strbuf_clear(mk->to_backend);
    term_clip_read_result(mk->term, L"again", 5);
    osc52_flush(mk);
    IEQUAL(mk->to_backend->len, 0);

    /* Selection parameter is echoed; platform newlines become LF */
    term_datapl(mk->term, PTRLEN_LITERAL("\033]52;;?\033\\"));
    IEQUAL(mk->nclipreads, 2);
    {
        static const wchar_t nl[] = SEL_NL;
        wchar_t buf[16];
        size_t n = 0;
        buf[n++] = L'a';
        for (size_t i = 0; i < lenof(nl); i++)
            buf[n++] = nl[i];
        buf[n++] = L'b';
        term_clip_read_result(mk->term, buf, n);
    }
    osc52_flush(mk);
    SEQUAL(mk->to_backend->s, "\033]52;;YQpi\007");     /* "a\nb" */

    /* Empty/unreadable clipboard: empty reply, not silence */
    strbuf_clear(mk->to_backend);
    term_datapl(mk->term, PTRLEN_LITERAL("\033]52;c;?\007"));
    term_clip_read_result(mk->term, NULL, 0);
    osc52_flush(mk);
    SEQUAL(mk->to_backend->s, "\033]52;c;\007");

    /* Read enabled, write disabled: a read is not a write */
    IEQUAL(mk->nclipwrites, 0);
}

static void test_osc52_multiplexers(Mock *mk)
{
    osc52_setup(mk, true, false);

    /*
     * GNU screen DCS passthrough, as emitted by Claude Code when $STY
     * is set: base64 split into 76-byte chunks, each wrapped in its
     * own DCS. If screen is NOT actually in the way (e.g. ssh from
     * inside screen to a host where PuTTY sees the raw bytes), the
     * first chunk's OSC 52 is still parsed.
     */
    term_datapl(mk->term,
                PTRLEN_LITERAL("\033P\033]52;c;aGVsbG8=\007\033\\"));
    IEQUAL(mk->nclipwrites, 1);
    SEQUAL(mk->clip_text->s, "hello");

    /*
     * tmux DCS passthrough, as sent by opencode and Claude Code when
     * $TMUX is set. tmux normally unwraps it, but if PuTTY sees it
     * directly it must not leave junk on the screen, and the OSC 52
     * inside should still take effect.
     */
    mk->nclipwrites = 0;
    term_datapl(mk->term, PTRLEN_LITERAL("\033[H\033[2J"));
    term_datapl(mk->term,
                PTRLEN_LITERAL("\033Ptmux;\033\033]52;c;aGk=\007\033\\"));
    IEQUAL(get_termchar(mk->term, 0, 0).chr, mk->term->basic_erase_char.chr);
    IEQUAL(mk->nclipwrites, 1);
    SEQUAL(mk->clip_text->s, "hi");

    /*
     * opencode and Claude Code inside tmux send both the raw and the
     * wrapped form; whichever reaches us, the result is the same.
     */
    mk->nclipwrites = 0;
    term_datapl(mk->term, PTRLEN_LITERAL(
                    "\033]52;c;aGVsbG8=\007"
                    "\033Ptmux;\033\033]52;c;aGVsbG8=\007\033\\"));
    IEQUAL(mk->nclipwrites, 2);
    SEQUAL(mk->clip_text->s, "hello");
    IEQUAL(get_termchar(mk->term, 0, 0).chr, mk->term->basic_erase_char.chr);

    /* ESC ESC inside an ordinary OSC also aborts it cleanly */
    term_datapl(mk->term, PTRLEN_LITERAL("\033]2;zz\033\033[Hq"));
    IEQUAL(get_termchar(mk->term, 0, 0).chr, CSET_ASCII | 'q');
}

int main(void)
{
    Mock *mk = mock_new();
    mk->term = term_init(mk->conf, mk->ucsdata, &mk->tw);
    Ldisc *ldisc = ldisc_create(mk->conf, mk->term, &mk->backend, &mk->seat);

    test_hello_world(mk);
    test_wrap(mk);
    test_nonwrap(mk);
    test_wintitle(mk);
    test_osc52_disabled_by_default(mk);
    test_osc52_write(mk);
    test_osc52_write_utf8(mk);
    test_osc52_clear(mk);
    test_osc52_rejects(mk);
    test_osc52_large(mk);
    test_osc52_read(mk);
    test_osc52_multiplexers(mk);

    bool failed = mk->any_test_failed;
    ldisc_free(ldisc);
    mock_free(mk);

    if (failed) {
        printf("Test suite FAILED!\n");
        return 1;
    } else {
        printf("Test suite passed\n");
        return 0;
    }
}
