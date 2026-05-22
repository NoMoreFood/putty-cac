/*
 * Wrapper for GetCaretBlinkTime() which turns it into a signed integer,
 * with 0 meaning "no blinking".
 */

#include "putty.h"
#include <winuser.h>

int get_caret_blink_time(void)
{
    UINT blinktime = GetCaretBlinkTime();
    if (blinktime == INFINITE)
        /* Windows' registry representation for 'no caret blinking'
         * is the string "-1", but we may as well use 0 as the sentinel
         * value, as it'd be bad to attempt blinking with period 0
         * in any case. */
        return 0;
    else
        /* assume this won't be so big that casting is a problem */
        return (int) blinktime;
}
