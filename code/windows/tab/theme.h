/*
 * theme.h - Windows light and dark theme integration for PuTTYTab.
 */

#ifndef PUTTY_PUTTYTAB_THEME_H
#define PUTTY_PUTTYTAB_THEME_H

#include <windows.h>

namespace theme
{
enum class ControlTheme
{
    Explorer,
    Edit,
    CustomDraw,
};

void Initialise();
void Shutdown();
bool Refresh();
bool IsDark();
bool IsSystemThemeChange(UINT message, LPARAM lParam);
void ApplyControl(HWND window, ControlTheme controlTheme = ControlTheme::Explorer);
void ApplyWindowTree(HWND window);
void ApplyMenuBar(HWND window, HMENU menu);
bool MeasureMenuItem(HWND owner, MEASUREITEMSTRUCT &item);
bool DrawMenuItem(const DRAWITEMSTRUCT &item);
HBRUSH BackgroundBrush();
HBRUSH HandleCtlColor(UINT message, HDC deviceContext, HWND control);
}

#endif
