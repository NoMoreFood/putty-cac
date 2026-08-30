/*
 * theme.cpp - Windows light and dark theme integration for PuTTYTab.
 */

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <windowsx.h>
#include <commctrl.h>
#include <dwmapi.h>
#include <uxtheme.h>
#include <winternl.h>

#include <algorithm>
#include <iterator>
#include <string>

#include "theme.h"

extern "C" NTSYSAPI NTSTATUS NTAPI RtlGetVersion(PRTL_OSVERSIONINFOW);

namespace theme
{
static constexpr wchar_t PersonaliseRegistryPath[] =
    L"Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize";
static constexpr wchar_t ImmersiveColorSet[] = L"ImmersiveColorSet";
static constexpr wchar_t HighContrastSetting[] = L"HighContrast";
static constexpr wchar_t WindowsThemeElement[] = L"WindowsThemeElement";
static constexpr wchar_t TabHoverProperty[] = L"PuTTYTab.Theme.TabHover";

static constexpr COLORREF DarkBackground = RGB(32, 32, 32);
static constexpr COLORREF DarkSurface = RGB(45, 45, 48);
static constexpr COLORREF DarkControl = RGB(55, 55, 58);
static constexpr COLORREF DarkHover = RGB(64, 64, 68);
static constexpr COLORREF DarkText = RGB(240, 240, 240);
static constexpr COLORREF DarkDisabledText = RGB(145, 145, 145);
static constexpr COLORREF DarkBorder = RGB(82, 82, 86);

static constexpr UINT_PTR TabSubclassId = 1;
static constexpr UINT_PTR StatusSubclassId = 2;
static constexpr DWORD DarkModeMinimumBuild = 17763;
static constexpr DWORD DwmwaUseImmersiveDarkModeBefore20H1 = 19;
static constexpr DWORD DwmwaUseImmersiveDarkMode = 20;

enum class PreferredAppMode
{
    Default,
    AllowDark,
    ForceDark,
    ForceLight,
    Max,
};

using SetPreferredAppModeFn = PreferredAppMode(WINAPI *)(PreferredAppMode);
using AllowDarkModeForAppFn = bool(WINAPI *)(bool);
using AllowDarkModeForWindowFn = bool(WINAPI *)(HWND, bool);
using ShouldAppsUseDarkModeFn = bool(WINAPI *)();
using RefreshImmersiveColorPolicyStateFn = void(WINAPI *)();
using FlushMenuThemesFn = void(WINAPI *)();

struct State
{
    HMODULE uxTheme = nullptr;
    SetPreferredAppModeFn setPreferredAppMode = nullptr;
    AllowDarkModeForAppFn allowDarkModeForApp = nullptr;
    AllowDarkModeForWindowFn allowDarkModeForWindow = nullptr;
    ShouldAppsUseDarkModeFn shouldAppsUseDarkMode = nullptr;
    RefreshImmersiveColorPolicyStateFn refreshImmersiveColorPolicyState = nullptr;
    FlushMenuThemesFn flushMenuThemes = nullptr;
    HBRUSH backgroundBrush = nullptr;
    HBRUSH surfaceBrush = nullptr;
    HBRUSH controlBrush = nullptr;
    HBRUSH hoverBrush = nullptr;
    HBRUSH borderBrush = nullptr;
    bool initialised = false;
    bool dark = false;
};

static State state;

template <typename Function>
static Function LoadFunction(HMODULE module, LPCSTR name)
{
    return module ? reinterpret_cast<Function>(GetProcAddress(module, name)) : nullptr;
}

static bool SystemRequestsDarkMode()
{
    // High contrast takes precedence over application colour preferences.
    HIGHCONTRASTW highContrast{sizeof(highContrast)};
    if (SystemParametersInfoW(SPI_GETHIGHCONTRAST, sizeof(highContrast), &highContrast, 0) &&
        (highContrast.dwFlags & HCF_HIGHCONTRASTON) != 0)
        return false;

    // Prefer the documented user setting, falling back to the immersive theme API when unavailable.
    DWORD value = 1, size = sizeof(value);
    if (RegGetValueW(HKEY_CURRENT_USER, PersonaliseRegistryPath, L"AppsUseLightTheme", RRF_RT_REG_DWORD, nullptr,
        &value, &size) == ERROR_SUCCESS && size == sizeof(value))
        return value == 0;
    return state.shouldAppsUseDarkMode && state.shouldAppsUseDarkMode();
}

static COLORREF TextColor()
{
    return IsDark() ? DarkText : GetSysColor(COLOR_WINDOWTEXT);
}

static COLORREF DisabledTextColor()
{
    return IsDark() ? DarkDisabledText : GetSysColor(COLOR_GRAYTEXT);
}

HBRUSH BackgroundBrush()
{
    return IsDark() && state.backgroundBrush ? state.backgroundBrush : GetSysColorBrush(COLOR_BTNFACE);
}

static HBRUSH SurfaceBrush()
{
    return IsDark() && state.surfaceBrush ? state.surfaceBrush : GetSysColorBrush(COLOR_WINDOW);
}

static HBRUSH ControlBrush()
{
    return IsDark() && state.controlBrush ? state.controlBrush : GetSysColorBrush(COLOR_BTNFACE);
}

static int Scale(HDC deviceContext, int value)
{
    int dpi = GetDeviceCaps(deviceContext, LOGPIXELSX);
    return std::max(1, MulDiv(value, dpi > 0 ? dpi : 96, 96));
}

static HFONT CreateMenuFont()
{
    NONCLIENTMETRICSW metrics{sizeof(metrics)};
    if (!SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, sizeof(metrics), &metrics, 0)) return nullptr;
    return CreateFontIndirectW(&metrics.lfMenuFont);
}

static void Fill(HDC deviceContext, const RECT &rectangle, HBRUSH brush)
{
    if (brush) FillRect(deviceContext, &rectangle, brush);
}

static void PaintDarkTabs(HWND tabs, HDC deviceContext)
{
    // Prepare the shared drawing state and locate the hot and selected tabs.
    RECT client{};
    GetClientRect(tabs, &client);
    Fill(deviceContext, client, BackgroundBrush());

    HFONT font = reinterpret_cast<HFONT>(SendMessageW(tabs, WM_GETFONT, 0, 0));
    if (!font) font = reinterpret_cast<HFONT>(GetStockObject(DEFAULT_GUI_FONT));
    HGDIOBJ previousFont = SelectObject(deviceContext, font);
    int previousBackgroundMode = SetBkMode(deviceContext, TRANSPARENT);
    COLORREF previousTextColor = SetTextColor(deviceContext, TextColor());

    int hovered = static_cast<int>(reinterpret_cast<DWORD_PTR>(GetPropW(tabs, TabHoverProperty))) - 2;
    int selected = TabCtrl_GetCurSel(tabs);
    int count = TabCtrl_GetItemCount(tabs);
    int padding = Scale(deviceContext, 8);
    int accentHeight = Scale(deviceContext, 2);

    // Paint each tab surface, selection accent, border, and clipped label.
    for (int index = 0; index < count; ++index)
    {
        RECT item{};
        if (!TabCtrl_GetItemRect(tabs, index, &item)) continue;

        HBRUSH brush = BackgroundBrush();
        if (index == selected) brush = SurfaceBrush();
        else if (index == hovered && state.hoverBrush) brush = state.hoverBrush;
        Fill(deviceContext, item, brush);
        if (index == selected || index == hovered)
            FrameRect(deviceContext, &item, state.borderBrush ? state.borderBrush : ControlBrush());
        if (index == selected)
        {
            RECT accent{item.left + 1, item.top, item.right - 1, item.top + accentHeight};
            HBRUSH accentBrush = GetSysColorBrush(COLOR_HIGHLIGHT);
            Fill(deviceContext, accent, accentBrush);
        }

        wchar_t text[256]{};
        TCITEMW tabItem{};
        tabItem.mask = TCIF_TEXT;
        tabItem.pszText = text;
        tabItem.cchTextMax = static_cast<int>(std::size(text));
        TabCtrl_GetItem(tabs, index, &tabItem);
        RECT textRectangle = item;
        textRectangle.left += padding;
        textRectangle.right -= padding;
        DrawTextW(deviceContext, text, -1, &textRectangle,
            DT_CENTER | DT_END_ELLIPSIS | DT_NOPREFIX | DT_SINGLELINE | DT_VCENTER);
    }

    // Finish the shared lower edge and restore the caller's drawing state.
    RECT border{client.left, client.bottom - 1, client.right, client.bottom};
    Fill(deviceContext, border, state.controlBrush ? state.controlBrush : ControlBrush());
    SetTextColor(deviceContext, previousTextColor);
    SetBkMode(deviceContext, previousBackgroundMode);
    if (previousFont) SelectObject(deviceContext, previousFont);
}

static void DrawSizeGrip(HWND status, HDC deviceContext, const RECT &client)
{
    if ((GetWindowLongPtrW(status, GWL_STYLE) & SBARS_SIZEGRIP) == 0) return;

    // Draw the diagonal size-grip strokes with DPI-scaled spacing.
    HPEN pen = CreatePen(PS_SOLID, 1, IsDark() ? DarkBorder : GetSysColor(COLOR_3DSHADOW));
    if (!pen) return;
    HGDIOBJ previousPen = SelectObject(deviceContext, pen);
    int step = Scale(deviceContext, 4);
    for (int offset = step; offset <= step * 3; offset += step)
    {
        MoveToEx(deviceContext, client.right - offset, client.bottom - 1, nullptr);
        LineTo(deviceContext, client.right - 1, client.bottom - offset);
    }
    if (previousPen) SelectObject(deviceContext, previousPen);
    DeleteObject(pen);
}

static void PaintDarkStatus(HWND status, HDC deviceContext)
{
    // Prepare the shared status-bar drawing state.
    RECT client{};
    GetClientRect(status, &client);
    Fill(deviceContext, client, SurfaceBrush());

    HFONT font = reinterpret_cast<HFONT>(SendMessageW(status, WM_GETFONT, 0, 0));
    if (!font) font = reinterpret_cast<HFONT>(GetStockObject(DEFAULT_GUI_FONT));
    HGDIOBJ previousFont = SelectObject(deviceContext, font);
    int previousBackgroundMode = SetBkMode(deviceContext, TRANSPARENT);
    COLORREF previousTextColor = SetTextColor(deviceContext, TextColor());
    int padding = Scale(deviceContext, 6);
    int count = static_cast<int>(SendMessageW(status, SB_GETPARTS, 0, 0));

    // Paint each status part and its separator using the live control text.
    for (int part = 0; part < count; ++part)
    {
        RECT rectangle{};
        if (!SendMessageW(status, SB_GETRECT, part, reinterpret_cast<LPARAM>(&rectangle))) continue;
        size_t length = LOWORD(SendMessageW(status, SB_GETTEXTLENGTHW, part, 0));
        std::wstring text(length + 1, L'\0');
        text.resize(LOWORD(SendMessageW(status, SB_GETTEXTW, part, reinterpret_cast<LPARAM>(text.data()))));
        RECT textRectangle = rectangle;
        textRectangle.left += padding;
        textRectangle.right -= padding;
        DrawTextW(deviceContext, text.c_str(), -1, &textRectangle,
            DT_END_ELLIPSIS | DT_NOPREFIX | DT_SINGLELINE | DT_VCENTER);

        if (part + 1 < count)
        {
            RECT separator{rectangle.right - 1, rectangle.top + 2, rectangle.right, rectangle.bottom - 2};
            Fill(deviceContext, separator, state.borderBrush ? state.borderBrush : ControlBrush());
        }
    }

    // Add the resize grip and restore the caller's drawing state.
    DrawSizeGrip(status, deviceContext, client);
    SetTextColor(deviceContext, previousTextColor);
    SetBkMode(deviceContext, previousBackgroundMode);
    if (previousFont) SelectObject(deviceContext, previousFont);
}

static LRESULT CALLBACK ControlSubclassProc(HWND window, UINT message, WPARAM wParam, LPARAM lParam,
    UINT_PTR subclassId, DWORD_PTR)
{
    if (message == WM_NCDESTROY)
    {
        if (subclassId == TabSubclassId) RemovePropW(window, TabHoverProperty);
        RemoveWindowSubclass(window, ControlSubclassProc, subclassId);
        return DefSubclassProc(window, message, wParam, lParam);
    }

    // Preserve native control behavior outside custom dark-mode painting.
    if (!IsDark()) return DefSubclassProc(window, message, wParam, lParam);
    if (message == WM_ERASEBKGND) return 1;

    // Repaint only the tabs whose hover state changed.
    if (subclassId == TabSubclassId && (message == WM_MOUSEMOVE || message == WM_MOUSELEAVE))
    {
        DWORD_PTR hoverState = reinterpret_cast<DWORD_PTR>(GetPropW(window, TabHoverProperty));
        if (message == WM_MOUSEMOVE)
        {
            if (!hoverState)
            {
                TRACKMOUSEEVENT tracking{sizeof(tracking), TME_LEAVE, window, 0};
                TrackMouseEvent(&tracking);
            }
            TCHITTESTINFO hitTest{{GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam)}};
            int hovered = TabCtrl_HitTest(window, &hitTest);
            DWORD_PTR nextState = static_cast<DWORD_PTR>(hovered + 2);
            if (nextState == hoverState) return DefSubclassProc(window, message, wParam, lParam);

            RECT item{};
            int previous = static_cast<int>(hoverState) - 2;
            if (previous >= 0 && TabCtrl_GetItemRect(window, previous, &item)) InvalidateRect(window, &item, FALSE);
            if (hovered >= 0 && TabCtrl_GetItemRect(window, hovered, &item)) InvalidateRect(window, &item, FALSE);
            SetPropW(window, TabHoverProperty, reinterpret_cast<HANDLE>(nextState));
        }
        else
        {
            RECT item{};
            int previous = static_cast<int>(hoverState) - 2;
            if (previous >= 0 && TabCtrl_GetItemRect(window, previous, &item)) InvalidateRect(window, &item, FALSE);
            RemovePropW(window, TabHoverProperty);
        }
    }

    // Paint tabs and status bars through both normal and print-client paths.
    auto paintControl = subclassId == TabSubclassId ? PaintDarkTabs : PaintDarkStatus;
    if (message == WM_PAINT)
    {
        PAINTSTRUCT paint{};
        HDC deviceContext = BeginPaint(window, &paint);
        paintControl(window, deviceContext);
        EndPaint(window, &paint);
        return 0;
    }
    if (message == WM_PRINTCLIENT)
    {
        paintControl(window, reinterpret_cast<HDC>(wParam));
        return 0;
    }
    return DefSubclassProc(window, message, wParam, lParam);
}

static bool InstallCustomSubclass(HWND control, UINT_PTR subclassId)
{
    if (!control || !SetWindowSubclass(control, ControlSubclassProc, subclassId, 0)) return false;
    if (subclassId == TabSubclassId) RemovePropW(control, TabHoverProperty);
    ApplyControl(control, ControlTheme::CustomDraw);
    return true;
}

static BOOL CALLBACK ApplyChildTheme(HWND window, LPARAM)
{
    // Embedded PuTTY terminals belong to another process and must retain their own theme state.
    DWORD processId = 0;
    GetWindowThreadProcessId(window, &processId);
    if (processId != GetCurrentProcessId()) return TRUE;

    // Select the native or custom treatment appropriate for each child class.
    wchar_t className[64]{};
    GetClassNameW(window, className, static_cast<int>(std::size(className)));
    if (_wcsicmp(className, WC_TABCONTROLW) == 0) InstallCustomSubclass(window, TabSubclassId);
    else if (_wcsicmp(className, STATUSCLASSNAMEW) == 0) InstallCustomSubclass(window, StatusSubclassId);
    else if (_wcsicmp(className, L"Edit") == 0 || _wcsicmp(className, L"ComboBox") == 0)
        ApplyControl(window, ControlTheme::Edit);
    else if (_wcsicmp(className, L"Static") == 0) ApplyControl(window, ControlTheme::CustomDraw);
    else
        ApplyControl(window, ControlTheme::Explorer);
    return TRUE;
}

void Initialise()
{
    if (state.initialised) return;
    state.initialised = true;

    // Load optional dark-mode entry points, whose ordinal ABI changed in Windows 10 1903.
    state.uxTheme = GetModuleHandleW(L"uxtheme.dll");
    if (state.uxTheme)
    {
        DWORD windowsBuild = 0;
        RTL_OSVERSIONINFOW version{sizeof(version)};
        if (RtlGetVersion(&version) >= 0) windowsBuild = version.dwBuildNumber;
        if (windowsBuild >= DarkModeMinimumBuild)
        {
            FARPROC appModeFunction = GetProcAddress(state.uxTheme, MAKEINTRESOURCEA(135));
            if (windowsBuild >= 18362)
                state.setPreferredAppMode = reinterpret_cast<SetPreferredAppModeFn>(appModeFunction);
            else
                state.allowDarkModeForApp = reinterpret_cast<AllowDarkModeForAppFn>(appModeFunction);
            state.allowDarkModeForWindow =
                LoadFunction<AllowDarkModeForWindowFn>(state.uxTheme, MAKEINTRESOURCEA(133));
            state.shouldAppsUseDarkMode =
                LoadFunction<ShouldAppsUseDarkModeFn>(state.uxTheme, MAKEINTRESOURCEA(132));
            state.refreshImmersiveColorPolicyState =
                LoadFunction<RefreshImmersiveColorPolicyStateFn>(state.uxTheme, MAKEINTRESOURCEA(104));
            state.flushMenuThemes = LoadFunction<FlushMenuThemesFn>(state.uxTheme, MAKEINTRESOURCEA(136));
        }
    }

    // Allocate the reusable dark palette.
    state.backgroundBrush = CreateSolidBrush(DarkBackground);
    state.surfaceBrush = CreateSolidBrush(DarkSurface);
    state.controlBrush = CreateSolidBrush(DarkControl);
    state.hoverBrush = CreateSolidBrush(DarkHover);
    state.borderBrush = CreateSolidBrush(DarkBorder);
    Refresh();
}

void Shutdown()
{
    if (!state.initialised) return;

    // Release the reusable GDI resources.
    if (state.backgroundBrush) DeleteObject(state.backgroundBrush);
    if (state.surfaceBrush) DeleteObject(state.surfaceBrush);
    if (state.controlBrush) DeleteObject(state.controlBrush);
    if (state.hoverBrush) DeleteObject(state.hoverBrush);
    if (state.borderBrush) DeleteObject(state.borderBrush);
    state = {};
}

bool Refresh()
{
    Initialise();

    // Re-evaluate system policy and propagate the resulting application theme.
    if (state.refreshImmersiveColorPolicyState) state.refreshImmersiveColorPolicyState();
    bool dark = SystemRequestsDarkMode();
    bool changed = state.dark != dark;
    state.dark = dark;
    if (state.setPreferredAppMode)
        state.setPreferredAppMode(dark ? PreferredAppMode::ForceDark : PreferredAppMode::ForceLight);
    else if (state.allowDarkModeForApp) state.allowDarkModeForApp(dark);
    if (state.flushMenuThemes) state.flushMenuThemes();
    return changed;
}

bool IsDark()
{
    Initialise();
    return state.dark;
}

bool IsSystemThemeChange(UINT message, LPARAM lParam)
{
    if (message == WM_SYSCOLORCHANGE) return true;
    if (message != WM_SETTINGCHANGE) return false;
    if (!lParam) return true;
    const wchar_t *setting = reinterpret_cast<const wchar_t *>(lParam);
    return _wcsicmp(setting, ImmersiveColorSet) == 0 || _wcsicmp(setting, HighContrastSetting) == 0 ||
        _wcsicmp(setting, WindowsThemeElement) == 0;
}

static void ApplyTopLevel(HWND window)
{
    if (!window) return;
    bool dark = IsDark();
    if (state.allowDarkModeForWindow) state.allowDarkModeForWindow(window, dark);

    // Prefer the current title-bar attribute, with its pre-20H1 identifier as a fallback.
    BOOL enabled = dark;
    if (FAILED(DwmSetWindowAttribute(window, DwmwaUseImmersiveDarkMode, &enabled, sizeof(enabled))))
        DwmSetWindowAttribute(window, DwmwaUseImmersiveDarkModeBefore20H1, &enabled, sizeof(enabled));
    SetWindowTheme(window, dark ? L"DarkMode_Explorer" : nullptr, nullptr);
    DrawMenuBar(window);
}

void ApplyControl(HWND window, ControlTheme controlTheme)
{
    if (!window) return;
    bool dark = IsDark();
    if (state.allowDarkModeForWindow) state.allowDarkModeForWindow(window, dark);
    // Select the built-in theme best suited to the control's rendering path.
    if (!dark) SetWindowTheme(window, nullptr, nullptr);
    else if (controlTheme == ControlTheme::CustomDraw) SetWindowTheme(window, L"", L"");
    else if (controlTheme == ControlTheme::Edit) SetWindowTheme(window, L"DarkMode_CFD", nullptr);
    else SetWindowTheme(window, L"DarkMode_Explorer", nullptr);
}

void ApplyWindowTree(HWND window)
{
    if (!window) return;
    ApplyTopLevel(window);
    EnumChildWindows(window, ApplyChildTheme, 0);
    RedrawWindow(window, nullptr, nullptr, RDW_ALLCHILDREN | RDW_ERASE | RDW_FRAME | RDW_INVALIDATE);
}

void ApplyMenuBar(HWND window, HMENU menu)
{
    if (!window || !menu) return;
    MENUINFO info{sizeof(info)};
    info.fMask = MIM_BACKGROUND;
    info.hbrBack = IsDark() ? BackgroundBrush() : GetSysColorBrush(COLOR_MENU);
    SetMenuInfo(menu, &info);
    DrawMenuBar(window);
}

bool MeasureMenuItem(HWND owner, MEASUREITEMSTRUCT &item)
{
    if (item.CtlType != ODT_MENU || !item.itemData) return false;
    HDC deviceContext = GetDC(owner);
    if (!deviceContext) return false;

    // Measure owner-drawn text with the current system menu font and DPI.
    HFONT font = CreateMenuFont();
    HGDIOBJ previousFont = SelectObject(deviceContext,
        font ? font : reinterpret_cast<HFONT>(GetStockObject(DEFAULT_GUI_FONT)));
    RECT textRectangle{};
    DrawTextW(deviceContext, reinterpret_cast<const wchar_t *>(item.itemData), -1, &textRectangle,
        DT_CALCRECT | DT_SINGLELINE);
    item.itemWidth = textRectangle.right - textRectangle.left + Scale(deviceContext, 16);
    item.itemHeight = std::max(static_cast<int>(textRectangle.bottom - textRectangle.top) + Scale(deviceContext, 4),
        GetSystemMetricsForDpi(SM_CYMENU, GetDpiForWindow(owner)));
    if (previousFont) SelectObject(deviceContext, previousFont);
    if (font) DeleteObject(font);
    ReleaseDC(owner, deviceContext);
    return true;
}

bool DrawMenuItem(const DRAWITEMSTRUCT &item)
{
    if (item.CtlType != ODT_MENU || !item.itemData || !item.hDC) return false;

    // Resolve the menu state into matching native or dark palette colours.
    bool dark = IsDark();
    bool selected = (item.itemState & (ODS_HOTLIGHT | ODS_SELECTED)) != 0;
    bool disabled = (item.itemState & (ODS_DISABLED | ODS_GRAYED | ODS_INACTIVE)) != 0;
    HBRUSH brush = dark ? (selected ? ControlBrush() : BackgroundBrush()) :
        GetSysColorBrush(selected ? COLOR_MENUHILIGHT : COLOR_MENU);
    FillRect(item.hDC, &item.rcItem, brush);

    HFONT font = CreateMenuFont();
    HGDIOBJ previousFont = SelectObject(
        item.hDC, font ? font : reinterpret_cast<HFONT>(GetStockObject(DEFAULT_GUI_FONT)));
    int previousMode = SetBkMode(item.hDC, TRANSPARENT);
    COLORREF textColor = dark ? (disabled ? DisabledTextColor() : TextColor()) :
        GetSysColor(disabled ? COLOR_GRAYTEXT : selected ? COLOR_HIGHLIGHTTEXT : COLOR_MENUTEXT);
    COLORREF previousColor = SetTextColor(item.hDC, textColor);
    RECT textRectangle = item.rcItem;
    int padding = Scale(item.hDC, 8);
    textRectangle.left += padding;
    textRectangle.right -= padding;
    UINT format = DT_LEFT | DT_SINGLELINE | DT_VCENTER;
    if ((item.itemState & ODS_NOACCEL) != 0) format |= DT_HIDEPREFIX;
    DrawTextW(item.hDC, reinterpret_cast<const wchar_t *>(item.itemData), -1, &textRectangle, format);

    // Restore and release the GDI state used for this menu item.
    SetTextColor(item.hDC, previousColor);
    SetBkMode(item.hDC, previousMode);
    if (previousFont) SelectObject(item.hDC, previousFont);
    if (font) DeleteObject(font);
    return true;
}

HBRUSH HandleCtlColor(UINT message, HDC deviceContext, HWND control)
{
    bool dark = IsDark();
    bool enabled = !control || IsWindowEnabled(control);

    // Supply control-specific text, background, and brush state to the parent window.
    switch (message)
    {
      case WM_CTLCOLORDLG:
        SetBkColor(deviceContext, IsDark() ? DarkBackground : GetSysColor(COLOR_BTNFACE));
        SetTextColor(deviceContext, TextColor());
        return BackgroundBrush();
      case WM_CTLCOLORSTATIC:
        SetBkMode(deviceContext, TRANSPARENT);
        SetTextColor(deviceContext, enabled ? TextColor() : DisabledTextColor());
        return BackgroundBrush();
      case WM_CTLCOLORBTN:
        SetBkColor(deviceContext, IsDark() ? DarkControl : GetSysColor(COLOR_BTNFACE));
        SetTextColor(deviceContext, enabled ? TextColor() : DisabledTextColor());
        return ControlBrush();
      case WM_CTLCOLOREDIT:
      case WM_CTLCOLORLISTBOX:
        SetBkColor(deviceContext, IsDark() ? DarkSurface : GetSysColor(COLOR_WINDOW));
        SetTextColor(deviceContext, enabled ? TextColor() : DisabledTextColor());
        return SurfaceBrush();
    }
    return dark ? BackgroundBrush() : nullptr;
}
}
