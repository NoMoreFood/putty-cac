#pragma once

#include <windows.h>
#include <algorithm>
#include <memory>
#include <string>
#include <string_view>

using UniqueHandle = std::unique_ptr<void, decltype([](HANDLE handle)
{
    if (handle && handle != INVALID_HANDLE_VALUE) CloseHandle(handle);
})>;

using UniqueGdiObject = std::unique_ptr<void, decltype([](void *object)
{
    if (object) DeleteObject(object);
})>;

inline std::wstring WindowText(HWND window)
{
    int length = GetWindowTextLengthW(window);
    if (length <= 0) return {};
    std::wstring text(static_cast<size_t>(length) + 1, L'\0');
    int copied = GetWindowTextW(window, text.data(), static_cast<int>(text.size()));
    text.resize(copied > 0 ? static_cast<size_t>(copied) : 0);
    return text;
}

inline SIZE MeasureControlText(HWND control, std::wstring_view text, UINT format = DT_NOPREFIX, int width = 0)
{
    // Measure with the control's font, including wrapped text and empty-line height.
    HDC context = GetDC(control);
    if (!context) return {};
    HFONT font = reinterpret_cast<HFONT>(SendMessageW(control, WM_GETFONT, 0, 0));
    HGDIOBJ previous = SelectObject(context, font ? font : GetStockObject(DEFAULT_GUI_FONT));
    RECT bounds{0, 0, width, 0};
    DrawTextW(context, text.data(), static_cast<int>(text.size()), &bounds,
        DT_CALCRECT | (width > 0 ? DT_WORDBREAK : DT_SINGLELINE) | format);
    TEXTMETRICW metrics{};
    GetTextMetricsW(context, &metrics);
    if (previous) SelectObject(context, previous);
    ReleaseDC(control, context);
    return {bounds.right, std::max(bounds.bottom, metrics.tmHeight)};
}

inline UniqueGdiObject CreateMessageFont(HWND window)
{
    // Use the system's message font at the window's current DPI and text scale.
    NONCLIENTMETRICSW metrics{sizeof(metrics)};
    if (!SystemParametersInfoForDpi(SPI_GETNONCLIENTMETRICS, sizeof(metrics), &metrics, 0, GetDpiForWindow(window)))
        return {};
    return UniqueGdiObject(CreateFontIndirectW(&metrics.lfMessageFont));
}
