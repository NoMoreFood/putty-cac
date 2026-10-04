#pragma once

#include <algorithm>
#include <cwctype>
#include <memory>
#include <string>
#include <vector>

// Import the sibling's C layouts with C++-compatible declarations.
#pragma push_macro("private")
#pragma push_macro("plug_log")
#pragma push_macro("min")
#pragma push_macro("max")
#define private private_value
#define plug_log(...) \
    plug_log(Plug *p, Socket *s, PlugLogType type, SockAddr *addr, int port, const char *msg, int code)
extern "C"
{
#include "putty.h"
#include "terminal.h"
#include "win-gui-seat.h"
}
#pragma pop_macro("max")
#pragma pop_macro("min")
#pragma pop_macro("plug_log")
#pragma pop_macro("private")

namespace urls
{
inline std::wstring Find(const std::wstring &text, size_t clicked, bool allowEnd = false)
{
    // Recognise web URLs while retaining balanced parentheses inside their paths.
    for (size_t start = 0; start <= clicked && start < text.size(); ++start)
    {
        size_t scheme = _wcsnicmp(text.c_str() + start, L"http://", 7) == 0 ? 7 :
            _wcsnicmp(text.c_str() + start, L"https://", 8) == 0 ? 8 : 0;
        if (!scheme || (start && (iswalnum(text[start - 1]) || text[start - 1] == L'_'))) continue;
        size_t end = start + scheme;
        while (end < text.size() && !iswspace(text[end]) && !iswcntrl(text[end]) &&
            wcschr(L"<>\"`", text[end]) == nullptr && !(start && text[start - 1] == L'\'' && text[end] == L'\''))
            ++end;
        if ((!allowEnd && end == text.size()) || end - start > 8192) continue;
        while (end > start + scheme)
        {
            wchar_t last = text[end - 1];
            if (wcschr(L".,;:!?", last))
            {
                --end;
                continue;
            }
            constexpr wchar_t closings[] = L")]}";
            const wchar_t *closing = wcschr(closings, last);
            if (!closing) break;
            wchar_t opening = L"([{"[closing - closings];
            auto begin = text.begin() + start;
            auto finish = text.begin() + end;
            if (std::count(begin, finish, last) <= std::count(begin, finish, opening)) break;
            --end;
        }
        if (end > start + scheme && !wcschr(L"/?#", text[start + scheme]) && clicked < end)
            return text.substr(start, end - start);
    }
    return {};
}

inline std::wstring AtPoint(HWND terminal, POINT point)
{
    // Read the sibling PuTTY's painted cells without changing its selection or clipboard.
    RECT client{};
    DWORD processId = 0;

    // PuTTY uses an arrow when the remote application owns mouse input.
    if (!IsWindowEnabled(terminal) || IsHungAppWindow(terminal) ||
        reinterpret_cast<HCURSOR>(GetClassLongPtrW(terminal, GCLP_HCURSOR)) != LoadCursorW(nullptr, IDC_IBEAM) ||
        !GetClientRect(terminal, &client) || !PtInRect(&client, point) ||
        !GetWindowThreadProcessId(terminal, &processId)) return {};
    std::unique_ptr<void, decltype(&CloseHandle)> process(OpenProcess(PROCESS_VM_READ, FALSE, processId), CloseHandle);
    if (!process) return {};
    auto read = [&](const void *address, void *data, size_t bytes)
    {
        return address && ReadProcessMemory(process.get(), address, data, bytes, nullptr) != 0;
    };
    WinGuiSeat seat{};
    Terminal view{};
    if (!read(reinterpret_cast<void *>(GetWindowLongPtrW(terminal, GWLP_USERDATA)), &seat, sizeof(seat)) ||
        seat.term_hwnd != terminal || seat.font_width <= 0 || seat.font_width > 1000 ||
        seat.font_height <= 0 || seat.font_height > 1000 || seat.offset_width < 0 || seat.offset_height < 0 ||
        seat.offset_width > point.x || seat.offset_height > point.y || !read(seat.term, &view, sizeof(view)) ||
        view.rows <= 0 || view.rows > 4096 || view.cols <= 0 || view.cols > 4096 || !view.disptext)
        return {};
    int clickedRow = (point.y - seat.offset_height) / seat.font_height;
    int clickedColumn = (point.x - seat.offset_width) / seat.font_width;
    if (clickedRow >= view.rows || clickedColumn >= view.cols) return {};
    std::vector<termline *> rows(view.rows);
    if (!read(view.disptext, rows.data(), rows.size() * sizeof(rows[0]))) return {};
    termline line{};
    auto readLine = [&](int row)
    {
        return read(rows[row], &line, sizeof(line)) && line.cols == view.cols &&
            line.size >= line.cols && line.size <= line.cols * (CC_LIMIT + 1) && line.chars;
    };
    if (!readLine(clickedRow)) return {};
    if ((line.lattr & LATTR_MODE) != LATTR_NORM) clickedColumn /= 2;

    // Include the complete visible logical line when it spans multiple terminal rows.
    ULONGLONG deadline = GetTickCount64() + 25;
    int firstRow = clickedRow;
    while (firstRow > 0)
    {
        if (GetTickCount64() >= deadline || !readLine(firstRow - 1)) return {};
        if (!(line.lattr & LATTR_WRAPPED)) break;
        --firstRow;
    }
    std::wstring text;
    size_t clicked = std::wstring::npos;
    size_t bytes = 0;
    bool wrapped = false;
    for (int row = firstRow; row < view.rows; ++row)
    {
        if (GetTickCount64() >= deadline || !readLine(row)) return {};
        const termchar *source = line.chars;
        int sourceColumn = clickedColumn;

        // Map displayed columns back to logical text before bidirectional shaping.
        if ((!view.no_bidi || !view.no_arabicshaping || line.trusted) && view.pre_bidi_cache &&
            view.post_bidi_cache && static_cast<size_t>(row) < view.bidi_cache_size)
        {
            bidi_cache_entry before{}, after{};
            if (!read(view.pre_bidi_cache + row, &before, sizeof(before)) ||
                !read(view.post_bidi_cache + row, &after, sizeof(after)) || before.width != view.cols ||
                after.width != view.cols || !before.chars || !after.backward) return {};
            source = before.chars;
            if (row == clickedRow && (!read(after.backward + clickedColumn, &sourceColumn, sizeof(sourceColumn)) ||
                sourceColumn < 0 || sourceColumn >= view.cols)) return {};
        }
        bytes += static_cast<size_t>(line.cols) * sizeof(termchar);
        if (bytes > 8 * 1024 * 1024) return {};
        std::vector<termchar> characters(line.cols);
        if (!read(source, characters.data(), characters.size() * sizeof(characters[0]))) return {};
        int columns = (line.lattr & LATTR_MODE) == LATTR_NORM ? line.cols : (line.cols + 1) / 2;
        if (line.lattr & LATTR_WRAPPED2) --columns;
        size_t previous = text.size();
        for (int column = 0; column < columns; ++column)
        {
            bool atPoint = row == clickedRow && column == sourceColumn;
            if (characters[column].chr == UCSWIDE)
            {
                if (atPoint && column) clicked = previous;
                continue;
            }
            previous = text.size();
            if (atPoint) clicked = previous;
            int cell = column;
            termchar glyph = characters[cell];
            for (int count = 0; count <= CC_LIMIT; ++count)
            {
                unsigned long character = glyph.chr;
                switch (character & CSET_MASK)
                {
                case CSET_ASCII: character = seat.ucsdata.unitab_line[character & 0xFF]; break;
                case CSET_LINEDRW: character = seat.ucsdata.unitab_xterm[character & 0xFF]; break;
                case CSET_SCOACS: character = seat.ucsdata.unitab_scoacs[character & 0xFF]; break;
                }
                switch (character & CSET_MASK)
                {
                case CSET_ACP: character = seat.ucsdata.unitab_font[character & 0xFF]; break;
                case CSET_OEMCP: character = seat.ucsdata.unitab_oemcp[character & 0xFF]; break;
                }
                if (character > 0x10FFFF || (character >= 0xD800 && character <= 0xDFFF)) character = L' ';
                if (character > 0xFFFF)
                {
                    text += static_cast<wchar_t>(0xD800 + ((character - 0x10000) >> 10));
                    text += static_cast<wchar_t>(0xDC00 + ((character - 0x10000) & 0x3FF));
                }
                else text += static_cast<wchar_t>(character);
                int next = glyph.cc_next;
                if (!next) break;
                if (count == CC_LIMIT || next < -cell || next >= line.cols * (CC_LIMIT + 1) - cell) return {};
                cell += next;
                if (cell < line.cols) glyph = characters[cell];
                else if (!read(source + cell, &glyph, sizeof(glyph))) return {};
            }
        }
        wrapped = (line.lattr & LATTR_WRAPPED) != 0;
        if (!wrapped) break;
    }

    // Discard a snapshot if the terminal grid changed while it was being read.
    Terminal current{};
    if (clicked == std::wstring::npos || !read(seat.term, &current, sizeof(current)) ||
        current.rows != view.rows || current.cols != view.cols || current.disptop != view.disptop ||
        current.disptext != view.disptext) return {};
    return Find(text, clicked, !wrapped);
}
}
