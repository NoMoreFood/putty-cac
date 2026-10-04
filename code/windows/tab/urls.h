#pragma once

#include <algorithm>
#include <cwctype>
#include <string>
#include <vector>
#include "terminaltext.h"

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

    // PuTTY uses an arrow when the remote application owns mouse input.
    if (!IsWindowEnabled(terminal) || IsHungAppWindow(terminal) ||
        reinterpret_cast<HCURSOR>(GetClassLongPtrW(terminal, GCLP_HCURSOR)) != LoadCursorW(nullptr, IDC_IBEAM) ||
        !GetClientRect(terminal, &client) || !PtInRect(&client, point)) return {};
    terminaltext::Reader reader(terminal, {}, 25);
    const auto &seat = reader.seat;
    const auto &view = reader.view;
    if (!reader.ready || seat.offset_width < 0 || seat.offset_height < 0 ||
        seat.offset_width > point.x || seat.offset_height > point.y || !view.disptext) return {};
    int clickedRow = (point.y - seat.offset_height) / seat.font_height;
    int clickedColumn = (point.x - seat.offset_width) / seat.font_width;
    if (clickedRow >= view.rows || clickedColumn >= view.cols) return {};
    std::vector<termline *> rows(view.rows);
    if (!reader.Read(view.disptext, rows.data(), rows.size() * sizeof(rows[0]))) return {};
    termline line{};
    auto readLine = [&](int row)
    {
        return reader.Read(rows[row], &line, sizeof(line)) && line.cols == view.cols &&
            line.size >= line.cols && line.size <= line.cols * (CC_LIMIT + 1) && line.chars;
    };
    if (!readLine(clickedRow)) return {};
    if ((line.lattr & LATTR_MODE) != LATTR_NORM) clickedColumn /= 2;

    // Include the complete visible logical line when it spans multiple terminal rows.
    int firstRow = clickedRow;
    while (firstRow > 0)
    {
        if (!readLine(firstRow - 1)) return {};
        if (!(line.lattr & LATTR_WRAPPED)) break;
        --firstRow;
    }
    std::wstring text;
    std::vector<std::wstring> glyphs;
    size_t clicked = std::wstring::npos;
    size_t bytes = 0;
    bool wrapped = false;
    for (int row = firstRow; row < view.rows; ++row)
    {
        if (!readLine(row)) return {};
        const termchar *source = line.chars;
        int sourceColumn = clickedColumn;

        // Map displayed columns back to logical text before bidirectional shaping.
        if ((!view.no_bidi || !view.no_arabicshaping || line.trusted) && view.pre_bidi_cache &&
            view.post_bidi_cache && static_cast<size_t>(row) < view.bidi_cache_size)
        {
            bidi_cache_entry before{}, after{};
            if (!reader.Read(view.pre_bidi_cache + row, &before, sizeof(before)) ||
                !reader.Read(view.post_bidi_cache + row, &after, sizeof(after)) || before.width != view.cols ||
                after.width != view.cols || !before.chars || !after.backward) return {};
            source = before.chars;
            if (row == clickedRow &&
                (!reader.Read(after.backward + clickedColumn, &sourceColumn, sizeof(sourceColumn)) ||
                 sourceColumn < 0 || sourceColumn >= view.cols)) return {};
        }
        bytes += static_cast<size_t>(line.cols) * sizeof(termchar);
        if (bytes > 8 * 1024 * 1024) return {};
        unsigned short attributes = 0;
        if (!reader.Plain(rows[row], glyphs, attributes, source) || attributes != line.lattr ||
            glyphs.size() != static_cast<size_t>(line.cols)) return {};
        int columns = (line.lattr & LATTR_MODE) == LATTR_NORM ? line.cols : (line.cols + 1) / 2;
        if (line.lattr & LATTR_WRAPPED2) --columns;
        size_t previous = text.size();
        for (int column = 0; column < columns; ++column)
        {
            bool atPoint = row == clickedRow && column == sourceColumn;
            if (glyphs[column].empty())
            {
                if (atPoint && column) clicked = previous;
                continue;
            }
            previous = text.size();
            if (atPoint) clicked = previous;
            text += glyphs[column];
        }
        wrapped = (line.lattr & LATTR_WRAPPED) != 0;
        if (!wrapped) break;
    }

    // Discard a snapshot if the terminal grid changed while it was being read.
    Terminal current{};
    if (clicked == std::wstring::npos || !reader.Read(seat.term, &current, sizeof(current)) ||
        current.rows != view.rows || current.cols != view.cols || current.disptop != view.disptop ||
        current.disptext != view.disptext) return {};
    return Find(text, clicked, !wrapped);
}
}
