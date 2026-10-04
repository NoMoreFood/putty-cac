#pragma once

#include <algorithm>
#include <functional>
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

namespace terminaltext
{
inline void Append(std::wstring &text, unsigned long character, const unicode_data &encoding)
{
    // Decode terminal character sets before encoding Unicode as UTF-16.
    switch (character & CSET_MASK)
    {
    case CSET_ASCII: character = encoding.unitab_line[character & 0xFF]; break;
    case CSET_LINEDRW: character = encoding.unitab_xterm[character & 0xFF]; break;
    case CSET_SCOACS: character = encoding.unitab_scoacs[character & 0xFF]; break;
    }
    switch (character & CSET_MASK)
    {
    case CSET_ACP: character = encoding.unitab_font[character & 0xFF]; break;
    case CSET_OEMCP: character = encoding.unitab_oemcp[character & 0xFF]; break;
    }
    if (character > 0x10FFFF || (character >= 0xD800 && character <= 0xDFFF)) character = L' ';
    if (character > 0xFFFF)
    {
        text += static_cast<wchar_t>(0xD800 + ((character - 0x10000) >> 10));
        text += static_cast<wchar_t>(0xDC00 + ((character - 0x10000) & 0x3FF));
    }
    else text += static_cast<wchar_t>(character);
}

struct Cell
{
    int row, column, width;
};

struct Line
{
    std::wstring text;
    std::vector<Cell> cells;
};

struct Snapshot
{
    std::vector<Line> lines;
    int history = 0;
    int top = 0;
    unsigned long long stamp = 0;
};

class Reader
{
  public:
    explicit Reader(HWND terminal, std::function<bool()> cancelled = {}, DWORD timeout = 2000) :
        cancelled_(std::move(cancelled)), deadline_(GetTickCount64() + timeout)
    {
        // Open only read access to the matching sibling's terminal state.
        DWORD processId = 0;
        if (!IsWindowEnabled(terminal) || IsHungAppWindow(terminal) ||
            !GetWindowThreadProcessId(terminal, &processId)) return;
        process_.reset(OpenProcess(PROCESS_VM_READ, FALSE, processId));
        ready = Read(reinterpret_cast<void *>(GetWindowLongPtrW(terminal, GWLP_USERDATA)), &seat, sizeof(seat)) &&
            seat.term_hwnd == terminal && seat.font_width > 0 && seat.font_width <= 1000 &&
            seat.font_height > 0 && seat.font_height <= 1000 && Read(seat.term, &view, sizeof(view)) &&
            view.rows > 0 && view.rows <= 4096 && view.cols > 0 && view.cols <= 4096;
    }

    bool Read(const void *address, void *data, size_t bytes)
    {
        if (GetTickCount64() >= deadline_)
        {
            error = L"Terminal history took too long to read.";
            return false;
        }
        return address && process_ && (!cancelled_ || !cancelled_()) &&
            ReadProcessMemory(process_.get(), address, data, bytes, nullptr) != 0;
    }

    bool Capture(Snapshot &snapshot, bool history = true)
    {
        // Walk history and the active screen in terminal order, joining only soft-wrapped rows.
        if (!ready) return false;
        std::vector<void *> saved, alternate, screen;
        int savedCount = 0;
        if (!Tree(view.scrollback, saved, !history, &savedCount) || !Tree(view.screen, screen) ||
            screen.size() != static_cast<size_t>(view.rows)) return false;
        int extra = view.erase_to_scrollback && view.alt_which && view.alt_screen ? view.alt_sblines : 0;
        if (extra < 0 || extra > view.rows || (extra && !Tree(view.alt_screen, alternate)) ||
            extra > static_cast<int>(alternate.size())) return false;
        snapshot.history = savedCount + extra;
        snapshot.top = view.disptop;
        Hash(snapshot.stamp, view.rows);
        Hash(snapshot.stamp, view.cols);
        Hash(snapshot.stamp, view.alt_which);
        Hash(snapshot.stamp, snapshot.history);
        if (!saved.empty())
        {
            Hash(snapshot.stamp, reinterpret_cast<uintptr_t>(saved.front()));
            Hash(snapshot.stamp, reinterpret_cast<uintptr_t>(saved.back()));
        }
        Line logical;
        size_t characters = 0;
        auto append = [&](void *address, int row, bool compressed)
        {
            std::vector<std::wstring> glyphs;
            unsigned short attributes = 0;
            if (!(compressed ? Compressed(address, glyphs, attributes) : Plain(address, glyphs, attributes)))
                return false;
            int scale = (attributes & LATTR_MODE) == LATTR_NORM ? 1 : 2;
            int columns = std::min(static_cast<int>(glyphs.size()), (view.cols + scale - 1) / scale);
            if (attributes & LATTR_WRAPPED2) --columns;
            if (!(attributes & LATTR_WRAPPED))
                while (columns > 0 && glyphs[columns - 1] == L" ") --columns;
            for (int column = 0; column < columns; ++column)
            {
                const auto &glyph = glyphs[column];
                if (glyph.empty()) continue;
                int width = column + 1 < columns && glyphs[column + 1].empty() ? 2 : 1;
                logical.text += glyph;
                logical.cells.insert(logical.cells.end(), glyph.size(), Cell{row, column, width});
                characters += glyph.size();
                if (characters > 4 * 1024 * 1024)
                {
                    error = L"Terminal history is too large to search.";
                    return false;
                }
            }
            if (row >= 0)
            {
                Hash(snapshot.stamp, attributes);
                for (const auto &glyph : glyphs)
                    for (wchar_t character : glyph) Hash(snapshot.stamp, character);
            }
            if (!(attributes & LATTR_WRAPPED))
            {
                snapshot.lines.push_back(std::move(logical));
                logical = {};
            }
            return true;
        };
        if (history)
        {
            for (size_t row = 0; row < saved.size(); ++row)
                if (!append(saved[row], static_cast<int>(row) - snapshot.history, true)) return false;
            for (int row = 0; row < extra; ++row)
                if (!append(alternate[row], row - extra, false)) return false;
        }
        for (int row = 0; row < view.rows; ++row)
            if (!append(screen[row], row, false)) return false;
        if (!logical.text.empty()) snapshot.lines.push_back(std::move(logical));

        // Reject geometry or screen swaps that raced with the read.
        Terminal current{};
        return Read(seat.term, &current, sizeof(current)) && current.rows == view.rows &&
            current.cols == view.cols && current.screen == view.screen && current.alt_which == view.alt_which;
    }

    bool Plain(const void *address, std::vector<std::wstring> &glyphs, unsigned short &attributes,
        const termchar *source = nullptr)
    {
        // Follow relative combining-character links without modifying terminal cells.
        termline line{};
        if (!Read(address, &line, sizeof(line)) || line.cols <= 0 || line.cols > 4096 ||
            line.size < line.cols || line.size > line.cols * (CC_LIMIT + 1)) return false;
        if (!source) source = line.chars;
        std::vector<termchar> characters(line.cols);
        if (!Read(source, characters.data(), characters.size() * sizeof(termchar))) return false;
        attributes = line.lattr;
        glyphs.resize(line.cols);
        for (int column = 0; column < line.cols; ++column)
        {
            if (characters[column].chr == UCSWIDE) continue;
            int cell = column;
            termchar glyph = characters[cell];
            for (int count = 0; count <= CC_LIMIT; ++count)
            {
                Append(glyphs[column], glyph.chr, seat.ucsdata);
                int next = glyph.cc_next;
                if (!next) break;
                if (count == CC_LIMIT || next < -cell || next >= line.cols * (CC_LIMIT + 1) - cell) return false;
                cell += next;
                if (cell < line.cols) glyph = characters[cell];
                else if (!Read(source + cell, &glyph, sizeof(glyph))) return false;
            }
        }
        return true;
    }

    WinGuiSeat seat{};
    Terminal view{};
    bool ready = false;
    std::wstring error;

  private:
    struct Node
    {
        Node *parent;
        Node *kids[4];
        int counts[4];
        void *elements[3];
    };

    static void Hash(unsigned long long &hash, unsigned long long value)
    {
        hash = (hash ^ value) * 1099511628211ULL;
    }

    bool Tree(tree234 *tree, std::vector<void *> &elements, bool endsOnly = false, int *countOutput = nullptr)
    {
        // The counted tree layout matches utils/tree234.c in the sibling build.
        Node *root = nullptr;
        Node node{};
        if (countOutput) *countOutput = 0;
        if (!Read(tree, &root, sizeof(root))) return false;
        if (!root) return true;
        if (!Read(root, &node, sizeof(node))) return false;
        int count = 0;
        for (int index = 0; index < 4; ++index)
        {
            if (node.counts[index] < 0 || node.counts[index] > 1000000 - count) return false;
            count += node.counts[index];
            if (index < 3 && node.elements[index]) ++count;
        }
        if (count <= 0 || count > 1000000) return false;
        if (countOutput) *countOutput = count;
        elements.reserve(endsOnly ? 2 : count);
        auto visit = [&](auto &self, Node *address, int depth) -> bool
        {
            if (!address) return true;
            Node current{};
            if (depth > 32 || !Read(address, &current, sizeof(current))) return false;
            for (int index = 0; index < 4; ++index)
            {
                if (!self(self, current.kids[index], depth + 1)) return false;
                if (index < 3 && current.elements[index]) elements.push_back(current.elements[index]);
                if (elements.size() > static_cast<size_t>(count)) return false;
            }
            return true;
        };
        if (!endsOnly) return visit(visit, root, 0) && elements.size() == static_cast<size_t>(count);
        elements.resize(2);
        for (bool last : {false, true})
        {
            Node *address = root;
            for (int depth = 0; depth <= 32; ++depth)
            {
                if (!Read(address, &node, sizeof(node))) return false;
                int index = 0;
                if (last) while (index < 3 && node.elements[index]) ++index;
                if (node.kids[index]) address = node.kids[index];
                else
                {
                    if (last) --index;
                    if (index < 0 || !node.elements[index]) return false;
                    elements[last ? 1 : 0] = node.elements[index];
                    break;
                }
                if (depth == 32) return false;
            }
        }
        return true;
    }

    bool Compressed(void *address, std::vector<std::wstring> &glyphs, unsigned short &attributes)
    {
        // Decode the four bounded RLE streams used by terminal.c's scrollback format.
#ifdef NO_SCROLLBACK_COMPRESSION
        return Plain(address, glyphs, attributes);
#else
        size_t length = 0;
        if (!Read(address, &length, sizeof(length)) || length > 2 * 1024 * 1024) return false;
        std::vector<unsigned char> bytes(length);
        if (!Read(static_cast<unsigned char *>(address) + sizeof(length), bytes.data(), bytes.size())) return false;
        size_t offset = 0;
        bool valid = true;
        auto byte = [&]() -> unsigned long
        {
            if (offset == bytes.size()) { valid = false; return 0; }
            return bytes[offset++];
        };
        auto number = [&]()
        {
            unsigned long value = 0;
            for (int shift = 0; shift < 28; shift += 7)
            {
                unsigned long part = byte();
                value |= (part & 127) << shift;
                if (!(part & 128)) return value;
            }
            valid = false;
            return 0UL;
        };
        int columns = static_cast<int>(number());
        attributes = static_cast<unsigned short>(number());
        if (!valid || columns <= 0 || columns > 4096) return false;
        glyphs.resize(columns);
        std::vector<unsigned long> characters(columns);
        auto character = [&](unsigned long &state)
        {
            unsigned long first = byte();
            int following = first < 0x80 ? 0 : first < 0xC0 ? 1 : first < 0xE0 ? 2 : first < 0xF0 ? 3 : 4;
            unsigned long value = following ? first & ((1UL << (7 - following)) - 1) : first | state;
            if (following == 4)
            {
                if (first != 0xF0) valid = false;
                value = 0;
            }
            while (following--) value = (value << 8) | byte();
            state = value & ~0xFFUL;
            return value;
        };
        for (int stream = 0; stream < 4 && valid; ++stream)
        {
            unsigned long state = 0;
            int column = 0;
            while (column < columns && valid)
            {
                unsigned long header = byte();
                int count = header < 128 ? header + 1 : header - 128 + 2;
                if (count > columns - column) return false;
                size_t literal = offset;
                while (count-- && valid)
                {
                    if (header >= 128) offset = literal;
                    if (stream == 0) characters[column] = character(state);
                    else if (stream == 1)
                    {
                        unsigned long first = byte();
                        byte();
                        if (first & 128) { byte(); byte(); }
                    }
                    else if (stream == 2)
                    {
                        unsigned long flags = byte();
                        if (flags & ~3UL) return false;
                        for (int remaining = ((flags & 1) ? 3 : 0) + ((flags & 2) ? 3 : 0); remaining; --remaining)
                            byte();
                    }
                    else
                    {
                        if (characters[column] != UCSWIDE) Append(glyphs[column], characters[column], seat.ucsdata);
                        for (int combining = 0; valid; ++combining)
                        {
                            unsigned long initial = 0;
                            unsigned long value = character(initial);
                            if (!value) break;
                            if (combining == CC_LIMIT) return false;
                            if (characters[column] != UCSWIDE) Append(glyphs[column], value, seat.ucsdata);
                        }
                    }
                    ++column;
                }
            }
        }
        return valid && offset == bytes.size();
#endif
    }

    std::unique_ptr<void, decltype(&CloseHandle)> process_{nullptr, CloseHandle};
    std::function<bool()> cancelled_;
    ULONGLONG deadline_;
};
}
