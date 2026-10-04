#pragma once

#include <atomic>
#include <condition_variable>
#include <exception>
#include <locale>
#include <mutex>
#include <optional>
#include <regex>
#include <thread>

#include "puttytab-rc.h"
#include "terminaltext.h"
#include "theme.h"

class TerminalSearch
{
  public:
    ~TerminalSearch() { Shutdown(); }

    void Shutdown()
    {
        // Finish background reads before releasing windows and shared search state.
        worker_.request_stop();
        wake_.notify_all();
        if (worker_.joinable()) worker_.join();
        if (overlay_) DestroyWindow(overlay_);
        if (dialog_) DestroyWindow(dialog_);
        overlay_ = dialog_ = nullptr;
    }

    bool Owns(HWND window) const
    {
        return dialog_ && (window == dialog_ || IsChild(dialog_, window));
    }

    bool Translate(MSG &message)
    {
        // Keep Find's navigation keys on the host thread instead of sending terminal input.
        if (!Owns(message.hwnd)) return false;
        if (message.message == WM_KEYDOWN && message.wParam == VK_RETURN &&
            (GetFocus() == GetDlgItem(dialog_, IDC_TEXT_VALUE) || (GetKeyState(VK_SHIFT) & 0x8000)))
        {
            Request((GetKeyState(VK_SHIFT) & 0x8000) ? -1 : 1, true);
            return true;
        }
        return IsDialogMessageW(dialog_, &message) != 0;
    }

    void Open(HINSTANCE instance, HWND owner, HWND terminal, int direction = 0)
    {
        if (!terminal || !IsWindowEnabled(terminal) || IsHungAppWindow(terminal)) return;
        owner_ = owner;
        if (!dialog_)
        {
            // Create a modeless native Find window and an input-transparent match highlight.
            dialog_ = CreateDialogParamW(instance, MAKEINTRESOURCEW(IDD_FIND), owner, DialogProc,
                reinterpret_cast<LPARAM>(this));
            if (!dialog_) return;
            WNDCLASSW windowClass{};
            windowClass.lpfnWndProc = OverlayProc;
            windowClass.hInstance = instance;
            windowClass.lpszClassName = L"PuTTYTabSearchHighlight";
            RegisterClassW(&windowClass);
            overlay_ = CreateWindowExW(WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_NOACTIVATE,
                windowClass.lpszClassName, L"", WS_POPUP, 0, 0, 0, 0, owner, nullptr, instance, this);
            if (overlay_) SetLayeredWindowAttributes(overlay_, RGB(0, 0, 0), 100, LWA_COLORKEY | LWA_ALPHA);
            worker_ = std::jthread([this](std::stop_token stop) { Work(stop); });
        }
        bool visible = IsWindowVisible(dialog_) != 0;
        Update(terminal);
        if (!visible)
        {
            ShowWindow(dialog_, SW_SHOW);
            Changed();
        }
        if (direction && visible) Request(direction, true);
        if (!direction || !visible)
        {
            SetForegroundWindow(dialog_);
            SetFocus(GetDlgItem(dialog_, IDC_TEXT_VALUE));
            SendDlgItemMessageW(dialog_, IDC_TEXT_VALUE, EM_SETSEL, 0, -1);
        }
    }

    void Update(HWND terminal)
    {
        // Invalidate results whenever the selected terminal changes or disappears.
        if (terminal_ != terminal)
        {
            terminal_ = terminal;
            anchor_.reset();
            Changed();
        }
        if (!dialog_ || !IsWindowVisible(dialog_)) return;
        if (!terminal_) { Close(); return; }

        // Refresh after output changes; scrolling alone keeps the current search position.
        terminaltext::Reader reader(terminal_, {}, 40);
        terminaltext::Snapshot screen;
        if (!reader.Capture(screen, false)) { HideHighlight(); return; }
        if (screen.stamp != stamp_)
        {
            stamp_ = screen.stamp;
            refreshAt_ = GetTickCount64() + 300;
            HideHighlight();
        }
        if (!busy_ && refreshAt_ && GetTickCount64() >= refreshAt_) Request(0, false);
        if (!busy_) Highlight();
    }

  private:
    struct Match
    {
        size_t line, offset, length;
    };

    struct Task
    {
        unsigned revision;
        HWND terminal, dialog;
        std::wstring query;
        bool matchCase, regex, advance;
        int direction, history;
        std::optional<terminaltext::Cell> anchor;
    };

    struct Result
    {
        Task task;
        terminaltext::Snapshot snapshot;
        std::vector<Match> matches;
        std::wstring error;
        size_t selected = 0;
    };

    static constexpr UINT ReadyMessage = WM_APP + 100;
    static constexpr UINT_PTR QueryTimer = 1;

    static INT_PTR CALLBACK DialogProc(HWND window, UINT message, WPARAM wParam, LPARAM lParam)
    {
        auto *search = reinterpret_cast<TerminalSearch *>(GetWindowLongPtrW(window, GWLP_USERDATA));
        if (message == WM_INITDIALOG)
        {
            search = reinterpret_cast<TerminalSearch *>(lParam);
            search->dialog_ = window;
            SetWindowLongPtrW(window, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(search));
            SetDialogDpiChangeBehavior(window, DDC_DISABLE_ALL, DDC_DISABLE_ALL);
            SendDlgItemMessageW(window, IDC_TEXT_VALUE, EM_SETLIMITTEXT, 4096, 0);
            search->Layout();
            return TRUE;
        }
        if (!search) return FALSE;
        if (message == WM_CLOSE) { search->Close(); return TRUE; }
        if (message == ReadyMessage) { search->Accept(static_cast<unsigned>(wParam)); return TRUE; }
        if (message == WM_TIMER && wParam == QueryTimer) { search->Request(0, false); return TRUE; }
        if (message == WM_SETTINGCHANGE || theme::IsSystemThemeChange(message, lParam) || message == WM_DPICHANGED)
        {
            theme::Refresh();
            search->Layout(message == WM_DPICHANGED ? reinterpret_cast<RECT *>(lParam) : nullptr);
            return TRUE;
        }
        if (message == WM_CTLCOLORDLG || message == WM_CTLCOLORSTATIC || message == WM_CTLCOLORBTN ||
            message == WM_CTLCOLOREDIT || message == WM_CTLCOLORLISTBOX)
            return reinterpret_cast<INT_PTR>(theme::HandleCtlColor(message,
                reinterpret_cast<HDC>(wParam), reinterpret_cast<HWND>(lParam)));
        if (message != WM_COMMAND) return FALSE;
        switch (LOWORD(wParam))
        {
        case IDC_TEXT_VALUE:
            if (HIWORD(wParam) == EN_CHANGE) search->Changed();
            break;
        case IDC_FIND_CASE:
        case IDC_FIND_REGEX: search->Changed(); break;
        case IDOK: search->Request(1, true); break;
        case IDC_FIND_PREVIOUS: search->Request(-1, true); break;
        case IDCANCEL: search->Close(); break;
        default: return FALSE;
        }
        return TRUE;
    }

    static LRESULT CALLBACK OverlayProc(HWND window, UINT message, WPARAM wParam, LPARAM lParam)
    {
        auto *search = reinterpret_cast<TerminalSearch *>(GetWindowLongPtrW(window, GWLP_USERDATA));
        if (message == WM_NCCREATE)
        {
            auto *create = reinterpret_cast<CREATESTRUCTW *>(lParam);
            search = static_cast<TerminalSearch *>(create->lpCreateParams);
            SetWindowLongPtrW(window, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(search));
        }
        if (message == WM_NCHITTEST) return HTTRANSPARENT;
        if (message == WM_PAINT && search)
        {
            // Tint the current match without changing PuTTY's buffer, selection, or clipboard.
            PAINTSTRUCT paint{};
            HDC context = BeginPaint(window, &paint);
            RECT client{};
            GetClientRect(window, &client);
            FillRect(context, &client, reinterpret_cast<HBRUSH>(GetStockObject(BLACK_BRUSH)));
            HBRUSH brush = CreateSolidBrush(RGB(255, 190, 40));
            for (const RECT &rectangle : search->rectangles_) FillRect(context, &rectangle, brush);
            DeleteObject(brush);
            EndPaint(window, &paint);
            return 0;
        }
        return DefWindowProcW(window, message, wParam, lParam);
    }

    void Layout(const RECT *suggested = nullptr)
    {
        // Size native controls from the system message font, text scaling, and current monitor DPI.
        UINT dpi = GetDpiForWindow(dialog_);
        NONCLIENTMETRICSW metrics{sizeof(metrics)};
        if (SystemParametersInfoForDpi(SPI_GETNONCLIENTMETRICS, sizeof(metrics), &metrics, 0, dpi))
        {
            std::unique_ptr<void, decltype(&DeleteObject)> font(
                CreateFontIndirectW(&metrics.lfMessageFont), DeleteObject);
            for (HWND control = GetWindow(dialog_, GW_CHILD); control; control = GetWindow(control, GW_HWNDNEXT))
                SendMessageW(control, WM_SETFONT, reinterpret_cast<WPARAM>(font.get()), TRUE);
            font_ = std::move(font);
        }
        theme::ApplyWindowTree(dialog_);
        HDC context = GetDC(dialog_);
        HGDIOBJ previous = SelectObject(context, font_ ? font_.get() : GetStockObject(DEFAULT_GUI_FONT));
        auto size = [&](int id)
        {
            wchar_t text[128]{};
            GetDlgItemTextW(dialog_, id, text, static_cast<int>(std::size(text)));
            RECT bounds{};
            DrawTextW(context, text, -1, &bounds, DT_CALCRECT | DT_SINGLELINE);
            return SIZE{bounds.right, bounds.bottom};
        };
        TEXTMETRICW text{};
        GetTextMetricsW(context, &text);
        int gap = MulDiv(8, dpi, USER_DEFAULT_SCREEN_DPI);
        int margin = gap + gap / 2;
        int controlHeight = text.tmHeight + gap;
        int caseWidth = size(IDC_FIND_CASE).cx + text.tmHeight + gap;
        int regexWidth = size(IDC_FIND_REGEX).cx + text.tmHeight + gap;
        int buttonWidth = std::max({size(IDOK).cx, size(IDCANCEL).cx, size(IDC_FIND_PREVIOUS).cx}) + margin * 2;
        int width = std::max({MulDiv(460, dpi, USER_DEFAULT_SCREEN_DPI), caseWidth + regexWidth + gap + margin * 2,
            buttonWidth * 3 + gap * 2 + margin * 2});
        SelectObject(context, previous);
        ReleaseDC(dialog_, context);
        auto move = [&](int id, int x, int y, int controlWidth, int height)
        {
            SetWindowPos(GetDlgItem(dialog_, id), nullptr, x, y, controlWidth, height,
                SWP_NOACTIVATE | SWP_NOZORDER);
        };
        HWND label = GetWindow(dialog_, GW_CHILD);
        SetWindowPos(label, nullptr, margin, margin + gap / 2, text.tmHeight * 2, text.tmHeight,
            SWP_NOACTIVATE | SWP_NOZORDER);
        int inputLeft = margin + text.tmHeight * 2 + gap;
        move(IDC_TEXT_VALUE, inputLeft, margin, width - inputLeft - margin, controlHeight);
        int optionsTop = margin + controlHeight + gap;
        move(IDC_FIND_CASE, margin, optionsTop, caseWidth, controlHeight);
        move(IDC_FIND_REGEX, margin + caseWidth + gap, optionsTop, regexWidth, controlHeight);
        int statusTop = optionsTop + controlHeight + gap;
        move(IDC_FIND_STATUS, margin, statusTop, width - margin * 2, text.tmHeight * 2);
        int buttonsTop = statusTop + text.tmHeight * 2 + gap;
        move(IDC_FIND_PREVIOUS, width - margin - buttonWidth * 3 - gap * 2, buttonsTop, buttonWidth, controlHeight);
        move(IDOK, width - margin - buttonWidth * 2 - gap, buttonsTop, buttonWidth, controlHeight);
        move(IDCANCEL, width - margin - buttonWidth, buttonsTop, buttonWidth, controlHeight);
        RECT border{};
        AdjustWindowRectExForDpi(&border, static_cast<DWORD>(GetWindowLongPtrW(dialog_, GWL_STYLE)), FALSE,
            static_cast<DWORD>(GetWindowLongPtrW(dialog_, GWL_EXSTYLE)), dpi);
        int height = buttonsTop + controlHeight + margin + border.bottom - border.top;
        width += border.right - border.left;
        RECT position{};
        if (suggested) position = *suggested;
        else if (IsWindowVisible(dialog_)) GetWindowRect(dialog_, &position);
        else
        {
            GetWindowRect(owner_, &position);
            position.left = position.right - width - margin;
            position.top += MulDiv(80, dpi, USER_DEFAULT_SCREEN_DPI);
        }
        MONITORINFO monitor{sizeof(monitor)};
        if (GetMonitorInfoW(MonitorFromRect(&position, MONITOR_DEFAULTTONEAREST), &monitor))
        {
            position.left = std::clamp(position.left, monitor.rcWork.left, std::max(monitor.rcWork.left,
                monitor.rcWork.right - width));
            position.top = std::clamp(position.top, monitor.rcWork.top, std::max(monitor.rcWork.top,
                monitor.rcWork.bottom - height));
        }
        SetWindowPos(dialog_, nullptr, position.left, position.top, width, height, SWP_NOACTIVATE | SWP_NOZORDER);
    }

    void Status(const wchar_t *text)
    {
        SetDlgItemTextW(dialog_, IDC_FIND_STATUS, text);
    }

    void HideHighlight()
    {
        if (overlay_ && IsWindowVisible(overlay_)) ShowWindow(overlay_, SW_HIDE);
    }

    void Close()
    {
        ++revision_;
        KillTimer(dialog_, QueryTimer);
        ShowWindow(dialog_, SW_HIDE);
        HideHighlight();
        SetForegroundWindow(owner_);
        SetFocus(owner_);
    }

    void Changed()
    {
        if (!dialog_) return;
        ++revision_;
        anchor_.reset();
        result_.reset();
        busy_ = false;
        HideHighlight();
        Status(L"Enter text to search the screen and scrollback.");
        if (IsWindowVisible(dialog_)) SetTimer(dialog_, QueryTimer, 150, nullptr);
    }

    void Request(int direction, bool advance)
    {
        // Replace pending work; the worker discards reads and matches from superseded requests.
        KillTimer(dialog_, QueryTimer);
        refreshAt_ = 0;
        wchar_t query[4097]{};
        GetDlgItemTextW(dialog_, IDC_TEXT_VALUE, query, static_cast<int>(std::size(query)));
        if (!query[0] || !terminal_)
        {
            Changed();
            KillTimer(dialog_, QueryTimer);
            return;
        }
        Task task{++revision_, terminal_, dialog_, query, IsDlgButtonChecked(dialog_, IDC_FIND_CASE) == BST_CHECKED,
            IsDlgButtonChecked(dialog_, IDC_FIND_REGEX) == BST_CHECKED, advance, direction,
            result_ ? result_->snapshot.history : 0, anchor_};
        {
            std::lock_guard lock(mutex_);
            request_ = std::move(task);
        }
        busy_ = true;
        HideHighlight();
        Status(L"Searching...");
        wake_.notify_one();
    }

    void Work(std::stop_token stop)
    {
        // Search off the UI thread so large histories and regex matching leave the host responsive.
        while (!stop.stop_requested())
        {
            std::unique_lock lock(mutex_);
            if (!wake_.wait(lock, stop, [&]() { return request_.has_value(); })) return;
            auto result = std::make_unique<Result>();
            result->task = std::move(*request_);
            request_.reset();
            lock.unlock();
            Task &task = result->task;
            auto cancelled = [&]() { return stop.stop_requested() || task.revision != revision_; };
            try
            {
                std::optional<std::wregex> pattern;
                if (task.regex)
                {
                    pattern.emplace();
                    pattern->imbue(std::locale(""));
                    pattern->assign(task.query, std::regex_constants::ECMAScript |
                        (task.matchCase ? std::regex_constants::syntax_option_type{} : std::regex_constants::icase));
                }
                terminaltext::Reader reader(task.terminal, cancelled);
                terminaltext::Snapshot current;
                if (!reader.Capture(result->snapshot))
                    result->error = reader.error.empty() ? L"Unable to read terminal history. Press Enter to retry." :
                        reader.error;
                else if (!terminaltext::Reader(task.terminal, cancelled).Capture(current, false) ||
                    current.stamp != result->snapshot.stamp)
                    result->error = L"Output changed. Retrying...";
                else
                {
                    std::wstring query = task.query;
                    if (!task.matchCase && !pattern)
                        CharUpperBuffW(query.data(), static_cast<DWORD>(query.size()));
                    for (size_t index = 0; index < result->snapshot.lines.size() && !cancelled(); ++index)
                    {
                        const auto &line = result->snapshot.lines[index];
                        if (pattern)
                        {
                            for (std::wsregex_iterator match(line.text.begin(), line.text.end(), *pattern), end;
                                match != end && !cancelled(); ++match)
                                if (match->length()) result->matches.push_back({index,
                                    static_cast<size_t>(match->position()), static_cast<size_t>(match->length())});
                        }
                        else
                        {
                            std::wstring text = line.text;
                            if (!task.matchCase) CharUpperBuffW(text.data(), static_cast<DWORD>(text.size()));
                            for (size_t offset = 0; !cancelled() &&
                                (offset = text.find(query, offset)) != std::wstring::npos; offset += query.size())
                                result->matches.push_back({index, offset, query.size()});
                        }
                    }
                    if (!cancelled() && !result->matches.empty())
                    {
                        Choose(*result);
                        if (task.advance || !task.anchor) ScrollToMatch(*result, cancelled);
                    }
                }
            }
            catch (const std::regex_error &error)
            {
                result->error = error.code() == std::regex_constants::error_complexity ||
                    error.code() == std::regex_constants::error_stack ? L"Regular expression is too complex." :
                    L"Invalid regular expression.";
            }
            catch (const std::exception &) { result->error = L"Unable to search terminal history."; }
            if (cancelled()) continue;
            unsigned revision = task.revision;
            HWND dialog = task.dialog;
            lock.lock();
            completed_ = std::move(result);
            lock.unlock();
            PostMessageW(dialog, ReadyMessage, revision, 0);
        }
    }

    void Accept(unsigned revision)
    {
        if (revision != revision_) return;
        {
            std::lock_guard lock(mutex_);
            if (!completed_ || completed_->task.revision != revision) return;
            result_ = std::move(completed_);
        }
        busy_ = false;
        if (!result_->error.empty())
        {
            Status(result_->error.c_str());
            if (result_->error.starts_with(L"Output changed")) refreshAt_ = GetTickCount64() + 500;
            return;
        }
        stamp_ = result_->snapshot.stamp;
        refreshAt_ = 0;
        if (result_->matches.empty()) { anchor_.reset(); Status(L"No matches."); return; }

        selected_ = result_->selected;
        const Match &match = result_->matches[selected_];
        anchor_ = result_->snapshot.lines[match.line].cells[match.offset];
        std::wstring status = std::to_wstring(selected_ + 1) + L" of " + std::to_wstring(result_->matches.size()) +
            (result_->matches.size() == 1 ? L" match" : L" matches");
        Status(status.c_str());
        Highlight();
    }

    static void Choose(Result &result)
    {
        // Continue from the selected match, accounting for lines newly added to scrollback.
        const Task &task = result.task;
        terminaltext::Cell target{result.snapshot.top, 0, 1};
        if (task.anchor)
        {
            target = *task.anchor;
            target.row -= result.snapshot.history - task.history;
        }
        auto before = [](const terminaltext::Cell &left, const terminaltext::Cell &right)
        {
            return left.row < right.row || (left.row == right.row && left.column < right.column);
        };
        auto cell = [&](const Match &match) { return result.snapshot.lines[match.line].cells[match.offset]; };
        size_t selected = 0;
        if (task.direction < 0)
        {
            selected = result.matches.size() - 1;
            for (size_t index = 0; index < result.matches.size(); ++index)
            {
                if (!before(cell(result.matches[index]), target)) break;
                selected = index;
            }
        }
        else
        {
            for (size_t index = 0; index < result.matches.size(); ++index)
            {
                auto candidate = cell(result.matches[index]);
                if (before(target, candidate) || (!(task.advance && task.anchor) && !before(candidate, target)))
                {
                    selected = index;
                    break;
                }
            }
        }
        result.selected = selected;
    }

    static void ScrollToMatch(const Result &result, const std::function<bool()> &cancelled)
    {
        // Navigate through native scrolling operations without relying on scrollbar thumb state.
        HWND terminal = result.task.terminal;
        const Match &match = result.matches[result.selected];
        auto anchor = result.snapshot.lines[match.line].cells[match.offset];
        terminaltext::Reader reader(terminal, cancelled, 40);
        if (!reader.ready || (anchor.row >= reader.view.disptop &&
            anchor.row < reader.view.disptop + reader.view.rows)) return;
        int target = std::clamp(anchor.row - reader.view.rows / 3, -result.snapshot.history, 0);
        int top = reader.view.disptop;
        auto send = [&](WPARAM value)
        {
            DWORD_PTR returned = 0;
            return !cancelled() && SendMessageTimeoutW(terminal, WM_VSCROLL, value, 0,
                SMTO_ABORTIFHUNG | SMTO_ERRORONEXIT, 100, &returned) != 0;
        };
        if (target + result.snapshot.history < abs(target - top))
        {
            if (!send(SB_TOP)) return;
            top = -result.snapshot.history;
        }
        else if (-target < abs(target - top))
        {
            if (!send(SB_BOTTOM)) return;
            top = 0;
        }
        int page = reader.view.rows / 2;
        while (top != target)
        {
            int difference = target - top;
            bool wholePage = page && abs(difference) >= page;
            if (!send(wholePage ? (difference < 0 ? SB_PAGEUP : SB_PAGEDOWN) :
                (difference < 0 ? SB_LINEUP : SB_LINEDOWN))) return;
            top += (difference < 0 ? -1 : 1) * (wholePage ? page : 1);
        }
    }

    void Highlight()
    {
        // Verify the selected cells and map logical positions through PuTTY's bidi cache.
        if (!overlay_ || !result_ || result_->matches.empty() || !result_->error.empty() || IsIconic(owner_) ||
            GetAncestor(GetForegroundWindow(), GA_ROOTOWNER) != owner_)
        {
            HideHighlight();
            return;
        }
        terminaltext::Reader reader(terminal_, {}, 40);
        if (!reader.ready || !reader.view.disptext) { HideHighlight(); return; }
        std::vector<termline *> rows(reader.view.rows);
        if (!reader.Read(reader.view.disptext, rows.data(), rows.size() * sizeof(rows[0])))
        {
            HideHighlight();
            return;
        }
        const Match &match = result_->matches[selected_];
        const auto &line = result_->snapshot.lines[match.line];
        std::vector<RECT> rectangles;
        int activeRow = -1;
        std::vector<std::wstring> glyphs;
        std::vector<int> forward;
        unsigned short attributes = 0;
        for (size_t offset = match.offset; offset < match.offset + match.length; ++offset)
        {
            auto cell = line.cells[offset];
            int row = cell.row - reader.view.disptop;
            if (row < 0 || row >= reader.view.rows) continue;
            if (row != activeRow)
            {
                const termchar *source = nullptr;
                termline painted{};
                if (!reader.Read(rows[row], &painted, sizeof(painted))) { HideHighlight(); return; }
                forward.clear();
                if ((!reader.view.no_bidi || !reader.view.no_arabicshaping || painted.trusted) &&
                    reader.view.pre_bidi_cache &&
                    reader.view.post_bidi_cache && static_cast<size_t>(row) < reader.view.bidi_cache_size)
                {
                    bidi_cache_entry before{}, after{};
                    if (!reader.Read(reader.view.pre_bidi_cache + row, &before, sizeof(before)) ||
                        !reader.Read(reader.view.post_bidi_cache + row, &after, sizeof(after)) ||
                        before.width != reader.view.cols || after.width != reader.view.cols || !before.chars)
                    {
                        HideHighlight();
                        return;
                    }
                    source = before.chars;
                    forward.resize(reader.view.cols);
                    if (!reader.Read(after.forward, forward.data(), forward.size() * sizeof(int)))
                    {
                        HideHighlight();
                        return;
                    }
                }
                glyphs.clear();
                if (!reader.Plain(rows[row], glyphs, attributes, source)) { HideHighlight(); return; }
                activeRow = row;
            }
            size_t initial = offset;
            while (initial && line.cells[initial - 1].row == cell.row &&
                line.cells[initial - 1].column == cell.column) --initial;
            size_t character = offset - initial;
            if (cell.column >= static_cast<int>(glyphs.size()) || character >= glyphs[cell.column].size() ||
                glyphs[cell.column][character] != line.text[offset])
            {
                rectangles.clear();
                break;
            }
            int column = forward.empty() ? cell.column : forward[cell.column];
            if (!forward.empty() && cell.width == 2 && cell.column + 1 < static_cast<int>(forward.size()))
                column = std::min(column, forward[cell.column + 1]);
            if (column < 0 || column + cell.width > reader.view.cols) { HideHighlight(); return; }
            int scale = (attributes & LATTR_MODE) == LATTR_NORM ? 1 : 2;
            int left = reader.seat.offset_width + column * scale * reader.seat.font_width;
            int top = reader.seat.offset_height + row * reader.seat.font_height;
            rectangles.push_back({left, top, left + cell.width * scale * reader.seat.font_width,
                top + reader.seat.font_height});
        }
        if (rectangles.empty()) { HideHighlight(); return; }
        Terminal current{};
        if (!reader.Read(reader.seat.term, &current, sizeof(current)) || current.rows != reader.view.rows ||
            current.cols != reader.view.cols || current.disptop != reader.view.disptop ||
            current.disptext != reader.view.disptext)
        {
            HideHighlight();
            return;
        }
        RECT client{};
        GetClientRect(GetParent(terminal_), &client);
        MapWindowPoints(GetParent(terminal_), terminal_, reinterpret_cast<POINT *>(&client), 2);
        POINT origin{client.left, client.top};
        ClientToScreen(terminal_, &origin);
        for (RECT &rectangle : rectangles) OffsetRect(&rectangle, -client.left, -client.top);
        rectangles_ = std::move(rectangles);
        SetWindowPos(overlay_, dialog_, origin.x, origin.y, client.right - client.left, client.bottom - client.top,
            SWP_NOACTIVATE | SWP_SHOWWINDOW);
        InvalidateRect(overlay_, nullptr, FALSE);
    }

    HWND owner_ = nullptr, dialog_ = nullptr, terminal_ = nullptr, overlay_ = nullptr;
    std::unique_ptr<void, decltype(&DeleteObject)> font_{nullptr, DeleteObject};
    std::vector<RECT> rectangles_;
    std::optional<terminaltext::Cell> anchor_;
    std::unique_ptr<Result> result_, completed_;
    std::optional<Task> request_;
    std::mutex mutex_;
    std::condition_variable_any wake_;
    std::atomic<unsigned> revision_ = 0;
    std::jthread worker_;
    size_t selected_ = 0;
    unsigned long long stamp_ = 0;
    ULONGLONG refreshAt_ = 0;
    bool busy_ = false;
};
