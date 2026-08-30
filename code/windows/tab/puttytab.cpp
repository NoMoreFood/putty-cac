/*
 * puttytab.cpp - a tabbed host for independent PuTTY processes.
 *
 * Keeping each terminal in its own process lets this program provide tabs
 * without depending on PuTTY internals. In particular, configuration dialogs,
 * authentication prompts, and protocol handling remain entirely in PuTTY.
 */

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <windowsx.h>
#include <commctrl.h>

#include <algorithm>
#include <array>
#include <iterator>
#include <memory>
#include <string>
#include <utility>
#include <vector>

extern "C"
{
#include "cert_portable.h"
}
#include "puttytab-rc.h"
#include "theme.h"

constexpr wchar_t WindowClassName[] = L"PuTTYTab";
constexpr wchar_t WindowTitle[] = L"PuTTYTab";
constexpr wchar_t SessionRegistryPath[] = L"Software\\SimonTatham\\PuTTY\\Sessions";
constexpr wchar_t SettingsRegistryPath[] = L"Software\\SimonTatham\\PuTTY\\PuTTYTab";
constexpr wchar_t AlwaysOnTopSetting[] = L"AlwaysOnTop";
constexpr wchar_t StatusBarVisibleSetting[] = L"StatusBarVisible";
constexpr wchar_t ConnectBarVisibleSetting[] = L"ConnectBarVisible";

constexpr UINT_PTR PollTimer = 1;
constexpr UINT PollInterval = 200;
constexpr ULONGLONG ScrollbarHideDelay = 1000;
constexpr ULONGLONG CloseRequestTimeout = 1500;
constexpr UINT WmShortcut = WM_APP + 1;
constexpr UINT WmActivateTab = WM_APP + 2;
constexpr UINT WmMenuMnemonic = WM_APP + 3;
constexpr UINT WmFocusConnectBar = WM_APP + 4;
constexpr UINT_PTR TabHostSubclass = 101;
constexpr UINT_PTR ConnectBarSubclass = 102;

// Private WM_SYSCOMMAND values used by the sibling PuTTY executable.
constexpr WPARAM PuttyShowLog = 0x0010;
constexpr WPARAM PuttyDuplicateSession = 0x0030;
constexpr WPARAM PuttyRestart = 0x0040;
constexpr WPARAM PuttyReconfigure = 0x0050;
constexpr WPARAM PuttyClearScrollback = 0x0060;
constexpr WPARAM PuttyReset = 0x0070;
constexpr WPARAM PuttyHelp = 0x0140;
constexpr WPARAM PuttyAbout = 0x0150;
constexpr WPARAM PuttyCopyAll = 0x0170;
constexpr WPARAM PuttyCopy = 0x0190;
constexpr WPARAM PuttyPaste = 0x01A0;

using UniqueHandle = std::unique_ptr<void, decltype([](HANDLE handle)
{
    if (handle && handle != INVALID_HANDLE_VALUE) CloseHandle(handle);
})>;

struct ProcessWindows
{
    DWORD processId = 0;
    HWND terminal = nullptr;
    HWND dialog = nullptr;
    HWND visible = nullptr;
};

enum class KeyState : BYTE
{
    Idle,
    Passed,
    Consumed
};

struct Session
{
    DWORD processId = 0;
    UniqueHandle process;
    HWND terminal = nullptr;
    HWND originalParent = nullptr;
    LONG_PTR originalStyle = 0;
    LONG_PTR originalExtendedStyle = 0;
    RECT originalRect{};
    std::wstring title = L"Starting PuTTY...";
    std::wstring detectedTitle = title;
    std::wstring customTitle;
    ULONGLONG closeRequestedAt = 0;
    ULONGLONG scrollbarMissingSince = 0;
    bool attached = false;
    bool attachFailed = false;
    bool hasScrollbar = false;
    bool closing = false;
    bool closeBlocked = false;
    bool locked = false;
};

static std::wstring WindowText(HWND window)
{
    int length = GetWindowTextLengthW(window);
    if (length <= 0) return {};
    std::wstring text(static_cast<size_t>(length) + 1, L'\0');
    int copied = GetWindowTextW(window, text.data(), static_cast<int>(text.size()));
    text.resize(copied > 0 ? static_cast<size_t>(copied) : 0);
    return text;
}

static bool IsPuttyTerminal(HWND window)
{
    wchar_t className[64]{};
    if (!GetClassNameW(window, className, static_cast<int>(std::size(className)))) return false;
    return wcscmp(className, L"PuTTY") == 0 || wcscmp(className, L"PuTTY.ansi") == 0;
}

static bool IsSessionTerminal(const Session &session)
{
    if (!session.terminal || !IsWindow(session.terminal) || !IsPuttyTerminal(session.terminal)) return false;
    DWORD processId = 0;
    GetWindowThreadProcessId(session.terminal, &processId);
    return processId == session.processId;
}

static bool HasVisibleScrollbar(HWND window)
{
    if (GetWindowLongPtrW(window, GWL_STYLE) & WS_VSCROLL) return true;
    SCROLLBARINFO scrollbar{sizeof(scrollbar)};
    return GetScrollBarInfo(window, OBJID_VSCROLL, &scrollbar) &&
        !(scrollbar.rgstate[0] & (STATE_SYSTEM_INVISIBLE | STATE_SYSTEM_OFFSCREEN));
}

static bool IsDisconnectedTerminal(const Session &session)
{
    return IsSessionTerminal(session) && session.detectedTitle.ends_with(L" (inactive)");
}

static bool ReadBooleanSetting(const wchar_t *name, bool fallback)
{
    DWORD value = 0;
    DWORD size = sizeof(value);
    LSTATUS status =
        RegGetValueW(HKEY_CURRENT_USER, SettingsRegistryPath, name, RRF_RT_REG_DWORD, nullptr, &value, &size);
    return status == ERROR_SUCCESS && size == sizeof(value) ? value != 0 : fallback;
}

static void WriteBooleanSetting(const wchar_t *name, bool enabled)
{
    DWORD value = enabled ? 1 : 0;
    RegSetKeyValueW(HKEY_CURRENT_USER, SettingsRegistryPath, name, REG_DWORD, &value, sizeof(value));
}

static bool SetWindowLongPtrValue(HWND window, int index, LONG_PTR value)
{
    SetLastError(ERROR_SUCCESS);
    LONG_PTR previous = SetWindowLongPtrW(window, index, value);
    return previous || GetLastError() == ERROR_SUCCESS;
}

static BOOL CALLBACK FindProcessWindows(HWND window, LPARAM parameter)
{
    // Capture PuTTY's terminal, dialog, and first visible window for the target process.
    auto &result = *reinterpret_cast<ProcessWindows *>(parameter);
    DWORD processId = 0;
    GetWindowThreadProcessId(window, &processId);
    if (processId != result.processId) return TRUE;
    if (IsPuttyTerminal(window)) result.terminal = window;
    if (IsWindowVisible(window))
    {
        if (!result.visible) result.visible = window;

        wchar_t className[64]{};
        if (!result.dialog && GetClassNameW(window, className, static_cast<int>(std::size(className))) &&
            wcscmp(className, L"#32770") == 0)
            result.dialog = window;
    }
    return TRUE;
}

static ProcessWindows WindowsForProcess(DWORD processId)
{
    ProcessWindows result{processId};
    EnumWindows(FindProcessWindows, reinterpret_cast<LPARAM>(&result));
    return result;
}

static std::wstring QuoteArgument(const std::wstring &argument)
{
    if (!argument.empty() && argument.find_first_of(L" \t\n\v\"") == std::wstring::npos) return argument;

    // Apply Windows command-line quoting rules for embedded backslashes and quotation marks.
    std::wstring result = L"\"";
    size_t backslashes = 0;
    for (wchar_t character : argument)
    {
        if (character == L'\\')
        {
            ++backslashes;
            continue;
        }

        if (character == L'\"')
        {
            result.append(backslashes * 2 + 1, L'\\');
            result.push_back(character);
        }
        else
        {
            result.append(backslashes, L'\\');
            result.push_back(character);
        }
        backslashes = 0;
    }

    result.append(backslashes * 2, L'\\');
    result.push_back(L'\"');
    return result;
}

static bool AppendTopMenu(HMENU parent, HMENU submenu, const wchar_t *label)
{
    MENUITEMINFOW item{sizeof(item)};
    item.fMask = MIIM_DATA | MIIM_FTYPE | MIIM_STRING | MIIM_SUBMENU;
    item.fType = MFT_OWNERDRAW;
    item.hSubMenu = submenu;
    item.dwItemData = reinterpret_cast<ULONG_PTR>(label);
    item.dwTypeData = const_cast<wchar_t *>(label);
    item.cch = static_cast<UINT>(wcslen(label));
    return InsertMenuItemW(parent, GetMenuItemCount(parent), TRUE, &item) != FALSE;
}

static int HexValue(wchar_t character)
{
    if (character >= L'0' && character <= L'9') return character - L'0';
    if (character >= L'a' && character <= L'f') return character - L'a' + 10;
    if (character >= L'A' && character <= L'F') return character - L'A' + 10;
    return -1;
}

static std::wstring DecodeSessionName(const std::wstring &encoded)
{
    // Decode PuTTY's percent-escaped registry key into its display name.
    std::string bytes;
    bytes.reserve(encoded.size());
    for (size_t index = 0; index < encoded.size(); ++index)
    {
        if (encoded[index] == L'%' && index + 2 < encoded.size())
        {
            int high = HexValue(encoded[index + 1]);
            int low = HexValue(encoded[index + 2]);
            if (high >= 0 && low >= 0)
            {
                bytes.push_back(static_cast<char>((high << 4) | low));
                index += 2;
                continue;
            }
        }

        if (encoded[index] > 0xFF) return encoded;
        bytes.push_back(static_cast<char>(encoded[index]));
    }
    int length = MultiByteToWideChar(CP_ACP, 0, bytes.data(), static_cast<int>(bytes.size()), nullptr, 0);
    std::wstring result(static_cast<size_t>(length), L'\0');
    if (length) MultiByteToWideChar(CP_ACP, 0, bytes.data(), static_cast<int>(bytes.size()), result.data(), length);
    return result;
}

static std::wstring ErrorText(const wchar_t *operation, DWORD error = GetLastError())
{
    // Format a Win32 error and trim trailing line endings for inline display.
    wchar_t *message = nullptr;
    FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr,
        error, 0, reinterpret_cast<wchar_t *>(&message), 0, nullptr);
    std::wstring result = operation;
    result += L" failed";
    if (message)
    {
        result += L": ";
        result += message;
        while (!result.empty() && (result.back() == L'\r' || result.back() == L'\n')) result.pop_back();
        LocalFree(message);
    }
    return result;
}

static INT_PTR CALLBACK TextDialogProc(HWND dialog, UINT message, WPARAM wParam, LPARAM lParam)
{
    // Reapply themed dialog controls when Windows changes colour preferences.
    if (theme::IsSystemThemeChange(message, lParam))
    {
        theme::Refresh();
        theme::ApplyWindowTree(dialog);
        return TRUE;
    }

    // Theme and center the modal text-entry dialog over its owner.
    if (message == WM_INITDIALOG)
    {
        SetWindowLongPtrW(dialog, GWLP_USERDATA, lParam);
        auto &value = *reinterpret_cast<std::wstring *>(lParam);
        SetWindowTextW(GetDlgItem(dialog, IDC_TEXT_VALUE), value.c_str());
        SendDlgItemMessageW(dialog, IDC_TEXT_VALUE, EM_SETSEL, 0, -1);
        theme::ApplyWindowTree(dialog);
        HWND owner = GetWindow(dialog, GW_OWNER);
        RECT dialogRect{}, ownerRect{};
        if (owner && GetWindowRect(dialog, &dialogRect) && GetWindowRect(owner, &ownerRect))
        {
            int width = dialogRect.right - dialogRect.left;
            int height = dialogRect.bottom - dialogRect.top;
            int x = ownerRect.left + (ownerRect.right - ownerRect.left - width) / 2;
            int y = ownerRect.top + (ownerRect.bottom - ownerRect.top - height) / 2;
            MONITORINFO monitor{sizeof(monitor)};
            if (GetMonitorInfoW(MonitorFromWindow(owner, MONITOR_DEFAULTTONEAREST), &monitor))
            {
                int workLeft = monitor.rcWork.left;
                int workTop = monitor.rcWork.top;
                int workRight = monitor.rcWork.right;
                int workBottom = monitor.rcWork.bottom;
                x = std::clamp(x, workLeft, std::max(workLeft, workRight - width));
                y = std::clamp(y, workTop, std::max(workTop, workBottom - height));
            }
            SetWindowPos(dialog, nullptr, x, y, 0, 0, SWP_NOACTIVATE | SWP_NOSIZE | SWP_NOZORDER);
        }
        SetFocus(GetDlgItem(dialog, IDC_TEXT_VALUE));
        return FALSE;
    }
    if (message == WM_CTLCOLORDLG || message == WM_CTLCOLORSTATIC || message == WM_CTLCOLORBTN ||
        message == WM_CTLCOLOREDIT || message == WM_CTLCOLORLISTBOX)
        return reinterpret_cast<INT_PTR>(
            theme::HandleCtlColor(message, reinterpret_cast<HDC>(wParam), reinterpret_cast<HWND>(lParam)));

    // Return the entered text only when the user accepts the dialog.
    UINT command = LOWORD(wParam);
    if (message != WM_COMMAND || (command != IDOK && command != IDCANCEL)) return FALSE;
    auto *value = reinterpret_cast<std::wstring *>(GetWindowLongPtrW(dialog, GWLP_USERDATA));
    if (command == IDOK) *value = WindowText(GetDlgItem(dialog, IDC_TEXT_VALUE));
    EndDialog(dialog, command);
    return TRUE;
}

class App
{
  public:

    explicit App(HINSTANCE instance) : instance_(instance)
    {
        current_ = this;
    }

    ~App()
    {
        if (keyboardHook_) UnhookWindowsHookEx(keyboardHook_);
        theme::Shutdown();
        current_ = nullptr;
    }

    bool Initialise(int showCommand)
    {
        INITCOMMONCONTROLSEX controls{sizeof(controls), ICC_TAB_CLASSES | ICC_BAR_CLASSES};
        InitCommonControlsEx(&controls);
        theme::Initialise();
        alwaysOnTop_ = ReadBooleanSetting(AlwaysOnTopSetting, false);
        statusVisible_ = ReadBooleanSetting(StatusBarVisibleSetting, true);
        connectBarVisible_ = ReadBooleanSetting(ConnectBarVisibleSetting, true);

        // Resolve the sibling PuTTY executable and initialise host integration state.
        wchar_t modulePath[32768]{};
        DWORD length = GetModuleFileNameW(nullptr, modulePath, static_cast<DWORD>(std::size(modulePath)));
        if (!length || length == std::size(modulePath))
        {
            MessageBoxW(nullptr, L"Unable to locate puttytab.exe.", WindowTitle, MB_OK | MB_ICONERROR);
            return false;
        }
        std::wstring executable(modulePath, length);
        size_t separator = executable.find_last_of(L"\\/");
        puttyDirectory_ = separator == std::wstring::npos ? L"." : executable.substr(0, separator);
        puttyPath_ = puttyDirectory_ + L"\\putty.exe";

        using SetAppId = HRESULT(WINAPI *)(PCWSTR);
        HMODULE shell = GetModuleHandleW(L"shell32.dll");
        auto setAppId =
            shell ? reinterpret_cast<SetAppId>(GetProcAddress(shell, "SetCurrentProcessExplicitAppUserModelID"))
            : nullptr;
        if (setAppId) setAppId(L"NoMoreFood.PuTTYTab");

        job_.reset(CreateJobObjectW(nullptr, nullptr));

        // Register and create the top-level host window.
        WNDCLASSEXW windowClass{sizeof(windowClass)};
        windowClass.style = 0;
        windowClass.lpfnWndProc = WindowProc;
        windowClass.hInstance = instance_;
        windowClass.hIcon = LoadIconW(instance_, MAKEINTRESOURCEW(IDI_PUTTYTAB));
        windowClass.hIconSm = windowClass.hIcon;
        windowClass.hCursor = LoadCursorW(nullptr, IDC_ARROW);
        windowClass.hbrBackground = nullptr;
        windowClass.lpszClassName = WindowClassName;
        if (!RegisterClassExW(&windowClass))
        {
            MessageBoxW(nullptr, ErrorText(L"Registering the PuTTYTab window").c_str(), WindowTitle,
                MB_OK | MB_ICONERROR);
            return false;
        }

        frame_ = CreateWindowExW(alwaysOnTop_ ? WS_EX_TOPMOST : 0, WindowClassName, WindowTitle,
            WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN, CW_USEDEFAULT, CW_USEDEFAULT, 1100, 760,
            nullptr, nullptr, instance_, this);
        if (!frame_)
        {
            MessageBoxW(nullptr, ErrorText(L"Creating the PuTTYTab window").c_str(), WindowTitle, MB_OK | MB_ICONERROR);
            return false;
        }

        // Start shortcut and session monitoring before showing the interface.
        keyboardHook_ = SetWindowsHookExW(WH_KEYBOARD_LL, KeyboardProc, instance_, 0);
        if (!keyboardHook_)
        {
            MessageBoxW(frame_, ErrorText(L"Installing PuTTYTab keyboard shortcuts").c_str(), WindowTitle,
                MB_OK | MB_ICONERROR);
            DestroyWindow(frame_);
            return false;
        }
        if (!SetTimer(frame_, PollTimer, PollInterval, nullptr))
        {
            MessageBoxW(frame_, L"Unable to start PuTTYTab session monitoring.", WindowTitle, MB_OK | MB_ICONERROR);
            DestroyWindow(frame_);
            return false;
        }

        ShowWindow(frame_, showCommand);
        UpdateWindow(frame_);
        return true;
    }

    int Run(const std::wstring &initialArguments)
    {
        // Launch the requested session and pump host messages until shutdown.
        Launch(initialArguments);

        MSG message{};
        while (GetMessageW(&message, nullptr, 0, 0) > 0)
        {
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }
        return static_cast<int>(message.wParam);
    }

  private:
    static App *current_;

    static LRESULT CALLBACK WindowProc(HWND window, UINT message, WPARAM wParam, LPARAM lParam)
    {
        // Bind WM_NCCREATE to the owning App and forward subsequent host messages.
        App *app = reinterpret_cast<App *>(GetWindowLongPtrW(window, GWLP_USERDATA));
        if (message == WM_NCCREATE)
        {
            auto *create = reinterpret_cast<CREATESTRUCTW *>(lParam);
            app = reinterpret_cast<App *>(create->lpCreateParams);
            app->frame_ = window;
            SetWindowLongPtrW(window, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(app));
        }
        return app ? app->HandleMessage(message, wParam, lParam) : DefWindowProcW(window, message, wParam, lParam);
    }

    static LRESULT CALLBACK KeyboardProc(int code, WPARAM wParam, LPARAM lParam)
    {
        if (code < 0 || !current_) return CallNextHookEx(nullptr, code, wParam, lParam);
        return current_->HandleKeyboard(code, wParam, *reinterpret_cast<KBDLLHOOKSTRUCT *>(lParam));
    }

    static LRESULT CALLBACK TabProc(HWND window, UINT message, WPARAM wParam, LPARAM lParam, UINT_PTR, DWORD_PTR data)
    {
        return reinterpret_cast<App *>(data)->HandleTabMessage(window, message, wParam, lParam);
    }

    static LRESULT CALLBACK ConnectProc(HWND window, UINT message, WPARAM wParam, LPARAM lParam, UINT_PTR,
        DWORD_PTR data)
    {
        return reinterpret_cast<App *>(data)->HandleConnectMessage(window, message, wParam, lParam);
    }

    LRESULT HandleMessage(UINT message, WPARAM wParam, LPARAM lParam)
    {
        // Route host lifecycle, theming, commands, and session events.
        switch (message)
        {
        case WM_CREATE: return CreateControls() ? 0 : -1;
        case WM_ERASEBKGND:
        {
            RECT client{};
            GetClientRect(frame_, &client);
            FillRect(reinterpret_cast<HDC>(wParam), &client, theme::BackgroundBrush());
            return 1;
        }
        case WM_NCPAINT:
        case WM_NCACTIVATE:
        {
            LRESULT result = DefWindowProcW(frame_, message, wParam, lParam);
            PaintMenuSeparator();
            return result;
        }
        case WM_SETTINGCHANGE:
        case WM_SYSCOLORCHANGE:
            if (theme::IsSystemThemeChange(message, lParam))
            {
                theme::Refresh();
                theme::ApplyWindowTree(frame_);
                theme::ApplyControl(TabCtrl_GetToolTips(tabs_));
                theme::ApplyControl(connectList_);
                theme::ApplyMenuBar(frame_, menu_);
                SyncScrollbar();
                return 0;
            }
            break;
        case WM_MEASUREITEM:
            if (theme::MeasureMenuItem(frame_, *reinterpret_cast<MEASUREITEMSTRUCT *>(lParam))) return TRUE;
            break;
        case WM_DRAWITEM:
            if (theme::DrawMenuItem(*reinterpret_cast<DRAWITEMSTRUCT *>(lParam))) return TRUE;
            break;
        case WM_CTLCOLORDLG:
        case WM_CTLCOLORSTATIC:
        case WM_CTLCOLORBTN:
        case WM_CTLCOLOREDIT:
        case WM_CTLCOLORLISTBOX:
            return reinterpret_cast<LRESULT>(
                theme::HandleCtlColor(message, reinterpret_cast<HDC>(wParam), reinterpret_cast<HWND>(lParam)));
        case WM_WINDOWPOSCHANGING:
        {
            // Preposition child windows before a frame resize can expose PuTTY's native scrollbar.
            auto *position = reinterpret_cast<WINDOWPOS *>(lParam);
            RECT client{}, window{};
            if (!(position->flags & SWP_NOSIZE) && GetClientRect(frame_, &client) && GetWindowRect(frame_, &window))
            {
                SIZE target{std::max(0L, position->cx - (window.right - window.left - client.right)),
                    std::max(0L, position->cy - (window.bottom - window.top - client.bottom))};
                Layout(false, &target);
            }
            break;
        }
        case WM_SIZE: Layout(); return 0;
        case WM_SETFOCUS: FocusCurrentSession(); return 0;
        case WM_COMMAND:
            if (LOWORD(wParam) == IDC_CONNECT_BUTTON && HIWORD(wParam) == BN_CLICKED) ConnectFromBar();
            else if (LOWORD(wParam) == IDC_CONNECT_SESSION && HIWORD(wParam) == CBN_EDITCHANGE)
                AutoCompleteConnectBar();
            else if (LOWORD(wParam) == IDC_CONNECT_SESSION && HIWORD(wParam) == CBN_DROPDOWN)
                RebuildSavedSessionsMenu();
            else HandleCommand(LOWORD(wParam));
            return 0;
        case WM_VSCROLL:
            if (reinterpret_cast<HWND>(lParam) == scrollbar_)
            {
                HandleScrollbar(wParam);
                return 0;
            }
            break;
        case WM_NOTIFY: return HandleNotification(*reinterpret_cast<NMHDR *>(lParam));
        case WM_INITMENUPOPUP:
            if (reinterpret_cast<HMENU>(wParam) == savedMenu_) RebuildSavedSessionsMenu();
            UpdateMenuState();
            return 0;
        case WM_CONTEXTMENU:
            if (reinterpret_cast<HWND>(wParam) == page_ ||
                (reinterpret_cast<HWND>(wParam) == tabs_ && GET_X_LPARAM(lParam) == -1))
            {
                ShowTabContextMenu(GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam));
                return 0;
            }
            break;
        case WM_TIMER:
            if (wParam == PollTimer) PollSessions();
            return 0;
        case WM_DPICHANGED:
        {
            auto *suggested = reinterpret_cast<RECT *>(lParam);
            SetWindowPos(frame_, nullptr, suggested->left, suggested->top, suggested->right - suggested->left,
                suggested->bottom - suggested->top, SWP_NOACTIVATE | SWP_NOZORDER);
            UpdateTabMetrics();
            Layout();
            return 0;
        }
        case WM_GETMINMAXINFO:
        {
            auto *limits = reinterpret_cast<MINMAXINFO *>(lParam);
            UINT dpi = GetDpiForWindow(frame_);
            limits->ptMinTrackSize.x = MulDiv(480, dpi, USER_DEFAULT_SCREEN_DPI);
            limits->ptMinTrackSize.y = MulDiv(320, dpi, USER_DEFAULT_SCREEN_DPI);
            return 0;
        }
        case WmShortcut:
            if (lParam)
            {
                size_t index = SessionIndex(static_cast<DWORD>(lParam));
                if (index == sessions_.size()) return 0;
                ActivateSession(index, false);
            }
            HandleCommand(static_cast<UINT>(wParam));
            return 0;
        case WmActivateTab: ActivateSession(SessionIndex(static_cast<DWORD>(wParam))); return 0;
        case WmMenuMnemonic:
            if (fullscreen_) ToggleFullscreen();
            return DefWindowProcW(frame_, WM_SYSCOMMAND, SC_KEYMENU, static_cast<LPARAM>(wParam));
        case WmFocusConnectBar: FocusConnectBar(); return 0;
        case WM_QUERYENDSESSION: return TRUE;
        case WM_ENDSESSION:
            if (wParam) RequestCloseAll(true);
            return 0;
        case WM_CLOSE: BeginExit(); return 0;
        case WM_DESTROY:
            KillTimer(frame_, PollTimer);
            if (tabs_) RemoveWindowSubclass(tabs_, TabProc, TabHostSubclass);
            if (connectEdit_) RemoveWindowSubclass(connectEdit_, ConnectProc, ConnectBarSubclass);
            DetachAll();
            PostQuitMessage(0);
            return 0;
        }
        return DefWindowProcW(frame_, message, wParam, lParam);
    }

    bool CreateControls()
    {
        // Build the menu hierarchy and its PuTTY-facing commands.
        menu_ = CreateMenu();
        HMENU fileMenu = CreatePopupMenu();
        savedMenu_ = CreatePopupMenu();
        HMENU sessionMenu = CreatePopupMenu();
        HMENU viewMenu = CreatePopupMenu();
        if (!menu_ || !fileMenu || !savedMenu_ || !sessionMenu || !viewMenu) return false;

        AppendMenuW(fileMenu, MF_STRING, IDM_FILE_NEW, L"&New Session...\tCtrl+Shift+T");
        AppendMenuW(fileMenu, MF_POPUP, reinterpret_cast<UINT_PTR>(savedMenu_), L"Open &Saved Session");
        AppendMenuW(fileMenu, MF_STRING, IDM_FILE_ARGUMENTS, L"Open with &Arguments...\tCtrl+Shift+N");
        AppendMenuW(fileMenu, MF_SEPARATOR, 0, nullptr);
        AppendMenuW(fileMenu, MF_STRING, IDM_FILE_DUPLICATE, L"&Duplicate Session\tCtrl+Shift+D");
        AppendMenuW(fileMenu, MF_STRING, IDM_FILE_CLOSE, L"&Close Tab\tCtrl+Shift+W");
        AppendMenuW(fileMenu, MF_STRING, IDM_FILE_CLOSE_OTHERS, L"Close &Other Tabs");
        AppendMenuW(fileMenu, MF_STRING, IDM_FILE_CLOSE_ALL, L"Close A&ll Tabs");
        AppendMenuW(fileMenu, MF_SEPARATOR, 0, nullptr);
        AppendMenuW(fileMenu, MF_STRING, IDM_FILE_EXIT, L"E&xit");

        AppendMenuW(sessionMenu, MF_STRING, IDM_SESSION_LOG, L"&Event Log");
        AppendMenuW(sessionMenu, MF_STRING, IDM_SESSION_RECONFIGURE, L"Chan&ge Settings...");
        AppendMenuW(sessionMenu, MF_STRING, IDM_SESSION_RESTART, L"&Reconnect Session\tCtrl+Shift+R");
        AppendMenuW(sessionMenu, MF_SEPARATOR, 0, nullptr);
        AppendMenuW(sessionMenu, MF_STRING, IDM_SESSION_RENAME, L"Re&name Tab...");
        AppendMenuW(sessionMenu, MF_STRING, IDM_SESSION_RESET_NAME, L"Reset Tab Na&me");
        AppendMenuW(sessionMenu, MF_STRING, IDM_SESSION_LOCK, L"Loc&k Tab");
        AppendMenuW(sessionMenu, MF_STRING, IDM_SESSION_MOVE_LEFT, L"Move Tab Le&ft\tCtrl+Shift+PgUp");
        AppendMenuW(sessionMenu, MF_STRING, IDM_SESSION_MOVE_RIGHT, L"Move Tab R&ight\tCtrl+Shift+PgDn");
        AppendMenuW(sessionMenu, MF_SEPARATOR, 0, nullptr);
        AppendMenuW(sessionMenu, MF_STRING, IDM_SESSION_COPY, L"&Copy");
        AppendMenuW(sessionMenu, MF_STRING, IDM_SESSION_PASTE, L"&Paste");
        AppendMenuW(sessionMenu, MF_STRING, IDM_SESSION_COPY_ALL, L"C&opy All to Clipboard");
        AppendMenuW(sessionMenu, MF_STRING, IDM_SESSION_CLEAR_SCROLLBACK, L"C&lear Scrollback");
        AppendMenuW(sessionMenu, MF_STRING, IDM_SESSION_RESET, L"Rese&t Terminal");
        AppendMenuW(sessionMenu, MF_SEPARATOR, 0, nullptr);
        AppendMenuW(sessionMenu, MF_STRING, IDM_SESSION_HELP, L"PuTTY &Help");
        AppendMenuW(sessionMenu, MF_STRING, IDM_SESSION_ABOUT, L"&About PuTTY");

        AppendMenuW(viewMenu, MF_STRING, IDM_VIEW_NEXT, L"&Next Tab\tCtrl+Tab");
        AppendMenuW(viewMenu, MF_STRING, IDM_VIEW_PREVIOUS, L"&Previous Tab\tCtrl+Shift+Tab");
        AppendMenuW(viewMenu, MF_SEPARATOR, 0, nullptr);
        AppendMenuW(viewMenu, MF_STRING, IDM_VIEW_ALWAYS_ON_TOP, L"Always on &Top");
        AppendMenuW(viewMenu, MF_STRING, IDM_VIEW_FULLSCREEN, L"&Full Screen\tF11");
        AppendMenuW(viewMenu, MF_STRING, IDM_VIEW_STATUS_BAR, L"&Status Bar");
        AppendMenuW(viewMenu, MF_STRING, IDM_VIEW_CONNECT_BAR, L"&Connect Bar\tAlt+R");

        if (!AppendTopMenu(menu_, fileMenu, L"&File") || !AppendTopMenu(menu_, sessionMenu, L"&Session") ||
            !AppendTopMenu(menu_, viewMenu, L"&View"))
            return false;
        SetMenu(frame_, menu_);

        // Create the connect bar, tab host, terminal page, status bar, and fullscreen control.
        DWORD connectStyle = WS_CHILD | (connectBarVisible_ ? WS_VISIBLE : 0);
        connectLabel_ = CreateWindowExW(0, L"STATIC", L"Session or host:", connectStyle | SS_CENTERIMAGE, 0, 0, 0, 0,
            frame_, nullptr, instance_, nullptr);
        connectCombo_ = CreateWindowExW(0, WC_COMBOBOXW, L"", connectStyle | WS_TABSTOP | WS_VSCROLL | CBS_DROPDOWN |
            CBS_AUTOHSCROLL,
            0, 0, 0, 0, frame_,
            reinterpret_cast<HMENU>(static_cast<UINT_PTR>(IDC_CONNECT_SESSION)), instance_, nullptr);
        connectButton_ = CreateWindowExW(0, L"BUTTON", L"&Connect", connectStyle | WS_TABSTOP | BS_PUSHBUTTON, 0, 0,
            0, 0, frame_, reinterpret_cast<HMENU>(static_cast<UINT_PTR>(IDC_CONNECT_BUTTON)), instance_, nullptr);
        tabs_ = CreateWindowExW(0, WC_TABCONTROLW, L"", WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS | TCS_TOOLTIPS, 0, 0, 0,
            0, frame_, nullptr, instance_, nullptr);
        page_ = CreateWindowExW(0, L"STATIC", L"", WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN | WS_CLIPSIBLINGS, 0, 0, 0,
            0, frame_, nullptr, instance_, nullptr);
        scrollbar_ = CreateWindowExW(0, L"SCROLLBAR", L"", WS_CHILD | WS_CLIPSIBLINGS | SBS_VERT, 0, 0, 0, 0, frame_,
            nullptr, instance_, nullptr);
        status_ =
            CreateWindowExW(0, STATUSCLASSNAMEW, L"", WS_CHILD | SBARS_SIZEGRIP | (statusVisible_ ? WS_VISIBLE : 0), 0,
            0, 0, 0, frame_, nullptr, instance_, nullptr);
        fullscreenExit_ =
            CreateWindowExW(WS_EX_TOPMOST, L"BUTTON", L"Exit Full Screen", WS_CHILD | BS_PUSHBUTTON, 0, 0, 0, 0, frame_,
            reinterpret_cast<HMENU>(static_cast<UINT_PTR>(IDM_VIEW_FULLSCREEN)), instance_, nullptr);
        COMBOBOXINFO comboInfo{sizeof(comboInfo)};
        if (connectCombo_) GetComboBoxInfo(connectCombo_, &comboInfo);
        connectEdit_ = comboInfo.hwndItem;
        connectList_ = comboInfo.hwndList;
        if (!connectLabel_ || !connectCombo_ || !connectEdit_ || !connectList_ || !connectButton_ || !tabs_ || !page_ ||
            !scrollbar_ || !status_ || !fullscreenExit_)
            return false;
        if (!SetWindowSubclass(tabs_, TabProc, TabHostSubclass, reinterpret_cast<DWORD_PTR>(this)) ||
            !SetWindowSubclass(connectEdit_, ConnectProc, ConnectBarSubclass, reinterpret_cast<DWORD_PTR>(this)))
            return false;

        HFONT font = reinterpret_cast<HFONT>(GetStockObject(DEFAULT_GUI_FONT));
        for (HWND control : {connectLabel_, connectCombo_, connectButton_, tabs_})
            SendMessageW(control, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
        SendMessageW(status_, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
        SendMessageW(fullscreenExit_, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
        UpdateTabMetrics();
        theme::ApplyWindowTree(frame_);
        HWND tabTooltips = TabCtrl_GetToolTips(tabs_);
        SetWindowLongPtrW(tabTooltips, GWL_STYLE, GetWindowLongPtrW(tabTooltips, GWL_STYLE) | TTS_NOPREFIX);
        theme::ApplyControl(tabTooltips);
        theme::ApplyControl(connectList_);
        SendMessageW(tabTooltips, TTM_SETMAXTIPWIDTH, 0,
            MulDiv(640, GetDpiForWindow(tabs_), USER_DEFAULT_SCREEN_DPI));
        theme::ApplyMenuBar(frame_, menu_);
        RebuildSavedSessionsMenu();
        UpdateStatus();
        return true;
    }

    void HandleCommand(UINT command)
    {
        // Resolve dynamic saved-session commands before dispatching fixed menu actions.
        if (command >= IDM_SAVED_SESSION_FIRST && command <= IDM_SAVED_SESSION_LAST)
        {
            size_t index = command - IDM_SAVED_SESSION_FIRST;
            if (index < savedSessions_.size()) Launch(L"-load " + QuoteArgument(savedSessions_[index]));
            return;
        }

        // Dispatch host actions and commands forwarded to the active PuTTY process.
        switch (command)
        {
        case IDM_FILE_NEW: Launch({}); break;
        case IDM_FILE_ARGUMENTS:
        {
            std::wstring arguments;
            if (DialogBoxParamW(instance_, MAKEINTRESOURCEW(IDD_COMMAND_LINE), frame_, TextDialogProc,
                reinterpret_cast<LPARAM>(&arguments)) == IDOK)
                Launch(arguments);
            break;
        }
        case IDM_FILE_DUPLICATE: ForwardToPutty(PuttyDuplicateSession); break;
        case IDM_FILE_CLOSE: RequestClose(CurrentIndex()); break;
        case IDM_FILE_CLOSE_OTHERS:
        {
            size_t current = CurrentIndex();
            for (size_t index = 0; index < sessions_.size(); ++index)
                if (index != current) RequestClose(index);
            break;
        }
        case IDM_FILE_CLOSE_ALL: RequestCloseAll(); break;
        case IDM_FILE_EXIT: BeginExit(); break;
        case IDM_SESSION_LOG: ForwardToPutty(PuttyShowLog); break;
        case IDM_SESSION_RECONFIGURE: ForwardToPutty(PuttyReconfigure); break;
        case IDM_SESSION_RESTART:
            if (Session *session = CurrentSession(); session && IsDisconnectedTerminal(*session))
                ForwardToPutty(PuttyRestart);
            break;
        case IDM_SESSION_RENAME: RenameCurrentSession(); break;
        case IDM_SESSION_RESET_NAME:
        {
            // Restore the current tab to PuTTY's most recently observed title.
            size_t index = CurrentIndex();
            if (index < sessions_.size())
            {
                sessions_[index].customTitle.clear();
                SetSessionTitle(index, sessions_[index].detectedTitle);
            }
            break;
        }
        case IDM_SESSION_LOCK:
            if (Session *session = CurrentSession()) session->locked = !session->locked;
            UpdateStatus();
            break;
        case IDM_SESSION_MOVE_LEFT: MoveCurrentSession(-1); break;
        case IDM_SESSION_MOVE_RIGHT: MoveCurrentSession(1); break;
        case IDM_SESSION_COPY: ForwardToPutty(PuttyCopy); break;
        case IDM_SESSION_PASTE: ForwardToPutty(PuttyPaste); break;
        case IDM_SESSION_COPY_ALL: ForwardToPutty(PuttyCopyAll); break;
        case IDM_SESSION_CLEAR_SCROLLBACK: ForwardToPutty(PuttyClearScrollback); break;
        case IDM_SESSION_RESET: ForwardToPutty(PuttyReset); break;
        case IDM_SESSION_HELP: ForwardToPutty(PuttyHelp); break;
        case IDM_SESSION_ABOUT: ForwardToPutty(PuttyAbout); break;
        case IDM_VIEW_NEXT: CycleSession(1); break;
        case IDM_VIEW_PREVIOUS: CycleSession(-1); break;
        case IDM_VIEW_ALWAYS_ON_TOP:
        {
            bool enabled = !alwaysOnTop_;
            if (SetWindowPos(frame_, enabled ? HWND_TOPMOST : HWND_NOTOPMOST, 0, 0, 0, 0,
                SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE))
            {
                alwaysOnTop_ = enabled;
                WriteBooleanSetting(AlwaysOnTopSetting, enabled);
            }
            break;
        }
        case IDM_VIEW_FULLSCREEN: ToggleFullscreen(); break;
        case IDM_VIEW_STATUS_BAR:
            statusVisible_ = !statusVisible_;
            ShowWindow(status_, statusVisible_ && !fullscreen_ ? SW_SHOW : SW_HIDE);
            Layout();
            WriteBooleanSetting(StatusBarVisibleSetting, statusVisible_);
            break;
        case IDM_VIEW_CONNECT_BAR:
            connectBarVisible_ = !connectBarVisible_;
            ShowConnectBar(connectBarVisible_);
            WriteBooleanSetting(ConnectBarVisibleSetting, connectBarVisible_);
            break;
        }
        UpdateMenuState();
    }

    LRESULT HandleNotification(const NMHDR &notification)
    {
        // Supply unclipped live titles and state for tab tooltips.
        if (notification.hwndFrom == TabCtrl_GetToolTips(tabs_) && notification.code == TTN_GETDISPINFOW)
        {
            size_t index = notification.idFrom;
            if (index >= sessions_.size()) return 0;
            const Session &session = sessions_[index];
            tooltipText_ = session.title;
            if (!session.customTitle.empty() && session.detectedTitle != session.customTitle)
                tooltipText_ += L"\nPuTTY title: " + session.detectedTitle;
            if (session.locked) tooltipText_ += L"\nLocked against accidental closure";
            reinterpret_cast<NMTTDISPINFOW *>(const_cast<NMHDR *>(&notification))->lpszText = tooltipText_.data();
            return 0;
        }

        // React to tab selection and pointer context-menu notifications.
        if (notification.hwndFrom != tabs_) return 0;
        if (notification.code == TCN_SELCHANGE) ActivateSession(CurrentIndex());
        else if (notification.code == NM_RCLICK)
        {
            POINT point{};
            GetCursorPos(&point);
            ShowTabContextMenu(point.x, point.y);
            return 1;
        }
        return 0;
    }

    void ShowTabContextMenu(int x, int y)
    {
        // Position keyboard menus predictably or activate the tab beneath a pointer invocation.
        if (x == -1 && y == -1)
        {
            RECT rectangle{};
            GetWindowRect(tabs_, &rectangle);
            x = rectangle.left + 24;
            y = rectangle.top + 24;
        }
        else
        {
            POINT point{x, y};
            ScreenToClient(tabs_, &point);
            TCHITTESTINFO hit{point};
            int tab = TabCtrl_HitTest(tabs_, &hit);
            if (tab >= 0) ActivateSession(static_cast<size_t>(tab), false);
        }

        // Build a transient menu whose availability reflects the selected session.
        HMENU menu = CreatePopupMenu();
        AppendMenuW(menu, MF_STRING, IDM_FILE_NEW, L"New Session");
        AppendMenuW(menu, MF_STRING, IDM_FILE_DUPLICATE, L"Duplicate Session");
        AppendMenuW(menu, MF_STRING, IDM_SESSION_RESTART, L"Reconnect Session");
        AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
        AppendMenuW(menu, MF_STRING, IDM_SESSION_RENAME, L"Rename Tab...");
        AppendMenuW(menu, MF_STRING, IDM_SESSION_RESET_NAME, L"Reset Tab Name");
        AppendMenuW(menu, MF_STRING, IDM_SESSION_LOCK, L"Lock Tab");
        AppendMenuW(menu, MF_STRING, IDM_SESSION_MOVE_LEFT, L"Move Tab Left");
        AppendMenuW(menu, MF_STRING, IDM_SESSION_MOVE_RIGHT, L"Move Tab Right");
        AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
        AppendMenuW(menu, MF_STRING, IDM_FILE_CLOSE, L"Close Tab");
        AppendMenuW(menu, MF_STRING, IDM_FILE_CLOSE_OTHERS, L"Close Other Tabs");
        Session *session = CurrentSession();
        UINT hasSession = session ? MF_ENABLED : MF_GRAYED;
        UINT hasTerminal = session && IsSessionTerminal(*session) ? MF_ENABLED : MF_GRAYED;
        UINT canReconnect = session && IsDisconnectedTerminal(*session) ? MF_ENABLED : MF_GRAYED;
        UINT hasUnlockedSession = session && !session->locked ? MF_ENABLED : MF_GRAYED;
        size_t current = CurrentIndex();
        DWORD targetProcess = session ? session->processId : 0;
        bool hasUnlockedOther = std::ranges::any_of(sessions_, [session](const Session &candidate)
            { return &candidate != session && !candidate.locked; });
        EnableMenuItem(menu, IDM_FILE_DUPLICATE, MF_BYCOMMAND | hasTerminal);
        EnableMenuItem(menu, IDM_SESSION_RESTART, MF_BYCOMMAND | canReconnect);
        EnableMenuItem(menu, IDM_SESSION_RENAME, MF_BYCOMMAND | hasSession);
        EnableMenuItem(menu, IDM_SESSION_RESET_NAME,
            MF_BYCOMMAND | (session && !session->customTitle.empty() ? MF_ENABLED : MF_GRAYED));
        EnableMenuItem(menu, IDM_SESSION_LOCK, MF_BYCOMMAND | hasSession);
        EnableMenuItem(menu, IDM_SESSION_MOVE_LEFT, MF_BYCOMMAND | (current > 0 ? MF_ENABLED : MF_GRAYED));
        EnableMenuItem(menu, IDM_SESSION_MOVE_RIGHT,
            MF_BYCOMMAND | (current + 1 < sessions_.size() ? MF_ENABLED : MF_GRAYED));
        EnableMenuItem(menu, IDM_FILE_CLOSE, MF_BYCOMMAND | hasUnlockedSession);
        EnableMenuItem(menu, IDM_FILE_CLOSE_OTHERS, MF_BYCOMMAND | (hasUnlockedOther ? MF_ENABLED : MF_GRAYED));
        CheckMenuItem(menu, IDM_SESSION_LOCK, MF_BYCOMMAND | (session && session->locked ? MF_CHECKED : MF_UNCHECKED));
        UINT command = TrackPopupMenu(menu, TPM_RETURNCMD | TPM_RIGHTBUTTON, x, y, 0, frame_, nullptr);
        DestroyMenu(menu);
        if (command && command != IDM_FILE_NEW)
        {
            size_t index = SessionIndex(targetProcess);
            if (index < sessions_.size())
                ActivateSession(index, false);
            else command = 0;
        }
        if (command) HandleCommand(command);
        FocusCurrentSession();
    }

    LRESULT HandleTabMessage(HWND window, UINT message, WPARAM wParam, LPARAM lParam)
    {
        // Track pointer gestures for native tab selection, drag ordering, and middle-click closure.
        if (message == WM_LBUTTONDOWN)
        {
            LRESULT result = DefSubclassProc(window, message, wParam, lParam);
            POINT point{GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam)};
            TCHITTESTINFO hit{point};
            int tab = TabCtrl_HitTest(window, &hit);
            draggedProcess_ = tab >= 0 ? sessions_[tab].processId : 0;
            dragOrigin_ = point;
            draggingTab_ = false;
            return result;
        }
        if (message == WM_LBUTTONDBLCLK)
        {
            POINT point{GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam)};
            TCHITTESTINFO hit{point};
            int tab = TabCtrl_HitTest(window, &hit);
            if (tab >= 0)
            {
                ActivateSession(static_cast<size_t>(tab), false);
                RenameCurrentSession();
            }
            else Launch({});
            return 0;
        }
        if (message == WM_MOUSEMOVE && draggedProcess_ && (wParam & MK_LBUTTON))
        {
            POINT point{GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam)};
            if (!draggingTab_)
            {
                UINT dpi = GetDpiForWindow(window);
                int horizontal = GetSystemMetricsForDpi(SM_CXDRAG, dpi);
                int vertical = GetSystemMetricsForDpi(SM_CYDRAG, dpi);
                if (point.x >= dragOrigin_.x - horizontal && point.x <= dragOrigin_.x + horizontal &&
                    point.y >= dragOrigin_.y - vertical && point.y <= dragOrigin_.y + vertical)
                    return DefSubclassProc(window, message, wParam, lParam);
                draggingTab_ = true;
                SetCapture(window);
            }

            TCHITTESTINFO hit{point};
            int target = TabCtrl_HitTest(window, &hit);
            size_t from = SessionIndex(draggedProcess_);
            if (from >= sessions_.size())
            {
                if (GetCapture() == window) ReleaseCapture();
                draggedProcess_ = 0;
                draggingTab_ = false;
                return 0;
            }
            if (target >= 0 && static_cast<size_t>(target) != from) MoveSession(from, static_cast<size_t>(target));
            return 0;
        }
        if (message == WM_LBUTTONUP)
        {
            if (draggingTab_ && GetCapture() == window) ReleaseCapture();
            draggedProcess_ = 0;
            draggingTab_ = false;
        }
        else if (message == WM_CAPTURECHANGED)
        {
            draggedProcess_ = 0;
            draggingTab_ = false;
        }
        else if (message == WM_MBUTTONUP)
        {
            POINT point{GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam)};
            TCHITTESTINFO hit{point};
            int tab = TabCtrl_HitTest(window, &hit);
            if (tab >= 0) RequestClose(static_cast<size_t>(tab));
            return 0;
        }
        return DefSubclassProc(window, message, wParam, lParam);
    }

    LRESULT HandleConnectMessage(HWND window, UINT message, WPARAM wParam, LPARAM lParam)
    {
        // Make Enter connect and Escape return directly to the active terminal.
        if (message == WM_KEYDOWN && wParam == VK_RETURN)
        {
            if (lParam & (1LL << 30)) return 0;
            ComboBox_ShowDropdown(connectCombo_, FALSE);
            PostMessageW(frame_, WM_COMMAND, MAKEWPARAM(IDC_CONNECT_BUTTON, BN_CLICKED),
                reinterpret_cast<LPARAM>(connectButton_));
            return 0;
        }
        if (message == WM_KEYDOWN && wParam == VK_ESCAPE)
        {
            if (lParam & (1LL << 30)) return 0;
            if (ComboBox_GetDroppedState(connectCombo_)) ComboBox_ShowDropdown(connectCombo_, FALSE);
            else FocusCurrentSession();
            return 0;
        }
        if (message == WM_CHAR && (wParam == L'\r' || wParam == L'\x1B')) return 0;
        return DefSubclassProc(window, message, wParam, lParam);
    }

    void AutoCompleteConnectBar()
    {
        // Complete typed prefixes from the portable-aware saved-session list.
        if (autocompletingConnectBar_) return;
        std::wstring typed = WindowText(connectCombo_);
        if (typed.empty()) return;
        DWORD selection = static_cast<DWORD>(SendMessageW(connectCombo_, CB_GETEDITSEL, 0, 0));
        if (LOWORD(selection) != HIWORD(selection)) return;
        auto match = std::ranges::find_if(savedSessions_, [&typed](const std::wstring &candidate)
            {
                return candidate.size() >= typed.size() &&
                    _wcsnicmp(candidate.c_str(), typed.c_str(), typed.size()) == 0;
            });
        if (match == savedSessions_.end() || match->size() == typed.size()) return;
        autocompletingConnectBar_ = true;
        SetWindowTextW(connectCombo_, match->c_str());
        SendMessageW(connectCombo_, CB_SETEDITSEL, 0, MAKELPARAM(typed.size(), match->size()));
        autocompletingConnectBar_ = false;
    }

    void ConnectFromBar()
    {
        // Resolve an exact saved-session name or pass a direct host to PuTTY.
        std::wstring value = WindowText(connectCombo_);
        auto saved = std::ranges::find_if(savedSessions_, [&value](const std::wstring &candidate)
            { return _wcsicmp(candidate.c_str(), value.c_str()) == 0; });
        std::wstring arguments;
        if (saved != savedSessions_.end()) arguments = L"-load " + QuoteArgument(*saved);
        else
        {
            size_t first = value.find_first_not_of(L" \t\r\n");
            if (first == std::wstring::npos)
            {
                MessageBeep(MB_ICONINFORMATION);
                return;
            }
            value.erase(0, first);
            value.erase(value.find_last_not_of(L" \t\r\n") + 1);
            arguments = value.starts_with(L'-') ? value : QuoteArgument(value);
        }
        SetWindowTextW(connectCombo_, L"");
        ComboBox_ShowDropdown(connectCombo_, FALSE);
        Launch(arguments);
    }

    void ShowConnectBar(bool visible)
    {
        // Show or hide the complete connect-bar row and preserve terminal focus when hiding it.
        HWND focus = GetFocus();
        for (HWND control : {connectLabel_, connectCombo_, connectButton_})
            ShowWindow(control, visible && !fullscreen_ ? SW_SHOW : SW_HIDE);
        Layout();
        if (!visible && (focus == connectCombo_ || IsChild(connectCombo_, focus) || focus == connectButton_))
            FocusCurrentSession();
    }

    void FocusConnectBar()
    {
        // Reveal and focus the connect bar from SecureCRT's familiar Alt+R shortcut.
        if (fullscreen_) ToggleFullscreen();
        if (!connectBarVisible_)
        {
            connectBarVisible_ = true;
            ShowConnectBar(true);
            WriteBooleanSetting(ConnectBarVisibleSetting, true);
        }
        SetForegroundWindow(frame_);
        SetFocus(connectCombo_);
        SendMessageW(connectCombo_, CB_SETEDITSEL, 0, MAKELPARAM(0, -1));
        ComboBox_ShowDropdown(connectCombo_, TRUE);
    }

    void RenameCurrentSession()
    {
        // Edit a host-owned alias without losing PuTTY's live terminal title.
        Session *session = CurrentSession();
        if (!session) return;
        DWORD processId = session->processId;
        std::wstring name = session->customTitle.empty() ? session->title : session->customTitle;
        INT_PTR result = DialogBoxParamW(instance_, MAKEINTRESOURCEW(IDD_RENAME_TAB), frame_, TextDialogProc,
            reinterpret_cast<LPARAM>(&name));
        size_t index = SessionIndex(processId);
        if (index >= sessions_.size()) return;
        if (result != IDOK)
        {
            ActivateSession(index);
            return;
        }
        sessions_[index].customTitle = name;
        SetSessionTitle(index, name.empty() ? sessions_[index].detectedTitle : name);
        UpdateMenuState();
        ActivateSession(index);
    }

    void MoveCurrentSession(int direction)
    {
        size_t current = CurrentIndex();
        if (current >= sessions_.size()) return;
        if (direction < 0 && current > 0) MoveSession(current, current - 1);
        else if (direction > 0 && current + 1 < sessions_.size()) MoveSession(current, current + 1);
    }

    void MoveSession(size_t from, size_t to)
    {
        // Reorder the tab model while keeping the selected terminal process active.
        if (from >= sessions_.size() || to >= sessions_.size() || from == to) return;
        Session *active = CurrentSession();
        DWORD activeProcess = active ? active->processId : 0;
        if (from < to)
            std::ranges::rotate(sessions_.begin() + from, sessions_.begin() + from + 1, sessions_.begin() + to + 1);
        else
            std::ranges::rotate(sessions_.begin() + to, sessions_.begin() + from, sessions_.begin() + from + 1);

        // Refresh only the tab labels affected by the move.
        size_t first = std::min(from, to);
        size_t last = std::max(from, to);
        for (size_t index = first; index <= last; ++index)
        {
            TCITEMW item{};
            item.mask = TCIF_TEXT;
            item.pszText = sessions_[index].title.data();
            TabCtrl_SetItem(tabs_, static_cast<int>(index), &item);
        }
        size_t selected = activeProcess ? SessionIndex(activeProcess) : to;
        TabCtrl_SetCurSel(tabs_, static_cast<int>(selected));
        LayoutChildren();
        SetSessionTitle(selected, sessions_[selected].title);
        UpdateStatus();
        UpdateMenuState();
    }

    void Launch(const std::wstring &arguments)
    {
        // Resolve and quote the sibling PuTTY executable with caller-supplied arguments.
        DWORD attributes = GetFileAttributesW(puttyPath_.c_str());
        if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_DIRECTORY))
        {
            std::wstring message = L"PuTTYTab could not find its sibling executable:\n\n" + puttyPath_;
            MessageBoxW(frame_, message.c_str(), WindowTitle, MB_OK | MB_ICONERROR);
            return;
        }
        std::wstring commandLine = QuoteArgument(puttyPath_);
        if (!arguments.empty()) commandLine += L" " + arguments;
        std::vector<wchar_t> mutableCommand(commandLine.begin(), commandLine.end());
        mutableCommand.push_back(L'\0');

        // Start PuTTY suspended so it can join the session-tracking job before executing.
        STARTUPINFOW startup{sizeof(startup)};
        PROCESS_INFORMATION processInfo{};
        if (!CreateProcessW(puttyPath_.c_str(), mutableCommand.data(), nullptr, nullptr, FALSE,
            CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT, nullptr, puttyDirectory_.c_str(), &startup, &processInfo))
        {
            MessageBoxW(frame_, ErrorText(L"Starting putty.exe").c_str(), WindowTitle, MB_OK | MB_ICONERROR);
            return;
        }

        UniqueHandle process(processInfo.hProcess);
        UniqueHandle thread(processInfo.hThread);
        if (job_ && !AssignProcessToJobObject(job_.get(), processInfo.hProcess))
        {
            job_.reset();
            MessageBoxW(frame_,
                L"Automatic tracking of sessions duplicated by PuTTY is unavailable. Those "
                L"sessions may open in separate windows.", WindowTitle, MB_OK | MB_ICONWARNING);
        }

        if (ResumeThread(processInfo.hThread) == static_cast<DWORD>(-1))
        {
            MessageBoxW(frame_, ErrorText(L"Starting putty.exe").c_str(), WindowTitle, MB_OK | MB_ICONERROR);
            TerminateProcess(processInfo.hProcess, ERROR_PROCESS_ABORTED);
            return;
        }

        AddSession(processInfo.dwProcessId, std::move(process));
    }

    void AddSession(DWORD processId, UniqueHandle process)
    {
        // Add a tracked PuTTY process to the tab model and activate it.
        if (SessionIndex(processId) != sessions_.size()) return;
        Session session{.processId = processId, .process = std::move(process), .closing = exiting_};

        TCITEMW item{};
        item.mask = TCIF_TEXT;
        item.pszText = session.title.data();
        int index = TabCtrl_InsertItem(tabs_, static_cast<int>(sessions_.size()), &item);
        if (index < 0) return;
        sessions_.push_back(std::move(session));
        Layout();
        ActivateSession(sessions_.size() - 1);
        UpdateStatus();
    }

    void AdoptJobProcesses()
    {
        if (!job_) return;

        // Adopt PuTTY-created sibling processes from the job as new tabs.
        std::vector<BYTE> buffer(sizeof(JOBOBJECT_BASIC_PROCESS_ID_LIST) + sizeof(ULONG_PTR) * 1024);
        auto *processes = reinterpret_cast<JOBOBJECT_BASIC_PROCESS_ID_LIST *>(buffer.data());
        if (!QueryInformationJobObject(job_.get(), JobObjectBasicProcessIdList, processes,
            static_cast<DWORD>(buffer.size()), nullptr))
            return;
        for (DWORD index = 0; index < processes->NumberOfProcessIdsInList; ++index)
        {
            DWORD processId = static_cast<DWORD>(processes->ProcessIdList[index]);
            if (processId == GetCurrentProcessId() || SessionIndex(processId) != sessions_.size()) continue;

            UniqueHandle process(OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId));
            if (!process) continue;

            wchar_t imagePath[32768]{};
            DWORD length = static_cast<DWORD>(std::size(imagePath));
            if (!QueryFullProcessImageNameW(process.get(), 0, imagePath, &length) ||
                _wcsicmp(imagePath, puttyPath_.c_str()) != 0)
                continue;

            AddSession(processId, std::move(process));
        }
    }

    void PollSessions()
    {
        AdoptJobProcesses();
        std::vector<size_t> finished;
        bool exitCancelled = false;

        // Refresh each tracked PuTTY process, dialog, terminal, and tab title.
        for (size_t index = 0; index < sessions_.size(); ++index)
        {
            Session &session = sessions_[index];
            DWORD exitCode = 0;
            if (!GetExitCodeProcess(session.process.get(), &exitCode) || exitCode != STILL_ACTIVE)
            {
                finished.push_back(index);
                continue;
            }

            if (session.terminal && !IsSessionTerminal(session))
            {
                session.terminal = nullptr;
                session.attached = false;
                session.hasScrollbar = false;
                session.scrollbarMissingSince = 0;
            }
            ProcessWindows windows = WindowsForProcess(session.processId);
            if (!session.terminal && windows.terminal)
            {
                session.terminal = windows.terminal;
                if (session.closing && PostMessageW(session.terminal, WM_CLOSE, 0, 0))
                    session.closeRequestedAt = GetTickCount64();
            }
            if (!session.closing && session.terminal && !session.attached && !session.attachFailed &&
                IsWindowVisible(session.terminal) && !IsHungAppWindow(session.terminal))
                Attach(session);

            bool terminalEnabled = session.terminal && IsWindowEnabled(session.terminal);
            if (session.closing && session.terminal && !terminalEnabled) session.closeBlocked = true;
            if (session.closing && !session.terminal && !session.closeRequestedAt && windows.visible &&
                PostMessageW(windows.visible, WM_CLOSE, 0, 0))
                session.closeRequestedAt = GetTickCount64();
            bool closeCancelled =
                session.closing && terminalEnabled && session.closeRequestedAt &&
                (session.closeBlocked || GetTickCount64() - session.closeRequestedAt >= CloseRequestTimeout);
            if (closeCancelled)
            {
                session.closing = false;
                session.closeBlocked = false;
                session.closeRequestedAt = 0;
                exitCancelled = true;
            }
            HWND titledWindow = session.terminal ? session.terminal : windows.dialog ? windows.dialog : windows.visible;
            if (titledWindow)
            {
                std::wstring title = WindowText(titledWindow);
                if (!title.empty() && title != session.detectedTitle) SetDetectedTitle(index, title);
            }

            if (windows.dialog && GetForegroundWindow() == windows.dialog && index != CurrentIndex())
                ActivateSession(index, false);
            if (session.attached) EnsureEmbedded(session);
        }

        // Remove completed sessions and resolve any pending host exit.
        for (auto iterator = finished.rbegin(); iterator != finished.rend(); ++iterator) RemoveSession(*iterator);
        if (exitCancelled) exiting_ = false;
        if (exiting_ && sessions_.empty()) DestroyWindow(frame_);
        else
        {
            SyncScrollbar();
            UpdateStatus();
        }
    }

    bool Attach(Session &session)
    {
        // Preserve focus when the host or PuTTY currently owns user interaction.
        HWND foreground = GetForegroundWindow();
        DWORD foregroundProcess = 0;
        if (foreground) GetWindowThreadProcessId(foreground, &foregroundProcess);
        bool restoreFocus = foreground && (foreground == frame_ || IsChild(frame_, foreground) ||
            foregroundProcess == session.processId);
        // Hide the native frame before reparenting can expose it.
        ShowWindow(session.terminal, SW_HIDE);

        // Preserve enough top-level state to detach PuTTY safely if the host exits.
        GetWindowRect(session.terminal, &session.originalRect);
        session.originalStyle = GetWindowLongPtrW(session.terminal, GWL_STYLE);
        session.originalExtendedStyle = GetWindowLongPtrW(session.terminal, GWL_EXSTYLE);
        session.hasScrollbar = HasVisibleScrollbar(session.terminal);
        session.scrollbarMissingSince = 0;
        LONG_PTR style = (session.originalStyle & ~WS_POPUP) | WS_CHILD | WS_CLIPSIBLINGS;
        LONG_PTR extendedStyle = session.originalExtendedStyle & ~(WS_EX_APPWINDOW | WS_EX_TOPMOST);
        bool stylesChanged = SetWindowLongPtrValue(session.terminal, GWL_STYLE, style) &&
            SetWindowLongPtrValue(session.terminal, GWL_EXSTYLE, extendedStyle);
        SetLastError(ERROR_SUCCESS);
        HWND previousParent = stylesChanged ? SetParent(session.terminal, page_) : nullptr;
        if (!stylesChanged || (!previousParent && GetLastError() != ERROR_SUCCESS))
        {
            SetWindowLongPtrW(session.terminal, GWL_STYLE, session.originalStyle);
            SetWindowLongPtrW(session.terminal, GWL_EXSTYLE, session.originalExtendedStyle);
            session.hasScrollbar = false;
            session.scrollbarMissingSince = 0;
            session.attachFailed = true;
            ShowWindowAsync(session.terminal, SW_SHOW);
            SetDetectedTitle(SessionIndex(session.processId), WindowText(session.terminal) + L" (separate window)");
            return false;
        }
        session.originalParent = previousParent;
        session.attached = true;
        Layout(true);
        if (CurrentSession() == &session && restoreFocus) FocusCurrentSession();
        return true;
    }

    void EnsureEmbedded(Session &session)
    {
        // Correct PuTTY scrollbar, maximize, visibility, and geometry drift while embedded.
        if (!session.attached || !IsSessionTerminal(session)) return;
        bool hasScrollbar = HasVisibleScrollbar(session.terminal);
        ULONGLONG now = GetTickCount64();
        // Keep the proxy through transient style changes while PuTTY rebuilds its non-client scrollbar.
        if (hasScrollbar) session.scrollbarMissingSince = 0;
        else if (session.hasScrollbar && !session.scrollbarMissingSince) session.scrollbarMissingSince = now;
        if (!hasScrollbar && session.hasScrollbar && now - session.scrollbarMissingSince < ScrollbarHideDelay)
            hasScrollbar = true;
        if (session.hasScrollbar != hasScrollbar)
        {
            session.hasScrollbar = hasScrollbar;
            if (CurrentSession() == &session) Layout();
            return;
        }
        if (IsZoomed(session.terminal))
        {
            ShowWindowAsync(session.terminal, SW_RESTORE);
            return;
        }
        if (CurrentSession() == &session) PositionEmbedded(session, false);
        else if (IsWindowVisible(session.terminal)) ShowWindowAsync(session.terminal, SW_HIDE);
    }

    void PositionEmbedded(Session &session, bool bringToTop, bool refreshFrame = false,
        const SIZE *targetSize = nullptr)
    {
        // Match PuTTY's adjusted outer window bounds to the tab page.
        RECT desired{}, windowRect{};
        if (targetSize)
        {
            desired.right = targetSize->cx;
            desired.bottom = targetSize->cy;
        }
        else if (!GetClientRect(page_, &desired)) return;
        if (!GetWindowRect(session.terminal, &windowRect)) return;
        UINT dpi = GetDpiForWindow(session.terminal);
        LONG_PTR style = GetWindowLongPtrW(session.terminal, GWL_STYLE);
        AdjustWindowRectExForDpi(&desired, static_cast<DWORD>(style), FALSE,
            static_cast<DWORD>(GetWindowLongPtrW(session.terminal, GWL_EXSTYLE)), dpi);
        if (session.hasScrollbar) desired.right += GetSystemMetricsForDpi(SM_CXVSCROLL, dpi);
        MapWindowPoints(nullptr, page_, reinterpret_cast<POINT *>(&windowRect), 2);
        bool moved = !EqualRect(&windowRect, &desired);
        if (moved && session.hasScrollbar) session.scrollbarMissingSince = 0;
        if (!moved && IsWindowVisible(session.terminal) && !bringToTop && !refreshFrame) return;
        UINT flags = SWP_NOACTIVATE | SWP_NOSENDCHANGING | SWP_SHOWWINDOW;
        if (!bringToTop) flags |= SWP_NOZORDER;
        if (refreshFrame) flags |= SWP_FRAMECHANGED;
        if (IsHungAppWindow(session.terminal)) flags |= SWP_ASYNCWINDOWPOS;
        SetWindowPos(session.terminal, bringToTop ? HWND_TOP : nullptr, desired.left, desired.top,
            desired.right - desired.left, desired.bottom - desired.top, flags);
    }

    bool Detach(Session &session)
    {
        if (!session.attached) return true;
        if (!IsSessionTerminal(session))
        {
            session.attached = false;
            return true;
        }

        // Restore PuTTY's original parent, styles, and top-level placement as one transaction.
        ShowWindowAsync(session.terminal, SW_HIDE);
        SetLastError(ERROR_SUCCESS);
        HWND previousParent = SetParent(session.terminal, session.originalParent);
        if (!previousParent && GetLastError() != ERROR_SUCCESS)
        {
            ShowWindowAsync(session.terminal, SW_SHOW);
            return false;
        }
        constexpr LONG_PTR styleMask = WS_POPUP | WS_CHILD | WS_CLIPSIBLINGS;
        constexpr LONG_PTR extendedStyleMask = WS_EX_APPWINDOW | WS_EX_TOPMOST;
        LONG_PTR restoredStyle = GetWindowLongPtrW(session.terminal, GWL_STYLE) & ~styleMask;
        LONG_PTR restoredExtendedStyle = GetWindowLongPtrW(session.terminal, GWL_EXSTYLE) & ~extendedStyleMask;
        restoredStyle |= session.originalStyle & styleMask;
        restoredExtendedStyle |= session.originalExtendedStyle & extendedStyleMask;
        bool styleRestored = SetWindowLongPtrValue(session.terminal, GWL_STYLE, restoredStyle) &&
            SetWindowLongPtrValue(session.terminal, GWL_EXSTYLE, restoredExtendedStyle);
        bool positionRestored =
            SetWindowPos(session.terminal, nullptr, session.originalRect.left, session.originalRect.top,
            session.originalRect.right - session.originalRect.left,
            session.originalRect.bottom - session.originalRect.top,
            SWP_ASYNCWINDOWPOS | SWP_FRAMECHANGED | SWP_NOACTIVATE | SWP_NOZORDER) != FALSE;
        bool parentRestored = GetAncestor(session.terminal, GA_PARENT) == session.originalParent;
        bool valuesRestored =
            ((GetWindowLongPtrW(session.terminal, GWL_STYLE) ^ session.originalStyle) & styleMask) == 0 &&
            ((GetWindowLongPtrW(session.terminal, GWL_EXSTYLE) ^ session.originalExtendedStyle) & extendedStyleMask) ==
            0;
        if (!styleRestored || !positionRestored || !parentRestored || !valuesRestored)
        {
            // Re-embed the terminal if any part of restoration was incomplete.
            LONG_PTR style = (GetWindowLongPtrW(session.terminal, GWL_STYLE) & ~WS_POPUP) | WS_CHILD | WS_CLIPSIBLINGS;
            LONG_PTR extendedStyle =
                GetWindowLongPtrW(session.terminal, GWL_EXSTYLE) & ~(WS_EX_APPWINDOW | WS_EX_TOPMOST);
            bool rollbackStyle = SetWindowLongPtrValue(session.terminal, GWL_STYLE, style) &&
                SetWindowLongPtrValue(session.terminal, GWL_EXSTYLE, extendedStyle);
            SetLastError(ERROR_SUCCESS);
            SetParent(session.terminal, page_);
            bool rollbackParent = GetParent(session.terminal) == page_;
            bool rollbackValues = (GetWindowLongPtrW(session.terminal, GWL_STYLE) & WS_CHILD) != 0 &&
                (GetWindowLongPtrW(session.terminal, GWL_EXSTYLE) & extendedStyleMask) == 0;
            session.attached = rollbackStyle && rollbackParent && rollbackValues;
            if (session.attached) PositionEmbedded(session, true, true);
            else session.attachFailed = true;
            ShowWindowAsync(session.terminal, SW_SHOW);
            return false;
        }
        ShowWindowAsync(session.terminal, SW_SHOW);
        session.attached = false;
        return true;
    }

    bool DetachAll()
    {
        bool detached = true;
        for (auto &session : sessions_)
            if (!Detach(session)) detached = false;
        return detached;
    }

    void Layout(bool refreshFrame = false, const SIZE *targetSize = nullptr)
    {
        if (!frame_ || !tabs_ || !page_ || !status_) return;
        RECT client{};
        if (!targetSize && !GetClientRect(frame_, &client)) return;
        int width = targetSize ? targetSize->cx : client.right;
        int height = targetSize ? targetSize->cy : client.bottom;
        Session *session = CurrentSession();
        int scrollbarWidth = session && session->attached && session->hasScrollbar && IsSessionTerminal(*session)
            ? GetSystemMetricsForDpi(SM_CXVSCROLL, GetDpiForWindow(session->terminal)) : 0;
        if (!fullscreen_) ShowWindow(fullscreenExit_, SW_HIDE);

        // Apply each layout as one compositor-visible window-position transaction.
        std::array<WINDOWPOS, 6> placements{};
        size_t placementCount = 0;
        HDWP layout = BeginDeferWindowPos(6);
        auto move = [&](HWND window, int left, int top, int childWidth, int childHeight, bool reorder = false,
            HWND insertAfter = HWND_TOP)
        {
            UINT flags = SWP_NOACTIVATE | (reorder ? 0 : SWP_NOZORDER);
            placements[placementCount++] = {window, insertAfter, left, top, childWidth, childHeight, flags};
            if (layout)
                layout = DeferWindowPos(layout, window, insertAfter, left, top, childWidth, childHeight, flags);
        };
        // Reserve and preposition the proxy strip outside the clipped terminal page.
        auto moveScrollbar = [&](const RECT &page, HWND insertAfter)
        {
            if (!scrollbarWidth) return;
            move(scrollbar_, page.right, page.top, scrollbarWidth,
                std::max(0L, page.bottom - page.top), true, insertAfter);
        };
        auto commit = [&]()
        {
            if (layout && EndDeferWindowPos(layout)) return;
            for (size_t index = 0; index < placementCount; ++index)
            {
                const WINDOWPOS &position = placements[index];
                SetWindowPos(position.hwnd, position.hwndInsertAfter, position.x, position.y, position.cx, position.cy,
                    position.flags);
            }
        };
        // Resize the terminal before expanding its parent keeps the clipped native scrollbar outside the page.
        auto prepositionTerminal = [&](const RECT &page)
        {
            RECT current{};
            SIZE target{page.right - page.left, page.bottom - page.top};
            if (!session || !session->attached || !IsSessionTerminal(*session) ||
                !GetClientRect(page_, &current) || target.cx <= current.right)
                return false;
            PositionEmbedded(*session, false, refreshFrame, &target);
            return true;
        };

        // Give the terminal the fullscreen client area except for its host-owned scrollbar strip.
        if (fullscreen_)
        {
            RECT page{0, 0, std::max(0, width - scrollbarWidth), height};
            move(page_, page.left, page.top, page.right - page.left, page.bottom - page.top, true, scrollbar_);
            moveScrollbar(page, fullscreenExit_);
            move(fullscreenExit_, std::max(4, width - 120), 4, 116, 26, true);
            bool terminalPrepositioned = prepositionTerminal(page);
            commit();
            ShowWindow(fullscreenExit_, SW_SHOW);
            LayoutChildren(terminalPrepositioned ? false : refreshFrame);
            return;
        }

        // Lay out the optional connect bar, standard tab page, and multipart status bar.
        int statusHeight = 0;
        if (statusVisible_)
        {
            SendMessageW(status_, WM_SIZE, 0, 0);
            RECT statusRect{};
            GetWindowRect(status_, &statusRect);
            statusHeight = statusRect.bottom - statusRect.top;
        }
        UINT dpi = GetDpiForWindow(frame_);
        int connectHeight = connectBarVisible_ ? MulDiv(36, dpi, USER_DEFAULT_SCREEN_DPI) : 0;
        if (connectBarVisible_)
        {
            int gap = MulDiv(6, dpi, USER_DEFAULT_SCREEN_DPI);
            int labelWidth = MulDiv(96, dpi, USER_DEFAULT_SCREEN_DPI);
            int buttonWidth = MulDiv(76, dpi, USER_DEFAULT_SCREEN_DPI);
            int controlHeight = MulDiv(24, dpi, USER_DEFAULT_SCREEN_DPI);
            int comboLeft = gap + labelWidth;
            int comboWidth = std::max(MulDiv(80, dpi, USER_DEFAULT_SCREEN_DPI),
                width - comboLeft - buttonWidth - gap * 3);
            move(connectLabel_, gap, gap, labelWidth, controlHeight);
            move(connectCombo_, comboLeft, gap, comboWidth, MulDiv(240, dpi, USER_DEFAULT_SCREEN_DPI));
            move(connectButton_, comboLeft + comboWidth + gap, gap, buttonWidth, controlHeight);
        }
        int tabHeight = std::max(0, height - statusHeight - connectHeight);
        move(tabs_, 0, connectHeight, width, tabHeight);
        RECT display{0, 0, width, tabHeight};
        TabCtrl_AdjustRect(tabs_, FALSE, &display);
        OffsetRect(&display, 0, connectHeight);
        display.right = std::max(display.left, display.right - scrollbarWidth);
        move(page_, display.left, display.top, display.right - display.left, display.bottom - display.top, true,
            scrollbar_);
        moveScrollbar(display, HWND_TOP);
        bool terminalPrepositioned = prepositionTerminal(display);
        commit();
        int parts[] = {std::max(120, width / 4), std::max(300, width / 2), -1};
        SendMessageW(status_, SB_SETPARTS, static_cast<WPARAM>(std::size(parts)), reinterpret_cast<LPARAM>(parts));
        LayoutChildren(terminalPrepositioned ? false : refreshFrame);
    }

    void PaintMenuSeparator()
    {
        // Cover the native one-pixel menu divider with the themed client background.
        WINDOWINFO info{sizeof(info)};
        if (!GetMenu(frame_) || !GetWindowInfo(frame_, &info)) return;
        int top = info.rcClient.top - info.rcWindow.top;
        RECT separator{info.rcClient.left - info.rcWindow.left, top - 1, info.rcClient.right - info.rcWindow.left, top};
        HDC deviceContext = GetWindowDC(frame_);
        if (!deviceContext) return;
        FillRect(deviceContext, &separator, theme::BackgroundBrush());
        ReleaseDC(frame_, deviceContext);
    }

    void UpdateTabMetrics()
    {
        // Scale tab padding and width for the current monitor DPI.
        if (!tabs_) return;
        UINT dpi = GetDpiForWindow(tabs_);
        int horizontalPadding = MulDiv(8, dpi, USER_DEFAULT_SCREEN_DPI);
        int verticalPadding = MulDiv(4, dpi, USER_DEFAULT_SCREEN_DPI);
        SendMessageW(tabs_, TCM_SETPADDING, 0, MAKELPARAM(horizontalPadding, verticalPadding));
        TabCtrl_SetMinTabWidth(tabs_, MulDiv(180, dpi, USER_DEFAULT_SCREEN_DPI));
    }

    void LayoutChildren(bool refreshFrame = false)
    {
        // Hide inactive terminals before positioning the selected terminal and scrollbar.
        if (!page_) return;
        Session *active = CurrentSession();
        for (const auto &session : sessions_)
        {
            if (!session.attached || !IsSessionTerminal(session)) continue;
            if (&session != active) ShowWindowAsync(session.terminal, SW_HIDE);
        }
        if (active && active->attached && IsSessionTerminal(*active)) PositionEmbedded(*active, true, refreshFrame);
        SyncScrollbar();
    }

    void SyncScrollbar()
    {
        // Place a host-owned themed scrollbar beside the clipped PuTTY terminal page.
        Session *session = CurrentSession();
        SCROLLINFO scroll{sizeof(scroll), SIF_RANGE | SIF_PAGE | SIF_POS};
        bool visible = scrollbar_ && session && session->attached && session->hasScrollbar &&
            IsSessionTerminal(*session) && IsWindowVisible(session->terminal) &&
            GetScrollInfo(session->terminal, SB_VERT, &scroll);
        if (!visible)
        {
            if (scrollbar_ && IsWindowVisible(scrollbar_)) ShowWindow(scrollbar_, SW_HIDE);
            return;
        }

        RECT rectangle{};
        if (!GetClientRect(page_, &rectangle))
        {
            ShowWindow(scrollbar_, SW_HIDE);
            return;
        }
        MapWindowPoints(page_, frame_, reinterpret_cast<POINT *>(&rectangle), 2);
        int scrollbarWidth = GetSystemMetricsForDpi(SM_CXVSCROLL, GetDpiForWindow(session->terminal));
        rectangle.left = rectangle.right;
        rectangle.right += scrollbarWidth;

        if (!scrollbarTracking_)
        {
            SCROLLINFO current{sizeof(current), SIF_RANGE | SIF_PAGE | SIF_POS};
            bool changed = !GetScrollInfo(scrollbar_, SB_CTL, &current) || current.nMin != scroll.nMin ||
                current.nMax != scroll.nMax || current.nPage != scroll.nPage || current.nPos != scroll.nPos;
            if (changed)
            {
                scroll.fMask |= SIF_DISABLENOSCROLL;
                SetScrollInfo(scrollbar_, SB_CTL, &scroll, TRUE);
            }
        }
        bool enabled = IsWindowEnabled(session->terminal) && !IsHungAppWindow(session->terminal);
        if (!!IsWindowEnabled(scrollbar_) != enabled) EnableWindow(scrollbar_, enabled);
        RECT current{};
        GetWindowRect(scrollbar_, &current);
        MapWindowPoints(nullptr, frame_, reinterpret_cast<POINT *>(&current), 2);
        HWND above = GetWindow(scrollbar_, GW_HWNDPREV);
        bool positioned = EqualRect(&current, &rectangle) && IsWindowVisible(scrollbar_) &&
            (fullscreen_ ? above == fullscreenExit_ : !above);
        if (!positioned)
            SetWindowPos(scrollbar_, fullscreen_ ? fullscreenExit_ : HWND_TOP, rectangle.left, rectangle.top,
                rectangle.right - rectangle.left, rectangle.bottom - rectangle.top, SWP_NOACTIVATE | SWP_SHOWWINDOW);
    }

    void HandleScrollbar(WPARAM value)
    {
        // Forward proxy scrollbar actions to the active embedded terminal.
        UINT request = LOWORD(value);
        Session *session = CurrentSession();
        if (!session || !session->attached || !IsSessionTerminal(*session) || !IsWindowEnabled(session->terminal) ||
            IsHungAppWindow(session->terminal))
            return;

        // Prime PuTTY's full-width position before forwarding WM_VSCROLL's 16-bit thumb value.
        bool thumb = request == SB_THUMBTRACK || request == SB_THUMBPOSITION;
        SCROLLINFO native{sizeof(native), SIF_POS};
        int position = HIWORD(value);
        if (thumb)
        {
            SCROLLINFO proxy{sizeof(proxy), SIF_TRACKPOS};
            if (!GetScrollInfo(scrollbar_, SB_CTL, &proxy) || !GetScrollInfo(session->terminal, SB_VERT, &native))
                return;
            position = proxy.nTrackPos;
            SCROLLINFO primed{sizeof(primed), SIF_POS, 0, 0, 0, position};
            SetScrollInfo(session->terminal, SB_VERT, &primed, FALSE);
        }

        scrollbarTracking_ = request == SB_THUMBTRACK;
        DWORD_PTR result = 0;
        bool sent = SendMessageTimeoutW(session->terminal, WM_VSCROLL, MAKEWPARAM(request, LOWORD(position)), 0,
            SMTO_ABORTIFHUNG | SMTO_BLOCK, PollInterval, &result) != 0;
        if (!sent && thumb) SetScrollInfo(session->terminal, SB_VERT, &native, TRUE);
        if (!scrollbarTracking_) SyncScrollbar();
        if (request == SB_ENDSCROLL) FocusCurrentSession();
    }

    void ActivateSession(size_t index, bool focus = true)
    {
        // Synchronize the selected tab, terminal visibility, captions, status, and focus.
        if (index >= sessions_.size())
        {
            UpdateStatus();
            return;
        }

        TabCtrl_SetCurSel(tabs_, static_cast<int>(index));
        Layout();
        UpdateStatus();
        SetSessionTitle(index, sessions_[index].title);
        if (focus) FocusCurrentSession();
    }

    void FocusCurrentSession()
    {
        // Prefer active dialogs, then embedded or separate terminal windows.
        Session *session = CurrentSession();
        if (!session) return;
        ProcessWindows windows = WindowsForProcess(session->processId);
        if (windows.dialog && (!IsSessionTerminal(*session) || !IsWindowEnabled(session->terminal)))
        {
            ShowWindowAsync(windows.dialog, SW_RESTORE);
            SetForegroundWindow(windows.dialog);
            return;
        }
        if (session->attached && IsSessionTerminal(*session))
        {
            SetForegroundWindow(frame_);
            DWORD hostThread = GetCurrentThreadId();
            DWORD terminalThread = GetWindowThreadProcessId(session->terminal, nullptr);
            bool attachedThreads = terminalThread != hostThread && AttachThreadInput(hostThread, terminalThread, TRUE);
            SetFocus(session->terminal);
            if (attachedThreads) AttachThreadInput(hostThread, terminalThread, FALSE);
            return;
        }
        HWND target = windows.dialog ? windows.dialog : windows.terminal ? windows.terminal : windows.visible;
        if (target)
        {
            ShowWindowAsync(target, SW_RESTORE);
            SetForegroundWindow(target);
        }
    }

    void CycleSession(int direction)
    {
        if (sessions_.empty()) return;
        int current = TabCtrl_GetCurSel(tabs_);
        int count = static_cast<int>(sessions_.size());
        int next = (current + direction + count) % count;
        ActivateSession(static_cast<size_t>(next));
    }

    void SetDetectedTitle(size_t index, const std::wstring &title)
    {
        // Retain PuTTY's live title while respecting any host-owned tab alias.
        if (index >= sessions_.size()) return;
        Session &session = sessions_[index];
        session.detectedTitle = title.empty() ? L"PuTTY" : title;
        if (session.customTitle.empty()) SetSessionTitle(index, session.detectedTitle);
    }

    void SetSessionTitle(size_t index, const std::wstring &title)
    {
        // Keep the tab label and active host title synchronized.
        if (index >= sessions_.size()) return;
        Session &session = sessions_[index];
        session.title = title.empty() ? L"PuTTY" : title;

        TCITEMW item{};
        item.mask = TCIF_TEXT;
        item.pszText = session.title.data();
        TabCtrl_SetItem(tabs_, static_cast<int>(index), &item);
        if (index == CurrentIndex())
        {
            std::wstring frameTitle = WindowTitle;
            frameTitle += L" - ";
            frameTitle += session.title;
            SetWindowTextW(frame_, frameTitle.c_str());
        }
    }

    void RemoveSession(size_t index)
    {
        // Remove completed tab state and select the nearest surviving session.
        if (index >= sessions_.size()) return;
        bool restoreFocus = HostForeground();
        bool wasCurrent = index == CurrentIndex();
        TabCtrl_DeleteItem(tabs_, static_cast<int>(index));
        sessions_.erase(sessions_.begin() + static_cast<ptrdiff_t>(index));
        Layout();
        if (sessions_.empty())
        {
            SetWindowTextW(frame_, WindowTitle);
            UpdateStatus();
            return;
        }
        size_t next = std::min(index, sessions_.size() - 1);
        if (wasCurrent || CurrentIndex() >= sessions_.size()) ActivateSession(next, restoreFocus);
        else UpdateStatus();
    }

    void RequestClose(size_t index, bool force = false)
    {
        // Route close requests to the terminal or its currently visible PuTTY dialog.
        if (index >= sessions_.size()) return;
        Session &session = sessions_[index];
        if (session.locked && !force) return;
        session.closing = true;
        session.closeBlocked = false;
        session.closeRequestedAt = 0;
        if (IsSessionTerminal(session))
        {
            if (PostMessageW(session.terminal, WM_CLOSE, 0, 0)) session.closeRequestedAt = GetTickCount64();
        }
        else
        {
            ProcessWindows windows = WindowsForProcess(session.processId);
            HWND target = windows.dialog ? windows.dialog : windows.visible;
            if (target && PostMessageW(target, WM_CLOSE, 0, 0)) session.closeRequestedAt = GetTickCount64();
        }
        UpdateStatus();
    }

    void RequestCloseAll(bool force = false)
    {
        for (size_t index = 0; index < sessions_.size(); ++index) RequestClose(index, force);
    }

    void ExitLeavingSessions()
    {
        // Detach every terminal before closing only the tab host.
        if (!DetachAll())
        {
            MessageBoxW(frame_,
                L"PuTTYTab could not detach every session. The host will remain open so the "
                L"sessions are not interrupted.", WindowTitle, MB_OK | MB_ICONERROR);
            return;
        }
        DestroyWindow(frame_);
    }

    void BeginExit()
    {
        // Offer safe close or detach behavior for all active sessions.
        if (sessions_.empty())
        {
            DestroyWindow(frame_);
            return;
        }

        if (exiting_)
        {
            int answer = MessageBoxW(frame_,
                L"Some PuTTY sessions are still closing. Exit PuTTYTab now and "
                L"detach the remaining windows? Pending close requests may still be processed by PuTTY.",
                WindowTitle, MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2);
            if (answer == IDYES) ExitLeavingSessions();
            return;
        }
        int answer = MessageBoxW(frame_,
            L"Close all PuTTY sessions before exiting?\n\nChoose No to leave them running as separate windows.",
            WindowTitle, MB_YESNOCANCEL | MB_ICONQUESTION | MB_DEFBUTTON3);
        if (answer == IDCANCEL) return;
        if (answer == IDNO)
        {
            ExitLeavingSessions();
            return;
        }

        exiting_ = true;
        RequestCloseAll(true);
        UpdateStatus();
    }

    void ForwardToPutty(WPARAM command)
    {
        Session *session = CurrentSession();
        if (!session || !IsSessionTerminal(*session)) return;
        PostMessageW(session->terminal, WM_SYSCOMMAND, command, 0);
    }

    void ToggleFullscreen()
    {
        // Save and restore the standard frame around borderless fullscreen mode.
        if (!fullscreen_)
        {
            normalPlacement_.length = sizeof(normalPlacement_);
            GetWindowPlacement(frame_, &normalPlacement_);
            normalFrameStyle_ = GetWindowLongPtrW(frame_, GWL_STYLE);
            MONITORINFO monitor{sizeof(monitor)};
            GetMonitorInfoW(MonitorFromWindow(frame_, MONITOR_DEFAULTTONEAREST), &monitor);

            fullscreen_ = true;
            SetMenu(frame_, nullptr);
            for (HWND control : {connectLabel_, connectCombo_, connectButton_}) ShowWindow(control, SW_HIDE);
            ShowWindow(tabs_, SW_HIDE);
            ShowWindow(status_, SW_HIDE);
            SetWindowLongPtrW(frame_, GWL_STYLE, normalFrameStyle_ & ~WS_OVERLAPPEDWINDOW);
            SetWindowPos(frame_, alwaysOnTop_ ? HWND_TOPMOST : HWND_TOP, monitor.rcMonitor.left, monitor.rcMonitor.top,
                monitor.rcMonitor.right - monitor.rcMonitor.left, monitor.rcMonitor.bottom - monitor.rcMonitor.top,
                SWP_FRAMECHANGED | SWP_NOACTIVATE);
        }
        else
        {
            fullscreen_ = false;
            SetWindowLongPtrW(frame_, GWL_STYLE, normalFrameStyle_);
            SetMenu(frame_, menu_);
            for (HWND control : {connectLabel_, connectCombo_, connectButton_})
                ShowWindow(control, connectBarVisible_ ? SW_SHOW : SW_HIDE);
            ShowWindow(tabs_, SW_SHOW);
            ShowWindow(status_, statusVisible_ ? SW_SHOW : SW_HIDE);
            SetWindowPlacement(frame_, &normalPlacement_);
            SetWindowPos(frame_, alwaysOnTop_ ? HWND_TOPMOST : HWND_NOTOPMOST, 0, 0, 0, 0,
                SWP_FRAMECHANGED | SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
            DrawMenuBar(frame_);
        }
        Layout();
        FocusCurrentSession();
    }

    void RebuildSavedSessionsMenu()
    {
        // Enumerate portable-aware PuTTY sessions and rebuild the launch menu.
        std::wstring connectText = connectCombo_ ? WindowText(connectCombo_) : L"";
        while (GetMenuItemCount(savedMenu_) > 0) DeleteMenu(savedMenu_, 0, MF_BYPOSITION);
        if (connectCombo_) ComboBox_ResetContent(connectCombo_);
        savedSessions_.clear();
        HKEY key = nullptr;
        if (RegOpenKeyExW(HKEY_CURRENT_USER, SessionRegistryPath, 0, KEY_ENUMERATE_SUB_KEYS, &key) == ERROR_SUCCESS)
        {
            std::array<wchar_t, 256> name{};
            for (DWORD index = 0;; ++index)
            {
                LSTATUS status = RegEnumKeyW(key, index, name.data(), static_cast<DWORD>(name.size()));
                if (status == ERROR_NO_MORE_ITEMS) break;
                if (status != ERROR_SUCCESS) continue;
                std::wstring decoded = DecodeSessionName(name.data());
                if (_wcsicmp(decoded.c_str(), L"Default Settings") != 0) savedSessions_.push_back(std::move(decoded));
            }
            RegCloseKey(key);
        }

        // Sort and render menu-safe labels within the reserved command range.
        std::ranges::sort(savedSessions_,
            [](const std::wstring &left, const std::wstring &right)
            {
                return _wcsicmp(left.c_str(), right.c_str()) < 0;
            });
        size_t maximum = IDM_SAVED_SESSION_LAST - IDM_SAVED_SESSION_FIRST + 1;
        if (savedSessions_.empty())
        {
            AppendMenuW(savedMenu_, MF_STRING | MF_GRAYED, 0, L"(No saved sessions)");
            if (connectCombo_) SetWindowTextW(connectCombo_, connectText.c_str());
            return;
        }

        for (size_t index = 0; index < std::min(savedSessions_.size(), maximum); ++index)
        {
            if (connectCombo_) ComboBox_AddString(connectCombo_, savedSessions_[index].c_str());
            std::wstring label = savedSessions_[index];
            for (size_t offset = 0; (offset = label.find(L'&', offset)) != std::wstring::npos; offset += 2)
                label.insert(offset, 1, L'&');
            AppendMenuW(savedMenu_, MF_STRING, IDM_SAVED_SESSION_FIRST + index, label.c_str());
        }
        if (savedSessions_.size() > maximum)
            AppendMenuW(savedMenu_, MF_STRING | MF_GRAYED, 0, L"(Additional sessions omitted)");
        if (connectCombo_) SetWindowTextW(connectCombo_, connectText.c_str());
    }

    void UpdateMenuState()
    {
        // Enable and check menu items from the current session and view state.
        if (!menu_) return;
        Session *session = CurrentSession();
        UINT hasSession = session ? MF_ENABLED : MF_GRAYED;
        UINT hasTerminal = session && IsSessionTerminal(*session) ? MF_ENABLED : MF_GRAYED;
        UINT hasUnlockedSession = session && !session->locked ? MF_ENABLED : MF_GRAYED;
        const UINT terminalCommands[] = {
            IDM_SESSION_LOG,   IDM_SESSION_RECONFIGURE, IDM_SESSION_COPY, IDM_SESSION_PASTE, IDM_SESSION_COPY_ALL,
            IDM_SESSION_CLEAR_SCROLLBACK, IDM_SESSION_RESET, IDM_SESSION_HELP, IDM_SESSION_ABOUT};
        for (UINT command : terminalCommands) EnableMenuItem(menu_, command, MF_BYCOMMAND | hasTerminal);

        EnableMenuItem(menu_, IDM_FILE_DUPLICATE, MF_BYCOMMAND | hasTerminal);
        EnableMenuItem(menu_, IDM_SESSION_RESTART,
            MF_BYCOMMAND | (session && IsDisconnectedTerminal(*session) ? MF_ENABLED : MF_GRAYED));
        EnableMenuItem(menu_, IDM_FILE_CLOSE, MF_BYCOMMAND | hasUnlockedSession);
        bool hasUnlocked = std::ranges::any_of(sessions_, [](const Session &candidate) { return !candidate.locked; });
        bool hasUnlockedOther = std::ranges::any_of(sessions_, [session](const Session &candidate)
            { return &candidate != session && !candidate.locked; });
        EnableMenuItem(menu_, IDM_FILE_CLOSE_OTHERS, MF_BYCOMMAND | (hasUnlockedOther ? MF_ENABLED : MF_GRAYED));
        EnableMenuItem(menu_, IDM_FILE_CLOSE_ALL, MF_BYCOMMAND | (hasUnlocked ? MF_ENABLED : MF_GRAYED));
        EnableMenuItem(menu_, IDM_SESSION_RENAME, MF_BYCOMMAND | hasSession);
        EnableMenuItem(menu_, IDM_SESSION_RESET_NAME,
            MF_BYCOMMAND | (session && !session->customTitle.empty() ? MF_ENABLED : MF_GRAYED));
        EnableMenuItem(menu_, IDM_SESSION_LOCK, MF_BYCOMMAND | hasSession);
        size_t current = CurrentIndex();
        EnableMenuItem(menu_, IDM_SESSION_MOVE_LEFT, MF_BYCOMMAND | (current > 0 ? MF_ENABLED : MF_GRAYED));
        EnableMenuItem(menu_, IDM_SESSION_MOVE_RIGHT,
            MF_BYCOMMAND | (current + 1 < sessions_.size() ? MF_ENABLED : MF_GRAYED));
        EnableMenuItem(menu_, IDM_VIEW_NEXT, MF_BYCOMMAND | (sessions_.size() > 1 ? MF_ENABLED : MF_GRAYED));
        EnableMenuItem(menu_, IDM_VIEW_PREVIOUS, MF_BYCOMMAND | (sessions_.size() > 1 ? MF_ENABLED : MF_GRAYED));
        CheckMenuItem(menu_, IDM_SESSION_LOCK, MF_BYCOMMAND | (session && session->locked ? MF_CHECKED : MF_UNCHECKED));
        CheckMenuItem(menu_, IDM_VIEW_ALWAYS_ON_TOP, MF_BYCOMMAND | (alwaysOnTop_ ? MF_CHECKED : MF_UNCHECKED));
        CheckMenuItem(menu_, IDM_VIEW_FULLSCREEN, MF_BYCOMMAND | (fullscreen_ ? MF_CHECKED : MF_UNCHECKED));
        CheckMenuItem(menu_, IDM_VIEW_STATUS_BAR, MF_BYCOMMAND | (statusVisible_ ? MF_CHECKED : MF_UNCHECKED));
        CheckMenuItem(menu_, IDM_VIEW_CONNECT_BAR, MF_BYCOMMAND | (connectBarVisible_ ? MF_CHECKED : MF_UNCHECKED));
    }

    void UpdateStatus()
    {
        // Summarize the session count and active PuTTY lifecycle state.
        if (!status_) return;
        std::wstring count = std::to_wstring(sessions_.size());
        count += sessions_.size() == 1 ? L" session" : L" sessions";
        std::wstring state = L"No active session";
        Session *session = CurrentSession();
        if (session)
        {
            ProcessWindows windows = WindowsForProcess(session->processId);
            if (session->closing && session->terminal && !IsWindowEnabled(session->terminal))
                state = L"Close confirmation open";
            else if (session->closing) state = L"Closing...";
            else if (session->attachFailed) state = L"Running in a separate window";
            else if (!session->terminal) state = L"Waiting for PuTTY...";
            else if (windows.dialog) state = L"PuTTY dialog open";
            else if (IsHungAppWindow(session->terminal)) state = L"PuTTY is not responding";
            else if (IsDisconnectedTerminal(*session)) state = L"Session inactive";
            else state = L"PuTTY terminal active";
            if (session->locked) state += L" | Tab locked";
        }
        if (exiting_) state = L"Waiting for sessions to close...";

        std::array text{count, state, std::wstring(L"Alt+R: connect   Ctrl+Shift+T: new   F11: full screen")};
        for (size_t part = 0; part < text.size(); ++part)
        {
            if (text[part] == statusText_[part]) continue;
            if (SendMessageW(status_, SB_SETTEXTW, part, reinterpret_cast<LPARAM>(text[part].c_str())))
                statusText_[part] = std::move(text[part]);
        }
    }

    size_t CurrentIndex() const
    {
        int index = tabs_ ? TabCtrl_GetCurSel(tabs_) : -1;
        return index >= 0 ? static_cast<size_t>(index) : sessions_.size();
    }

    Session *CurrentSession()
    {
        size_t index = CurrentIndex();
        return index < sessions_.size() ? &sessions_[index] : nullptr;
    }

    size_t SessionIndex(DWORD processId) const
    {
        auto iterator = std::ranges::find(sessions_, processId, &Session::processId);
        return static_cast<size_t>(std::distance(sessions_.begin(), iterator));
    }

    bool HostForeground() const
    {
        HWND foreground = GetForegroundWindow();
        return foreground && (foreground == frame_ || IsChild(frame_, foreground));
    }

    LRESULT HandleKeyboard(int code, WPARAM message, const KBDLLHOOKSTRUCT &key)
    {
        // Translate host-wide shortcuts while keyboard focus belongs to embedded PuTTY.
        auto pass = [&]()
        {
            return CallNextHookEx(keyboardHook_, code, message, reinterpret_cast<LPARAM>(&key));
        };
        if (key.vkCode >= keys_.size()) return pass();

        // Preserve each key's pass-through decision across auto-repeat and key-up.
        KeyState &state = keys_[key.vkCode];
        bool down = message == WM_KEYDOWN || message == WM_SYSKEYDOWN;
        bool up = message == WM_KEYUP || message == WM_SYSKEYUP;
        if (up)
        {
            bool consumed = state == KeyState::Consumed;
            state = KeyState::Idle;
            return consumed ? 1 : pass();
        }
        if (!down) return pass();
        if (state != KeyState::Idle) return state == KeyState::Consumed ? 1 : pass();
        state = KeyState::Passed;
        if (!HostForeground()) return pass();

        // Map scoped modifier chords to host commands without leaking consumed keys into PuTTY.
        bool control = (GetAsyncKeyState(VK_CONTROL) & 0x8000) != 0;
        bool shift = (GetAsyncKeyState(VK_SHIFT) & 0x8000) != 0;
        bool alt = (GetAsyncKeyState(VK_MENU) & 0x8000) != 0;
        bool windowsKey = (GetAsyncKeyState(VK_LWIN) & 0x8000) != 0 || (GetAsyncKeyState(VK_RWIN) & 0x8000) != 0;
        if (windowsKey) return pass();
        bool menuMnemonic = !control && !shift && alt && (key.vkCode == 'F' || key.vkCode == 'S' || key.vkCode == 'V');
        if (menuMnemonic || (!control && !shift && !alt && key.vkCode == VK_F10))
        {
            state = KeyState::Consumed;
            PostMessageW(frame_, WmMenuMnemonic, menuMnemonic ? key.vkCode : 0, 0);
            return 1;
        }
        if (!control && !shift && alt && key.vkCode == 'R')
        {
            state = KeyState::Consumed;
            PostMessageW(frame_, WmFocusConnectBar, 0, 0);
            return 1;
        }
        UINT command = 0;
        if (control && shift && !alt && key.vkCode == 'T') command = IDM_FILE_NEW;
        else if (control && shift && !alt && key.vkCode == 'D') command = IDM_FILE_DUPLICATE;
        else if (control && shift && !alt && key.vkCode == 'N') command = IDM_FILE_ARGUMENTS;
        else if (control && shift && !alt && key.vkCode == 'R') command = IDM_SESSION_RESTART;
        else if (control && shift && !alt && key.vkCode == 'W') command = IDM_FILE_CLOSE;
        else if (control && shift && !alt && key.vkCode == VK_PRIOR) command = IDM_SESSION_MOVE_LEFT;
        else if (control && shift && !alt && key.vkCode == VK_NEXT) command = IDM_SESSION_MOVE_RIGHT;
        else if (control && !alt && key.vkCode == VK_TAB) command = shift ? IDM_VIEW_PREVIOUS : IDM_VIEW_NEXT;
        else if (control && !shift && !alt && key.vkCode == VK_PRIOR) command = IDM_VIEW_PREVIOUS;
        else if (control && !shift && !alt && key.vkCode == VK_NEXT) command = IDM_VIEW_NEXT;
        else if (control && !shift && !alt && key.vkCode == VK_F4) command = IDM_FILE_CLOSE;
        else if (!control && !shift && alt && key.vkCode == VK_F4) command = IDM_FILE_EXIT;
        else if ((!control && !shift && !alt && key.vkCode == VK_F11) ||
            (!control && !shift && alt && key.vkCode == VK_RETURN))
            command = IDM_VIEW_FULLSCREEN;
        else if (fullscreen_ && !control && !shift && !alt && key.vkCode == VK_ESCAPE) command = IDM_VIEW_FULLSCREEN;
        if (control && !shift && !alt && key.vkCode >= '1' && key.vkCode <= '9' &&
            static_cast<size_t>(key.vkCode - '1') < sessions_.size())
        {
            state = KeyState::Consumed;
            PostMessageW(frame_, WmActivateTab, sessions_[key.vkCode - '1'].processId, 0);
            return 1;
        }

        if (!command) return pass();

        // Deliver target-sensitive commands to the session that owned the shortcut.
        state = KeyState::Consumed;
        Session *target = CurrentSession();
        LPARAM targetProcess = command == IDM_FILE_DUPLICATE || command == IDM_FILE_CLOSE ||
            command == IDM_SESSION_RESTART || command == IDM_SESSION_MOVE_LEFT || command == IDM_SESSION_MOVE_RIGHT
            ? static_cast<LPARAM>(target ? target->processId : 0)
            : 0;
        PostMessageW(frame_, WmShortcut, command, targetProcess);
        return 1;
    }

    HINSTANCE instance_ = nullptr;
    HWND frame_ = nullptr;
    HWND connectLabel_ = nullptr;
    HWND connectCombo_ = nullptr;
    HWND connectEdit_ = nullptr;
    HWND connectList_ = nullptr;
    HWND connectButton_ = nullptr;
    HWND tabs_ = nullptr;
    HWND page_ = nullptr;
    HWND scrollbar_ = nullptr;
    HWND status_ = nullptr;
    HWND fullscreenExit_ = nullptr;
    HMENU menu_ = nullptr;
    HMENU savedMenu_ = nullptr;
    HHOOK keyboardHook_ = nullptr;
    UniqueHandle job_;
    std::vector<Session> sessions_;
    std::vector<std::wstring> savedSessions_;
    std::wstring puttyPath_;
    std::wstring puttyDirectory_;
    std::wstring tooltipText_;
    std::array<std::wstring, 3> statusText_;
    std::array<KeyState, 256> keys_{};
    WINDOWPLACEMENT normalPlacement_{sizeof(normalPlacement_)};
    POINT dragOrigin_{};
    LONG_PTR normalFrameStyle_ = 0;
    DWORD draggedProcess_ = 0;
    bool alwaysOnTop_ = false;
    bool fullscreen_ = false;
    bool statusVisible_ = true;
    bool connectBarVisible_ = true;
    bool autocompletingConnectBar_ = false;
    bool draggingTab_ = false;
    bool scrollbarTracking_ = false;
    bool exiting_ = false;
};

App *App::current_ = nullptr;

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR arguments, int showCommand)
{
    App app(instance);
    if (!app.Initialise(showCommand)) return 1;
    return app.Run(arguments ? arguments : L"");
}
