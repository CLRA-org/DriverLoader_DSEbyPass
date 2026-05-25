#define UNICODE
#define _UNICODE

#include <windows.h>
#include <commctrl.h>
#include <shellapi.h>   // 拖拽文件
#include <string>
#include <vector>
#include <cstring>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <windows.h>
#include <winternl.h>
#include <ntstatus.h>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "shell32.lib")

// ------------------------------------------------------------------
// 核心数据结构与函数 (原样保留)
// ------------------------------------------------------------------

// 全局变量定义
HANDLE gDevice = NULL;
DWORD_PTR gKernelImageSize = 0;
DWORD_PTR gKernelImageExecuteSize = 0;
PVOID gKernelImageBase = NULL;
PVOID gKernelBase = NULL;
PVOID gKernelImageExecuteBase = NULL;
PVOID gCiBase = NULL;
PVOID gCiImageBase = NULL;
SIZE_T gCiImageSize = 0;

// 系统模块信息结构体
typedef struct _SYSTEM_MODULE_INFORMATION {
    ULONG_PTR Reserved1[2];
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

typedef struct _SYSTEM_MODULES {
    ULONG ModulesCount;
    SYSTEM_MODULE_INFORMATION Modules[1];
} SYSTEM_MODULES, * PSYSTEM_MODULES;

// 驱动IOCTL控制码
#define IOCTL_KERNEL_WRITE 0x8000204c
#define IOCTL_KERNEL_READ 0x80002048


void AppendLog(const wchar_t* format, ...);


#pragma pack(push, 1)
typedef struct _KERNEL_WRITE_REQUEST {
    ULONG_PTR Unknown1;
    PVOID BaseAddress;
    DWORD Reserved1;
    DWORD Offset;
    DWORD WriteSize;
    ULONG WriteValue;
    DWORD Reserved2[4];
} KERNEL_WRITE_REQUEST, * PKERNEL_WRITE_REQUEST;

typedef struct _KERNEL_READ_REQUEST {
    BYTE Unknown1[8];
    LONGLONG BaseAddress;
    DWORD Reserved1;
    DWORD Offset;
    DWORD ReadSize;
    DWORD ReadValue;
    BYTE Reserved2[16];
} KERNEL_READ_REQUEST, * PKERNEL_READ_REQUEST;
#pragma pack(pop)

inline BOOL GetNTHeaders(PVOID baseAddress, PIMAGE_NT_HEADERS* ntHeaders)
{
    if (!baseAddress || !ntHeaders) return FALSE;
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)baseAddress;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;
    *ntHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)baseAddress + dosHeader->e_lfanew);
    if ((*ntHeaders)->Signature != IMAGE_NT_SIGNATURE) return FALSE;
    return TRUE;
}

inline BOOL GetImageExportDirectory(PVOID baseAddress, PIMAGE_EXPORT_DIRECTORY* exportDirectory)
{
    if (!baseAddress || !exportDirectory) return FALSE;
    PIMAGE_NT_HEADERS ntHeaders = NULL;
    if (!GetNTHeaders(baseAddress, &ntHeaders)) return FALSE;
    if (ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0) return FALSE;
    *exportDirectory = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)baseAddress +
        ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    return TRUE;
}

BOOL EnableDebugPrivilege()
{
    HANDLE hToken = NULL;
    TOKEN_PRIVILEGES tp = { 0 };
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return FALSE;
    if (!LookupPrivilegeValueW(NULL, L"SeDebugPrivilege", &tp.Privileges[0].Luid))
    {
        CloseHandle(hToken);
        return FALSE;
    }
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    BOOL result = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    CloseHandle(hToken);
    return result && GetLastError() == ERROR_SUCCESS;
}

PVOID GetKernelModuleBase(const char* ModuleName, size_t* ImageLength) {
    if (!ModuleName) return NULL;
    DWORD moduleLength = 0;
    NTSTATUS status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)11, NULL, 0, &moduleLength);
    if (status != STATUS_INFO_LENGTH_MISMATCH) {
        return NULL;
    }
    PSYSTEM_MODULES modulesInfo = (PSYSTEM_MODULES)malloc(moduleLength);
    if (!modulesInfo) {
        return NULL;
    }
    status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)11, modulesInfo, moduleLength, &moduleLength);
    if (status != STATUS_SUCCESS) {
        free(modulesInfo);
        return NULL;
    }
    for (DWORD i = 0; i < modulesInfo->ModulesCount; i++) {
        PCHAR moduleName = (PCHAR)(modulesInfo->Modules[i].FullPathName + modulesInfo->Modules[i].OffsetToFileName);
        if (!_strnicmp(moduleName, ModuleName, strlen(ModuleName))) {
            PVOID baseAddr = modulesInfo->Modules[i].ImageBase;
            if (ImageLength)
                *ImageLength = modulesInfo->Modules[i].ImageSize;
            free(modulesInfo);
            return baseAddr;
        }
    }
    free(modulesInfo);
    return NULL;
}

PVOID SearchPattern(PVOID baseAddr, SIZE_T size, BYTE* pattern, const char* mask)
{
    PVOID result = NULL;
    __int64 patternLength = strlen(mask);
    BOOL found = FALSE;
    for (__int64 i = 0; i <= (__int64)size - patternLength; i++) {
        found = TRUE;
        for (__int64 j = 0; j < patternLength; j++) {
            if (mask[j] != '?' && *(BYTE*)((DWORD_PTR)baseAddr + i + j) != pattern[j]) {
                found = FALSE;
                break;
            }
        }
        if (found) {
            result = (PVOID)((DWORD_PTR)baseAddr + i);
            break;
        }
    }
    return result;
}

BOOL KernelReadMemory(PVOID TargetAddress, PBYTE lpBuffer, size_t BufferSize)
{
    if (!gDevice) return FALSE;
    PBYTE baseAddress = (PBYTE)TargetAddress;
    for (size_t i = 0; i < BufferSize; i++) {
        KERNEL_READ_REQUEST readRequest = { 0 };
        readRequest.BaseAddress = (DWORD64)(baseAddress + i);
        readRequest.ReadSize = 1;
        DWORD bytesReturned = 0;
        BOOL result = DeviceIoControl(gDevice, IOCTL_KERNEL_READ, &readRequest, 0x30,
            &readRequest, 0x30, &bytesReturned, NULL);
        if (!result) {
            return FALSE;
        }
        lpBuffer[i] = readRequest.ReadValue & 0xFF;
    }
    return TRUE;
}

BOOL KernelWriteMemory(PVOID TargetAddress, PBYTE lpBuffer, size_t BufferSize)
{
    if (!gDevice) return FALSE;
    PBYTE baseAddress = (PBYTE)TargetAddress;
    for (size_t i = 0; i < BufferSize; i++) {
        KERNEL_WRITE_REQUEST writeRequest = { 0 };
        writeRequest.BaseAddress = baseAddress + i;
        writeRequest.WriteSize = 1;
        writeRequest.WriteValue = lpBuffer[i];
        DWORD bytesReturned = 0;
        BOOL result = DeviceIoControl(gDevice, IOCTL_KERNEL_WRITE, &writeRequest, 0x30,
            NULL, 0, &bytesReturned, NULL);
        if (!result)
            return FALSE;
    }
    return TRUE;
}
// 增加错误码输出
BOOL ExtractDriverFromResource(const WCHAR* destPath)
{
    AppendLog(L"[INFO] 尝试从资源中提取驱动...");
    HRSRC hRes = FindResourceW(NULL, MAKEINTRESOURCEW(101), RT_RCDATA);
    if (!hRes) {
        AppendLog(L"[ERROR] FindResourceW 失败，错误码: %d", GetLastError());
        AppendLog(L"[INFO] 请确认资源已正确嵌入 (RTCORE_SYS / RCDATA)");
        return FALSE;
    }
    AppendLog(L"[INFO] 找到资源，大小: %d 字节", SizeofResource(NULL, hRes));
    HGLOBAL hData = LoadResource(NULL, hRes);
    if (!hData) {
        AppendLog(L"[ERROR] LoadResource 失败，错误码: %d", GetLastError());
        return FALSE;
    }
    void* pData = LockResource(hData);
    if (!pData) {
        AppendLog(L"[ERROR] LockResource 失败");
        return FALSE;
    }
    DWORD size = SizeofResource(NULL, hRes);
    
    // 尝试创建目录（如果不存在）
    WCHAR destDir[MAX_PATH];
    wcscpy_s(destDir, destPath);
    WCHAR* lastSlash = wcsrchr(destDir, L'\\');
    if (lastSlash) {
        *lastSlash = 0;
        CreateDirectoryW(destDir, NULL); // 忽略错误，可能已存在
    }
    
    HANDLE hFile = CreateFileW(destPath, GENERIC_WRITE, 0, NULL,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        AppendLog(L"[ERROR] 无法创建文件 %s, error=%d", destPath, GetLastError());
        AppendLog(L"[INFO] 请确保以管理员身份运行，且目标目录可写");
        return FALSE;
    }
    DWORD written = 0;
    BOOL ok = WriteFile(hFile, pData, size, &written, NULL);
    CloseHandle(hFile);
    if (!ok || written != size) {
        AppendLog(L"[ERROR] 写入驱动文件失败，写入了 %d / %d 字节", written, size);
        return FALSE;
    }
    AppendLog(L"[SUCCESS] 驱动已释放至: %s", destPath);
    return TRUE;
}

BOOL CopyDriverToSystemDirectory()
{
    WCHAR destPath[MAX_PATH] = L"C:\\Windows\\System32\\drivers\\RTCore64.sys";
    // 先尝试删除已存在的旧文件（避免占用）
    DeleteFileW(destPath);
    return ExtractDriverFromResource(destPath);
}

VOID InitDevice()
{
    // 复制驱动
    if (!CopyDriverToSystemDirectory()) {
        return;
    }

    // 删除旧服务
    system("sc stop RTCore 2>nul");
    system("sc delete RTCore 2>nul");
    Sleep(1000);

    // 创建服务
    system("sc create RTCore binpath= \"C:\\Windows\\System32\\drivers\\RTCore64.sys\" type= kernel start= demand");
    // 启动服务
    system("sc start RTCore");

    // 打开设备
    gDevice = CreateFileW(L"\\\\.\\RTCore64", GENERIC_READ | GENERIC_WRITE, 0, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
}

VOID CloseDevice()
{
    if (gDevice) {
        CloseHandle(gDevice);
        gDevice = NULL;
    }
    system("sc stop RTCore 2>nul");
    system("sc delete RTCore 2>nul");
}

PVOID GetKernelBase()
{
    size_t kernelSize = 0;
    gKernelBase = GetKernelModuleBase("ntoskrnl.exe", &kernelSize);
    return gKernelBase;
}

BOOL MapKernelImage()
{
    HANDLE hFile = NULL;
    PVOID ImageBuffer = NULL;
    PVOID ImageMemory = NULL;
    BOOL result = FALSE;
    do {
        hFile = CreateFileW(L"C:\\Windows\\System32\\ntoskrnl.exe", GENERIC_READ, FILE_SHARE_READ,
            NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) break;
        LARGE_INTEGER fileSize = { 0 };
        if (!GetFileSizeEx(hFile, &fileSize)) break;
        size_t qwFileSize = fileSize.QuadPart;
        if (!qwFileSize) break;
        ImageBuffer = VirtualAlloc(NULL, qwFileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!ImageBuffer) break;
        RtlSecureZeroMemory(ImageBuffer, qwFileSize);
        DWORD bytesRead = 0;
        if (!ReadFile(hFile, ImageBuffer, qwFileSize, &bytesRead, NULL) || bytesRead != qwFileSize) break;
        CloseHandle(hFile);
        hFile = NULL;
        PIMAGE_NT_HEADERS ntHeaders = NULL;
        if (!GetNTHeaders(ImageBuffer, &ntHeaders)) break;
        ImageMemory = VirtualAlloc(NULL, ntHeaders->OptionalHeader.SizeOfImage,
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!ImageMemory) break;
        RtlSecureZeroMemory(ImageMemory, ntHeaders->OptionalHeader.SizeOfImage);
        memcpy(ImageMemory, ImageBuffer, ntHeaders->OptionalHeader.SizeOfHeaders);
        PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
        for (DWORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
            PBYTE dest = (PBYTE)ImageMemory + sectionHeader[i].VirtualAddress;
            PBYTE src = (PBYTE)ImageBuffer + sectionHeader[i].PointerToRawData;
            memcpy(dest, src, sectionHeader[i].SizeOfRawData);
        }
        ImageBuffer = NULL;
        gKernelImageBase = ImageMemory;
        gKernelImageSize = ntHeaders->OptionalHeader.SizeOfImage;
        result = TRUE;
    } while (false);
    if (hFile && hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);
    if (ImageBuffer) VirtualFree(ImageBuffer, 0, MEM_RELEASE);
    return result;
}

VOID UnmapKernelImage()
{
    if (gKernelImageBase) {
        VirtualFree(gKernelImageBase, 0, MEM_RELEASE);
        gKernelImageBase = NULL;
    }
}

BOOL GetKernelImageExecuteBase()
{
    if (!gKernelImageBase) return FALSE;
    PIMAGE_NT_HEADERS ntHeaders = NULL;
    if (!GetNTHeaders(gKernelImageBase, &ntHeaders)) return FALSE;
    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
    for (DWORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if (strcmp((char*)sectionHeader[i].Name, ".text") == 0) {
            gKernelImageExecuteBase = (PBYTE)gKernelImageBase + sectionHeader[i].VirtualAddress;
            gKernelImageExecuteSize = sectionHeader[i].SizeOfRawData;
            break;
        }
    }
    return TRUE;
}

BOOL MapCiImage()
{
    HANDLE hFile = NULL;
    PVOID ImageBuffer = NULL;
    PVOID ImageMemory = NULL;
    BOOL result = FALSE;
    do {
        hFile = CreateFileW(L"C:\\Windows\\System32\\ci.dll", GENERIC_READ, FILE_SHARE_READ,
            NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) break;
        LARGE_INTEGER fileSize = { 0 };
        if (!GetFileSizeEx(hFile, &fileSize)) break;
        size_t qwFileSize = fileSize.QuadPart;
        if (!qwFileSize) break;
        ImageBuffer = VirtualAlloc(NULL, qwFileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!ImageBuffer) break;
        RtlSecureZeroMemory(ImageBuffer, qwFileSize);
        DWORD bytesRead = 0;
        if (!ReadFile(hFile, ImageBuffer, qwFileSize, &bytesRead, NULL) || bytesRead != qwFileSize) break;
        CloseHandle(hFile);
        hFile = NULL;
        PIMAGE_NT_HEADERS ntHeaders = NULL;
        if (!GetNTHeaders(ImageBuffer, &ntHeaders)) break;
        ImageMemory = VirtualAlloc(NULL, ntHeaders->OptionalHeader.SizeOfImage,
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!ImageMemory) break;
        RtlSecureZeroMemory(ImageMemory, ntHeaders->OptionalHeader.SizeOfImage);
        memcpy(ImageMemory, ImageBuffer, ntHeaders->OptionalHeader.SizeOfHeaders);
        PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
        for (DWORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
            PBYTE dest = (PBYTE)ImageMemory + sectionHeader[i].VirtualAddress;
            PBYTE src = (PBYTE)ImageBuffer + sectionHeader[i].PointerToRawData;
            memcpy(dest, src, sectionHeader[i].SizeOfRawData);
        }
        ImageBuffer = NULL;
        gCiImageBase = ImageMemory;
        gCiImageSize = ntHeaders->OptionalHeader.SizeOfImage;
        result = TRUE;
    } while (false);
    if (hFile && hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);
    if (ImageBuffer) VirtualFree(ImageBuffer, 0, MEM_RELEASE);
    return result;
}

VOID UnmapCiImage()
{
    if (gCiImageBase) {
        VirtualFree(gCiImageBase, 0, MEM_RELEASE);
        gCiImageBase = NULL;
    }
}

DWORD_PTR GetFuncRVA(PVOID BaseAddress, const char* FuncName)
{
    PIMAGE_EXPORT_DIRECTORY pExportDir = NULL;
    if (!GetImageExportDirectory(BaseAddress, &pExportDir)) return 0;
    PDWORD funcRVA = (PDWORD)((DWORD_PTR)BaseAddress + pExportDir->AddressOfFunctions);
    PDWORD nameRVA = (PDWORD)((DWORD_PTR)BaseAddress + pExportDir->AddressOfNames);
    PWORD nameOrdinal = (PWORD)((DWORD_PTR)BaseAddress + pExportDir->AddressOfNameOrdinals);
    for (DWORD i = 0; i < pExportDir->NumberOfNames; i++) {
        if (!strcmp(FuncName, (char*)BaseAddress + nameRVA[i]))
            return funcRVA[nameOrdinal[i]];
    }
    return 0;
}

DWORD_PTR GetMiGetPteAddressFuncRVA()
{
    BYTE pattern[] = "\x48\xc1\xe9\x09\x48\xb8\xf8\xff\xff\xff\x7f\x00\x00\x00\x48\x23\xc8\x48\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x48\x03\xc1\xc3";
    char mask[] = "xxxxxxxxxxxxxxxxxxxxxxx????xxxx";
    PBYTE funcAddr = (PBYTE)SearchPattern(gKernelImageExecuteBase, gKernelImageExecuteSize, pattern, mask);
    if (!funcAddr) return 0;
    return (DWORD_PTR)funcAddr - (DWORD_PTR)gKernelImageBase;
}

DWORD_PTR GetCiValidateImageHeaderRVA()
{
    PBYTE pCiInitialize = (PBYTE)gCiImageBase + GetFuncRVA(gCiImageBase, "CiInitialize");
    if (!pCiInitialize) return 0;

    BYTE pattern[] = "\x48\x8b\xd6\x8b\xcd";
    char mask[] = "xxxxx";
    PBYTE pCipInitialize = (PBYTE)SearchPattern(pCiInitialize, 0x1000, pattern, mask);
    if (!pCipInitialize) return 0;
    pCipInitialize += 5;
    INT32 offset = *(INT32*)(pCipInitialize + 1);
    pCipInitialize += 5;
    pCipInitialize += offset;

    BYTE pattern2[] = "\x48\x8d\x05\x00\x00\x00\x00";
    char mask2[] = "xxx??xx";
    PBYTE uValueA = (PBYTE)SearchPattern(pCipInitialize, 0x2000, pattern2, mask2);
    if (!uValueA) return 0;
    INT32 offset2 = *(INT32*)(uValueA + 3);
    DWORD_PTR next = (DWORD_PTR)uValueA + 7;
    return (next + offset2) - (DWORD_PTR)gCiImageBase;
}

BOOL LoadDriver(const char* DriverPath, const char* ServiceName)
{
    char cmd[512];
    int result;

    sprintf_s(cmd, "sc delete %s 2>nul", ServiceName);
    system(cmd);

    sprintf_s(cmd, "sc create %s binpath= \"%s\" type= kernel start= demand", ServiceName, DriverPath);
    result = system(cmd);
    if (result != 0) return FALSE;

    sprintf_s(cmd, "sc start %s", ServiceName);
    result = system(cmd);
    if (result != 0) return FALSE;

    return TRUE;
}

BOOL UnloadDriver(const char* ServiceName)
{
    char cmd[512];
    sprintf_s(cmd, "sc stop %s", ServiceName);
    system(cmd);
    sprintf_s(cmd, "sc delete %s", ServiceName);
    system(cmd);
    return TRUE;
}

// ------------------------------------------------------------------
// GUI 部分 (支持 Unicode 和文件拖拽)
// ------------------------------------------------------------------

HWND g_hLogEdit = NULL;
HWND g_hDriverPathEdit = NULL;
HWND g_hBtnInit = NULL;
HWND g_hBtnLoad = NULL;
HWND g_hBtnRestore = NULL;

// 保存 hook 相关信息用于恢复
PVOID g_pCiValidateImageHeader = NULL;
ULONG64* g_pPte = NULL;
ULONG64 g_pteValue = 0;
BYTE g_originalBytes[4] = { 0 };
bool g_bypassActive = false;
char g_lastServiceName[64] = { 0 };
bool g_driverLoaded = false;

// 向日志控件追加文本 (Unicode 安全)
void AppendLog(const wchar_t* format, ...)
{
    if (!g_hLogEdit) return;
    wchar_t buffer[2048];
    va_list args;
    va_start(args, format);
    vswprintf(buffer, 2048, format, args);
    va_end(args);
    // 添加换行
    wcscat_s(buffer, L"\r\n");
    // 获取当前文本长度
    int len = GetWindowTextLengthW(g_hLogEdit);
    SendMessageW(g_hLogEdit, EM_SETSEL, len, len);
    SendMessageW(g_hLogEdit, EM_REPLACESEL, FALSE, (LPARAM)buffer);
}

// 辅助：输出 ANSI 字符串（转换为宽字符）
void AppendLogA(const char* format, ...)
{
    char ansi[2048];
    va_list args;
    va_start(args, format);
    vsnprintf(ansi, 2048, format, args);
    va_end(args);
    wchar_t wide[2048];
    MultiByteToWideChar(CP_ACP, 0, ansi, -1, wide, 2048);
    AppendLog(L"%s", wide);
}

void InitDriverStep()
{
    AppendLog(L"[STEP 1] 启用调试权限...");
    if (!EnableDebugPrivilege())
        AppendLog(L"[WARN] 启用 SeDebugPrivilege 失败，可能影响后续操作");

    AppendLog(L"[STEP 2] 获取内核基址...");
    PBYTE kernelBase = (PBYTE)GetKernelBase();
    if (!kernelBase) {
        AppendLog(L"[ERROR] 无法获取内核基址");
        return;
    }
    AppendLog(L"[INFO] 内核基址: 0x%p", kernelBase);

    AppendLog(L"[STEP 3] 初始化 RTCore 驱动...");
    InitDevice();
    if (!gDevice || gDevice == INVALID_HANDLE_VALUE) {
        AppendLog(L"[ERROR] 设备初始化失败，请以管理员身份运行并确保 RTCore64.sys 在当前目录");
        return;
    }
    AppendLog(L"[SUCCESS] RTCore 驱动已加载，设备句柄已打开");

    AppendLog(L"[STEP 4] 映射内核镜像...");
    if (!MapKernelImage()) {
        AppendLog(L"[ERROR] 映射内核镜像失败");
        return;
    }
    if (!GetKernelImageExecuteBase()) {
        AppendLog(L"[ERROR] 获取 .text 段失败");
        UnmapKernelImage();
        return;
    }
    AppendLog(L"[SUCCESS] 内核镜像映射完成，.text 段大小: 0x%zX", gKernelImageExecuteSize);

    AppendLog(L"[STEP 5] 映射 ci.dll 镜像...");
    if (!MapCiImage()) {
        AppendLog(L"[ERROR] 映射 ci.dll 失败");
        UnmapKernelImage();
        return;
    }
    gCiBase = GetKernelModuleBase("ci.dll", NULL);
    if (!gCiBase) {
        AppendLog(L"[WARN] 无法获取 ci.dll 运行时基址");
    } else {
        AppendLog(L"[INFO] ci.dll 运行时基址: 0x%p", gCiBase);
    }

    AppendLog(L"[STEP 6] 搜索 MiGetPteAddress...");
    DWORD_PTR miGetPteAddressFuncRVA = GetMiGetPteAddressFuncRVA();
    if (!miGetPteAddressFuncRVA) {
        AppendLog(L"[ERROR] 未找到 MiGetPteAddress");
        UnmapCiImage();
        UnmapKernelImage();
        return;
    }
    PVOID miGetPteAddressFunc = (PBYTE)kernelBase + miGetPteAddressFuncRVA;
    AppendLog(L"[INFO] MiGetPteAddress 地址: 0x%p", miGetPteAddressFunc);

    DWORD64 pteBaseAddress = 0;
    if (gDevice) {
        KernelReadMemory((PBYTE)miGetPteAddressFunc + 19, (PBYTE)&pteBaseAddress, sizeof(pteBaseAddress));
    }
    BYTE uValueA = *(BYTE*)((DWORD64)gKernelImageBase + miGetPteAddressFuncRVA + 0x03);
    DWORD64 uValueB = *(DWORD64*)((DWORD64)gKernelImageBase + miGetPteAddressFuncRVA + 0x06);
    AppendLog(L"[INFO] uValueA=0x%02X, uValueB=0x%llX, PTE基址=0x%llX", uValueA, uValueB, pteBaseAddress);

    DWORD_PTR ciValidateRVA = GetCiValidateImageHeaderRVA();
    if (!ciValidateRVA) {
        AppendLog(L"[ERROR] 未找到 CiValidateImageHeader");
        UnmapCiImage();
        UnmapKernelImage();
        return;
    }
    g_pCiValidateImageHeader = (PVOID)((DWORD_PTR)gCiBase + ciValidateRVA);
    AppendLog(L"[INFO] CiValidateImageHeader 地址: 0x%p", g_pCiValidateImageHeader);

    ULONGLONG address = (ULONGLONG)g_pCiValidateImageHeader;
    g_pPte = (ULONG64*)(((address >> uValueA) & uValueB) + pteBaseAddress);
    AppendLog(L"[INFO] PTE 地址: 0x%p", g_pPte);

    // 执行 hook
    AppendLog(L"[STEP 7] 修改 PTE 写权限并 Hook...");
    if (!KernelReadMemory(g_pPte, (PBYTE)&g_pteValue, sizeof(g_pteValue))) {
        AppendLog(L"[ERROR] 读取 PTE 失败");
        return;
    }
    AppendLog(L"[INFO] 原始 PTE: 0x%llX", g_pteValue);
    ULONG64 newPte = g_pteValue | 2;
    if (!KernelWriteMemory(g_pPte, (PBYTE)&newPte, sizeof(newPte))) {
        AppendLog(L"[ERROR] 修改 PTE 失败");
        return;
    }
    AppendLog(L"[INFO] PTE 已增加写权限");

    if (!KernelReadMemory(g_pCiValidateImageHeader, g_originalBytes, sizeof(g_originalBytes))) {
        AppendLog(L"[ERROR] 读取原始函数字节失败");
        return;
    }
    BYTE hookBytes[] = { 0x48, 0x30, 0xC0, 0xC3 }; // xor rax,rax; ret
    if (!KernelWriteMemory(g_pCiValidateImageHeader, hookBytes, sizeof(hookBytes))) {
        AppendLog(L"[ERROR] Hook 写入失败");
        return;
    }
    AppendLog(L"[SUCCESS] Hook 安装成功，DSE 已绕过！");
    g_bypassActive = true;
    AppendLog(L"========================================");
    AppendLog(L"=== DSE Bypass Active ===");
    AppendLog(L"您现在可以加载未签名的驱动程序");
    AppendLog(L"========================================");
}

void LoadDriverStep()
{
    if (!g_bypassActive) {
        AppendLog(L"[ERROR] 请先完成 DSE 绕过（点击“1. 初始化并绕过DSE”）");
        return;
    }
    wchar_t driverPathW[MAX_PATH] = {0};
    GetWindowTextW(g_hDriverPathEdit, driverPathW, MAX_PATH);
    if (driverPathW[0] == 0) {
        AppendLog(L"[ERROR] 请输入驱动路径");
        return;
    }
    // 去除引号
    if (driverPathW[0] == L'"') {
        int len = wcslen(driverPathW);
        if (len > 2 && driverPathW[len-1] == L'"') {
            memmove(driverPathW, driverPathW+1, (len-2)*sizeof(wchar_t));
            driverPathW[len-2] = 0;
        }
    }
    // 检查文件是否存在
    if (GetFileAttributesW(driverPathW) == INVALID_FILE_ATTRIBUTES) {
        AppendLog(L"[ERROR] 文件不存在: %s", driverPathW);
        return;
    }
    // 转换为 ANSI 以便调用 LoadDriver
    char driverPathA[MAX_PATH];
    WideCharToMultiByte(CP_ACP, 0, driverPathW, -1, driverPathA, MAX_PATH, NULL, NULL);
    const char* lastSlash = strrchr(driverPathA, '\\');
    const char* fname = lastSlash ? lastSlash+1 : driverPathA;
    strcpy_s(g_lastServiceName, fname);
    char* dot = strrchr(g_lastServiceName, '.');
    if (dot) *dot = 0;

    AppendLog(L"[INFO] 加载驱动: %s", driverPathW);
    AppendLogA("[INFO] 服务名: %s", g_lastServiceName);
    if (LoadDriver(driverPathA, g_lastServiceName)) {
        AppendLog(L"[SUCCESS] 驱动加载成功！");
        g_driverLoaded = true;
    } else {
        AppendLog(L"[ERROR] 驱动加载失败，请检查签名或路径");
    }
}

void RestoreAndCleanup()
{
    if (g_bypassActive) {
        AppendLog(L"[INFO] 恢复 Hook 和 PTE...");
        if (g_pCiValidateImageHeader && g_originalBytes[0]) {
            KernelWriteMemory(g_pCiValidateImageHeader, g_originalBytes, sizeof(g_originalBytes));
            AppendLog(L"[INFO] 函数已恢复");
        }
        if (g_pPte) {
            ULONG64 restorePte = g_pteValue & ~2;
            KernelWriteMemory(g_pPte, (PBYTE)&restorePte, sizeof(restorePte));
            AppendLog(L"[INFO] PTE 已恢复");
        }
        g_bypassActive = false;
    }
    if (g_driverLoaded && g_lastServiceName[0]) {
        AppendLogA("[INFO] 卸载驱动 %s...", g_lastServiceName);
        UnloadDriver(g_lastServiceName);
        g_driverLoaded = false;
    }
    CloseDevice();
    UnmapCiImage();
    UnmapKernelImage();
    AppendLog(L"[INFO] 清理完成，设备已关闭");
}

LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg) {
    case WM_CREATE:
        {
            // 允许拖拽文件到窗口
            DragAcceptFiles(hWnd, TRUE);

            CreateWindowW(L"STATIC", L"日志输出:", WS_CHILD | WS_VISIBLE,
                10, 10, 460, 20, hWnd, NULL, NULL, NULL);
            g_hLogEdit = CreateWindowW(L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_READONLY,
                10, 30, 560, 250, hWnd, NULL, NULL, NULL);
            SendMessageW(g_hLogEdit, WM_SETFONT, (WPARAM)GetStockObject(DEFAULT_GUI_FONT), TRUE);

            g_hBtnInit = CreateWindowW(L"BUTTON", L"1. 初始化并绕过DSE", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                10, 290, 180, 30, hWnd, (HMENU)1, NULL, NULL);

            CreateWindowW(L"STATIC", L"驱动路径:", WS_CHILD | WS_VISIBLE,
                10, 330, 60, 20, hWnd, NULL, NULL, NULL);
            g_hDriverPathEdit = CreateWindowW(L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
                80, 330, 350, 22, hWnd, NULL, NULL, NULL);
            // 设置编辑框最大字符长度 (允许长路径)
            SendMessageW(g_hDriverPathEdit, EM_SETLIMITTEXT, MAX_PATH-1, 0);

            g_hBtnLoad = CreateWindowW(L"BUTTON", L"2. 加载驱动", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                440, 330, 130, 22, hWnd, (HMENU)2, NULL, NULL);

            g_hBtnRestore = CreateWindowW(L"BUTTON", L"3. 恢复并退出", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                10, 370, 180, 30, hWnd, (HMENU)3, NULL, NULL);
        }
        break;
    case WM_DROPFILES:
        {
            HDROP hDrop = (HDROP)wParam;
            // 获取第一个拖拽文件路径
            wchar_t filePath[MAX_PATH];
            if (DragQueryFileW(hDrop, 0, filePath, MAX_PATH)) {
                SetWindowTextW(g_hDriverPathEdit, filePath);
            }
            DragFinish(hDrop);
        }
        break;
    case WM_COMMAND:
        {
            int id = LOWORD(wParam);
            if (id == 1) {
                EnableWindow(g_hBtnInit, FALSE);
                InitDriverStep();
                EnableWindow(g_hBtnInit, TRUE);
            } else if (id == 2) {
                EnableWindow(g_hBtnLoad, FALSE);
                LoadDriverStep();
                EnableWindow(g_hBtnLoad, TRUE);
            } else if (id == 3) {
                RestoreAndCleanup();
                PostQuitMessage(0);
            }
        }
        break;
    case WM_DESTROY:
        RestoreAndCleanup();
        PostQuitMessage(0);
        break;
    default:
        return DefWindowProcW(hWnd, msg, wParam, lParam);
    }
    return 0;
}



int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR, int nCmdShow)
{
    // 初始化公共控件
    INITCOMMONCONTROLSEX icc = { sizeof(INITCOMMONCONTROLSEX), ICC_STANDARD_CLASSES };
    InitCommonControlsEx(&icc);

    WNDCLASSW wc = { 0 };
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursorW(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW+1);
    wc.lpszClassName = L"DSEBypassGUI";
    if (!RegisterClassW(&wc)) return 1;

    HWND hWnd = CreateWindowW(L"DSEBypassGUI", L"DSE绕过工具 - RTCore", WS_OVERLAPPEDWINDOW & ~WS_MAXIMIZEBOX & ~WS_THICKFRAME,
        CW_USEDEFAULT, CW_USEDEFAULT, 600, 450, NULL, NULL, hInstance, NULL);
    if (!hWnd) return 1;

    ShowWindow(hWnd, nCmdShow);
    UpdateWindow(hWnd);

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return (int)msg.wParam;
}