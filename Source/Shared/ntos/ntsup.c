/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2011 - 2020 UGN/HE
*
*  TITLE:       NTSUP.C
*
*  VERSION:     2.02
*
*  DATE:        22 July 2020
*
*  Native API support functions.
*
*  Only ntdll-bound import.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "ntsup.h"

/*
* ntsupHeapAlloc
*
* Purpose:
*
* Wrapper for RtlAllocateHeap with process heap.
*
*/
PVOID ntsupHeapAlloc(
    _In_ SIZE_T Size
)
{
    return RtlAllocateHeap(ntsupProcessHeap(), HEAP_ZERO_MEMORY, Size);
}

/*
* ntsupHeapFree
*
* Purpose:
*
* Wrapper for RtlFreeHeap with process heap.
*
*/
VOID ntsupHeapFree(
    _In_ PVOID BaseAddress
)
{
    RtlFreeHeap(ntsupProcessHeap(), 0, BaseAddress);
}

/*
* ntsupVirtualAllocEx
*
* Purpose:
*
* Wrapper for NtAllocateVirtualMemory.
*
*/
PVOID ntsupVirtualAllocEx(
    _In_ SIZE_T Size,
    _In_ ULONG AllocationType,
    _In_ ULONG Protect)
{
    NTSTATUS Status;
    PVOID Buffer = NULL;
    SIZE_T size;

    size = Size;
    Status = NtAllocateVirtualMemory(
        NtCurrentProcess(),
        &Buffer,
        0,
        &size,
        AllocationType,
        Protect);

    if (NT_SUCCESS(Status)) {
        return Buffer;
    }

    RtlSetLastWin32Error(RtlNtStatusToDosError(Status));
    return NULL;
}

/*
* ntsupVirtualAlloc
*
* Purpose:
*
* Wrapper for supVirtualAllocEx.
*
*/
PVOID ntsupVirtualAlloc(
    _In_ SIZE_T Size)
{
    return ntsupVirtualAllocEx(Size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
}

/*
* NtSupVirtualFree
*
* Purpose:
*
* Wrapper for NtFreeVirtualMemory.
*
*/
BOOL ntsupVirtualFree(
    _In_ PVOID Memory)
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    SIZE_T size = 0;

    if (Memory) {
        Status = NtFreeVirtualMemory(
            NtCurrentProcess(),
            &Memory,
            &size,
            MEM_RELEASE);
    }

    RtlSetLastWin32Error(RtlNtStatusToDosError(Status));
    return NT_SUCCESS(Status);
}

/*
* ntsupWriteBufferToFile
*
* Purpose:
*
* Create new file and write buffer to it.
*
*/
SIZE_T ntsupWriteBufferToFile(
    _In_ PWSTR lpFileName,
    _In_ PVOID Buffer,
    _In_ SIZE_T Size,
    _In_ BOOL Flush,
    _In_ BOOL Append
)
{
    NTSTATUS           Status;
    DWORD              dwFlag;
    HANDLE             hFile = NULL;
    OBJECT_ATTRIBUTES  attr;
    UNICODE_STRING     NtFileName;
    IO_STATUS_BLOCK    IoStatus;
    LARGE_INTEGER      Position;
    ACCESS_MASK        DesiredAccess;
    PLARGE_INTEGER     pPosition = NULL;
    ULONG_PTR          nBlocks, BlockIndex;
    ULONG              BlockSize, RemainingSize;
    PBYTE              ptr = (PBYTE)Buffer;
    SIZE_T             BytesWritten = 0;

    if (RtlDosPathNameToNtPathName_U(lpFileName, &NtFileName, NULL, NULL) == FALSE)
        return 0;

    DesiredAccess = FILE_WRITE_ACCESS | SYNCHRONIZE;
    dwFlag = FILE_OVERWRITE_IF;

    if (Append != FALSE) {
        DesiredAccess |= FILE_READ_ACCESS;
        dwFlag = FILE_OPEN_IF;
    }

    InitializeObjectAttributes(&attr, &NtFileName, OBJ_CASE_INSENSITIVE, 0, NULL);

    __try {
        Status = NtCreateFile(&hFile, DesiredAccess, &attr,
            &IoStatus, NULL, FILE_ATTRIBUTE_NORMAL, 0, dwFlag,
            FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, NULL, 0);

        if (!NT_SUCCESS(Status))
            __leave;

        pPosition = NULL;

        if (Append) {
            Position.LowPart = FILE_WRITE_TO_END_OF_FILE;
            Position.HighPart = -1;
            pPosition = &Position;
        }

        if (Size < 0x80000000) {
            BlockSize = (ULONG)Size;
            Status = NtWriteFile(hFile, 0, NULL, NULL, &IoStatus, ptr, BlockSize, pPosition, NULL);
            if (!NT_SUCCESS(Status))
                __leave;

            BytesWritten += IoStatus.Information;
        }
        else {
            BlockSize = 0x7FFFFFFF;
            nBlocks = (Size / BlockSize);
            for (BlockIndex = 0; BlockIndex < nBlocks; BlockIndex++) {

                Status = NtWriteFile(hFile, 0, NULL, NULL, &IoStatus, ptr, BlockSize, pPosition, NULL);
                if (!NT_SUCCESS(Status))
                    __leave;

                ptr += BlockSize;
                BytesWritten += IoStatus.Information;
            }
            RemainingSize = (ULONG)(Size % BlockSize);
            if (RemainingSize != 0) {
                Status = NtWriteFile(hFile, 0, NULL, NULL, &IoStatus, ptr, RemainingSize, pPosition, NULL);
                if (!NT_SUCCESS(Status))
                    __leave;
                BytesWritten += IoStatus.Information;
            }
        }
    }
    __finally {
        if (hFile != NULL) {
            if (Flush) NtFlushBuffersFile(hFile, &IoStatus);
            NtClose(hFile);
        }
        RtlFreeUnicodeString(&NtFileName);
    }
    return BytesWritten;
}

/*
* ntsupFindModuleEntryByName
*
* Purpose:
*
* Find Module entry for given name.
*
*/
PVOID ntsupFindModuleEntryByName(
    _In_ PRTL_PROCESS_MODULES pModulesList,
    _In_ LPCSTR ModuleName
)
{
    ULONG i, modulesCount, fnameOffset;
    LPSTR entryName;
    PRTL_PROCESS_MODULE_INFORMATION moduleEntry;

    modulesCount = pModulesList->NumberOfModules;
    if (modulesCount == 0)
        return NULL;

    for (i = 0; i < modulesCount; i++) {

        moduleEntry = &pModulesList->Modules[i];
        fnameOffset = moduleEntry->OffsetToFileName;
        entryName = (LPSTR)&moduleEntry->FullPathName[fnameOffset];

        if (entryName) {
            if (_strcmpi_a(entryName, ModuleName) == 0)
                return &pModulesList->Modules[i];
        }
    }

    return NULL;
}

/*
* ntsupFindModuleEntryByAddress
*
* Purpose:
*
* Find Module Entry for given Address.
*
*/
BOOL ntsupFindModuleEntryByAddress(
    _In_ PRTL_PROCESS_MODULES pModulesList,
    _In_ PVOID Address,
    _Out_ PULONG ModuleIndex
)
{
    ULONG i, modulesCount;

    *ModuleIndex = 0;

    modulesCount = pModulesList->NumberOfModules;
    if (modulesCount == 0)
        return FALSE;

    for (i = 0; i < modulesCount; i++) {
        if (IN_REGION(Address,
            pModulesList->Modules[i].ImageBase,
            pModulesList->Modules[i].ImageSize))
        {
            *ModuleIndex = i;
            return TRUE;
        }
    }
    return FALSE;
}

/*
* ntsupFindModuleNameByAddress
*
* Purpose:
*
* Find Module Name for given Address.
*
*/
BOOL ntsupFindModuleNameByAddress(
    _In_ PRTL_PROCESS_MODULES pModulesList,
    _In_ PVOID Address,
    _Inout_	LPWSTR Buffer,
    _In_ DWORD ccBuffer //size of buffer in chars
)
{
    ULONG i, modulesCount;
    NTSTATUS ntStatus;
    UNICODE_STRING usConvertedName;
    PRTL_PROCESS_MODULE_INFORMATION moduleEntry;

    if ((pModulesList == NULL) ||
        (Buffer == NULL) ||
        (ccBuffer == 0))
    {
        return FALSE;
    }

    modulesCount = pModulesList->NumberOfModules;
    if (modulesCount == 0) {
        return FALSE;
    }

    RtlInitEmptyUnicodeString(&usConvertedName, NULL, 0);

    for (i = 0; i < modulesCount; i++) {
        if (IN_REGION(Address,
            pModulesList->Modules[i].ImageBase,
            pModulesList->Modules[i].ImageSize))
        {
            moduleEntry = &pModulesList->Modules[i];

            ntStatus = ntsupConvertToUnicode(
                (LPSTR)&moduleEntry->FullPathName[moduleEntry->OffsetToFileName],
                &usConvertedName);

            if (NT_SUCCESS(ntStatus)) {

                _strncpy(
                    Buffer,
                    ccBuffer,
                    usConvertedName.Buffer,
                    usConvertedName.Length / sizeof(WCHAR));

                RtlFreeUnicodeString(&usConvertedName);

                return TRUE;
            }
            else {
                return FALSE;
            }
        }
    }
    return FALSE;
}

/*
* ntsupConvertToUnicode
*
* Purpose:
*
* Convert ANSI string to UNICODE string.
*
* N.B.
* If function succeeded - use RtlFreeUnicodeString to release allocated string.
*
*/
NTSTATUS ntsupConvertToUnicode(
    _In_ LPCSTR AnsiString,
    _Inout_ PUNICODE_STRING UnicodeString)
{
    ANSI_STRING ansiString;

    RtlInitString(&ansiString, AnsiString);
    return RtlAnsiStringToUnicodeString(UnicodeString, &ansiString, TRUE);
}

/*
* ntsupConvertToAnsi
*
* Purpose:
*
* Convert UNICODE string to ANSI string.
*
* N.B.
* If function succeeded - use RtlFreeAnsiString to release allocated string.
*
*/
NTSTATUS ntsupConvertToAnsi(
    _In_ LPCWSTR UnicodeString,
    _Inout_ PANSI_STRING AnsiString)
{
    UNICODE_STRING unicodeString;

    RtlInitUnicodeString(&unicodeString, UnicodeString);
    return RtlUnicodeStringToAnsiString(AnsiString, &unicodeString, TRUE);
}

/*
* ntsupEnablePrivilege
*
* Purpose:
*
* Enable/Disable given privilege.
*
* Return FALSE on any error.
*
*/
BOOL ntsupEnablePrivilege(
    _In_ DWORD PrivilegeName,
    _In_ BOOL fEnable
)
{
    BOOL             bResult = FALSE;
    NTSTATUS         ntStatus;
    ULONG            dummy;
    HANDLE           tokenHandle;
    TOKEN_PRIVILEGES tkPrivs;

    ntStatus = NtOpenProcessToken(
        NtCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
        &tokenHandle);

    if (!NT_SUCCESS(ntStatus)) {
        return bResult;
    }

    tkPrivs.PrivilegeCount = 1;
    tkPrivs.Privileges[0].Luid.LowPart = PrivilegeName;
    tkPrivs.Privileges[0].Luid.HighPart = 0;
    tkPrivs.Privileges[0].Attributes = (fEnable) ? SE_PRIVILEGE_ENABLED : 0;
    ntStatus = NtAdjustPrivilegesToken(tokenHandle, FALSE, &tkPrivs,
        sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PULONG)&dummy);
    if (ntStatus == STATUS_NOT_ALL_ASSIGNED) {
        ntStatus = STATUS_PRIVILEGE_NOT_HELD;
    }
    bResult = NT_SUCCESS(ntStatus);
    NtClose(tokenHandle);
    return bResult;
}

/*
* ntsupGetCurrentProcessToken
*
* Purpose:
*
* Return current process token value with TOKEN_QUERY access right.
*
*/
HANDLE ntsupGetCurrentProcessToken(
    VOID)
{
    HANDLE tokenHandle = NULL;

    if (NT_SUCCESS(NtOpenProcessToken(
        NtCurrentProcess(),
        TOKEN_QUERY,
        &tokenHandle)))
    {
        return tokenHandle;
    }
    return NULL;
}

/*
* ntsupQuerySystemRangeStart
*
* Purpose:
*
* Return MmSystemRangeStart value.
*
*/
ULONG_PTR ntsupQuerySystemRangeStart(
    VOID
)
{
    NTSTATUS  ntStatus;
    ULONG_PTR systemRangeStart = 0;
    ULONG     memIO = 0;

    ntStatus = NtQuerySystemInformation(
        SystemRangeStartInformation,
        (PVOID)&systemRangeStart,
        sizeof(ULONG_PTR),
        &memIO);

    if (!NT_SUCCESS(ntStatus)) {
        RtlSetLastWin32Error(RtlNtStatusToDosError(ntStatus));
    }
    return systemRangeStart;
}

/*
* ntsupIsProcess32bit
*
* Purpose:
*
* Return TRUE if process is wow64.
*
*/
BOOL ntsupIsProcess32bit(
    _In_ HANDLE hProcess
)
{
    ULONG                              returnLength;
    PROCESS_EXTENDED_BASIC_INFORMATION pebi;

    RtlSecureZeroMemory(&pebi, sizeof(pebi));
    pebi.Size = sizeof(PROCESS_EXTENDED_BASIC_INFORMATION);

    if (NT_SUCCESS(NtQueryInformationProcess(
        hProcess,
        ProcessBasicInformation,
        &pebi,
        sizeof(pebi),
        &returnLength)))
    {
        return (pebi.IsWow64Process == 1);
    }

    return FALSE;
}

/*
* supGetSystemInfoEx
*
* Purpose:
*
* Returns buffer with system information by given SystemInformationClass.
*
* Returned buffer must be freed with FreeMem function after usage.
*
*/
PVOID ntsupGetSystemInfoEx(
    _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
    _Out_opt_ PULONG ReturnLength,
    _In_ PNTSUPMEMALLOC AllocMem,
    _In_ PNTSUPMEMFREE FreeMem
)
{
    PVOID       buffer = NULL;
    ULONG       bufferSize = PAGE_SIZE;
    NTSTATUS    ntStatus;
    ULONG       returnedLength = 0;

    if (ReturnLength)
        *ReturnLength = 0;

    buffer = AllocMem((SIZE_T)bufferSize);
    if (buffer == NULL)
        return NULL;

    while ((ntStatus = NtQuerySystemInformation(
        SystemInformationClass,
        buffer,
        bufferSize,
        &returnedLength)) == STATUS_INFO_LENGTH_MISMATCH)
    {
        FreeMem(buffer);
        bufferSize *= 2;

        if (bufferSize > NTQSI_MAX_BUFFER_LENGTH)
            return NULL;

        buffer = AllocMem((SIZE_T)bufferSize);
    }

    if (NT_SUCCESS(ntStatus)) {
        if (ReturnLength)
            *ReturnLength = returnedLength;
        return buffer;
    }

    if (buffer)
        FreeMem(buffer);

    return NULL;
}

/*
* ntsupGetSystemInfo
*
* Purpose:
*
* Returns buffer with system information by given SystemInformationClass.
*
* Returned buffer must be freed with supHeapFree after usage.
*
*/
PVOID ntsupGetSystemInfo(
    _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
    _Out_opt_ PULONG ReturnLength
)
{
    return ntsupGetSystemInfoEx(
        SystemInformationClass,
        ReturnLength,
        (PNTSUPMEMALLOC)ntsupHeapAlloc,
        (PNTSUPMEMFREE)ntsupHeapFree);
}


/*
* ntsupResolveSymbolicLink
*
* Purpose:
*
* Resolve symbolic link target and copy it to the supplied buffer.
*
* Return FALSE on any error.
*
*/
BOOL ntsupResolveSymbolicLink(
    _In_opt_ HANDLE RootDirectoryHandle,
    _In_ PUNICODE_STRING LinkName,
    _Inout_ LPWSTR Buffer,
    _In_ DWORD cbBuffer //size of buffer in bytes
)
{
    BOOL                bResult = FALSE;
    HANDLE              linkHandle = NULL;
    DWORD               cLength = 0;
    NTSTATUS            ntStatus;
    UNICODE_STRING      infoUString;
    OBJECT_ATTRIBUTES   objectAttr;

    if ((cbBuffer == 0) || (Buffer == NULL)) {
        RtlSetLastWin32Error(ERROR_INVALID_PARAMETER);
        return bResult;
    }

    InitializeObjectAttributes(&objectAttr,
        LinkName, OBJ_CASE_INSENSITIVE, RootDirectoryHandle, NULL);

    ntStatus = NtOpenSymbolicLinkObject(&linkHandle,
        SYMBOLIC_LINK_QUERY,
        &objectAttr);

    if (!NT_SUCCESS(ntStatus) || (linkHandle == NULL)) {
        RtlSetLastWin32Error(RtlNtStatusToDosError(ntStatus));
        return bResult;
    }

    cLength = (DWORD)(cbBuffer - sizeof(UNICODE_NULL));
    if (cLength >= MAX_USTRING) {
        cLength = MAX_USTRING - sizeof(UNICODE_NULL);
    }

    infoUString.Buffer = Buffer;
    infoUString.Length = (USHORT)cLength;
    infoUString.MaximumLength = (USHORT)(cLength + sizeof(UNICODE_NULL));

    ntStatus = NtQuerySymbolicLinkObject(linkHandle,
        &infoUString,
        NULL);

    bResult = (NT_SUCCESS(ntStatus));
    NtClose(linkHandle);
    return bResult;
}

/*
* ntsupQueryThreadWin32StartAddress
*
* Purpose:
*
* Lookups thread win32 start address.
*
*/
BOOL ntsupQueryThreadWin32StartAddress(
    _In_ HANDLE ThreadHandle,
    _Out_ PULONG_PTR Win32StartAddress
)
{
    ULONG returnLength;
    NTSTATUS ntStatus;
    ULONG_PTR win32StartAddress = 0;

    ntStatus = NtQueryInformationThread(
        ThreadHandle,
        ThreadQuerySetWin32StartAddress,
        &win32StartAddress,
        sizeof(ULONG_PTR),
        &returnLength);

    if (Win32StartAddress)
        *Win32StartAddress = win32StartAddress;

    return NT_SUCCESS(ntStatus);
}

/*
* ntsupOpenDirectory
*
* Purpose:
*
* Open directory handle with DIRECTORY_QUERY access, with root directory support.
*
*/
HANDLE ntsupOpenDirectory(
    _In_opt_ HANDLE RootDirectoryHandle,
    _In_ LPWSTR DirectoryName,
    _In_ ACCESS_MASK DesiredAccess
)
{
    NTSTATUS          ntStatus;
    HANDLE            directoryHandle = NULL;
    UNICODE_STRING    usDirectory;
    OBJECT_ATTRIBUTES objectAttrbutes;

    RtlInitUnicodeString(&usDirectory, DirectoryName);
    InitializeObjectAttributes(&objectAttrbutes,
        &usDirectory, OBJ_CASE_INSENSITIVE, RootDirectoryHandle, NULL);

    ntStatus = NtOpenDirectoryObject(&directoryHandle,
        DesiredAccess,
        &objectAttrbutes);

    if (!NT_SUCCESS(ntStatus)) {
        RtlSetLastWin32Error(RtlNtStatusToDosError(ntStatus));
        return NULL;
    }

    return directoryHandle;
}


/*
* ntsupQueryProcessName
*
* Purpose:
*
* Lookups process name by given process ID.
*
* If nothing found return FALSE.
*
*/
BOOL ntsupQueryProcessName(
    _In_ ULONG_PTR dwProcessId,
    _In_ PVOID ProcessList,
    _Inout_ LPWSTR Buffer,
    _In_ DWORD ccBuffer //size of buffer in chars
)
{
    ULONG NextEntryDelta = 0;

    union {
        PSYSTEM_PROCESSES_INFORMATION Processes;
        PBYTE ListRef;
    } List;

    List.ListRef = (PBYTE)ProcessList;

    do {

        List.ListRef += NextEntryDelta;

        if ((ULONG_PTR)List.Processes->UniqueProcessId == dwProcessId) {

            _strncpy(
                Buffer,
                ccBuffer,
                List.Processes->ImageName.Buffer,
                List.Processes->ImageName.Length / sizeof(WCHAR));

            return TRUE;
        }

        NextEntryDelta = List.Processes->NextEntryDelta;

    } while (NextEntryDelta);

    return FALSE;
}

/*
* ntsupQueryProcessEntryById
*
* Purpose:
*
* Lookups process entry by given process id.
*
* If nothing found return FALSE.
*
*/
BOOL ntsupQueryProcessEntryById(
    _In_ HANDLE UniqueProcessId,
    _In_ PVOID ProcessList,
    _Out_ PSYSTEM_PROCESSES_INFORMATION* Entry
)
{
    ULONG NextEntryDelta = 0;

    union {
        PSYSTEM_PROCESSES_INFORMATION Processes;
        PBYTE ListRef;
    } List;

    List.ListRef = (PBYTE)ProcessList;

    *Entry = NULL;

    do {

        List.ListRef += NextEntryDelta;

        if (List.Processes->UniqueProcessId == UniqueProcessId) {
            *Entry = List.Processes;
            return TRUE;
        }

        NextEntryDelta = List.Processes->NextEntryDelta;

    } while (NextEntryDelta);

    return FALSE;
}


/*
* ntsupQueryHVCIState
*
* Purpose:
*
* Query HVCI/IUM state.
*
*/
BOOLEAN ntsupQueryHVCIState(
    _Out_ PBOOLEAN pbHVCIEnabled,
    _Out_ PBOOLEAN pbHVCIStrictMode,
    _Out_ PBOOLEAN pbHVCIIUMEnabled
)
{
    BOOLEAN hvciEnabled;
    ULONG returnLength;
    NTSTATUS ntStatus;
    SYSTEM_CODEINTEGRITY_INFORMATION ci;

    if (pbHVCIEnabled) *pbHVCIEnabled = FALSE;
    if (pbHVCIStrictMode) *pbHVCIStrictMode = FALSE;
    if (pbHVCIIUMEnabled) *pbHVCIIUMEnabled = FALSE;

    ci.Length = sizeof(ci);

    ntStatus = NtQuerySystemInformation(
        SystemCodeIntegrityInformation,
        &ci,
        sizeof(ci),
        &returnLength);

    if (NT_SUCCESS(ntStatus)) {

        hvciEnabled = ((ci.CodeIntegrityOptions & CODEINTEGRITY_OPTION_ENABLED) &&
            (ci.CodeIntegrityOptions & CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED));

        if (pbHVCIEnabled)
            *pbHVCIEnabled = hvciEnabled;

        if (pbHVCIStrictMode)
            *pbHVCIStrictMode = hvciEnabled &&
            (ci.CodeIntegrityOptions & CODEINTEGRITY_OPTION_HVCI_KMCI_STRICTMODE_ENABLED);

        if (pbHVCIIUMEnabled)
            *pbHVCIIUMEnabled = (ci.CodeIntegrityOptions & CODEINTEGRITY_OPTION_HVCI_IUM_ENABLED) > 0;

        return TRUE;
    }
    else {
        RtlSetLastWin32Error(RtlNtStatusToDosError(ntStatus));
    }

    return FALSE;
}

/*
* ntsupLookupImageSectionByName
*
* Purpose:
*
* Lookup section pointer and size for section name.
*
*/
PVOID ntsupLookupImageSectionByName(
    _In_ CHAR* SectionName,
    _In_ ULONG SectionNameLength,
    _In_ PVOID DllBase,
    _Out_ PULONG SectionSize
)
{
    BOOLEAN bFound = FALSE;
    ULONG i;
    PVOID Section;
    IMAGE_NT_HEADERS* NtHeaders = RtlImageNtHeader(DllBase);
    IMAGE_SECTION_HEADER* SectionTableEntry;

    //
    // Assume failure.
    //
    if (SectionSize)
        *SectionSize = 0;

    if (NtHeaders == NULL)
        return NULL;

    SectionTableEntry = (PIMAGE_SECTION_HEADER)((PCHAR)NtHeaders +
        sizeof(ULONG) +
        sizeof(IMAGE_FILE_HEADER) +
        NtHeaders->FileHeader.SizeOfOptionalHeader);

    //
    // Locate section.
    //
    i = NtHeaders->FileHeader.NumberOfSections;
    while (i > 0) {

        if (_strncmp_a(
            (CHAR*)SectionTableEntry->Name,
            SectionName,
            SectionNameLength) == 0)
        {
            bFound = TRUE;
            break;
        }

        i -= 1;
        SectionTableEntry += 1;
    }

    //
    // Section not found, abort scan.
    //
    if (!bFound)
        return NULL;

    Section = (PVOID)((ULONG_PTR)DllBase + SectionTableEntry->VirtualAddress);
    if (SectionSize)
        *SectionSize = SectionTableEntry->Misc.VirtualSize;

    return Section;
}

/*
* ntsupOpenProcess
*
* Purpose:
*
* NtOpenProcess wrapper.
*
*/
NTSTATUS ntsupOpenProcess(
    _In_ HANDLE UniqueProcessId,
    _In_ ACCESS_MASK DesiredAccess,
    _Out_ PHANDLE ProcessHandle
)
{
    NTSTATUS ntStatus;
    HANDLE processHandle = NULL;
    OBJECT_ATTRIBUTES objectAttributes = RTL_INIT_OBJECT_ATTRIBUTES((PUNICODE_STRING)NULL, 0);
    CLIENT_ID ClientId;

    ClientId.UniqueProcess = UniqueProcessId;
    ClientId.UniqueThread = NULL;

    ntStatus = NtOpenProcess(
        &processHandle, 
        DesiredAccess, 
        &objectAttributes,
        &ClientId);

    if (NT_SUCCESS(ntStatus)) {
        *ProcessHandle = processHandle;
    }

    return ntStatus;
}

/*
* ntsupOpenThread
*
* Purpose:
*
* NtOpenThread wrapper.
*
*/
NTSTATUS ntsupOpenThread(
    _In_ PCLIENT_ID ClientId,
    _In_ ACCESS_MASK DesiredAccess,
    _Out_ PHANDLE ThreadHandle
)
{
    NTSTATUS ntStatus;
    HANDLE threadHandle = NULL;
    OBJECT_ATTRIBUTES objectAttributes = RTL_INIT_OBJECT_ATTRIBUTES((PUNICODE_STRING)NULL, 0);

    ntStatus = NtOpenThread(
        &threadHandle, 
        DesiredAccess, 
        &objectAttributes,
        ClientId);

    if (NT_SUCCESS(ntStatus)) {
        *ThreadHandle = threadHandle;
    }

    return ntStatus;
}

/*
* ntsupCICustomKernelSignersAllowed
*
* Purpose:
*
* Return license state if present (EnterpriseG).
*
*/
NTSTATUS ntsupCICustomKernelSignersAllowed(
    _Out_ PBOOLEAN bAllowed)
{
    NTSTATUS ntStatus;
    ULONG uLicense = 0, dataSize;
    UNICODE_STRING usLicenseValue = RTL_CONSTANT_STRING(L"CodeIntegrity-AllowConfigurablePolicy-CustomKernelSigners");

    *bAllowed = FALSE;

    ntStatus = NtQueryLicenseValue(
        &usLicenseValue,
        NULL,
        (PVOID)&uLicense,
        sizeof(DWORD),
        &dataSize);

    if (NT_SUCCESS(ntStatus)) {
        *bAllowed = (uLicense != 0);
    }
    return ntStatus;
}

/*
* ntsupPrivilegeEnabled
*
* Purpose:
*
* Tests if the given token has the given privilege enabled/enabled by default.
*
*/
NTSTATUS ntsupPrivilegeEnabled(
    _In_ HANDLE ClientToken,
    _In_ ULONG Privilege,
    _Out_ LPBOOL pfResult
)
{
    NTSTATUS status;
    PRIVILEGE_SET Privs;
    BOOLEAN bResult = FALSE;

    Privs.Control = PRIVILEGE_SET_ALL_NECESSARY;
    Privs.PrivilegeCount = 1;
    Privs.Privilege[0].Luid.LowPart = Privilege;
    Privs.Privilege[0].Luid.HighPart = 0;
    Privs.Privilege[0].Attributes = SE_PRIVILEGE_ENABLED_BY_DEFAULT | SE_PRIVILEGE_ENABLED;

    status = NtPrivilegeCheck(ClientToken, &Privs, &bResult);

    *pfResult = bResult;

    return status;
}

/*
* ntsupExpandEnvironmentStrings
*
* Purpose:
*
* Reimplemented ExpandEnvironmentStrings.
*
*/
DWORD ntsupExpandEnvironmentStrings(
    _In_ LPCWSTR lpSrc,
    _Out_writes_to_opt_(nSize, return) LPWSTR lpDst,
    _In_ DWORD nSize
)
{
    NTSTATUS ntStatus;
    SIZE_T srcLength = 0, returnLength = 0, dstLength = (SIZE_T)nSize;

    if (lpSrc) {
        srcLength = _strlen(lpSrc);
    }

    ntStatus = RtlExpandEnvironmentStrings(
        NULL,
        (PWSTR)lpSrc,
        srcLength,
        (PWSTR)lpDst,
        dstLength,
        &returnLength);

    if ((NT_SUCCESS(ntStatus)) || (ntStatus == STATUS_BUFFER_TOO_SMALL)) {

        if (returnLength <= MAXDWORD32)
            return (DWORD)returnLength;

        ntStatus = STATUS_UNSUCCESSFUL;
    }
    RtlSetLastWin32Error(RtlNtStatusToDosError(ntStatus));
    return 0;
}

/*
* ntsupIsUserHasInteractiveSid
*
* Purpose:
*
* pbInteractiveSid will be set to TRUE if current user has interactive sid, FALSE otherwise.
*
* Function return operation status code.
*
*/
NTSTATUS ntsupIsUserHasInteractiveSid(
    _In_ HANDLE hToken,
    _Out_ PBOOL pbInteractiveSid)
{
    BOOL isInteractiveSid = FALSE;
    NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
    HANDLE heapHandle = NtCurrentPeb()->ProcessHeap;
    ULONG neededLength = 0;

    DWORD i;

    SID_IDENTIFIER_AUTHORITY SidAuth = SECURITY_NT_AUTHORITY;
    PSID pInteractiveSid = NULL;
    PTOKEN_GROUPS groupInfo = NULL;

    do {

        ntStatus = NtQueryInformationToken(
            hToken,
            TokenGroups,
            NULL,
            0,
            &neededLength);

        if (ntStatus != STATUS_BUFFER_TOO_SMALL)
            break;

        groupInfo = (PTOKEN_GROUPS)RtlAllocateHeap(
            heapHandle,
            HEAP_ZERO_MEMORY,
            neededLength);

        if (groupInfo == NULL)
            break;

        ntStatus = NtQueryInformationToken(
            hToken,
            TokenGroups,
            groupInfo,
            neededLength,
            &neededLength);

        if (!NT_SUCCESS(ntStatus))
            break;

        ntStatus = RtlAllocateAndInitializeSid(
            &SidAuth,
            1,
            SECURITY_INTERACTIVE_RID,
            0, 0, 0, 0, 0, 0, 0,
            &pInteractiveSid);

        if (!NT_SUCCESS(ntStatus))
            break;

        for (i = 0; i < groupInfo->GroupCount; i++) {

            if (RtlEqualSid(
                pInteractiveSid,
                groupInfo->Groups[i].Sid))
            {
                isInteractiveSid = TRUE;
                break;
            }
        }

    } while (FALSE);

    if (groupInfo != NULL)
        RtlFreeHeap(heapHandle, 0, groupInfo);

    if (pbInteractiveSid)
        *pbInteractiveSid = isInteractiveSid;

    if (pInteractiveSid)
        RtlFreeSid(pInteractiveSid);

    return ntStatus;
}

/*
* ntsupIsLocalSystem
*
* Purpose:
*
* pbResult will be set to TRUE if current account is run by system user, FALSE otherwise.
*
* Function return operation status code.
*
*/
NTSTATUS ntsupIsLocalSystem(
    _Out_ PBOOL pbResult)
{
    BOOL                            bResult = FALSE;

    NTSTATUS                        ntStatus = STATUS_UNSUCCESSFUL;
    HANDLE                          tokenHandle = NULL;
    HANDLE                          heapHandle = NtCurrentPeb()->ProcessHeap;

    ULONG                           neededLength = 0;

    PSID                            systemSid = NULL;
    PTOKEN_USER                     ptu = NULL;
    SID_IDENTIFIER_AUTHORITY        ntAuthority = SECURITY_NT_AUTHORITY;

    ntStatus = NtOpenProcessToken(
        NtCurrentProcess(),
        TOKEN_QUERY,
        &tokenHandle);

    if (NT_SUCCESS(ntStatus)) {

        ntStatus = NtQueryInformationToken(
            tokenHandle,
            TokenUser,
            NULL,
            0,
            &neededLength);

        if (ntStatus == STATUS_BUFFER_TOO_SMALL) {

            ptu = (PTOKEN_USER)RtlAllocateHeap(
                heapHandle,
                HEAP_ZERO_MEMORY,
                neededLength);

            if (ptu) {

                ntStatus = NtQueryInformationToken(
                    tokenHandle,
                    TokenUser,
                    ptu,
                    neededLength,
                    &neededLength);

                if (NT_SUCCESS(ntStatus)) {

                    ntStatus = RtlAllocateAndInitializeSid(
                        &ntAuthority,
                        1,
                        SECURITY_LOCAL_SYSTEM_RID,
                        0, 0, 0, 0, 0, 0, 0,
                        &systemSid);

                    if (NT_SUCCESS(ntStatus)) {

                        bResult = RtlEqualSid(
                            ptu->User.Sid,
                            systemSid);

                        RtlFreeSid(systemSid);
                    }

                }
                RtlFreeHeap(heapHandle, 0, ptu);
            }
            else {
                ntStatus = STATUS_INSUFFICIENT_RESOURCES;
            }
        } //STATUS_BUFFER_TOO_SMALL
        NtClose(tokenHandle);
    }

    if (pbResult)
        *pbResult = bResult;

    return ntStatus;
}

/*
* ntsupGetProcessElevationType
*
* Purpose:
*
* Returns process elevation type.
*
*/
BOOL ntsupGetProcessElevationType(
    _In_opt_ HANDLE ProcessHandle,
    _Out_ TOKEN_ELEVATION_TYPE * lpType
)
{
    HANDLE tokenHandle = NULL, processHandle = ProcessHandle;
    NTSTATUS ntStatus;
    ULONG returnedLength = 0;
    TOKEN_ELEVATION_TYPE tokenType = TokenElevationTypeDefault;

    if (ProcessHandle == NULL) {
        processHandle = GetCurrentProcess();
    }

    ntStatus = NtOpenProcessToken(processHandle, TOKEN_QUERY, &tokenHandle);
    if (NT_SUCCESS(ntStatus)) {

        ntStatus = NtQueryInformationToken(
            tokenHandle,
            TokenElevationType,
            &tokenType,
            sizeof(TOKEN_ELEVATION_TYPE),
            &returnedLength);

        NtClose(tokenHandle);
    }

    if (lpType)
        *lpType = tokenType;

    return (NT_SUCCESS(ntStatus));
}

/*
* ntsupIsProcessElevated
*
* Purpose:
*
* Returns process elevation state.
*
*/
NTSTATUS ntsupIsProcessElevated(
    _In_ ULONG ProcessId,
    _Out_ PBOOL Elevated)
{
    NTSTATUS ntStatus;
    ULONG returnedLength;
    HANDLE processHandle = NULL, tokenHandle = NULL;
    TOKEN_ELEVATION tokenInfo;

    if (Elevated) *Elevated = FALSE;

    ntStatus = ntsupOpenProcess(
        UlongToHandle(ProcessId), 
        MAXIMUM_ALLOWED, 
        &processHandle);
    
    if (NT_SUCCESS(ntStatus)) {

        ntStatus = NtOpenProcessToken(processHandle, TOKEN_QUERY, &tokenHandle);
        if (NT_SUCCESS(ntStatus)) {

            tokenInfo.TokenIsElevated = 0;
            ntStatus = NtQueryInformationToken(
                tokenHandle,
                TokenElevation,
                &tokenInfo,
                sizeof(TOKEN_ELEVATION),
                &returnedLength);

            if (NT_SUCCESS(ntStatus)) {

                if (Elevated)
                    *Elevated = (tokenInfo.TokenIsElevated > 0);

            }

            NtClose(tokenHandle);
        }
        NtClose(processHandle);
    }

    return ntStatus;
}


/*
* ntsupGetMappedFileName
*
* Purpose:
*
* Checks whether the specified address is within a memory-mapped file.
* If so, the function returns the name of the memory-mapped file.
*
*/
ULONG ntsupGetMappedFileName(
    _In_ PVOID BaseAddress,
    _Inout_ LPWSTR FileName,
    _In_ ULONG cchFileName,
    _Out_ PSIZE_T cbNeeded
)
{
    OBJECT_NAME_INFORMATION *ObjectNameInfo;
    NTSTATUS ntStatus;
    SIZE_T returnedLength = 0;
    ULONG errorCode, copyLength = 0;
    HANDLE processHeap = NtCurrentPeb()->ProcessHeap;

    *cbNeeded = 0;

    if (cchFileName == 0) {
        RtlSetLastWin32Error(ERROR_INSUFFICIENT_BUFFER);
        return 0;
    }

    //
    // Don't be like MS authors and ask actual size.
    //
    ntStatus = NtQueryVirtualMemory(
        NtCurrentProcess(),
        BaseAddress,
        MemoryMappedFilenameInformation,
        NULL,
        0,
        &returnedLength);

    if (ntStatus != STATUS_INFO_LENGTH_MISMATCH) {
        RtlSetLastWin32Error(RtlNtStatusToDosError(ntStatus));
        return 0;
    }

    //
    // Allocate required buffer.
    //
    ObjectNameInfo = (OBJECT_NAME_INFORMATION*)RtlAllocateHeap(
        processHeap,
        HEAP_ZERO_MEMORY, 
        returnedLength);

    if (ObjectNameInfo == NULL) {
        RtlSetLastWin32Error(ERROR_NOT_ENOUGH_MEMORY);
        return 0;
    }

    //
    // Query information.
    //
    ntStatus = NtQueryVirtualMemory(
        NtCurrentProcess(),
        BaseAddress,
        MemoryMappedFilenameInformation,
        ObjectNameInfo,
        returnedLength,
        &returnedLength);

    if (NT_SUCCESS(ntStatus)) {

        //
        // Copy filename.
        //
        copyLength = ObjectNameInfo->Name.Length >> 1;
        if (cchFileName > copyLength + 1) {
            errorCode = ERROR_SUCCESS;
        }
        else {
            *cbNeeded = ((SIZE_T)copyLength + 1) * sizeof(WCHAR);
            copyLength = cchFileName - 1;
            errorCode = ERROR_INSUFFICIENT_BUFFER;
        }

        RtlSetLastWin32Error(errorCode);

        if (copyLength) {

            RtlCopyMemory(
                FileName,
                ObjectNameInfo->Name.Buffer,
                copyLength * sizeof(WCHAR));

            FileName[copyLength] = 0;

        }

    }
    else {
        RtlSetLastWin32Error(RtlNtStatusToDosError(ntStatus));
    }

    RtlFreeHeap(processHeap, 0, ObjectNameInfo);
    return copyLength;
}