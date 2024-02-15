#include "stdafx.h"

#ifdef _WIN64
#define __movsp __movsq
#else
#define __movsp __movsd
#endif

#ifdef _X86_

#pragma warning(disable: 4483) // Allow use of __identifier

#define __imp_WaitForSingleObject __identifier("_imp__WaitForSingleObject@8")

#endif

EXTERN_C_START 

extern IMAGE_DOS_HEADER __ImageBase;
extern PVOID __imp_WaitForSingleObject;

EXTERN_C_END

struct RI  
{
	ULONG dwProcessId;
	PVOID BaseAddress;
	SIZE_T RegionSize;
};

BOOL RemapSelfRemote(PWSTR pszCmdLine, 
					 PPROCESS_INFORMATION ppi, 
					 PVOID ImageBase, 
					 PVOID TempBase, 
					 ULONG SizeOfImage,
					 PVOID WaitForSingleObject)
{
	STARTUPINFO si = { sizeof(si) };

	if (CreateProcessW(0, pszCmdLine, 0, 0, FALSE, 0, 0, 0, &si, ppi))
	{
		reinterpret_cast<DWORD (WINAPI*) ( HANDLE , DWORD )>(WaitForSingleObject)(ppi->hProcess, INFINITE);
		__movsp((ULONG_PTR*)ImageBase, (ULONG_PTR*)TempBase, SizeOfImage / sizeof(ULONG_PTR));
		return TRUE;
	}
	
	return FALSE;
}

void RemapSelf()
{
	if (PIMAGE_NT_HEADERS pinth = RtlImageNtHeader(&__ImageBase))
	{
		ULONG SizeOfImage = pinth->OptionalHeader.SizeOfImage;

		if (PVOID TempBase = VirtualAlloc(0, SizeOfImage, MEM_COMMIT, PAGE_EXECUTE_READWRITE))
		{
			memcpy(TempBase, &__ImageBase, SizeOfImage);

			RI ri = { GetCurrentProcessId(), &__ImageBase, SizeOfImage };

			if (PWSTR cmd = new WCHAR[MINSHORT])
			{
				PROCESS_INFORMATION pi;
				const WCHAR regsvr[] = L"regsvr32 /s /u /n /i:\"";
				const WCHAR ss[] = L"\" ";
				wcscpy(cmd, regsvr);
				ULONG cchMax = MINSHORT - _countof(regsvr) + 1, cch = cchMax;
				PWSTR psz = cmd + _countof(regsvr) - 1;
				if (CryptBinaryToStringW((PBYTE)&ri, sizeof(ri), CRYPT_STRING_BASE64|CRYPT_STRING_NOCRLF, psz, &cch) &&
					NOERROR == wcscpy_s(psz += cch, cchMax -= cch, ss) &&
					GetModuleFileNameW((HMODULE)&__ImageBase, psz += _countof(ss) - 1, cchMax - _countof(ss) + 1) &&
					reinterpret_cast<BOOL (*) (PWSTR , 
					PPROCESS_INFORMATION , 
					PVOID , 
					PVOID , 
					ULONG ,
					PVOID )>
					(RtlOffsetToPointer(TempBase, RtlPointerToOffset(&__ImageBase, RemapSelfRemote)))
					(cmd, &pi, &__ImageBase, TempBase, SizeOfImage, __imp_WaitForSingleObject))
				{
					NtClose(pi.hThread);
					NtClose(pi.hProcess);
				}

				delete [] cmd;
			}

			VirtualFree(TempBase, 0, MEM_RELEASE);
		}
	}
}

void ShowErrorBox(HRESULT hr, PCWSTR pzCaption, UINT uType)
{
	WCHAR msg[0x100];

	ULONG dwFlags = FORMAT_MESSAGE_IGNORE_INSERTS|FORMAT_MESSAGE_FROM_SYSTEM;
	HMODULE hmod = 0;

	if ((hr & FACILITY_NT_BIT) || (0 > hr && HRESULT_FACILITY(hr) == FACILITY_NULL))
	{
		hr &= ~FACILITY_NT_BIT;
__nt:
		dwFlags = FORMAT_MESSAGE_FROM_HMODULE | FORMAT_MESSAGE_IGNORE_INSERTS;
		hmod = GetModuleHandle(L"ntdll");
	}
	
	if (FormatMessageW(dwFlags, hmod, hr, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), msg, _countof(msg), 0))
	{
		MessageBoxW(0, msg, pzCaption, uType);
	}
	else if (FORMAT_MESSAGE_FROM_SYSTEM & dwFlags)
	{
		goto __nt;
	}
}

HRESULT WINAPI DllRegisterServer()
{
	NTSTATUS status = STATUS_NO_MEMORY;

	OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, 0, OBJ_CASE_INSENSITIVE };

	SIZE_T cb;
	if (oa.ObjectName = (PUNICODE_STRING)LocalAlloc(LMEM_FIXED, cb =0x10000))
	{
		if (0 > (status = ZwQueryVirtualMemory(NtCurrentProcess(), &__ImageBase, 
			MemoryMappedFilenameInformation, oa.ObjectName, cb, &cb)))
		{
			ShowErrorBox(HRESULT_FROM_NT(status), L"MemoryMappedFilenameInformation", MB_ICONHAND);
		}
		else
		{
			LONG f = 0;
			
			static const PCWSTR sz[] = { L"#2 try delete", L"#1 try delete" };
			ULONG n = _countof(sz);

			do 
			{
				status = ZwDeleteFile(&oa);
				
				ShowErrorBox(status ? HRESULT_FROM_NT(status) : S_OK, sz[--n], status ? MB_ICONWARNING : MB_ICONINFORMATION);
				
				if (!_bittestandset(&f, 0))
				{
					RemapSelf();
				}

			} while (n);
		}

		LocalFree(oa.ObjectName);
	}

	return RtlNtStatusToDosError(status);
}

HRESULT DllInstall(BOOL bInstall, _In_opt_ PCWSTR pszCmdLine)
{
	if (bInstall)
	{
		return DllRegisterServer();
	}
	union {
		const void* pv;
		RI* pri;
		PBYTE pb;
	};

	pv = pszCmdLine;
	ULONG cch = (ULONG)wcslen(pszCmdLine);
	if (CryptStringToBinaryW(pszCmdLine, cch, CRYPT_STRING_BASE64, pb, &cch, 0, 0) && cch == sizeof(RI))
	{
		if (HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pri->dwProcessId))
		{
			NtSuspendProcess(hProcess);
			ZwUnmapViewOfSection(hProcess, pri->BaseAddress);
			ZwAllocateVirtualMemory(hProcess, &pri->BaseAddress, 0, &pri->RegionSize, 
				MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			NtResumeProcess(hProcess);
			NtClose(hProcess);
		}
	}

	return S_OK;
}