//系统头文件
#include <intrin.h>
#include <ntifs.h>
#define STACK_WALK_WEIGHT 20
#define DebugPrint(...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, __VA_ARGS__)
extern "C" {
	NTKERNELAPI UCHAR* PsGetProcessImageFileName(__in PEPROCESS Process);
	NTKERNELAPI
		NTSTATUS
		NTAPI
		ZwQueryInformationProcess(
			_In_      HANDLE           ProcessHandle,
			_In_      PROCESSINFOCLASS ProcessInformationClass,
			_Out_     PVOID            ProcessInformation,
			_In_      ULONG            ProcessInformationLength,
			_Out_opt_ PULONG           ReturnLength
		);
};
typedef enum _PS_PROTECTED_TYPE {
	PsProtectedTypeNone = 0,
	PsProtectedTypeProtectedLight = 1,
	PsProtectedTypeProtected = 2
} PS_PROTECTED_TYPE, * PPS_PROTECTED_TYPE;
typedef enum _PS_PROTECTED_SIGNER {
	PsProtectedSignerNone = 0,
	PsProtectedSignerAuthenticode,
	PsProtectedSignerCodeGen,
	PsProtectedSignerAntimalware,
	PsProtectedSignerLsa,
	PsProtectedSignerWindows,
	PsProtectedSignerWinTcb,
	PsProtectedSignerWinSystem,
	PsProtectedSignerApp,
	PsProtectedSignerMax
} PS_PROTECTED_SIGNER, * PPS_PROTECTED_SIGNER;
typedef struct _PS_PROTECTION {
	union {
		UCHAR Level;
		struct {
			UCHAR Type : 3;
			UCHAR Audit : 1;                  // Reserved
			UCHAR Signer : 4;
		};
	};
} PS_PROTECTION, * PPS_PROTECTION;
namespace Global {
	bool hLoadImageNotify;
};
bool CheckProcessProtect() {
	PS_PROTECTION ProtectInfo = { 0 };
	NTSTATUS ntStatus = ZwQueryInformationProcess(NtCurrentProcess(), ProcessProtectionInformation, &ProtectInfo, sizeof(ProtectInfo), 0ull);
	bool Result1 = false;
	bool Result2 = false;
	if (NT_SUCCESS(ntStatus)) {
		Result1 = ProtectInfo.Type == PsProtectedTypeNone && ProtectInfo.Signer == PsProtectedSignerNone;
		PROCESS_EXTENDED_BASIC_INFORMATION ProcessExtenedInfo = { 0 };
		ntStatus = ZwQueryInformationProcess(NtCurrentProcess(), ProcessBasicInformation, &ProcessExtenedInfo, sizeof(ProcessExtenedInfo), 0ull);
		if (NT_SUCCESS(ntStatus)) {
			Result2 = ProcessExtenedInfo.IsProtectedProcess == false && ProcessExtenedInfo.IsSecureProcess == false;
		}
	}
	return Result2 && Result1;
}
bool CheckStackVAD(PVOID pAddress) {
	bool bResult = false;
	size_t iReturnlength;
	MEMORY_BASIC_INFORMATION MemoryInfomation[sizeof(MEMORY_BASIC_INFORMATION)] = { 0 };
	if (MemoryInfomation) {
		NTSTATUS nt_status = ZwQueryVirtualMemory(NtCurrentProcess(), (PVOID)pAddress, MemoryBasicInformation, MemoryInfomation, sizeof(MEMORY_BASIC_INFORMATION), &iReturnlength);
		if (NT_SUCCESS(nt_status)) {
			bool is_map_memory = (MemoryInfomation->Type == MEM_PRIVATE || MemoryInfomation->Type == MEM_MAPPED) && MemoryInfomation->State == MEM_COMMIT;
			bResult = is_map_memory &&
				(MemoryInfomation->Protect == PAGE_EXECUTE || MemoryInfomation->Protect == PAGE_EXECUTE_READWRITE ||
					MemoryInfomation->Protect == PAGE_EXECUTE_READ || MemoryInfomation->Protect == PAGE_EXECUTE_WRITECOPY);
			if (bResult) {
				DebugPrint("MemoryInfomation->Protect %08X MemoryInfomation->Type %08X \n", MemoryInfomation->Protect, MemoryInfomation->Type);
			}
		}
	}
	return bResult;
}
bool WalkStack(int pHeight)
{
	bool bResult = true;
	PVOID dwStackWalkAddress[STACK_WALK_WEIGHT] = { 0 };
	unsigned __int64  iWalkChainCount = RtlWalkFrameChain(dwStackWalkAddress, STACK_WALK_WEIGHT, 1);
	int iWalkLimit = 0;
	for (unsigned __int64 i = iWalkChainCount; i > 0; i--)
	{
		if (iWalkLimit > pHeight)
			break;
		iWalkLimit++;
		if (CheckStackVAD((PVOID)dwStackWalkAddress[i])) {
			DebugPrint("height: %d address %p \n", i, dwStackWalkAddress[i]);
			bResult = false;
			break;
		}
	}
	return bResult;
}
void LoadImageNotify(PUNICODE_STRING pFullImageName, HANDLE pProcessId, PIMAGE_INFO pImageInfo)
{
	UNREFERENCED_PARAMETER(pFullImageName);
	UNREFERENCED_PARAMETER(pProcessId);
	UNREFERENCED_PARAMETER(pImageInfo);
	if (KeGetCurrentIrql() != PASSIVE_LEVEL)
		return;
	if (PsGetCurrentProcessId() != (HANDLE)4 && PsGetCurrentProcessId() != (HANDLE)0) {
		if (WalkStack(10) == false) {

			DebugPrint("[!!!] CobaltStrike Shellcode Detected Process Name: %s\n", PsGetProcessImageFileName(PsGetCurrentProcess()));
			ZwTerminateProcess(NtCurrentProcess(), 0);
			return;
		}
	}
	return;
}
void DriverUnload(PDRIVER_OBJECT pDriverObject)
{
	UNREFERENCED_PARAMETER(pDriverObject);
	if (Global::hLoadImageNotify)
		PsRemoveLoadImageNotifyRoutine(LoadImageNotify);

	DebugPrint("[DebugMessage] Driver Uninstall \n");
}
extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegPath)
{
	UNREFERENCED_PARAMETER(pDriverObject);
	UNREFERENCED_PARAMETER(pRegPath);
	Global::hLoadImageNotify = NT_SUCCESS(PsSetLoadImageNotifyRoutine(LoadImageNotify));
	if (!Global::hLoadImageNotify) {
		DebugPrint("[DebugMessage] LoadImageNotify failed...\r\n");
		return STATUS_UNSUCCESSFUL;
	}
	pDriverObject->DriverUnload = DriverUnload;
	DebugPrint("[DebugMessage] Driver Installed \n");
	return STATUS_SUCCESS;
}