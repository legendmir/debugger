#include<windows.h>
#include<winternl.h>
#pragma comment(lib, "ntdll.lib")
BYTE g_opcode[5];
BYTE g_jmp_opcode[5] = { 0xE9 };

NTSTATUS MySetInformationThread(
	_In_  HANDLE ThreadHandle,
	_In_  THREAD_INFORMATION_CLASS ThreadInformationClass,
	_In_  PVOID ThreadInformation,
	_In_  ULONG ThreadInformationLength
)
{
	MessageBoxA(0, "调用ZwSetInformationThread函数失败", 0, 0);
	return 0;
}


BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		MessageBoxA(0, "注入成功", 0, 0);
		memcpy(g_opcode, MySetInformationThread, 5);
		DWORD old;
		HMODULE hmodule = LoadLibraryA("ntdll.dll");
		FARPROC pfun = GetProcAddress(hmodule, "ZwSetInformationThread");
		VirtualProtect(pfun, 1, PAGE_EXECUTE_READWRITE, &old);

		*(DWORD*)(g_jmp_opcode + 1) = (DWORD)MySetInformationThread - (DWORD)pfun - 5;
		memcpy(pfun, g_jmp_opcode, 5);
	}
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}