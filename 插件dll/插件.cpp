#include <stdio.h>
#include <tchar.h>
#include <string>
#include <Windows.h>
#include <vector>
#include <atlstr.h>
#include <winternl.h>
#include <TlHelp32.h>
#pragma comment(lib, "ntdll.lib")
using namespace std;
int a = 0;
typedef struct DLLINFO {
	LPVOID address;
	TCHAR NAME[100];
};
CHAR QueryArray[5] = { 0 };
CHAR QuerySet[5] = { 0xE9 };
typedef NTSTATUS(WINAPI *NtQueryInformationProcessPtr)(
	HANDLE processHandle,
	PROCESSINFOCLASS processInformationClass,
	PVOID processInformation,
	ULONG processInformationLength,
	PULONG returnLength);
NTSTATUS(WINAPI QueryProc)(
	HANDLE processHandle,
	PROCESSINFOCLASS processInformationClass,
	PVOID processInformation,
	ULONG processInformationLength,
	PULONG returnLength) {
	return false;
}

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

extern"C"
{
	_declspec(dllexport) int GetSizeOfImage(HWND hDlg, DWORD IDProcess)
	{
		//这个函数的作用是获取SizeOfImage的数值
		//当函数执行失败返回的是0
		//成功返回的是非0
		HANDLE hModuleSnap = NULL;
		MODULEENTRY32 stModE = { 0 };
		stModE.dwSize = sizeof(MODULEENTRY32);
		hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, IDProcess);  //快照，对本进程中所有的模块进行snap

		if (hModuleSnap == INVALID_HANDLE_VALUE)
		{
			MessageBox(hDlg, TEXT("The Module snapshot can't get!"), TEXT("Error!"), MB_OK | MB_ICONSTOP);
			return FALSE;    //返回0
		}
		if (!Module32First(hModuleSnap, &stModE))
		{
			MessageBox(hDlg, TEXT("The Module32First can't work!"), TEXT("Error!"), MB_OK | MB_ICONSTOP);
			CloseHandle(hModuleSnap);
			return FALSE;
		}
		CloseHandle(hModuleSnap);
		return stModE.modBaseSize;//初始化为0
	}
	BOOL dumpFun(int id) 
	{
		PROCESSENTRY32 pe = { sizeof(PROCESSENTRY32) };
		HANDLE hPro = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		BOOL isOK = Process32First(hPro, &pe);
		if (isOK == FALSE) {
			return FALSE;
		}
		do {
			if (id == pe.th32ProcessID) {
				SIZE_T imageSize = GetSizeOfImage(NULL, id);
				if (!(imageSize % 0x1000))                          //如果是文件对齐度的整数倍的时候就不处理
					imageSize = imageSize;
				else
					imageSize = (imageSize / 0x1000 + 1) * 0x1000;     //如果不是就增加一个文件对齐度

				TCHAR szBuffer[MAX_PATH] = { 0 };
				OPENFILENAME ofn = { 0 };
				ofn.lStructSize = sizeof(ofn);
				ofn.hwndOwner = NULL;
				ofn.lpstrFilter = _T("Exe文件(*.exe)\0*.exe\0所有文件(*.*)\0*.*\0");//要选择的文件后缀   
				ofn.lpstrInitialDir = _T("D:\\Program Files");//默认的文件路径   
				ofn.lpstrFile = szBuffer;//存放文件的缓冲区   
				ofn.nMaxFile = sizeof(szBuffer) / sizeof(*szBuffer);
				ofn.nFilterIndex = 0;
				ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_EXPLORER;//标志如果是多选要加上OFN_ALLOWMULTISELECT  
				BOOL bSel = GetSaveFileName(&ofn);

				CString path = szBuffer;
				path += ".exe";
				if (bSel) {
					HANDLE pro = OpenProcess(PROCESS_ALL_ACCESS, NULL, id);
					int a = (int)GetModuleHandle(NULL);
					HANDLE hFile = CreateFile(path, GENERIC_WRITE, NULL, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
					WriteFile(hFile, GetModuleHandle(NULL), imageSize, &imageSize, NULL);
					CloseHandle(hFile);
				}

			}
		} while (Process32Next(hPro, &pe));
	}
	extern "C"	__declspec(dllexport) bool __stdcall cmd(char* str, int id) {

		if (strcmp(str,"dump")==0) {
			dumpFun(id);
		}
		return FALSE;
	}

}


