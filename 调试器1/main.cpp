#include <windows.h>
#include "debugRegisters.h"
#include <vector>
#include <DbgHelp.h>
#include<TlHelp32.h>
#include<Winternl.h>
#include<string.h>

#define BEA_ENGINE_STATIC
#define BEA_USE_STDCALL
#include "BeaEngine_4.1\\Win32\\headers\\BeaEngine.h"

//1. ����ͷ�ļ�
#include "keystone/keystone.h"

//2. ������̬��
#pragma comment (lib,"keystone/x86/keystone_x86.lib")

#ifdef _WIN64
#pragma comment(lib,"BeaEngine_4.1\\Win64\\Win64\\Lib\\BeaEngine.lib")
#else
#pragma comment(lib,"BeaEngine_4.1\\Win32\\Win32\\Lib\\BeaEngine.lib")
#endif // _WIN32
#pragma comment(linker, "/NODEFAULTLIB:\"crt.lib\"")
#pragma comment(lib, "legacy_stdio_definitions.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "DbgHelp.lib")


#ifdef _DEBUG
#define DBG(str) printf("%s %s %d: %s\n",__FILE__,__FUNCTION__,__LINE__,str);
#define DBG_EXIT(str) printf("%s %s %d: %s\n",__FILE__,__FUNCTION__,__LINE__,str); exit(0);
#else
#define DBG(str) 
#endif // _DEBUG

typedef struct _CONDITIONBP
{
	char reg[5]{};
	DWORD val;
}CONDITIONBP;

char g_path[MAX_PATH];
HMODULE g_hmodule;



int g_num;
BOOL g_isdedebg;
PROCESS_INFORMATION g_pi{};
HANDLE g_proc;
HANDLE g_thread;
BOOL   g_isdbg_tf;
BOOL   g_ismem_access_bp;
BOOL   g_isconditon_dbg;

DWORD  g_hard_exec_bp;
DWORD  g_hard_rw_bp;
DWORD	g_mem_access_bp;
DWORD   g_mem_access_rw_bp;
CONDITIONBP g_condition_bp;
enum show_type {type_show_disasm_reg,type_show_stack,type_show_mem,type_show_module};
std::vector<LOAD_DLL_DEBUG_INFO> g_dll_info;




void user_input(EXCEPTION_RECORD* pexcept, CONTEXT* ct);//�û�����ָ��
void show_present_info(EXCEPTION_RECORD* pexcept, CONTEXT* ct, int type);//��ʾ��ǰ��Ϣ(��ַ,�����,�Ĵ���..)
void set_bp_tf();//�����ж϶ϵ�
bool set_bp_int3(LPVOID address);//��������ϵ�
void restore_bp_int3(LPVOID address);//�ָ�����ϵ�
void mod_mem(LPVOID address, BYTE newdata);//�޸��ڴ�
bool set_bp_hard_exec(DWORD addr);//Ӳ��ִ�жϵ�
bool set_bp_hard_rw(DWORD addr,int len);//Ӳ����д�ϵ�



typedef struct _BREAKPOINT {
	LPVOID address;
	BYTE   old_data;// ����int3�ϵ㸲�ǵ�1�ֽ�����
}BREAKPOINT;
std::vector<BREAKPOINT> g_vec_bp;// �ϵ��б�


// ����TF��������ϵ�
void set_bp_tf() {
	// 1. ��ȡ�߳�������
	CONTEXT ct = { CONTEXT_CONTROL };
	if (!GetThreadContext(g_thread, &ct)) {
		DBG("��ȡ�߳�������ʧ��");
	}
	EFLAGS* pEflags = (EFLAGS*)&ct.EFlags;
	// 2. �޸�TF��־λ
	pEflags->TF = 1;

	// 3. �����߳�������
	if (!SetThreadContext(g_thread, &ct)) {
		DBG("�����߳�������ʧ��");
	}
}

bool set_bp_int3(LPVOID address) {
	BREAKPOINT bp = { 0 };
	//1. ���¶ϵ�ĵ�ַ��1�ֽڵ����ݱ���
	SIZE_T read = 0;
	if (!ReadProcessMemory(g_proc, address, &bp.old_data, 1, &read)) {
		DBG_EXIT("��ȡ�����ڴ�ʧ��");
		return false;
	}
	//2. ��0xCCд���¶ϵ�ĵ�ַ
	if (!WriteProcessMemory(g_proc, address, "\xCC", 1, &read)) {
		DBG_EXIT("д������ڴ�ʧ��");
		return false;
	}
	bp.address = address;
	g_vec_bp.push_back(bp);
	return true;
}
void restore_bp_int3(LPVOID address) {
	// 1. ���ֽڸ��ǻ�ȥ
	SIZE_T write = 0;
	for (auto& i : g_vec_bp) {
		if (i.address == address) {
			if (!WriteProcessMemory(g_proc, i.address, &i.old_data, 1, &write)) {
				DBG("д������ڴ�ʧ��");
			}
			// 2. ���߳������ĵ�eip--
			CONTEXT ct = { CONTEXT_CONTROL };
			if (!GetThreadContext(g_thread, &ct)) {
				DBG("��ȡ�߳�������ʧ��\n");
			}
			ct.Eip--;
			if (!SetThreadContext(g_thread, &ct)) {
				DBG("�����߳�������ʧ��\n");
			}
			// ����һ�������ϵ�, �������°�װint3�ϵ�.
			set_bp_tf();
			g_isdbg_tf = TRUE;
		}
	}
}

bool set_bp_hard_exec(DWORD addr)
{
	CONTEXT ct = { CONTEXT_DEBUG_REGISTERS };
	GetThreadContext(g_thread, &ct);
	DBG_REG7* pdr7 = (DBG_REG7*)&ct.Dr7;
	if (pdr7->L0 == 0)
	{
		ct.Dr0 = addr;
		pdr7->RW0 = 0;
		pdr7->LEN0 = 0;
		pdr7->L0 = 1;
	}
	else if (pdr7->L1 == 0)
	{
		ct.Dr1 = addr;
		pdr7->RW1 = 0;
		pdr7->LEN1 = 0;
		pdr7->L1 = 1;
	}
	else if (pdr7->L2 == 0)
	{
		ct.Dr2 = addr;
		pdr7->RW2 = 0;
		pdr7->LEN2 = 0;
		pdr7->L2= 1;
	}
	else if (pdr7->L3 == 0)
	{
		ct.Dr3 = addr;
		pdr7->RW3 = 0;
		pdr7->LEN3 = 0;
		pdr7->L3 = 1;
	}
	else
	{
		return false;
	}
	SetThreadContext(g_thread, &ct);
	g_hard_exec_bp = addr;
	return true;
}
void restore_bp_hard_exec(DWORD addr)
{
	CONTEXT ct = { CONTEXT_DEBUG_REGISTERS };
	SetThreadContext(g_thread, &ct);
}
bool set_bp_hard_rw(DWORD addr, int len)
{
	CONTEXT ct = { CONTEXT_DEBUG_REGISTERS };
	GetThreadContext(g_thread, &ct);
	if (len == 1)
	{
		addr = addr - addr % 2;
	}
	else if (len == 3)
	{
		addr = addr - addr % 4;
	}


	DBG_REG7* pdr7 = (DBG_REG7*)&ct.Dr7;
	if (pdr7->L0 == 0)
	{
		ct.Dr0 = addr;
		pdr7->RW0 = 3;
		pdr7->LEN0 = len;
		pdr7->L0 = 1;
	}
	else if (pdr7->L1 == 0)
	{
		ct.Dr1 = addr;
		pdr7->RW1 = 3;
		pdr7->LEN1 = len;
		pdr7->L1 = 1;
	}
	else if (pdr7->L2 == 0)
	{
		ct.Dr2 = addr;
		pdr7->RW2 = 3;
		pdr7->LEN2 = len;
		pdr7->L2 = 1;
	}
	else if (pdr7->L3 == 0)
	{
		ct.Dr3 = addr;
		pdr7->RW3 = 3;
		pdr7->LEN3 = len;
		pdr7->L3 = 1;
	}
	else
	{
		return false;
	}
	SetThreadContext(g_thread, &ct);
	g_hard_rw_bp = addr;
	return true;
}


bool set_bp_mem_access_exec(DWORD addr)
{
	DWORD old;
	VirtualProtectEx(g_proc, (LPVOID)addr, 1, PAGE_READONLY, &old);
	g_mem_access_bp = addr;
	g_ismem_access_bp = 1;
	return true;
}
void set_bp_mem_access_rw(DWORD addr)
{
	g_mem_access_rw_bp = addr;
	DWORD old;
	VirtualProtectEx(g_proc, (LPVOID)addr, 1, PAGE_READONLY, &old);
}


void set_condition_bp(char* regname,DWORD addr)
{
	strcpy_s(g_condition_bp.reg, regname);
	g_condition_bp.val = addr;
	set_bp_tf();
	g_isconditon_dbg = 1;
}


void show_present_info(EXCEPTION_RECORD* pexcept, CONTEXT* ct,int type)
{
	if (type == type_show_disasm_reg)
	{
		int len = 10;
		printf("�ϵ��ڵ�ַ%08X�ϴ���\n", pexcept->ExceptionAddress);
		// ��������Ĳ���:
		LPBYTE opcode = new BYTE[len * 16];
		SIZE_T dwRead = 0;
		// 1. �õ�������
		if (!ReadProcessMemory(g_proc, (LPCVOID)ct->Eip, opcode, len * 16, &dwRead)) {
			DBG_EXIT("��ȡ�����ڴ�ʧ��");
		}
		// 2. ʹ�÷���������ȡ�������Ӧ�Ļ��
		DISASM da = { 0 };
		da.EIP = (UIntPtr)opcode;
		da.VirtualAddr = (UINT64)ct->Eip;
#ifdef _WIN64
		da.Archi = 64;
#else
		da.Archi = 0;
#endif // _WIN64
		while (len--)
		{
			int ret = Disasm(&da);
			if (ret == -1)
			{/*����-1��ʾ�������޷��ҵ���Ӧ�Ļ��ָ��*/
				break;
			}

			// 3. ���.
			if (len == 9)
			{
				printf("%I64X | %-40s | EAX: %08X\n", da.VirtualAddr, da.CompleteInstr,ct->Eax);
			}							    
			if (len == 8)				    
			{							    
				printf("%I64X | %-40s | ECX: %08X\n", da.VirtualAddr, da.CompleteInstr, ct->Ecx);
			}							    
			if (len == 7)				    
			{							    
				printf("%I64X | %-40s | EDX: %08X\n", da.VirtualAddr, da.CompleteInstr, ct->Edx);
			}							    
			if (len == 6)				    
			{							    
				printf("%I64X | %-40s | EBX: %08X\n", da.VirtualAddr, da.CompleteInstr, ct->Ebx);
			}							    
			if (len == 5)				    
			{							    
				printf("%I64X | %-40s | ESP: %08X\n", da.VirtualAddr, da.CompleteInstr, ct->Esp);
			}							    
			if (len == 4)				    
			{							    
				printf("%I64X | %-40s | EBP: %08X\n", da.VirtualAddr, da.CompleteInstr, ct->Ebp);
										    
			}							    
			if (len == 3)				    
			{							    
				printf("%I64X | %-40s | ESI: %08X\n", da.VirtualAddr, da.CompleteInstr, ct->Esi);
			}							    
			if (len == 2)				    
			{							    
				printf("%I64X | %-40s | EDI: %08X\n", da.VirtualAddr, da.CompleteInstr, ct->Edi);
			}							    
			if (len == 1)				    
			{							    
				printf("%I64X | %s       \n", da.VirtualAddr, da.CompleteInstr);
			}							    
			if (len == 0)				    
			{							    
				printf("%I64X | %-40s | EIP: %08X\n", da.VirtualAddr, da.CompleteInstr, ct->Eip);
			}
			da.VirtualAddr += ret;
			da.EIP += ret;
		}
	}
	if(type==type_show_stack)
	{ 
		printf("��ջ��Ϣ��\n");
		int num = (ct->Ebp - ct->Esp) / 4;
		DWORD esp = ct->Esp;
		while (num-->-1)
		{
			DWORD buff = 0;
			SIZE_T read = 0;
			ReadProcessMemory(g_proc, (LPCVOID)esp, &buff, 4, &read);
			printf("%08X | %08X\n", esp,buff);
			esp += 4;
		}
	}
	if (type == type_show_mem)
	{
		int len = 10;
		DWORD addr = ct->Eip;
		for (int j = 0;j < len;j++)
		{
			LPBYTE opcode = new BYTE[16];
			SIZE_T dwRead = 0;
			// 1. �õ�������
			if (!ReadProcessMemory(g_proc, (LPCVOID)addr, opcode, 16, &dwRead)) {
				DBG_EXIT("��ȡ�����ڴ�ʧ��");
			}
			printf("%08X|", addr);
			for (int i = 0;i < 16;i++)
			{
				if (i == 15)
				{
					printf("%02X\n", opcode[i]);
				}
				else if (i % 4 == 3)
				{
					printf("%02X|", opcode[i]);
				}
				else
				{
					printf("%02X ", opcode[i]);
				}
			}
			delete opcode;
			addr += 16;
		}
	}
	if (type == type_show_module)
	{
		printf("ģ������\n");
		MODULEENTRY32 me = { sizeof(MODULEENTRY32) };
		HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, g_pi.dwProcessId);
		Module32First(hSnap, &me);
		do
		{
			int len = wcslen(me.szModule);
			char* pname = new char[50];
			memset(pname, 0, 50);
			WideCharToMultiByte(CP_ACP, 0, me.szModule,len, pname,len*2, NULL, NULL);
			printf("%s\n", pname);
		} while (Module32Next(hSnap, &me));
	}
}

void mod_mem(LPVOID address, BYTE newdata)
{
	SIZE_T write = 0;
	DWORD old = 0;
	if (!VirtualProtectEx(g_proc, address, 1, PAGE_EXECUTE_READWRITE, &old))
	{
		printf("�޸��ڴ�ʧ��!");
	}
	if (WriteProcessMemory(g_proc, address, &newdata, 1, &write))
	{
		printf("�޸ĳɹ�!\n");
	}
}

void mod_reg(char* str, DWORD newdata, CONTEXT* ct)
{
	if (strcmp(str, "eax") == 0)
	{
		ct->Eax = newdata;
	}
}

bool mod_asm()
{
	DWORD addr = 0;
	char a[10]{};
	printf("�������ַ:");
	scanf("%X", &addr);
	getchar();
	printf("��������ָ��:");
	gets_s(a, 10);

	ks_engine *pengine = NULL;
	if (KS_ERR_OK != ks_open(KS_ARCH_X86, KS_MODE_32, &pengine))
	{
		printf("����������ʼ��ʧ��\n");
		return 0;
	}
	unsigned char* opcode = NULL; // ���õ���opcode�Ļ������׵�ַ
	unsigned int nOpcodeSize = 0; // ��������opcode���ֽ���

	int nRet = 0; // ���溯���ķ���ֵ�������жϺ����Ƿ�ִ�гɹ�
	size_t stat_count = 0; // ����ɹ�����ָ�������

	nRet = ks_asm(pengine, /* �����������ͨ��ks_open�����õ�*/
		a, /*Ҫת���Ļ��ָ��*/
		(DWORD)a, /*���ָ�����ڵĵ�ַ*/
		&opcode,/*�����opcode*/
		&nOpcodeSize,/*�����opcode���ֽ���*/
		&stat_count /*����ɹ�����ָ�������*/
	);
	DWORD write = 0;
	WriteProcessMemory(g_proc, (PVOID)addr, opcode, nOpcodeSize, &write);
	printf("�޸ĳɹ�\n");
	
}

void show_export(char* str)
{
	DWORD addr = 0;

	for (auto& i : g_dll_info)
	{
		DWORD pfile;
		DWORD read1 = 0;
		DWORD addr;
		DWORD read2 = 0;
		DWORD read3 = 0;

		IMAGE_DOS_HEADER* pdos = new IMAGE_DOS_HEADER[sizeof(IMAGE_DOS_HEADER)];
		ReadProcessMemory(g_proc, i.lpBaseOfDll,pdos, sizeof(IMAGE_DOS_HEADER),&read1);
		DWORD dw_nt = (DWORD)i.lpBaseOfDll + pdos->e_lfanew;
		IMAGE_NT_HEADERS* pnt = new IMAGE_NT_HEADERS[sizeof(IMAGE_NT_HEADERS)];
		ReadProcessMemory(g_proc, (LPCVOID)dw_nt, pnt, sizeof(IMAGE_NT_HEADERS), &read2);

	

		IMAGE_EXPORT_DIRECTORY* pout_tab = new IMAGE_EXPORT_DIRECTORY[sizeof(IMAGE_EXPORT_DIRECTORY)];
		DWORD dw_exptable = (DWORD)i.lpBaseOfDll + pnt->OptionalHeader.DataDirectory[0].VirtualAddress;
		ReadProcessMemory(g_proc, (LPCVOID)dw_exptable, pout_tab, sizeof(IMAGE_EXPORT_DIRECTORY), &read3);

		char pname[30];
		memset(pname, 0, 30);
		DWORD read4 = 0;
		ReadProcessMemory(g_proc, LPCVOID((DWORD)i.lpBaseOfDll + pout_tab->Name), pname, 30, &read4);
		if (strcmp(pname, str) == 0)
		{
			DWORD dw_paof = pout_tab->AddressOfFunctions + SIZE_T(i.lpBaseOfDll);//��ַ��
			DWORD dw_paon = pout_tab->AddressOfNames + SIZE_T(i.lpBaseOfDll);//���Ʊ�
			DWORD read5 = 0;
			DWORD read6 = 0;
			DWORD* paof = new DWORD[pout_tab->NumberOfNames]{};
			DWORD* paon = new DWORD[pout_tab->NumberOfNames]{};
			ReadProcessMemory(g_proc, (LPCVOID)(dw_paof), paof, pout_tab->NumberOfNames*4, &read5);
			ReadProcessMemory(g_proc, (LPCVOID)(dw_paon), paon, pout_tab->NumberOfNames*4, &read6);
			for (DWORD j = 0;j < pout_tab->NumberOfNames;j++)
			{
				DWORD name_table =((DWORD)i.lpBaseOfDll + paon[j]);
				char *name = new char[70]{};
				//DWORD addr = 0;
				DWORD read = 0;
				char byte = 0;
				int num = 0;
				ReadProcessMemory(g_proc, (LPCVOID)((DWORD)i.lpBaseOfDll + paof[j]), &addr, 4, &read);
				do
				{
					byte = 0;
					ReadProcessMemory(g_proc, (LPCVOID)name_table, &byte, 1, &read);
					name[num] = byte;
					num++;
					name_table++;
				} while (byte!=0);
				printf("%-60s %08X\n", name, addr);
				delete[]name;
			}
			break;
		}
	}
}

DWORD rva2foa(IMAGE_NT_HEADERS* pnt, DWORD dwrva)
{
	IMAGE_SECTION_HEADER* p_sectionhdr //����ͷfoa
		= (IMAGE_SECTION_HEADER*)((DWORD)&pnt->OptionalHeader + pnt->FileHeader.SizeOfOptionalHeader);//ntͷrva
	for (DWORD i = 0;i < pnt->FileHeader.NumberOfSections;i++)
	{
		if (dwrva <= p_sectionhdr[i].VirtualAddress + p_sectionhdr[i].SizeOfRawData&&dwrva >= p_sectionhdr[i].VirtualAddress)
		{
			return dwrva - p_sectionhdr[i].VirtualAddress + p_sectionhdr[i].PointerToRawData;
		}
	}
	return -1;
}


void show_import(char* str)
{
	for (auto& i : g_dll_info)
	{
		DWORD size = GetFileSize(i.hFile, 0);
		LPBYTE ptr = new BYTE[size];
		DWORD dwsize = 0;
		ReadFile(i.hFile, ptr, size, &dwsize, 0);
		IMAGE_DOS_HEADER* pdos = (IMAGE_DOS_HEADER*)ptr;
		IMAGE_NT_HEADERS* pnt = (IMAGE_NT_HEADERS*)(ptr + pdos->e_lfanew);

		DWORD foa = rva2foa(pnt, pnt->OptionalHeader.DataDirectory[1].VirtualAddress);
		IMAGE_IMPORT_DESCRIPTOR* pimptab = (IMAGE_IMPORT_DESCRIPTOR*)((SIZE_T)ptr + foa);
		DWORD foa_name = rva2foa(pnt, pimptab->Name);

		IMAGE_THUNK_DATA* piat = (IMAGE_THUNK_DATA*)(rva2foa(pnt, pimptab->FirstThunk) + (SIZE_T)pdos);
		char* pname = (char*)((DWORD)pdos + foa_name);
		if (strcmp(pname, str) == 0)
		{
			while (piat->u1.Ordinal)
			{
				if (IMAGE_SNAP_BY_ORDINAL(piat->u1.Ordinal) == 0)
				{
					IMAGE_IMPORT_BY_NAME* p = (IMAGE_IMPORT_BY_NAME*)((SIZE_T)pdos + rva2foa(pnt, piat->u1.AddressOfData));
					printf("%-10d%s\n", p->Hint, p->Name);
				}
				piat++;
			}
			break;
		}
	}
}

void user_input(EXCEPTION_RECORD* pexcept, CONTEXT* ct)
{
	while (true)
	{

		CONTEXT ct1 = { CONTEXT_ALL };
		GetThreadContext(g_thread, &ct1);
		char cmd[100];
		printf("����>");
		gets_s(cmd, 100);
		if (_stricmp(cmd, "t") == 0) {

			set_bp_tf();
			break;
		}
		else if (_stricmp(cmd, "j") == 0)
		{
			LPBYTE opcode = new BYTE[16]{};
			DISASM da = { 0 };
			DWORD dwRead = 0;
			ReadProcessMemory(g_proc, (LPCVOID)ct->Eip, opcode, 16, &dwRead);
			da.EIP = (UIntPtr)opcode;
			da.VirtualAddr = (UINT64)ct1.Eip;

			int len = Disasm(&da);
			da.VirtualAddr += len;
			da.EIP += len;

			if (_stricmp(da.Instruction.Mnemonic, "call ") == 0 || _stricmp(da.Instruction.Mnemonic, "rep ") == 0)
			{
				Disasm(&da);
				set_bp_int3((LPVOID)da.VirtualAddr);
			}
			else
			{
				set_bp_tf();
			}
			break;
		}
		else if (_stricmp(cmd, "g") == 0) {
			break;
		}
		else if (_stricmp(cmd, "set bp") == 0) {
			SIZE_T addr = 0;
			printf("�����¶ϵ�ַ:");
			scanf_s("%8X", &addr);
			if (set_bp_int3((LPVOID)addr))
			{
				printf("�¶ϵ�ɹ�\n");
				getchar();
			}
		}
		else if (_stricmp(cmd, "set he") == 0)
		{
			DWORD addr;
			printf("�������ַ:");
			scanf("%8X", &addr);

			if (set_bp_hard_exec(addr))
			{
				printf("����Ӳ��ִ�жϵ�ɹ�\n");
				getchar();
			}
		}
		else if (_stricmp(cmd, "set hrw") == 0)
		{
			DWORD addr;
			int len;
			printf("�������ַ:");
			scanf("%8X", &addr);
			printf("������ϵ㳤��:");
			scanf("%d", &len);
			if (set_bp_hard_rw(addr, len))
			{
				printf("����Ӳ����д�ϵ�ɹ�\n");
				getchar();
			}
		}
		else if (_stricmp(cmd, "set me") == 0)
		{
			DWORD addr;
			printf("�������ַ:");
			scanf("%8X", &addr);
			if (set_bp_mem_access_exec(addr))
			{
				printf("�����ڴ����ִ�жϵ�ɹ�\n");
				getchar();
			}
		}
		else if (_stricmp(cmd, "set mrw") == 0)
		{
			DWORD addr;
			printf("�������ַ:");
			scanf("%8X", &addr);
			set_bp_mem_access_rw(addr);
			printf("�����ڴ����ִ�жϵ�ɹ�\n");
			getchar();
		}
		else if (_stricmp(cmd, "set cbp") == 0)
		{
			char* str = new char[5]{};
			int val = 0;
			printf("������Ĵ�����:");
			scanf("%s", str);
			printf("����������ֵ:");
			scanf("%X", &val);
			strcpy_s(g_condition_bp.reg, str);
			g_condition_bp.val = val;
			set_bp_tf();
			g_isconditon_dbg = 1;
			break;
		}
		else if (_stricmp(cmd, "show stack") == 0) {
			show_present_info(pexcept, ct, type_show_stack);
		}
		else if (_stricmp(cmd, "show module") == 0) {
			show_present_info(pexcept, ct, type_show_module);
		}
		else if (_stricmp(cmd, "show mem") == 0)
		{
			show_present_info(pexcept, ct, type_show_mem);
		}
		else if (_stricmp(cmd, "mod mem") == 0)
		{
			DWORD addr = 0;
			BYTE newdata = 0;
			printf("�������ַ��������:");
			scanf_s("%X %X", &addr, &newdata);
			mod_mem((LPVOID)addr, newdata);
		}
		else if (_stricmp(cmd, "mod reg") == 0)
		{
			char str[10];
			DWORD newdata = 0;
			printf("������Ĵ�����ֵ:");
			scanf("%s %X", str, &newdata);
			mod_reg(str, newdata, ct);
			show_present_info(pexcept, ct, type_show_disasm_reg);
		}
		else if (_stricmp(cmd, "mod asm") == 0)
		{
			mod_asm();
		}
		else if (_stricmp(cmd, "show import") == 0)
		{

			char str[50];
			printf("������ģ����:");
			scanf("%s", str);
			show_import(str);

		}
		else if (_stricmp(cmd, "show export") == 0)
		{
			char str[50];
			printf("������ģ����:");
			scanf("%s", str);
			show_export(str);
		}
		else if (_stricmp(cmd, "insert dll") == 0)
		{
			char path[100];
			printf("����dll·��\n");
			//getchar();
			gets_s(path, 100);
			g_hmodule = LoadLibraryA(path);
			if (g_hmodule)
			{
				printf("װ�سɹ�\n");
			}
		}
		else if (_stricmp(cmd, "use dump") == 0)
		{
			FARPROC lpfnDllFunc1 = GetProcAddress(g_hmodule, "_cmd@8");
			char* str = "dump";
			printf("���������id:");
			int pid = 0;
			scanf("%d", &pid);
			_asm
			{
				push pid;
				push str;
				call lpfnDllFunc1;
			}
		}
		else if (_stricmp(cmd, "ld symb") == 0)
		{
			char path[100]{};
			printf("���������·��:");
			gets_s(path, 100);
			SymInitialize(g_proc, path, FALSE);
			for (auto& i : g_dll_info)
			{
				SymLoadModule64(g_proc, i.hFile, 0, 0, (DWORD64)i.lpBaseOfDll, 0);
			}
			printf("���ط��ųɹ�!\n");

		}
		else if (_stricmp(cmd, "show symb") == 0)
		{
			printf("������鿴���ŵ�ַ:");
			DWORD64 addr = 0;
			scanf("%X", &addr);
			SYMBOL_INFO* si = new SYMBOL_INFO{};
			si->SizeOfStruct = sizeof(SYMBOL_INFO);
			si->MaxNameLen = MAX_SYM_NAME;

			SymFromAddr(g_proc, addr, 0, si);
			printf("�÷�����Ϊ: %s\n", si->Name);
			printf("����>");
			while (1)
			{
				Sleep(50);
			}
		}
		else if (_stricmp(cmd, "hook") == 0)
		{
			LPVOID pbuff = VirtualAllocEx(g_proc, NULL, 1024 * 64, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
			if (!pbuff)
			{
				printf("�����ڴ�ʧ��\n");
			}
			SIZE_T write = 0;
			WriteProcessMemory(g_proc, pbuff, "F:\\15pbѧϰ��Ŀ\\new\\������1\\Debug\\hookdll.dll",MAX_PATH,&write);
			HANDLE hThread=CreateRemoteThread(g_proc, 0, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, pbuff, 0, 0);
			printf("HOOK���!\n");
		
		//	MessageBoxA(0,"ע��ɹ�",0,0);
		}
	}
}

DWORD dispatch_exception(EXCEPTION_RECORD* pexcept, DEBUG_EVENT* pdbg_event)
{
	CONTEXT ct = { CONTEXT_CONTROL };
	if (g_num == 10)
	{
		GetThreadContext(g_thread, &ct);
		ct.Eax = g_condition_bp.val;
		SetThreadContext(g_thread, &ct);
	}
	 //������int3�ϵ��������û�ȥ.
	SIZE_T read = 0;
	for (auto &i : g_vec_bp) {
		//2. ��0xCCд���¶ϵ�ĵ�ַ
		if (!WriteProcessMemory(g_proc, i.address, "\xCC", 1, &read)) {
			DBG_EXIT("д������ڴ�ʧ��");
		}
	}
	switch (pexcept->ExceptionCode)
	{
		// ��һ��������int3�쳣����ϵͳ�ϵ�.
	case EXCEPTION_BREAKPOINT:/*�ϵ��쳣,int3ָ���������쳣,������쳣*/
	{
		static bool isSystemBreakpoint = true;
		if (isSystemBreakpoint) {
			isSystemBreakpoint = false;
			printf("����ϵͳ�ϵ�:%08X\n", pexcept->ExceptionAddress);
			if (g_isdedebg == 1)
			{
				PROCESS_BASIC_INFORMATION pbi{};
				ULONG aa = 0;
				NtQueryInformationProcess(g_pi.hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &aa);
				DWORD write = 0;
				WriteProcessMemory(g_pi.hProcess, LPVOID(&pbi.PebBaseAddress->BeingDebugged), "\x00", 1, &write);
			}
		}
		else {
			// �޸�int3�쳣
			// 1. ����int3���ǵ����ݻ�ԭ��ȥ.
			// 2. int3�������쳣, ����֮��, eipָ����int3����һ���ֽ�.
			//    ����Ҫ��eip--.
			printf("��������ϵ�:%08X\n", pexcept->ExceptionAddress);
			restore_bp_int3(pexcept->ExceptionAddress);
		}
	}
	break;
	case EXCEPTION_ACCESS_VIOLATION:/*�ڴ�����쳣*/
	{

		if (g_ismem_access_bp)
		{
			if ((DWORD)pexcept->ExceptionAddress != g_mem_access_bp)
			{
				set_bp_tf();
				DWORD old = 0;
				VirtualProtectEx(g_proc, (LPVOID)g_mem_access_bp, 1, PAGE_EXECUTE_READWRITE, &old);
				printf("%08X �ڴ�����쳣,�ָ�Ȩ��,����TF\n", pexcept->ExceptionAddress);
				goto _DONE;
			}
			else
			{
				DWORD old = 0;
				printf("�����ڴ����ִ�жϵ�:%08X\n", pexcept->ExceptionAddress);
				VirtualProtectEx(g_proc, (LPVOID)g_mem_access_bp, 1, PAGE_EXECUTE_READWRITE, &old);
				g_ismem_access_bp = 0;
				g_mem_access_bp = 0;
			}
		}
		if (g_mem_access_rw_bp)
		{
			if (pexcept->ExceptionInformation[0] == 0)
			{
				printf("%08X �ڴ���ʶ�ȡ�쳣\n", pexcept->ExceptionInformation[1]);
			}
			if (pexcept->ExceptionInformation[0] == 1)
			{
				printf("%08X �ڴ����д���쳣\n", pexcept->ExceptionInformation[1]);
			}
			DWORD old;
			VirtualProtectEx(g_proc, (LPVOID)g_mem_access_rw_bp, 1, PAGE_EXECUTE_READWRITE, &old);
			printf("�����ڴ���ʶϵ� %08X\n", pexcept->ExceptionAddress);
		}
	}
	break;

	case EXCEPTION_SINGLE_STEP:/*Ӳ���ϵ��TF�����־�쳣*/
	{
		// ���tf�ϵ�, ���û����뵥��֮����µ�
		// ���ǵ��������õ�.����ǵ��������õ�, �Ͳ���
		// ���������������
		if ((DWORD)pexcept->ExceptionAddress == g_hard_exec_bp)
		{
			printf("����Ӳ��ִ�жϵ�:%08X\n", pexcept->ExceptionAddress);
			restore_bp_hard_exec((DWORD)pexcept->ExceptionAddress);
		}
		if ((DWORD)pexcept->ExceptionAddress == g_hard_rw_bp)
		{
			printf("����Ӳ����д�ϵ�:%08X\n", pexcept->ExceptionAddress);
			restore_bp_hard_exec((DWORD)pexcept->ExceptionAddress);
		}
		if (g_ismem_access_bp)
		{
			if ((DWORD)pexcept->ExceptionAddress != g_mem_access_bp)
			{
				DWORD old = 0;
				VirtualProtectEx(g_proc, (LPVOID)g_mem_access_bp, 1, PAGE_READONLY, &old);
				printf("%08X ����TF�ϵ�,�����ڴ��ִֹ��\n", pexcept->ExceptionAddress);
				goto _DONE;
			}
			else
			{
				DWORD old = 0;
				printf("�����ڴ����ִ�жϵ�:%08X\n", pexcept->ExceptionAddress);
				g_ismem_access_bp = 0;
				g_mem_access_bp = 0;
				VirtualProtectEx(g_proc, (LPVOID)g_mem_access_bp, 1, PAGE_EXECUTE_READWRITE, &old);
			}
		}
		if (g_isconditon_dbg)
		{
			if (ct.Eax == g_condition_bp.val)
			{
				printf("���������ϵ�: %s==%08X\n", g_condition_bp.reg, g_condition_bp.val);
				g_isconditon_dbg = 0;
			}
			else
			{
				g_num++;
				set_bp_tf();
				goto _DONE;
			}
		}
	}
	break;

	default:
		printf("�����Խ������������쳣:%08X\n", pexcept->ExceptionAddress);
		getchar();
		return DBG_EXCEPTION_NOT_HANDLED;
		break;
	}

	if (!GetThreadContext(g_thread, &ct)) {
		DBG("��ȡ�߳�������ʧ��\n");
	}
	show_present_info(pexcept,&ct,type_show_disasm_reg);
	user_input(pexcept, &ct);

_DONE:
	return DBG_CONTINUE;
}

DWORD dispatch_event(DEBUG_EVENT* pdbg_event)
{
	DWORD dw_ret = 0;
	switch (pdbg_event->dwDebugEventCode)
	{
	case EXCEPTION_DEBUG_EVENT:
		dw_ret = dispatch_exception(&pdbg_event->u.Exception.ExceptionRecord, pdbg_event);
		return dw_ret;
	case LOAD_DLL_DEBUG_EVENT:
		g_dll_info.push_back(pdbg_event->u.LoadDll);
		return DBG_CONTINUE;
	case UNLOAD_DLL_DEBUG_EVENT:
		for (int i = 0;i < g_dll_info.size();i++)
		{
			if (g_dll_info[i].lpBaseOfDll == pdbg_event->u.UnloadDll.lpBaseOfDll)
			{
				g_dll_info.erase(g_dll_info.begin() + i);
			}
		}
		return DBG_CONTINUE;
	default:
		return DBG_CONTINUE;
	}
}

BOOL SetPrivilege()
{
	HANDLE hToken;
	TOKEN_PRIVILEGES NewState;
	LUID luidPrivilegeLUID;

	//��ȡ��������
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken) || !LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luidPrivilegeLUID))
	{
		printf("SetPrivilege Error\n");
		return FALSE;
	}
	NewState.PrivilegeCount = 1;
	NewState.Privileges[0].Luid = luidPrivilegeLUID;
	NewState.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	//��ʾ����Ȩ�ޣ�ע��ú���Ҳ���Ըı��̵߳�Ȩ�ޣ����hTokenָ��һ���̵߳����� 
	if (!AdjustTokenPrivileges(hToken, FALSE, &NewState, NULL, NULL, NULL))
	{
		printf("AdjustTokenPrivilege Errro\n");
		return FALSE;
	}
	return TRUE;

}

int main()
{
	SetPrivilege();
	printf("--------------------������-------------------\n");
	printf("�������̵���(����'1')\n");
	printf("��������(����'2')\n");
	printf("���ӻ����(����'3')\n");
	int choice = 0;
	scanf_s("%d", &choice);
	if (choice == 1)
	{
		getchar();
		printf("����·��>> ");
		gets_s(g_path, MAX_PATH);
		STARTUPINFOA si = { sizeof(STARTUPINFO) };
		
		//1�������Իػ�
		if (!CreateProcessA(g_path, 0, 0, 0, 0, DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE, 0, 0, &si, &g_pi))
		{
			DBG("��������ʧ��");
		}
	}
	if (choice == 2)
	{
		getchar();
		printf("����·��>> ");
		gets_s(g_path, MAX_PATH);
		STARTUPINFOA si = { sizeof(STARTUPINFO) };

		//1�������Իػ�
		if (!CreateProcessA(g_path, 0, 0, 0, 0, DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE, 0, 0, &si, &g_pi))
		{
			DBG("��������ʧ��");
		}
		g_isdedebg = 1;
	}
	if (choice == 3)
	{
		int pid = 0;
		printf("�������ID>> ");
		scanf_s("%d", &pid);
		DebugActiveProcess(pid);
	}

	
	//2���յ��ԻỰ
	DEBUG_EVENT dbg_event{};
	DWORD dw_ret = 0;
	//g_proc = OpenProcess(PROCESS_ALL_ACCESS, 0, g_pi.dwProcessId);
	//g_thread = OpenThread(THREAD_ALL_ACCESS, 0, g_pi.dwThreadId);
	while (1)
	{
		WaitForDebugEvent(&dbg_event, -1);
		g_proc = OpenProcess(PROCESS_ALL_ACCESS, 0, dbg_event.dwProcessId);
		g_thread = OpenThread(THREAD_ALL_ACCESS, 0, dbg_event.dwThreadId);
		dw_ret = DBG_CONTINUE;
	
		dw_ret = dispatch_event(&dbg_event);

		ContinueDebugEvent(dbg_event.dwProcessId,
			dbg_event.dwThreadId,
			dw_ret);
		CloseHandle(g_proc);
		CloseHandle(g_thread);
	}

}