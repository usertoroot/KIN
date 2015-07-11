#include <Windows.h>

void Dispose();

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	if (fdwReason == DLL_PROCESS_DETACH)
		Dispose();
}

void Dispose()
{

}

extern "C" int _declspec(dllexport) ReplaceImportAddress(const char* dllName, const char* funcName, unsigned int addr)
{
	DWORD base = (DWORD)GetModuleHandle(NULL);
	_IMAGE_DOS_HEADER* dosHeader = (_IMAGE_DOS_HEADER*)base;
	IMAGE_NT_HEADERS32* fileHeader = (IMAGE_NT_HEADERS32*)(base + dosHeader->e_lfanew);
	_IMAGE_IMPORT_DESCRIPTOR* desc = (_IMAGE_IMPORT_DESCRIPTOR*)fileHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	IMAGE_THUNK_DATA* thunk;

	DWORD pThunk;
	DWORD pHintName;
	DWORD dwAPIaddress;
	DWORD pDllName;
	DWORD pAPIName;
	
	while (desc->Name!=0)
	{
		pThunk = base + desc->FirstThunk;
		pHintName = base;

		if (desc->OriginalFirstThunk != 0)
			pHintName += desc->OriginalFirstThunk;
		else
			pHintName += desc->FirstThunk;

		pDllName = desc->Name;
		thunk = (PIMAGE_THUNK_DATA)pHintName;
		while (thunk->u1.AddressOfData != 0)
		{
			dwAPIaddress = thunk->u1.AddressOfData;
			if ((dwAPIaddress & 0x80000000) == 0x80000000)
				dwAPIaddress &= 0x7FFFFFFF;
			else
				pAPIName = dwAPIaddress + 2;

			pThunk += 4;
			pHintName += 4;
			thunk += sizeof(IMAGE_THUNK_DATA);
		}
		desc += sizeof(_IMAGE_IMPORT_DESCRIPTOR);
	}

	return 0;
}

extern DWORD* ScanMemory(char* data, int len)
{
	MEMORY_BASIC_INFORMATION info;
	void* loc = 0;
	bool found = false;
	char* mem;
	unsigned int x;
	int y;

	DWORD* resultBuffer = new DWORD[1000];
	DWORD* temp;
	int resultLength = 1000;
	int resultIndex = 0;

	while (VirtualQuery(loc, &info, 0) != 0)
	{
		if (info.Protect == PAGE_READWRITE) //Implement PAGE_READ PRAGE_READEXECUTE PAGE_EXECUTE ??
		{
			//Not buffering blocks chance on memory being written to while reading
			mem = (char*)info.BaseAddress;
			for (x = 0; x < info.RegionSize; x++)
			{
				if (mem[x] == data[0])
				{
					for (y = 1; y < len; y++)
					{
						if (mem[x + y] != data[y])
						{
							found = false;
							break;
						}

						if (!found)
							break;

						if (++resultIndex >= resultLength)
						{
							temp = resultBuffer;
							resultBuffer = new DWORD[resultLength + 1000];
							memcpy(resultBuffer, temp, sizeof(DWORD) * resultLength);
							delete[] temp;

							resultLength += 1000;
						}

						resultBuffer[resultIndex] = (DWORD)info.BaseAddress + x;
					}
				}
			}
		}

		loc = (void*)((DWORD)info.BaseAddress + (DWORD)info.RegionSize);
	}

	resultBuffer[0] = resultLength;
	return resultBuffer;
}