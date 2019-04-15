#include<stdio.h>
#include<windows.h>
#include<time.h>
/*struct IMAGE_DOS_HEADER_STRUCT
{
	WORD e_magic;
	WORD e_cblp;

};*/
HANDLE pFile;
BOOL IsPEFile(LPTSTR Path)
{
	PIMAGE_DOS_HEADER HEADER;
	PIMAGE_NT_HEADERS NHEADER;
	HANDLE hFile = CreateFile(Path,
		GENERIC_READ,
		0,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_READONLY,
		NULL);
	if(hFile==NULL)
		return FALSE;
	HANDLE hMap = CreateFileMapping(hFile,
		NULL,
		PAGE_READONLY,
		0,0,NULL);
	if(hMap==NULL)
	{
		CloseHandle(hFile);
		return FALSE;
	}
	pFile = MapViewOfFile(hMap,
		FILE_MAP_READ,
		0,0,NULL);
	if(pFile==NULL)
	{
		CloseHandle(hFile);
		CloseHandle(hMap);
		return FALSE;
	}
	HEADER = (PIMAGE_DOS_HEADER)pFile;
	if(HEADER->e_magic!=IMAGE_DOS_SIGNATURE)
		return FALSE;
	NHEADER = (PIMAGE_NT_HEADERS)((DWORD)HEADER+HEADER->e_lfanew);
	if(NHEADER->Signature!=IMAGE_NT_SIGNATURE)
	{
		return FALSE;
	}
	return TRUE;
}
void ShowDosHeader(LPVOID LocalFHead)
{
	PIMAGE_DOS_HEADER PDH = NULL;
	PDH = (PIMAGE_DOS_HEADER)LocalFHead;
	printf("Magic: 0x%x\n",PDH->e_magic);
	printf("DOS_CS: 0x%x\n",PDH->e_cs);
	printf("DOS_IP: 0x%x\n",PDH->e_ip);
	printf("NT_HEADER_OFFSET: 0x%x\n",PDH->e_lfanew);
}
void ShowNtHeader(LPVOID LocalFHead)
{
	PIMAGE_DOS_HEADER PDH = NULL;
	PIMAGE_NT_HEADERS PNH = NULL;
	PIMAGE_FILE_HEADER PFH = NULL;
	PIMAGE_OPTIONAL_HEADER POH = NULL;
	PIMAGE_DATA_DIRECTORY PDD = NULL;
	PDH = (PIMAGE_DOS_HEADER)LocalFHead;
	PNH = (PIMAGE_NT_HEADERS)((DWORD)PDH+PDH->e_lfanew);
	printf("Signature: 0x%x\n",PNH->Signature);		//Signature
	PFH = &PNH->FileHeader;
	printf("\n");
	printf("FILE_HEADER\n");
	printf("Machine: 0x%x",PFH->Machine);			//Machine
	switch(PFH->Machine)
	{
	case IMAGE_FILE_MACHINE_I386:
		printf("\t\t\tArch: I386\n");
		break;
	case IMAGE_FILE_MACHINE_R3000:
		printf("\t\t\tArch: MIPS R3000\n");
		break;
	case IMAGE_FILE_MACHINE_R4000:
		printf("\t\t\tArch: MIPS R4000\n");
		break;
	case IMAGE_FILE_MACHINE_ALPHA:
		printf("\t\t\tArch: Alpha AXP\n");
		break;
	case IMAGE_FILE_MACHINE_POWERPC:
		printf("\t\t\tArch: Power PC\n");
		break;
	default:
		printf("\t\t\tUnknown\n");
		break;
	}
	printf("Number Of Sections:0x%x\t\tһ����%d������\n",PFH->NumberOfSections,PFH->NumberOfSections);			//NumbersOfSections
	printf("Time Date Stamp: %x\t",PFH->TimeDateStamp);
	time_t second;
	second = PFH->TimeDateStamp;
	printf("�ļ�����ʱ�䣺 %s",ctime(&second));			//TimeDateStamp
	printf("SizeOfOptionalHeader: 0x%x",PFH->SizeOfOptionalHeader);
	if(PFH->SizeOfOptionalHeader==0xe0)					//SizeOfOptionalHeader
		printf("\t32λ�ļ�\n");
	else if(PFH->SizeOfOptionalHeader==0xf0)
		printf("\t64λ�ļ�\n");
	printf("Characteristics: 0x%x\t\t",PFH->Characteristics);	//Characteristics
	WORD chara = PFH->Characteristics;
	int i;
	for(i=0;i<16;i++)
	{
		if((chara%2)&&(i==0))
		{
			printf("�ļ��������ض�λ��Ϣ,");
		}
		else if((chara%2)&&(i==1))
		{
			printf("�ļ���ִ��,");
		}
		else if((chara%2)&&(i==2))
		{
			printf("�к���Ϣ����ȥ,");
		}
		else if((chara%2)&&(i==3))
		{
			printf("������Ϣ����ȥ,");
		}
		else if((chara%2)&&(i==5))
		{
			printf("Ӧ�ó�����Դ�����2GB�ĵ�ַ��");
		}
		else if((chara%2)&&(i==7))
		{
			printf("������ĵ�λ�ֽ����෴�ģ�");
		}
		else if((chara%2)&&(i==8))
		{
			printf("Ŀ��ƽ̨Ϊ32λ������");
		}
		else if((chara%2)&&(i==9))
		{
			printf(".DBG�ļ��ĵ�����Ϣ����ȥ��");
		}
		else if((chara%2)&&(i==12))
		{
			printf("ϵͳ�ļ���");
		}
		else if((chara%2)&&(i==13))
		{
			printf("DLL�ļ���");
		}
		else if((chara%2)&&(i==14))
		{
			printf("�ļ�ֻ�������ڵ��������ϣ�");
		}
		else if((chara%2)&&(i==15))
		{
			printf("�������λ�ֽ����෴��");
		}
		chara = chara>>1;
	}
	printf("\n\n");
	printf("OPTIONAL_HEADER\n");
	POH = &PNH->OptionalHeader;
	printf("Magic: 0x%x",POH->Magic);			//Magic
	if(POH->Magic==IMAGE_NT_OPTIONAL_HDR32_MAGIC)
		printf("\t\t\tPE32\n");
	else if(POH->Magic==IMAGE_NT_OPTIONAL_HDR64_MAGIC)
		printf("\t\t\tPE32+\n");
	else if(POH->Magic==IMAGE_ROM_OPTIONAL_HDR_MAGIC)
		printf("\t\t\tROM\n");
	printf("MajorLinkerVersion: 0x%x\t\t���ӳ�������汾��\n",POH->MajorLinkerVersion);			//MajorLinkerVersion
	printf("MinorLinkerVersion: 0x%x\t\t���ӳ���Ĵΰ汾��\n",POH->MinorLinkerVersion);			//MinorLinkerVersion
	printf("SizeOfCode: 0x%x\n",POH->SizeOfCode);												//SizeOfCode
	printf("SizeOfInitializedData: 0x%x\t��ʼ�����ݿ��С\n",POH->SizeOfInitializedData);		//SizeOfInitializedData
	printf("SizeOfUninitalizedData: 0x%x\tδ��ʼ�����ݿ��С\n",POH->SizeOfUninitializedData);	//SizeOfUninitializedData
	printf("AddressOfEntryPoint: 0x%x\t�������RVA\n",POH->AddressOfEntryPoint);				//AddressOfEntryPoint
	printf("BaseOfCode: 0x%x\t\t�������ʼ��RVA\n",POH->BaseOfCode);							//BaseOfCode
	printf("BaseOfData: 0x%x\t\t���ݶ���ʼ��RVA\n",POH->BaseOfData);							//BaseOfData
	printf("ImageBase: 0x%x\t\t�ļ���ѡ�����ַ\n",POH->ImageBase);								//ImageBase
	printf("SectionAlignment: 0x%x\t��������С\n",POH->SectionAlignment);						//SectionAlignment
	printf("FileAlignment: 0x%x\t\t�ļ�����������С\n",POH->FileAlignment);					//FileAlignment
	printf("MajorOperatingSystemVersion: 0x%xҪ�����ϵͳ��Ͱ汾��ϵͳ�汾��\n",POH->MajorOperatingSystemVersion);//MajorOperatingSystemVersion
	printf("MinorOperatingSystemVersion: 0x%xҪ�����ϵͳ��Ͱ汾��ϵͳ�汾��\n",POH->MinorOperatingSystemVersion);//MinorOperatingSystemVersion
	printf("MajorImageVersion: 0x%x\n",POH->MajorImageVersion);
	printf("MinorImageVersion: 0x%x\n",POH->MinorImageVersion);
	printf("MajorSubsystemVersion: 0x%x\tҪ����ϵͳ��Ͱ汾���汾��\n",POH->MajorSubsystemVersion);
	printf("MinorSubsystemVersion: 0x%x\tҪ����ϵͳ��Ͱ汾�ΰ汾��\n",POH->MinorSubsystemVersion);
	printf("Win32VersionValue: 0x%x\n",POH->Win32VersionValue);
	printf("SizeOfImage: 0x%x\t\t�����ڴ��ļ��Ĵ�С����Ҫ����\n",POH->SizeOfImage);				//SizeOfImage
	printf("SizeOfHeaders: 0x%x\t\tDOSͷ��PEͷ���������ܶ����С\n",POH->SizeOfHeaders);		//SizeOfHeaders
	printf("CheckSum: 0x%x\t\t\tУ���\n",POH->CheckSum);										//CheckSum
	printf("Subsystem: 0x%x\t\t\tһ����������������ϵͳ���û��������ͣ�,0x%xΪ",POH->Subsystem,POH->Subsystem);
	switch(POH->Subsystem)																		//Subsystem
	{
		case 0:
			printf("δ֪\n");
			break;
		case 1:
			printf("����Ҫ��ϵͳ����������\n");
			break;
		case 2:
			printf("GUI\n");
			break;
		case 3:
			printf("GCI\n");
			break;
		case 5:
			printf("OS/2�ַ���ϵͳ\n");
			break;
		case 7:
			printf("POSIX�ַ���ϵͳ\n");
			break;
		case 8:
			printf("����\n");
			break;
		case 9:
			printf("Windows CEͼ�ν���\n");
			break;
	}
	printf("DllCharacteristics: 0x%x\tDLL�ں�ʱ������\n",POH->DllCharacteristics);	//DllCharacteristics
	printf("SizeOfStackReserve: 0x%x\t����ջ�Ĵ�С\n",POH->SizeOfStackReserve);		//SizeOfStackReserve
	printf("SizeOfStackCommit: 0x%x\tһ��ʼ�ͷ����ջ\n",POH->SizeOfStackCommit);	//SizeOfStackCommit
	printf("SizeOfHeapReserve: 0x%x\t�����ѵĴ�С\n",POH->SizeOfHeapReserve);		//SizeOfHeapReserve
	printf("SizeOfHeapCommit: 0x%x\tһ��ʼ�ͷ���Ķ�\n",POH->SizeOfHeapCommit);		//SizeOfHeapCommit
	printf("LoaderFlags: 0x%x\t\t������й�Ĭ��Ϊ0\n",POH->LoaderFlags);			//LoaderFlags
	printf("NumberOfRvaAndSizes: 0x%x\t���ݱ��������һֱΪ16\n",POH->NumberOfRvaAndSizes);//NumberOfRvaAndSizes
	printf("\nData_Directory\n");
	PDD = (PIMAGE_DATA_DIRECTORY)&(POH->DataDirectory);
	printf("Export Table Size: 0x%x\n",PDD[0].Size);
	printf("Export Table VA: 0x%x\n",PDD[0].VirtualAddress);
	printf("Import Table Size: 0x%x\n",PDD[1].Size);
	printf("Import Table VA: 0x%x\n",PDD[1].VirtualAddress);
	printf("Resources Table Size: 0x%x\n",PDD[2].Size);
	printf("Resources Table VA: 0x%x\n",PDD[2].VirtualAddress);
	printf("Exception Table Size: 0x%x\n",PDD[3].Size);
	printf("Exception Table VA: 0x%x\n",PDD[3].VirtualAddress);
	printf("Security Table Size: 0x%x\n",PDD[4].Size);
	printf("Security Table VA: 0x%x\n",PDD[4].VirtualAddress);
	printf("Base relocation Table Size: 0x%x\n",PDD[5].Size);
	printf("Base relocation Table VA: 0x%x\n",PDD[5].VirtualAddress);
	printf("Debug Size: 0x%x\n",PDD[6].Size);
	printf("Debug VA: 0x%x\n",PDD[6].VirtualAddress);
	printf("Copyright Size: 0x%x\n",PDD[7].Size);
	printf("Copyright VA: 0x%x\n",PDD[7].VirtualAddress);
	printf("Global Ptr Size: 0x%x\n",PDD[8].Size);
	printf("Global Ptr VA: 0x%x\n",PDD[8].VirtualAddress);
	printf("TLS Size: 0x%x\n",PDD[9].Size);
	printf("TLS VA: 0x%x\n",PDD[9].VirtualAddress);
	printf("Load conf Size: 0x%x\n",PDD[10].Size);
	printf("Load conf VA: 0x%x\n",PDD[10].VirtualAddress);
	printf("Bound Import Size: 0x%x\n",PDD[11].Size);
	printf("Bound Import VA: 0x%x\n",PDD[11].VirtualAddress);
	printf("IAT Size: 0x%x\n",PDD[12].Size);
	printf("IAT VA: 0x%x\n",PDD[12].VirtualAddress);
	printf("Delay Import Size: 0x%x\n",PDD[13].Size);
	printf("Delay Import VA: 0x%x\n",PDD[13].VirtualAddress);
	printf("COM desc Size: 0x%x\n",PDD[14].Size);
	printf("COM desc VA: 0x%x\n",PDD[14].VirtualAddress);
	printf("0x%x\n",PDD[15].Size);
	printf("0x%x\n",PDD[15].VirtualAddress);
}
void ShowSectionTable(LPVOID LocalFHead)
{
	PIMAGE_DOS_HEADER PDH = NULL;
	PIMAGE_NT_HEADERS PNH = NULL;
	PIMAGE_FILE_HEADER PFH = NULL;
	PDH = (PIMAGE_DOS_HEADER)LocalFHead;
	PNH = (PIMAGE_NT_HEADERS)((DWORD)PDH+PDH->e_lfanew);
	PFH = &PNH->FileHeader;
	PIMAGE_SECTION_HEADER PSH = (PIMAGE_SECTION_HEADER)IMAGE_FIRST_SECTION(PNH);
	int i,j;
	for(i=0;i<PFH->NumberOfSections;i++)
	{
		printf("-------------------------------");
		for(j=0;(j<=7)&&(PSH->Name[j]);j++)
		{
			printf("%c",PSH->Name[j]);
		}
		printf("---------------------------------\n");
		printf("\n");
		printf("Section Name: ");
		for(j=0;(j<=7)&&(PSH->Name[j]);j++)
		{
			printf("%c",PSH->Name[j]);
		}
		printf("\t\t\t��������\n");
		printf("Section VirtualSize: 0x%x\t\tʵ�������С\n",PSH->Misc.VirtualSize);
		printf("Section VirtualAddres: 0x%x\t\tװ�ص��ڴ��RVA\n",PSH->VirtualAddress);
		printf("Section SizeOfRawData: 0x%x\t\t��������ڴ�������ռ�Ŀռ�\n",PSH->SizeOfRawData);
		printf("Section Pointer To Raw Data: 0x%x\t�ÿ��ڴ��̵�ƫ��\n",PSH->PointerToRawData);
		printf("Section PointerToRelocations: 0x%x\n",PSH->PointerToRelocations);
		printf("Section PointerToLinenumbers: 0x%x\n",PSH->PointerToLinenumbers);
		printf("Section NumberOfRelocations: 0x%x\n",PSH->NumberOfRelocations);
		printf("Section NumberOfLinenumbers: 0x%x\n",PSH->NumberOfLinenumbers);
		printf("Section Characteristics :0x%x\t������\n",PSH->Characteristics);
		PSH++;
	}
	
}
int Rva_To_Rwa(PIMAGE_NT_HEADERS PNH,DWORD RVA)
{
	WORD i;
	DWORD RWA;
	PIMAGE_FILE_HEADER PFH = (PIMAGE_FILE_HEADER)&PNH->FileHeader;
	PIMAGE_SECTION_HEADER PSH = IMAGE_FIRST_SECTION(PNH);
	for(i=0;i<PFH->NumberOfSections;i++)
	{
		if((PSH->VirtualAddress<=RVA)&&(PSH->VirtualAddress+PSH->Misc.VirtualSize>RVA))
		{
			RWA = RVA-PSH->VirtualAddress+PSH->PointerToRawData;
			return RWA;
		}
		PSH++;
	}
}
void ShowImportTable(LPVOID LocalFHead)
{
	PIMAGE_DOS_HEADER PDH = NULL;
	PIMAGE_NT_HEADERS PNH = NULL;
	PIMAGE_FILE_HEADER PFH = NULL;
	PIMAGE_SECTION_HEADER PSH = NULL;
	PIMAGE_OPTIONAL_HEADER POH = NULL;
	PIMAGE_DATA_DIRECTORY PDD = NULL;
	PIMAGE_IMPORT_DESCRIPTOR PID = NULL;
	PDH = (PIMAGE_DOS_HEADER)LocalFHead;
	PNH = (PIMAGE_NT_HEADERS)((DWORD)PDH+PDH->e_lfanew);
	PFH = (PIMAGE_FILE_HEADER)&PNH->FileHeader;
	POH = (PIMAGE_OPTIONAL_HEADER)&PNH->OptionalHeader;
	PDD = (PIMAGE_DATA_DIRECTORY)POH->DataDirectory;
	DWORD Import_RVA;
	DWORD Import_RWA;
	Import_RVA = PDD[1].VirtualAddress;
	if(Import_RVA==0)
	{
		printf("No Import Table!!!\n");
		return ;
	}
	Import_RWA = Rva_To_Rwa(PNH,Import_RVA);
	printf("Import Raw To Data: 0x%x\n",Import_RWA);
	PID = (PIMAGE_IMPORT_DESCRIPTOR)(Import_RWA+(DWORD)LocalFHead);
	while((PID->OriginalFirstThunk!=0)||(PID->TimeDateStamp!=0)||(PID->ForwarderChain!=0)||(PID->Name!=0)||(PID->FirstThunk!=0))
	{
		DWORD Real_Rwa,RWA;
		RWA = Rva_To_Rwa(PNH,PID->Name);
		Real_Rwa = RWA+(DWORD)LocalFHead;
		printf("------------------------------%s-----------------------------\n",Real_Rwa);
		printf("OriginalFirstThunk: 0x%x\n",PID->OriginalFirstThunk);
		RWA = Rva_To_Rwa(PNH,PID->OriginalFirstThunk);
		Real_Rwa = RWA+(DWORD)LocalFHead;
		printf("OriginalFirstThunkRaw: 0x%x\n",RWA);
		PIMAGE_THUNK_DATA PTDN,PTDA = NULL;
		PTDN = (PIMAGE_THUNK_DATA)Real_Rwa;
		printf("TimeDateStamp: 0x%x\n",PID->TimeDateStamp);
		printf("ForwarderChain: 0x%x\n",PID->ForwarderChain);
		printf("FirstThunk: 0x%x\n",PID->FirstThunk);
		RWA = Rva_To_Rwa(PNH,PID->FirstThunk);
		printf("FirstThunkRwa: 0x%x\n",RWA);
		Real_Rwa = RWA+(DWORD)LocalFHead;
		PTDA = (PIMAGE_THUNK_DATA)Real_Rwa;
		printf("RVA\t\tFile Offset\t\tHint\t\tAPiName\n");
		while(PTDN->u1.AddressOfData!=0)
		{
			RWA = Rva_To_Rwa(PNH,(DWORD)PTDN->u1.AddressOfData);
			Real_Rwa = RWA+(DWORD)LocalFHead;
			PIMAGE_IMPORT_BY_NAME PIBN = (PIMAGE_IMPORT_BY_NAME)Real_Rwa;
			printf("0x%.8x\t0x%.8x\t\t0x%.4x\t\t%s\n",PTDN->u1.AddressOfData,RWA,PIBN->Hint,PIBN->Name);
			PTDN++;
		}
		PID++;
	}
}
void ShowExportTable(LPVOID LocalFHead)
{
	PIMAGE_DOS_HEADER PDH = NULL;
	PIMAGE_NT_HEADERS PNH = NULL;
	PIMAGE_FILE_HEADER PFH = NULL;
	PIMAGE_SECTION_HEADER PSH = NULL;
	PIMAGE_OPTIONAL_HEADER POH = NULL;
	PIMAGE_DATA_DIRECTORY PDD = NULL;
	PIMAGE_EXPORT_DIRECTORY PED = NULL;
	DWORD RWA,Real_Name_RWA;
	PDH = (PIMAGE_DOS_HEADER)LocalFHead;
	PNH = (PIMAGE_NT_HEADERS)((DWORD)PDH+PDH->e_lfanew);
	PFH = (PIMAGE_FILE_HEADER)&PNH->FileHeader;
	POH = (PIMAGE_OPTIONAL_HEADER)&PNH->OptionalHeader;
	PDD = (PIMAGE_DATA_DIRECTORY)POH->DataDirectory;
	DWORD Export_RVA;
	DWORD Export_RWA;
	Export_RVA = PDD[0].VirtualAddress;
	if(Export_RVA==0)
	{
		printf("No Export Table!!!\n");
		return ;
	}
	Export_RWA = Rva_To_Rwa(PNH,Export_RVA);
	printf("Export Raw To Data: 0x%x\n",Export_RWA);
	PED = (PIMAGE_EXPORT_DIRECTORY)(Export_RWA+(DWORD)LocalFHead);
	RWA = Rva_To_Rwa(PNH,PED->Name);
	Real_Name_RWA = RWA+(DWORD)LocalFHead;
	printf("Name: %s\n",Real_Name_RWA);
	printf("Characteristics: 0x%x\n",PED->Characteristics);
	printf("TimeDateStamp: 0x%x\n",PED->TimeDateStamp);
	printf("MajorVersion: 0x%x\n",PED->MajorVersion);
	printf("MinorVersion: 0x%x\n",PED->MinorVersion);
	printf("Name RVA: 0x%x\n",PED->Name);
	printf("Name Raw: 0x%x\n",RWA);
	printf("Base: 0x%x\n",PED->Base);
	printf("NumberOfFunctions: 0x%x\n",PED->NumberOfFunctions);
	printf("NumberOfNames: 0x%x\n",PED->NumberOfNames);
	printf("AddressOfFunctions: 0x%x\n",PED->AddressOfFunctions);
	printf("AddressOfFunctionsRaw: 0x%x\n",Rva_To_Rwa(PNH,PED->AddressOfFunctions));
	printf("AddressOfNames: 0x%x\n",PED->AddressOfNames);
	printf("AddressOfNamesRaw: 0x%x\n",Rva_To_Rwa(PNH,PED->AddressOfNames));
	printf("AddressOfNameOrdinals: 0x%x\n",PED->AddressOfNameOrdinals);
	printf("AddressOfNameOrdinalsRaw: 0x%x\n",Rva_To_Rwa(PNH,PED->AddressOfNameOrdinals));
	printf("--------------------------Export Functions----------------------------\n");
	printf("Num\t\t\t\tName\t\t\t\tRva\n");
	WORD i;
	for(i=0;i<PED->NumberOfFunctions;i++)
	{
		WORD *NumAddr = (WORD *)((DWORD)LocalFHead+Rva_To_Rwa(PNH,PED->AddressOfNameOrdinals));
		WORD *FuncAddr = (WORD *)((DWORD)LocalFHead+Rva_To_Rwa(PNH,PED->AddressOfFunctions));
		WORD *NameAddr = (WORD *)((DWORD)LocalFHead+Rva_To_Rwa(PNH,PED->AddressOfNames));
		printf("0x%x\t\t\t\t%s\t\t\t\t0x%x\n",NumAddr[i]+1,(DWORD)LocalFHead+Rva_To_Rwa(PNH,NameAddr[i]),FuncAddr[i]);
	}
}
int main(int argv,char **args)
{
	if(argv==1)
	{
		printf("You Can User Argument!!!\n");
		return 0;
	}
	LPTSTR FilePath = args[1];
	if(!IsPEFile(FilePath))
	{
		printf("It Is Not PE File!!!\n");
		return 0;
	}
	printf("DOS HEADER\n");
	ShowDosHeader(pFile);						//�鿴IMAGE_DOS_HEADER
	printf("\n");
	printf("NT HEADER\n");
	ShowNtHeader(pFile);						//�鿴IMAGE_NT_HEADER
	printf("\nSection Table\n");
	ShowSectionTable(pFile);					//�鿴IMAGE_SECTION_HEADER
	printf("\nImport Table\n");
	ShowImportTable(pFile);						//�鿴IMPORT_TABLE
	printf("\nEmport Table\n");
	ShowExportTable(pFile);						//�鿴EXPORT_TABLE
	return 0;
}
