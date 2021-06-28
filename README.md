# inspect-PE
inspect PE file

```
// PeInsideCon.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <windows.h>
#include <WINNT.H>
#include <windef.h>
#include <stdio.h>
#include <delayimp.h>
#include <imagehlp.h>
#include <time.h>

#define ALIGN_DOWN(x, align)            (x & ~(align-1))//выравнивание вниз
#define ALIGN_UP(x, align)              ((x & (align-1))?ALIGN_DOWN(x,align)+align:x)//выравнивание вверх
#define NTSIGNATURE(a) ((LPVOID)((BYTE *)a+((PIMAGE_DOS_HEADER)a)->e_lfanew))


//Base - файл проецируется в память, это его база
//RVA - значение, которое нужно преобразовать в Offset
DWORD RVAtoOffset(DWORD Base,DWORD RVA)
{
	PIMAGE_NT_HEADERS pPE=(PIMAGE_NT_HEADERS)((long)Base+((PIMAGE_DOS_HEADER)Base)->e_lfanew);
	short NumberOfSection=pPE->FileHeader.NumberOfSections;
	long SectionAlign=pPE->OptionalHeader.SectionAlignment;
	PIMAGE_SECTION_HEADER Section=(PIMAGE_SECTION_HEADER)(pPE->FileHeader.SizeOfOptionalHeader+(long)&(pPE->FileHeader)+sizeof(IMAGE_FILE_HEADER));
	long VirtualAddress,PointerToRawData;
	bool flag=false;
	for (int i=0;i<NumberOfSection;i++)
	{
		if ((RVA>=(Section->VirtualAddress))&&(RVA<ALIGN_UP(Section->VirtualAddress+Section->Misc.VirtualSize,pPE->OptionalHeader.SectionAlignment))  ) 
		{
			VirtualAddress=Section->VirtualAddress;
			PointerToRawData=Section->PointerToRawData;
			flag=true;
			break;
		}
		
		Section++;
	}
	if (flag) return RVA-VirtualAddress+PointerToRawData;
	else return RVA;
}

void printDataDirectory(long hMap)
{
	PIMAGE_NT_HEADERS pPE=static_cast<struct _IMAGE_NT_HEADERS *>NTSIGNATURE((long)hMap);
	PIMAGE_DATA_DIRECTORY DataDirectory=(PIMAGE_DATA_DIRECTORY)&(pPE->OptionalHeader.DataDirectory);
	printf("#####Data Directory#####\n");
	for (unsigned int i=0;i<pPE->OptionalHeader.NumberOfRvaAndSizes;i++)
	{
		 switch (i)
		 {
		   case IMAGE_DIRECTORY_ENTRY_EXPORT:printf("---Export Directory---\nRVA: %X\nSize: %X\n",DataDirectory[i].VirtualAddress,DataDirectory[i].Size);break;
		   case IMAGE_DIRECTORY_ENTRY_IMPORT:printf("---Import Directory---\nRVA: %X\nSize: %X\n",DataDirectory[i].VirtualAddress,DataDirectory[i].Size);break;
		   case IMAGE_DIRECTORY_ENTRY_RESOURCE:printf("---Resource Directory---\nRVA: %X\nSize: %X\n",DataDirectory[i].VirtualAddress,DataDirectory[i].Size);break;
		   case IMAGE_DIRECTORY_ENTRY_EXCEPTION:printf("---Exception Directory---\nRVA: %X\nSize: %X\n",DataDirectory[i].VirtualAddress,DataDirectory[i].Size);break;
		   case IMAGE_DIRECTORY_ENTRY_SECURITY:printf("---Security Directory---\nRVA: %X\nSize: %X\n",DataDirectory[i].VirtualAddress,DataDirectory[i].Size);break;
		   case IMAGE_DIRECTORY_ENTRY_BASERELOC:printf("---Basereloc Directory---\nRVA: %X\nSize: %X\n",DataDirectory[i].VirtualAddress,DataDirectory[i].Size);break;
		   case IMAGE_DIRECTORY_ENTRY_DEBUG:printf("---Debug Directory---\nRVA: %X\nSize: %X\n",DataDirectory[i].VirtualAddress,DataDirectory[i].Size);break;
		   case IMAGE_DIRECTORY_ENTRY_ARCHITECTURE:printf("---Architecture Directory---\nRVA: %X\nSize: %X\n",DataDirectory[i].VirtualAddress,DataDirectory[i].Size);break;
		   case IMAGE_DIRECTORY_ENTRY_GLOBALPTR:printf("---GlobalPTR Directory---\nRVA: %X\nSize: %X\n",DataDirectory[i].VirtualAddress,DataDirectory[i].Size);break;
		   case IMAGE_DIRECTORY_ENTRY_TLS:printf("---TLS Directory---\nRVA: %X\nSize: %X\n",DataDirectory[i].VirtualAddress,DataDirectory[i].Size);break;
		   case IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG:printf("---LOADCONFIG Directory---\nRVA: %X\nSize: %X\n",DataDirectory[i].VirtualAddress,DataDirectory[i].Size);break;
		   case IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT:printf("---Bound-Import Directory---\nRVA: %X\nSize: %X\n",DataDirectory[i].VirtualAddress,DataDirectory[i].Size);break;
		   case IMAGE_DIRECTORY_ENTRY_IAT:printf("---IAT Directory---\nRVA: %X\nSize: %X\n",DataDirectory[i].VirtualAddress,DataDirectory[i].Size);break;
		   case IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT:printf("---Delay-Import Directory---\nRVA: %X\nSize: %X\n",DataDirectory[i].VirtualAddress,DataDirectory[i].Size);break;
		   case IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR:printf("---Com Descriptor Directory---\nRVA: %X\nSize: %X\n",DataDirectory[i].VirtualAddress,DataDirectory[i].Size);break;
		 }
	}
}
void printSectionHeader(long hMap)
{
	printf("#####Section Table#####\n");
	PIMAGE_NT_HEADERS pPE=static_cast<struct _IMAGE_NT_HEADERS *>NTSIGNATURE((long)hMap);
	PIMAGE_SECTION_HEADER Section=(PIMAGE_SECTION_HEADER)(pPE->FileHeader.SizeOfOptionalHeader+(long)&(pPE->OptionalHeader) );
	for (int i=0;i<pPE->FileHeader.NumberOfSections;i++)
	{

		printf("----------Section: %.8s----------\nVirtual Address: %X\nVirtual Size: %X\nSizeOfRawData: %X\n PointerToRawData: %X\nCharacteristics: %X\n",&(Section->Name)
			,Section->VirtualAddress,Section->Misc.VirtualSize,Section->SizeOfRawData,Section->PointerToRawData,Section->Characteristics);
		Section++;
	}
}
void printBoundImport(long hMap)
{
	printf("#####Bound Import#####\n");
	PIMAGE_NT_HEADERS pPE=(PIMAGE_NT_HEADERS)NTSIGNATURE((long)hMap);
	if (pPE->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress==0) return;
	PIMAGE_BOUND_IMPORT_DESCRIPTOR Bound=(PIMAGE_BOUND_IMPORT_DESCRIPTOR)(RVAtoOffset((long)hMap,pPE->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress)+(long)hMap);
	printf("DLL Name:%s TimeDateStamp:%X",(long)Bound+(long)(Bound->OffsetModuleName),Bound->TimeDateStamp);
	for (int i=0;i<Bound->NumberOfModuleForwarderRefs;i++)
	{
		Bound++;
		printf("DLL Name:%s TimeDateStamp:%X\n",(long)Bound+(long)(Bound->OffsetModuleName),Bound->TimeDateStamp);
	}
	printf("\n");
}

void printExportTable(long hMap)
{
	printf("#####Export Table#####\n");
	PIMAGE_NT_HEADERS pPE=(PIMAGE_NT_HEADERS)NTSIGNATURE(hMap);
	short NumberOfSection=pPE->FileHeader.NumberOfSections;
	DWORD ExportRVA=pPE->OptionalHeader.DataDirectory[0].VirtualAddress;

	PIMAGE_EXPORT_DIRECTORY Export=(PIMAGE_EXPORT_DIRECTORY)RVAtoOffset((long)hMap,ExportRVA);
	Export=(PIMAGE_EXPORT_DIRECTORY)((long)Export+(long)hMap);

	WORD* AddressOfNameOrdinals=(unsigned short *)RVAtoOffset((long)hMap,Export->AddressOfNameOrdinals);
	AddressOfNameOrdinals=(WORD*)((long)AddressOfNameOrdinals+(long)hMap);

	DWORD* AddressOfNames=(unsigned long *)RVAtoOffset((long)hMap,Export->AddressOfNames);
	AddressOfNames=(DWORD*)((long)AddressOfNames+(long)hMap);

	DWORD* AddressOfFunctions=(unsigned long *)RVAtoOffset((long)hMap,Export->AddressOfFunctions);
	AddressOfFunctions=(DWORD*)((long)AddressOfFunctions+(long)hMap);

	WORD index;
	printf("%4s      %-40s       %s\n-----------------------------------------------------------------------\n","Ordinal","NameOfFunctions","EntryPoint");
	for (unsigned int i=0;i<Export->NumberOfFunctions;i++)
	{
		index=0xFFFF;
		for (unsigned int j=0;j<Export->NumberOfNames;j++)
		{
			if (AddressOfNameOrdinals[j]==(i+Export->Base))
			{
				index=j;continue;
			}
		}
		if ((AddressOfFunctions[i]>=pPE->OptionalHeader.DataDirectory[0].VirtualAddress)&&(AddressOfFunctions[i]<=pPE->OptionalHeader.DataDirectory[0].VirtualAddress+pPE->OptionalHeader.DataDirectory[0].Size))
		{
			if (index!=0xFFFF) printf("%4d         |%-35s       |Forw->%s\n",i+Export->Base,(long)hMap+RVAtoOffset((long)hMap,AddressOfNames[index]),(long)hMap+RVAtoOffset((long)hMap,AddressOfFunctions[i]));
			else printf("%4d         |OrdinalOnly       |Forw->%s\n",i+Export->Base,(long)hMap+RVAtoOffset((long)hMap,AddressOfNames[i]),(long)hMap+RVAtoOffset((long)hMap,AddressOfFunctions[i]));
		}
		if (index!=0xFFFF) printf("%4d         |%-35s       |%X\n",i+Export->Base,(long)hMap+RVAtoOffset((long)hMap,AddressOfNames[index]),AddressOfFunctions[i]);
		else printf("%4d         |OrdinalOnly       |%X\n",i+Export->Base,AddressOfFunctions[i]);
	}
}

void printDelayImport(long hMap)
{
	printf("#####Delay Import#####\n");
	PIMAGE_NT_HEADERS pPE=(PIMAGE_NT_HEADERS)NTSIGNATURE((long)hMap);
	if (pPE->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress==0) return;
	PImgDelayDescr Delay=(PImgDelayDescr)(RVAtoOffset((long)hMap,pPE->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress)+(long)hMap);
	while (Delay->rvaIAT!=0)
	{
		if (Delay->grAttrs==1)
		{
			printf("-------%s-------\n",RVAtoOffset( (long)hMap,(long)(Delay->rvaDLLName))+(long)hMap);
			printf("Attrib: %X\nTimeDateStamp: %X\nImport Address Table: %X\nImport Name Table: %X\nBound IAT: %X\nUnload IAT:%X\n",Delay->grAttrs,Delay->dwTimeStamp,Delay->rvaIAT,Delay->rvaINT,Delay->rvaBoundIAT,Delay->rvaUnloadIAT);

		}
		else
		{
			printf("-------%s-------\n",RVAtoOffset( (long)hMap,(long)(Delay->rvaDLLName-pPE->OptionalHeader.ImageBase))+(long)hMap);
			printf("Attrib: %X\nTimeDateStamp: %X\nImport Address Table: %X\nImport Name Table: %X\nBound IAT: %X\nUnload IAT:%X\n",Delay->grAttrs,Delay->dwTimeStamp,Delay->rvaIAT,Delay->rvaINT,Delay->rvaBoundIAT,Delay->rvaUnloadIAT);
		}
		Delay++;
	}
}

void printImportTable(long hMap)
{
	printf("#####Import Table#####\n");
	PIMAGE_NT_HEADERS pPE=(PIMAGE_NT_HEADERS)NTSIGNATURE((long)hMap);
	PIMAGE_IMPORT_DESCRIPTOR Import=(PIMAGE_IMPORT_DESCRIPTOR)(RVAtoOffset((long)hMap,pPE->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress)+(long)hMap);
	IMAGE_THUNK_DATA32* Thunk;
	PIMAGE_IMPORT_BY_NAME ImportName;
	int x=0;
	while (Import->Characteristics!=0)
	{
		x++;
		printf("--------Library: %s-----------\n TimeDateStamp:%X\n ForwardedChain:%X\n OriginalFirstThunk:%X\n FirstThunk:%X\n",RVAtoOffset((long)hMap,Import->Name)+(long)hMap,Import->TimeDateStamp,Import->ForwarderChain,Import->OriginalFirstThunk,Import->FirstThunk);
		Thunk=(IMAGE_THUNK_DATA32*)(RVAtoOffset((long)hMap,Import->OriginalFirstThunk)+(long)hMap);
		while (Thunk->u1.Ordinal!=0)
		{
			if (  ( (Thunk->u1.Ordinal) & 0x80000000)!=0)
			{
				printf("Ordinal: %X\n",(long)(IMAGE_THUNK_DATA32*)Thunk->u1.Ordinal);
			}
			else 
			{
				ImportName=(PIMAGE_IMPORT_BY_NAME)(RVAtoOffset((long)hMap,(long)(Thunk->u1.AddressOfData))+(long)(hMap));
				printf("NameOfFunction:%s\n",&(ImportName->Name));
			}
			Thunk++;
		}
		Import++;
	}
}
void printHeaders(long hMap)
{
	PIMAGE_NT_HEADERS pPE=(PIMAGE_NT_HEADERS)NTSIGNATURE((long)hMap);
	printf("#####File Header#####\n");
	printf("Machine:%X\nNumber of Sections:%X\nTimeDateStamp:%X\nPointer to Symbol Table:%X\nNumber Of Symbols:%X\nSize Of Optional Header:%X\nCharacteristics:%X\n",pPE->FileHeader.Machine,pPE->FileHeader.NumberOfSections,pPE->FileHeader.TimeDateStamp,pPE->FileHeader.PointerToSymbolTable,pPE->FileHeader.NumberOfSymbols,pPE->FileHeader.SizeOfOptionalHeader);
	printf("#####Optional Header#####\n");
	printf("Magic:%X\nMajorLinkerVersion:%X\nMinorLinkerVersion:%X\nSizeOfCode:%X\nSizeOfInitializedData:%X\nSizeOfUninitializedData:%X\nAddressOfEntryPoint:%X\nBaseOfCode:%X\nBaseOfData:%X\nImageBase:%X\nSectionAlignment:%X\nFileAlignment:%X\nMajorOperatingSystemVersion:%X\nMinorOperatingSystemVersion:%X\nMajorImageVersion:%X\nMinorImageVersion:%X\nMajorSubsystemVersion:%X\nMinorSubsystemVersion:%X\nWin32VersionValue:%X\nSizeOfImage:%X\nSizeOfHeaders:%X\nCheckSum:%X\nSubsystem:%X\nDllCharacteristics:%X\nSizeOfStackReserve:%X\nSizeOfStackCommit:%X\nSizeOfHeapReserve:%X\nSizeOfHeapCommit:%X\nLoaderFlags:%X\nNumberOfRvaAndSizes:%X\n",
	pPE->OptionalHeader.Magic,pPE->OptionalHeader.MajorLinkerVersion,pPE->OptionalHeader.MinorLinkerVersion,pPE->OptionalHeader.SizeOfCode,pPE->OptionalHeader.SizeOfInitializedData,pPE->OptionalHeader.SizeOfUninitializedData,pPE->OptionalHeader.AddressOfEntryPoint,pPE->OptionalHeader.BaseOfCode,pPE->OptionalHeader.BaseOfData,pPE->OptionalHeader.ImageBase,pPE->OptionalHeader.SectionAlignment,pPE->OptionalHeader.FileAlignment,pPE->OptionalHeader.MajorOperatingSystemVersion,pPE->OptionalHeader.MinorOperatingSystemVersion,pPE->OptionalHeader.MajorImageVersion,pPE->OptionalHeader.MinorImageVersion,pPE->OptionalHeader.MajorSubsystemVersion,pPE->OptionalHeader.MinorSubsystemVersion,pPE->OptionalHeader.Win32VersionValue,pPE->OptionalHeader.SizeOfImage,pPE->OptionalHeader.SizeOfHeaders,pPE->OptionalHeader.CheckSum,pPE->OptionalHeader.Subsystem,pPE->OptionalHeader.DllCharacteristics,pPE->OptionalHeader.SizeOfStackReserve,pPE->OptionalHeader.SizeOfStackCommit,pPE->OptionalHeader.SizeOfHeapReserve,pPE->OptionalHeader.SizeOfHeapCommit,pPE->OptionalHeader.LoaderFlags,pPE->OptionalHeader.NumberOfRvaAndSizes);
}

void printTimeStamp(DWORD x)
{
	//struct tm* Time=gmtime((const long *)&x);
	//printf("Year:%d\nMonth:%d\nDay:%d\n",Time->tm_year+1900,Time->tm_mon,Time->tm_mday);
}

int main(int argc, char* argv[])
{
	PTSTR CommandLine;
	//while (1);
	CommandLine=GetCommandLine();
	int i=0;
	while (CommandLine[i]!=' ') i++;
	CommandLine=CommandLine+i+1;
	char Buffer[255];
	lstrcpy(Buffer,CommandLine);
	HANDLE hFile=CreateFile(Buffer,GENERIC_WRITE | GENERIC_READ,FILE_SHARE_WRITE,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
	HANDLE hMapping=CreateFileMapping(hFile,NULL,PAGE_READWRITE,0,0,NULL);
	HANDLE hMap=MapViewOfFile(hMapping,FILE_MAP_ALL_ACCESS,0,0,0);
	printHeaders((long)hMap);
	printDataDirectory((long)hMap);
	printSectionHeader((long)hMap);
	printExportTable((long)hMap);
	printImportTable((long)hMap);
	printBoundImport((long)hMap);
	printDelayImport((long)hMap);
	return 0;
}

```
