#include <stdio.h>
#include <Windows.h>
#include <time.h>

PIMAGE_DOS_HEADER dos_header;
PIMAGE_NT_HEADERS nt_header;
PIMAGE_SECTION_HEADER section_header;

void printDosHeader() {
    printf("DOS Header:\n");
    printf("\tMagic Value:%.2s\n",(char *) &dos_header->e_magic);
    printf("\tNT Header Location:%d\n", dos_header->e_lfanew);
}


void printNtHeader() {
    printf("NT Headers:\n");
    printf("\tSignature:%.2s\n", (char*)&nt_header->Signature);
    printf("\tFile Header:\n");
    printf("\t\tMachine:0x%.4x\n", nt_header->FileHeader.Machine);
    time_t time = (time_t)nt_header->FileHeader.TimeDateStamp;
    char* dateString = ctime(&time);
    printf("\t\tCompile Time:%s\n", dateString);
}


void printOptHeader() {
    printf("Optional Header:\n");
    unsigned char architecture = nt_header->OptionalHeader.Magic;
    if (architecture == 0x10b) { printf("\tPE Architecture:32bit\n"); }
    else { printf("\tPE Architecture:64bit\n"); }
}


void printSectionHeader() {
    printf("Section Header:\n\tSection Names:\n");
    for (int i = 0; i < (*nt_header).FileHeader.NumberOfSections; i++) {
        printf("%x", section_header[i]);
    }
}


void printImportTable() {
    
    // Check if there is an Import Table
    if (nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size != 0) {
        section_header = (PIMAGE_SECTION_HEADER)((PBYTE)dos_header + dos_header->e_lfanew + sizeof(IMAGE_NT_HEADERS));

        // Get RVA of IAT and convert it to Offset
        DWORD iat_rva = nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        int section_index = locate(iat_rva);
        DWORD iat_address = resolve(iat_rva, section_index);

        // Get the first Object (or Module) in the IAT
        PIMAGE_IMPORT_DESCRIPTOR imported_module = (PIMAGE_IMPORT_DESCRIPTOR)((PBYTE)dos_header + iat_address);
        printf("IAT:\n");

        // Iterate through all Modules that have functions imported
        while (imported_module->Characteristics != 0x00) {

            // Convert module name RVA to offset and print
            DWORD name_address = resolve(imported_module->Name, section_index);
            printf("\tModule Name:%s\n", (char*)((PBYTE)dos_header + name_address));

            // Get pointer to first Object (or function) that the module imports
            DWORD function_address = resolve(imported_module->FirstThunk, section_index);
            PIMAGE_THUNK_DATA function_list = (PIMAGE_THUNK_DATA)((PBYTE)dos_header + function_address);

            // Iterate through all Functions that are imported
            while (function_list->u1.AddressOfData != 0x00) {
                unsigned __int64 isordinal = function_list->u1.AddressOfData;

                // Check if the most significant bit of the functions address is even, if so, quit
                if (!(isordinal & 0xFFFF0000)) { printf("\t\t---Ordinal Import---\n"); break; } // Check if import is by name or ordinal, if ordinal quit

                // Convert function name RVA to Offset and print
                PIMAGE_IMPORT_BY_NAME function_name_rva = (PIMAGE_IMPORT_BY_NAME)function_list->u1.AddressOfData;
                DWORD function_name_address = resolve(function_name_rva->Name, section_index);
                printf("\t\t%s\n", (char*)((PBYTE)dos_header + function_name_address));
                function_list++;
            }
            imported_module++;
        }
    }
}

int locate(DWORD VA) {
    // This function finds out what section of the PE contains the virtual address supplied
    // and returns its index.
    int index = 0;
    printf("Section Headers:\n");
    for (int i = 0; i < (*nt_header).FileHeader.NumberOfSections; i++) {
        if (VA >= section_header[i].VirtualAddress
            && VA < (section_header[i].VirtualAddress + section_header[i].Misc.VirtualSize)) {
            index = i;
        }
        printf("\t\t%s:0x%x\n", section_header[i].Name, section_header[i].VirtualAddress);
    }
    return index;
}


DWORD resolve(DWORD VA, int index) {
    // This function converts from RVA to Offset
    return (VA - section_header[index].VirtualAddress) + section_header[index].PointerToRawData;
}


// This program prints some basic PE data for a hardcoded path.
int main() {

    /* declare a file pointer */
    HANDLE hFile;
    DWORD file_len;
    char* file_path = "C:\\Users\\u2222222\\Downloads\\BatYamTool.exe";

    /* open an existing file for reading */
    hFile = CreateFileA(file_path, GENERIC_READ, 0,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    /* quit if the file does not exist */
    if (hFile == INVALID_HANDLE_VALUE) {
        return 1;
    }
    /* copy all the text into the buffer */
    GetFileSizeEx(hFile, &file_len);
    unsigned char* buffer = (unsigned char*)malloc(file_len+1);

    /* quit if the allocation failed */
    if (!buffer) {
        return 1;
    }

    /* Read the file into memory */
    ReadFile(hFile, buffer, file_len, NULL, NULL);
    CloseHandle(hFile);

    /* maybe the buffer is too big so add a null terminator */
    buffer[file_len] = 0x00;
    dos_header = (PIMAGE_DOS_HEADER)buffer;
    nt_header = (PIMAGE_NT_HEADERS)((PBYTE)dos_header + dos_header->e_lfanew);

    /* print PE headers */
    printDosHeader();
    printNtHeader();
    printOptHeader();
    printImportTable();
    return 0;
}


