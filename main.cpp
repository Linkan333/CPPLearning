#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <psapi.h>
#include <stdint.h>

#pragma comment(lib, "psapi.lib")


char lastProcessName[MAX_PATH] = "<unknown>";
LPVOID lastMemoryAddress = NULL;


void memoryEditing(HANDLE hProcess, LPVOID dst, void* src, SIZE_T size) {
    DWORD oldProtect;

    if (VirtualProtectEx(hProcess, dst, size, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        if (WriteProcessMemory(hProcess, dst, src, size, NULL)) {
            printf("Memory written successfully at address: 0x%p\n", dst);
            lastMemoryAddress = dst;
        } else {
            printf("Failed to write memory. Error %ld\n", GetLastError());
        }

        VirtualProtectEx(hProcess, dst, size, oldProtect, &oldProtect);
    } else {
        printf("Failed to change memory protection. Error: %ld\n", GetLastError());
    }
}

void listAllProcesses() {
    DWORD processes[1024], count, needed;

    if (!EnumProcesses(processes, sizeof(processes), &needed)) {
        printf("Failed to enumrate processes. \n");
        return;
    }

    count = needed / sizeof(DWORD);

    for (DWORD i = 0; i < count; i++) {
        if (processes[i] != 0) {
            DWORD processID = processes[i];

            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, processID);
            if (hProcess) {
                HMODULE hMod;
                DWORD cbNeeded;
                char processName[MAX_PATH] = "<unknown>";

                if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded)) {
                    GetModuleBaseName(hProcess, hMod, processName, sizeof(processName) / sizeof(char));

                    MODULEINFO modInfo;
                    if (GetModuleInformation(hProcess, hMod, &modInfo, sizeof(modInfo))) {
                        printf("Process ID: %u, Process Name: %s, Base Address: 0x%p\n",
                        processID, processName, modInfo.lpBaseOfDll);


                        LPVOID addressToModify = (LPVOID)((uintptr_t)modInfo.lpBaseOfDll + 0x6D03);  // Example offset from base address
                        int newValue = 1234;

                        memoryEditing(hProcess, addressToModify, &newValue, sizeof(newValue));
                    }
                }
                CloseHandle(hProcess);
            }
        }
    }
}
int main() {
    listAllProcesses();
    if(lastMemoryAddress != NULL) {
        printf("new memory address in process %s is 0x%p\n", lastProcessName, lastMemoryAddress);
    } else {
        printf("No memory modifications were made. \n");
    }
    system("pause");
    return 0;
}