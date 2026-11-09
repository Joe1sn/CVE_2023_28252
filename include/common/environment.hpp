#pragma once
#include <windows.h>

namespace exploit
{
    typedef struct _OSVersionInfo
    {
        ULONG dwOSVersionInfoSize;
        ULONG dwMajorVersion;
        ULONG dwMinorVersion;
        ULONG dwBuildNumber;
        ULONG dwPlatformId;
        WCHAR szCSDVersion[128];
    }OSVersionInfo, * pOSVersionInfo;

    using RtlGetVersionFn = LONG(WINAPI*)(OSVersionInfo*);

    namespace env
    {
        // 64bit system check
        bool checkX64System();

        // Check if current system is: Windows 11 64-bit, build 10.0.22621.1105
        bool envCheck(unsigned int osVersion[]);

    } // namespace env

} // namespace exploit
