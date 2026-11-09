/*
 * @Date: 2026-10-26 11:14:38
 * @LastEditors: joe1sn joe1sn23333@gmail.com
 * @LastEditTime: 2026-10-26 11:21:27
 * @FilePath: \panicake\src\common\environment.cpp
 */
#include "include/common/environment.hpp"
#include <iostream>
using namespace exploit;

namespace exploit
{
    namespace env
    {
        bool checkX64System() {
            SYSTEM_INFO si;
            GetNativeSystemInfo(&si);
            if (si.wProcessorArchitecture != PROCESSOR_ARCHITECTURE_AMD64 &&
                si.wProcessorArchitecture != PROCESSOR_ARCHITECTURE_ARM64)
            {
                std::cerr << "[-] Not a 64-bit system (arch=" << si.wProcessorArchitecture << ")\n";
                return false;
            }
            std::cout << "[*] 64-bit system (arch="
                << (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ? "x64" : "ARM64")
                << ")\n";
            return true;
        }

        bool envCheck(unsigned int osVersion[])
        {
            // export os build info
            auto* ntdll = GetModuleHandleW(L"ntdll.dll");
            if (!ntdll)
            {
                std::cerr << "[-] Failed to get ntdll.dll handle\n";
                return false;
            }

            auto rtlGetVersion = reinterpret_cast<RtlGetVersionFn>(
                GetProcAddress(ntdll, "RtlGetVersion"));
            if (!rtlGetVersion)
            {
                std::cerr << "[-] Failed to resolve RtlGetVersion\n";
                return false;
            }

            OSVersionInfo osvi = { sizeof(osvi) };
            if (rtlGetVersion(&osvi) != 0)
            {
                std::cerr << "[-] RtlGetVersion failed\n";
                return false;
            }

            if (osvi.dwMajorVersion != osVersion[0] || osvi.dwMinorVersion != osVersion[1] || osvi.dwBuildNumber != osVersion[2])
            {
                std::cerr << "[-] OS version mismatch: got "
                    << osvi.dwMajorVersion << "." << osvi.dwMinorVersion << "."
                    << osvi.dwBuildNumber
                    << ", expected " << osVersion[0] << "." << osVersion[1] << "." << osVersion[2] << "." << "\n";
                return false;
            }
            std::cout << "[*] OS version: " << osvi.dwMajorVersion << "." << osvi.dwMinorVersion
                << "." << osvi.dwBuildNumber << "\n";

            // ---- 2. UBR (Update Build Revision): must be 1xxx ----
            HKEY hKey = nullptr;
            DWORD ubr = 0;
            DWORD ubrSize = sizeof(ubr);
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                0, KEY_READ, &hKey) == ERROR_SUCCESS)
            {
                RegQueryValueExW(hKey, L"UBR", nullptr, nullptr,
                    reinterpret_cast<LPBYTE>(&ubr), &ubrSize);
                RegCloseKey(hKey);
            }

            if (ubr != osVersion[3] / 1000)
            {
                std::cerr << "[-] UBR mismatch: got " << ubr << ", expected " << osVersion[3] << "\n";
                return false;
            }
            std::cout << "[*] UBR: " << ubr << "\n";

            // ---- 3. 64-bit system ----
            if (!checkX64System()) {
                return false;
            }
            std::cout << "[+] Environment check passed\n";
            return true;
        }

    } // namespace env

} // namespace exploit