#pragma once
#include <string>
#include <string>
namespace CVE_2023_28252
{
    void PoC();
    bool fixCRCFile(std::wstring filepath);
    void craftTriggerFile(std::wstring filepath);
    void craftSprayFile(std::wstring filepath);
    void blfParser(std::wstring filepath);

    inline std::wstring tFileName;
    inline std::wstring tFilePath;
    inline std::wstring tLogFilePath;
    inline std::wstring tContainerPath;

} // namespace CVE_2023_28252