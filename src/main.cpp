/*
 * @Date: 2026-11-09 08:45:59
 * @LastEditors: joe1sn joe1sn23333@gmail.com
 * @LastEditTime: 2026-11-11 17:41:32
 * @FilePath: \CVE_2023_28252\src\main.cpp
 */
#include <iostream>
#include <windows.h>
#include "include/common/memtools.hpp"
#include "exp/CVE_2023_28252/poc.hpp"
#include "exp/CVE_2023_28252/def.hpp"
using std::cout;

unsigned int io2num(unsigned int ioctl_num) {
    return ((ioctl_num ^ 0x220000) >> 2) & 0xfff;
}

int main()
{
    CVE_2023_28252::PoC();
    // CVE_2023_28252::blfParser(L"C:\\Users\\Public\\251_833.blf");
    // CVE_2023_28252::getVirtualFunction();
    return 0;
}