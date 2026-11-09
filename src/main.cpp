#include <iostream>
#include <windows.h>
#include "include/common/memtools.hpp"
using std::cout;

unsigned int io2num(unsigned int ioctl_num) {
    return ((ioctl_num ^ 0x220000) >> 2) & 0xfff;
}

int main()
{
    return 0;
}