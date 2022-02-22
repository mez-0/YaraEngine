#ifndef ERRORHANDLER_H_
#define ERRORHANDLER_H_

#include "pch.h"

namespace ErrorHandler
{
    class Show
    {
    public:
        BOOL bVerbose = FALSE;
        void print_win32error(std::string msg)
        {
#ifdef VERBOSE
            DWORD dwLastError = GetLastError();
            std::string error = std::system_category().message(dwLastError);
            printf("[!] %s: %s (%d)\n", msg.c_str(), error.c_str(), dwLastError);
#endif
        }
        void print_ntstatus(std::string msg, NTSTATUS status)
        {
#ifdef VERBOSE
            printf("[!] %s: 0x%x", msg.c_str(), status);
#endif            
        }
    };
}

#endif