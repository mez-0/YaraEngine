#ifndef RAII_H_
#define RAII_H_

#include "pch.h"

namespace RAII
{
    class Handle
    {
    public:
        Handle(HANDLE hHandle)
        {
            _hHandle = hHandle;
        }
        void Update(HANDLE hHandle)
        {
            _hHandle = hHandle;
        }
        HANDLE Get()
        {
            return _hHandle;
        }

        BOOL Empty()
        {
            if (_hHandle == NULL)
            {
                return TRUE;
            }
            else
            {
                return FALSE;
            }
        }

        BOOL Close()
        {
            if (CloseHandle(_hHandle))
            {
                return TRUE;
            }
            else
            {
                return FALSE;
            }
        }
        ~Handle()
        {
            if (_hHandle) CloseHandle(_hHandle);
        }
    private:
        HANDLE _hHandle;
    };
}
#endif