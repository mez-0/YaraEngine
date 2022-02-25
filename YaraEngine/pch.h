#ifndef PCH_H
#define PCH_H

#include <Windows.h>
#include <yara.h>
#include <string>
#include <vector>
#include <system_error>
#include <algorithm>

#define PROCESS_READ_FLAGS PROCESS_QUERY_INFORMATION | PROCESS_VM_READ

/// <summary>
/// A Struct to hold info on regions
/// </summary>
typedef struct REGIONINFO
{
    LPVOID pBase;
    LPVOID pAllocation;
    DWORD dwRegion;
    DWORD dwProtect;
    DWORD dwState;
    DWORD dwType;
} RegionInfo, * PRegionInfo;

/// <summary>
/// Struct to hold yara match
/// </summary>
typedef struct YARAINFO
{
    std::vector<std::string> matched_rules;
    RegionInfo infectedRegion;
} YaraInfo, * PYaraInfo;

/// <summary>
/// The main struct; each process is converted into this.
/// </summary>
typedef struct PROCESSINFO
{
    // name of process
    std::string processname;

    // process id
    DWORD dwPid = 0;

    // ALL regions
    std::vector<RegionInfo> allRegionInfo;

    // all yara info
    std::vector<YaraInfo> allYaraInfo;

} ProcessInfo, * PProcessInfo;

#include "ErrorHandler.hpp"
#include "Helpers.hpp"
#include "RAII.hpp"
#include "Yara.hpp"

#endif
