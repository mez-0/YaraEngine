#ifndef YARA_H_
#define YARA_H_

#include "pch.h"

/// <summary>
/// Yara Manager Namespace
/// </summary>
namespace Yara
{
	/// <summary>
	/// Class to handle it all!
	/// </summary>
	class Manager
	{
	public:

		// Set this to TRUE if everything is set up
		BOOL bSetup = FALSE;

		/// <summary>
		/// Constructor: Initialise Yara and create the compiler
		/// </summary>
		Manager()
		{
			// Do the init
			int init = yr_initialize();
			if (init != ERROR_SUCCESS)
			{
				printf("Initialise failed: %s\n", GetErrorMsg(init).c_str());
				return;
			}

			// Create the compiler
			if (CreateCompiler())
			{
				bSetup = TRUE;
			}
			else
			{
				bSetup = FALSE;
			}
		}

		/// <summary>
		/// Destructor: Kill it all!
		/// </summary>
		~Manager()
		{
			if (compiler != NULL)
			{
				// Kill the compiler
				yr_compiler_destroy(compiler);
			}
			if (scanner != NULL)
			{
				// Kill the scanner
				yr_scanner_destroy(scanner);
			}

			// Kill yara
			int finalise = yr_finalize();
			if (finalise != ERROR_SUCCESS)
			{
				printf("Finalise failed: %s\n", GetErrorMsg(finalise).c_str());
				return;
			}
		}

		BOOL LoadRule(std::string path, BOOL bVerbose)
		{
			std::string rule = ReadFileToStringA(path);

			if (rule.empty())
			{
				return TRUE;
			}

			// Add the rule to the compiler
			int result = yr_compiler_add_string(compiler, rule.c_str(), nullptr);
			if (result != ERROR_SUCCESS)
			{
				if(bVerbose) printf("Failed to add rules from %s: %s\n", path.c_str(), GetErrorMsg(result).c_str());
				return FALSE;
			}
			else
			{
				return TRUE;
			}
		}

		/// <summary>
		/// Add a .yar file to the compiler
		/// </summary>
		/// <param name="rule_path">Path to the .yar file</param>
		/// <returns>Returns TRUE if successful, otherwise FALSE.</returns>
		BOOL AddRuleFromFile(std::string file_name)
		{
			FILE* rule_file = NULL;

			int result = fopen_s(&rule_file, file_name.c_str(), "r");
			if (result != ERROR_SUCCESS)
			{
				printf("Failed to open %s: %s\n", file_name.c_str(), GetErrorMsg(result).c_str());
				return FALSE;
			}

			result = yr_compiler_add_file(compiler, rule_file, NULL, file_name.c_str());
			if (result != ERROR_SUCCESS)
			{
				printf("Failed to add rules from %s: %s\n", file_name.c_str(), GetErrorMsg(result).c_str());
				return FALSE;
			}

			result = yr_compiler_get_rules(compiler, &rules);

			if (result != ERROR_SUCCESS)
			{
				printf("Failed to get rules from %s: %s\n", file_name.c_str(), GetErrorMsg(result).c_str());
				return FALSE;
			}

			printf("\\_ Added %s!\n", file_name.c_str());

			return TRUE;
		}

		/// <summary>
		/// From a directory, add everything
		/// </summary>
		/// <param name="rule_directory">The directory to load</param>
		/// <returns>Return TRUE/FALSE depending on success</returns>
		BOOL AddRulesFromDirectory(std::string rule_directory, BOOL bVerbose)
		{
			int file_count = 0;
			int succes_count = 0;

			for (const auto& dirEntry : std::filesystem::recursive_directory_iterator(rule_directory))
			{
				if (".yar" != dirEntry.path().extension())
				{
					continue;
				}
				if (LoadRule(dirEntry.path().string(), bVerbose))
				{
					succes_count++;
				}
				file_count++;
			}

			printf("\\_ Added %ld/%ld rules!\n", succes_count, file_count);

			// Check the rule was added
			int result = yr_compiler_get_rules(compiler, &rules);

			if (result != ERROR_SUCCESS)
			{
				printf("Failed to get rules from %s: %s\n", rule_directory.c_str(), GetErrorMsg(result).c_str());
				return FALSE;
			}
			else
			{
				printf("\\_ Successfully verified rules!\n");
				return TRUE;
			}
		}

		/// <summary>
		/// Create the scanner (wraps yr_scanner_create)
		/// </summary>
		/// <returns>Returns TRUE if successful, otherwise FALSE.</returns>
		BOOL CreateScanner()
		{
			// Actually create it
			int result = yr_scanner_create(rules, &scanner);
			if (result == ERROR_SUCCESS)
			{
				return TRUE;
			}
			else
			{
				printf("Failed to create scanner: %d\n", result);
				return FALSE;
			}
		}

		/// <summary>
		/// Scan the memory of the process and return a vector of YaraInfo
		/// </summary>
		/// <param name="dwPid">PID to scan</param>
		/// <returns>A vector of YaraInfo (vector of rules and the infected region struct)</returns>
		std::vector<YaraInfo> ScanProcessMemory(DWORD dwPid)
		{
			// Get a handle with PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
			RAII::Handle hProcess = OpenProcess(PROCESS_READ_FLAGS, FALSE, dwPid);

			std::vector<YaraInfo> allYaraInfo;

			if (hProcess.Empty())
			{
				printf("[!] Failed to get handle to %ld: %ld\n", dwPid, GetLastError());
				return allYaraInfo;
			}

			printf("\\_ Handle to %ld: 0x%p\n", dwPid, hProcess.Get());

			printf("\\_ Getting all regions...\n");

			// Read all the regions
			std::vector<RegionInfo> regions = GetProcessRegions(hProcess.Get());
			if (regions.size() == 0)
			{
				printf("[!] 0 Regions obtained!\n");
				return allYaraInfo;
			}
			printf("\\_ Regions obtained: %I64u\n", regions.size());

			printf("\\_ Running rules against all %I64u regions...\n", regions.size());

			// Loop over the regions
			for (RegionInfo& regionInfo : regions)
			{
				// Read that tegion into a buffer
				std::vector<std::byte> region = ReadRegionToBuffer(regionInfo, hProcess.Get());
				if (region.empty()) continue;


				const unsigned char* buffer = (const unsigned char*)region.data();
				int buffer_size = region.size();

				if (strlen((char*)buffer) == 0) continue;

				YaraInfo yaraInfo;

				// Scan it!
				int result = yr_rules_scan_mem(rules, buffer, buffer_size, SCAN_FLAGS_NO_TRYCATCH, capture_matches, &yaraInfo, 0);

				// If it matched, add it.
				if (yaraInfo.matched_rules.size() > 0)
				{
					yaraInfo.infectedRegion = regionInfo;
					allYaraInfo.push_back(yaraInfo);
				}
			}
			return allYaraInfo;
		}

	private:
		// Compiler object
		YR_COMPILER* compiler = NULL;
		
		// Rules object
		YR_RULES* rules = NULL;

		// Scann object
		YR_SCANNER* scanner = NULL;

		/// <summary>
		/// Wrapper for yr_compiler_create
		/// </summary>
		/// <returns>Returns TRUE if successful, otherwise FALSE.</returns>
		BOOL CreateCompiler()
		{
			int create = yr_compiler_create(&compiler);

			if (create == ERROR_SUCCESS)
			{
				return TRUE;
			}
			else
			{
				return FALSE;
			}
		}

		/// <summary>
		/// Switch on the known error codes
		/// </summary>
		/// <param name="err">The error as an int</param>
		/// <returns>A String for the int error</returns>
		std::string GetErrorMsg(int err)
		{
			std::string msg;
			switch (err)
			{
			case 0:
				msg = "ERROR_SUCCESS";
				break;
			case 1:
				msg = "ERROR_INSUFFICIENT_MEMORY";
				break;
			case 2:
				msg = "ERROR_COULD_NOT_OPEN_FILE";
				break;
			case 3:
				msg = "ERROR_COULD_NOT_MAP_FILE";
				break;
			case 4:
				msg = "ERROR_INVALID_FILE";
				break;
			case 5:
				msg = "ERROR_UNSUPPORTED_FILE_VERSION";
				break;
			case 6:
				msg = "ERROR_TOO_MANY_SCAN_THREADS";
				break;
			case 7:
				msg = "ERROR_SCAN_TIMEOUT";
				break;
			case 8:
				msg = "ERROR_CALLBACK_ERROR";
				break;
			case 9:
				msg = "ERROR_TOO_MANY_MATCHES";
				break;
			default:
				break;
			}
			return msg;
		}
		
		/// <summary>
		/// The callback function to identify the matched rules
		/// </summary>
		static int capture_matches(YR_SCAN_CONTEXT* context, int message, void* message_data, void* user_data)
		{
			PYaraInfo yaraInfo = static_cast<PYaraInfo>(user_data);

			if (message == CALLBACK_MSG_RULE_MATCHING)
			{
				YR_RULE* rule = (YR_RULE*)message_data;
				YR_STRING* string;

				yr_rule_strings_foreach(rule, string)
				{
					std::string rule_name = rule->identifier;
					if (VectorContainsStringA(yaraInfo->matched_rules, rule_name) == FALSE)
					{
						printf("[MATCH] => %s\n", rule_name.c_str());
						yaraInfo->matched_rules.push_back(rule_name);
					}
				}
			}

			return CALLBACK_CONTINUE;
		}

		/// <summary>
		/// Read a region into a vector of bytes
		/// </summary>
		/// <param name="regionInfo">ThE RegionInfo struct to read th base address and size of the region</param>
		/// <param name="hProcess">Handle to the process</param>
		/// <returns>A vector of bytes for that region</returns>
		std::vector<std::byte> ReadRegionToBuffer(RegionInfo regionInfo, HANDLE hProcess)
		{
			if (regionInfo.dwProtect == PAGE_NOACCESS) return std::vector<std::byte>{};

			std::vector<std::byte> buffer(regionInfo.dwRegion);

			BOOL bRead = ReadProcessMemory(hProcess, (LPVOID)regionInfo.pBase, buffer.data(), regionInfo.dwRegion, NULL);
			if (bRead == FALSE)
			{
				ErrorHandler::Show().print_win32error("ReadProcessMemory()");
			}

			return buffer;
		}

		/// <summary>
		/// Use VirtualQueryEx to pull out each region as a RegionInfo Struct
		/// </summary>
		/// <param name="hProcess">Handle to the process</param>
		/// <returns>A vector of RegionInfo which represents the data of the region</returns>
		std::vector<RegionInfo> GetProcessRegions(HANDLE hProcess)
		{
			std::vector<RegionInfo> regions;
			MEMORY_BASIC_INFORMATION mbi = {};
			LPVOID offset = 0;

			while (VirtualQueryEx(hProcess, offset, &mbi, sizeof(mbi)))
			{
				offset = (LPVOID)((DWORD_PTR)mbi.BaseAddress + mbi.RegionSize);

				RegionInfo regionInfo;
				regionInfo.pBase = mbi.BaseAddress;
				regionInfo.pAllocation = mbi.AllocationBase;
				regionInfo.dwProtect = mbi.Protect;
				regionInfo.dwRegion = mbi.RegionSize;
				regionInfo.dwState = mbi.State;
				regionInfo.dwType = mbi.Type;
				regions.push_back(regionInfo);
			}
			if (regions.size() == 0)
			{
				ErrorHandler::Show().print_win32error("VirtualQueryEx()");
			}
			return regions;
		}

	};
}

#endif