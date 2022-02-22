#ifndef YARA_H_
#define YARA_H_

#include "pch.h"

namespace Yara
{
	class Manager
	{
	public:
		Manager()
		{
			int init = yr_initialize();
			if (init != ERROR_SUCCESS)
			{
				printf("Initialise failed: %s\n", GetErrorMsg(init).c_str());
				return;
			}

			if (CreateCompiler())
			{
				success = TRUE;
			}
			else
			{
				success = FALSE;
			}
		}

		~Manager()
		{
			if (compiler != NULL)
			{
				yr_compiler_destroy(compiler);
			}
			if (scanner != NULL)
			{
				yr_scanner_destroy(scanner);
			}

			// must be called when you are finished using the library.
			int finalise = yr_finalize();
			if (finalise != ERROR_SUCCESS)
			{
				printf("Finalise failed: %s\n", GetErrorMsg(finalise).c_str());
				return;
			}
		}

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

			return TRUE;
		}

		BOOL CreateScanner()
		{
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

		std::vector<YaraInfo> ScanProcessMemory(DWORD dwPid)
		{
			RAII::Handle hProcess = OpenProcess(PROCESS_READ_FLAGS, FALSE, dwPid);

			std::vector<YaraInfo> allYaraInfo;

			if (hProcess.Empty())
			{
				return allYaraInfo;
			}

			std::vector<RegionInfo> regions = GetProcessRegions(hProcess.Get());

			if (regions.size() == 0)
			{
				return allYaraInfo;
			}

			for (RegionInfo& regionInfo : regions)
			{
				std::vector<std::byte> region = ReadRegionToBuffer(regionInfo, hProcess.Get());
				if (region.empty()) continue;


				const unsigned char* buffer = (const unsigned char*)region.data();
				int buffer_size = region.size();

				if (strlen((char*)buffer) == 0) continue;

				YaraInfo yaraInfo;

				int result = yr_rules_scan_mem(rules, buffer, buffer_size, SCAN_FLAGS_NO_TRYCATCH, capture_matches, &yaraInfo, 0);

				if (yaraInfo.matched_rules.size() > 0)
				{
					yaraInfo.infectedRegion = regionInfo;
					allYaraInfo.push_back(yaraInfo);
				}
			}
			return allYaraInfo;
		}

		void LogRuleMatches(PProcessInfo processInfo)
		{
			printf("  |> Yara Rules Matched in the following regions:\n");

			for (YaraInfo& yaraInfo : processInfo->allYaraInfo)
			{
				for (std::string& rule_name : yaraInfo.matched_rules)
				{
					printf("    - %s: 0x%p (%ld)\n", rule_name.c_str(), yaraInfo.infectedRegion.pBase, yaraInfo.infectedRegion.dwProtect);
				}
			}

		}

	private:
		YR_COMPILER* compiler = NULL;
		YR_RULES* rules = NULL;
		YR_SCANNER* scanner = NULL;
		BOOL success = FALSE;

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
						yaraInfo->matched_rules.push_back(rule_name);
					}
				}
			}

			return CALLBACK_CONTINUE;
		}

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

		std::vector<RegionInfo> GetProcessRegions(HANDLE hProcess)
		{
			std::vector<RegionInfo> regions;
			MEMORY_BASIC_INFORMATION mbi = {};
			LPVOID offset = 0;

			while (VirtualQueryEx(hProcess, offset, &mbi, sizeof(mbi)))
			{
				offset = (LPVOID)((DWORD_PTR)mbi.BaseAddress + mbi.RegionSize);
				if (mbi.State == MEM_COMMIT || mbi.State == MEM_FREE)
				{
					RegionInfo regionInfo;
					regionInfo.pBase = mbi.BaseAddress;
					regionInfo.pAllocation = mbi.AllocationBase;
					regionInfo.dwProtect = mbi.Protect;
					regionInfo.dwRegion = mbi.RegionSize;
					regionInfo.dwState = mbi.State;
					regionInfo.dwType = mbi.Type;
					regions.push_back(regionInfo);
				}
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