#include "pch.h"

int main(int argc, char* argv[])
{
	printf("~ YaraEngine ~\n\n");

	// Path to yara file
	std::string path;

	// Pid to scan
	DWORD dwPid;

	if (argc != 3)
	{
		printf("PS> YaraEngine.exe <path to rule> <pid>\n");
		return -1;
	}
	else
	{
		path = argv[1];
		dwPid = atoi(argv[2]);
	}

	printf("\\_ Config:\n");
	printf("  | Rule Path: %s\n", path.c_str());
	printf("  | Process ID: %ld\n", dwPid);
	printf("\n");

	// Initialise yara
	Yara::Manager yara = Yara::Manager();

	if (yara.bSetup == FALSE)
	{
		return -1;
	}

	// Add the rules to yara
	if (CheckIfFile(path))
	{
		if (yara.AddRuleFromFile(path) == FALSE)
		{
			printf("[!] Failed to load file: %s\n", path.c_str());
			return -1;
		}
	}
	else
	{
		if (yara.AddRulesFromDirectory(path) == FALSE)
		{
			printf("[!] Failed to load directory: %s\n", path.c_str());
			return -1;
		}
	}

	printf("\\_ Loaded %s\n", path.c_str());

	// Scan all the memory regions of the process with the yara rules
	std::vector<YaraInfo> matches = yara.ScanProcessMemory(dwPid);

	if (matches.size() == 0)
	{
		printf("[!] No Yara matches!\n");
		return -1;
	}

	// Display it all

	printf("\n");

	int idx = 1;
	for (YaraInfo& match : matches)
	{
		printf("\\_ Match: %d/%I64u\n", idx, matches.size());
		printf("  | Base Address: 0x%p\n", match.infectedRegion.pBase);
		printf("  | Allocation Address: 0x%p\n", match.infectedRegion.pAllocation);
		printf("  | Page Protection: %ld\n", match.infectedRegion.dwProtect);
		printf("  | Page State: %ld\n", match.infectedRegion.dwState);
		printf("  | Page Type: %ld\n", match.infectedRegion.dwType);
		printf("  | Rules:\n");
		for (std::string& rule : match.matched_rules)
		{
			printf("   - %s\n", rule.c_str());
		}
		idx++;
		printf("\n");
	}


	return 0;
}
