#ifndef HELPERS_H
#define HELPERS_H

#include "pch.h"

inline std::string StringW2StringA(std::wstring ws)
{
	return std::string(ws.begin(), ws.end());
}

inline std::wstring StringA2StringW(std::string ss)
{
	return std::wstring(ss.begin(), ss.end());
}

inline BOOL CompareStringsW(std::wstring a, std::wstring b)
{
	if (a == b)
	{
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}

inline BOOL CompareStringsA(std::string a, std::string b)
{
	if (a == b)
	{
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}

inline BOOL CompareVectors(std::vector<unsigned char> a, std::vector<unsigned char> b)
{
	if (std::equal(a.begin(), a.end(), b.begin()))
	{
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}

inline std::vector<std::string> SplitA(const std::string& s, char seperator)
{
	std::vector<std::string> output;

	std::string::size_type prev_pos = 0, pos = 0;

	while ((pos = s.find(seperator, pos)) != std::string::npos)
	{
		std::string substring(s.substr(prev_pos, pos - prev_pos));
		if (substring.size() != 0)
		{
			output.push_back(substring);
		}
		prev_pos = ++pos;
	}
	output.push_back(s.substr(prev_pos, pos - prev_pos));
	return output;
}

inline std::wstring ConvToLowerW(std::wstring a)
{
	std::transform(a.begin(), a.end(), a.begin(), ::tolower);
	return a;
}

inline std::string ConvToLowerA(std::string a)
{
	std::transform(a.begin(), a.end(), a.begin(), ::tolower);
	return a;
}


inline BOOL VectorContainsStringA(std::vector<std::string> haystack, std::string needle)
{
	for (std::string& hay : haystack)
	{
		if (ConvToLowerA(hay) == ConvToLowerA(needle))
		{
			return TRUE;
		}
	}
	return FALSE;
}

inline std::string ReadFileToStringA(std::string path)
{
	std::ifstream t(path);
	std::string str((std::istreambuf_iterator<char>(t)), std::istreambuf_iterator<char>());
	return str;
}

inline BOOL CheckIfFile(std::string path)
{
	std::filesystem::path fs(path);
	std::error_code e;

	if (std::filesystem::is_regular_file(path, e))
	{
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}

#endif