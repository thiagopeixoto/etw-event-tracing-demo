#include "etwhelper.h"

int main()
{
	std::vector<GUID> providers;
	PCWSTR filename = L"T:\\Sample.etl";

	// Microsoft-Windows-Kernel-Process
	providers.push_back(StringToGuid("{22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}"));
	if (!RunSession(providers)) {
		printf("[x] Unable to run the ETW session\n");
	}

	return 0;
}