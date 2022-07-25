#include "etwhelper.h"

//#define ETW_HELPER_DEBUG

static HANDLE g_hStop;

GUID StringToGuid(const std::string& str)
{
	GUID guid;
	::sscanf_s(str.c_str(),
		"{%8x-%4hx-%4hx-%2hhx%2hhx-%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx}",
		&guid.Data1, &guid.Data2, &guid.Data3,
		&guid.Data4[0], &guid.Data4[1], &guid.Data4[2], &guid.Data4[3],
		&guid.Data4[4], &guid.Data4[5], &guid.Data4[6], &guid.Data4[7]);

	return guid;
}

void DisplayGeneralEventInfo(PEVENT_RECORD rec)
{
	WCHAR sguid[64];
	auto& header = rec->EventHeader;
	::StringFromGUID2(header.ProviderId, sguid, _countof(sguid));

	printf("[!] Provider: %ws Time: %ws PID: %u TID: %u\n",
		sguid,
		(PCWSTR)CTime(*(FILETIME*)&header.TimeStamp).Format(L"%c"),
		header.ProcessId, header.ThreadId
	);
}

void DisplayEventInfo(PEVENT_RECORD rec, PTRACE_EVENT_INFO info)
{
#ifdef ETW_HELPER_DEBUG
	if (info->KeywordsNameOffset) {
		printf("Keywords: %ws ",
			(PCWSTR)((BYTE*)info + info->KeywordsNameOffset));
	}
	if (info->OpcodeNameOffset) {
		printf("Opcode: %ws ",
			(PCWSTR)((BYTE*)info + info->OpcodeNameOffset));
	}
	if (info->LevelNameOffset) {
		printf("Level: %ws ",
			(PCWSTR)((BYTE*)info + info->LevelNameOffset));
	}
	if (info->TaskNameOffset) {
		printf("Task: %ws ",
			(PCWSTR)((BYTE*)info + info->TaskNameOffset));
	}
	if (info->EventMessageOffset) {
		printf("\nMessage: %ws\n",
			(PCWSTR)((BYTE*)info + info->EventMessageOffset));
	}

	printf("\nProperties: %u\n", info->TopLevelPropertyCount);
#endif
	auto userlen = rec->UserDataLength;
	auto data = (PBYTE)rec->UserData;
	auto pointerSize = (rec->EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER) ? 4 : 8;
	USHORT len;
	WCHAR value[512];

	// Iterating over properties
	for (DWORD i = 0; i < info->TopLevelPropertyCount; ++i) {
		auto& pi = info->EventPropertyInfoArray[i];
		auto propName = (PCWSTR)((BYTE*)info + pi.NameOffset);
		printf(" Name: %ws", propName);

		len = pi.length;
		if ((pi.Flags & (PropertyStruct | PropertyParamCount)) == 0) {
			// Simple properties only
			PEVENT_MAP_INFO mapInfo = nullptr;
			std::unique_ptr<BYTE[]> mapBuffer;
			PWSTR mapName = nullptr;

			if (pi.nonStructType.MapNameOffset) {
				ULONG size = 0;
				mapName = (PWSTR)((BYTE*)info + pi.nonStructType.MapNameOffset);
				if (::TdhGetEventMapInformation(rec, mapName, mapInfo, &size) == ERROR_INSUFFICIENT_BUFFER) {
					mapBuffer = std::make_unique<BYTE[]>(size);
					mapInfo = reinterpret_cast<PEVENT_MAP_INFO>(mapBuffer.get());
					if (::TdhGetEventMapInformation(rec, mapName, mapInfo, &size) != ERROR_SUCCESS) {
						mapInfo = nullptr;
					}
				}
			}
			
			ULONG size = sizeof(value);
			USHORT consumed;

			if (pi.nonStructType.InType == TDH_INTYPE_BINARY &&
				pi.nonStructType.OutType == TDH_OUTTYPE_IPV6) {
				len = sizeof(IN6_ADDR);
			}

			auto error = ::TdhFormatProperty(info, mapInfo, pointerSize, pi.nonStructType.InType,
				pi.nonStructType.OutType, (USHORT)len, userlen, data, &size, value, &consumed);
			if (error == ERROR_SUCCESS) {
				printf("Value: %ws", value);
				len = consumed;
				if (mapName) {
					printf(" (%ws)", (PCWSTR)mapName);
				}
				printf("\n");
			}
			else if (mapInfo) {
				auto error = ::TdhFormatProperty(info, nullptr, pointerSize, pi.nonStructType.InType,
					pi.nonStructType.OutType, (USHORT)len, userlen, data, &size, value, &consumed);
				if (error == ERROR_SUCCESS) {
					printf("Value: %ws\n", value);
				}
			}
			if (error != ERROR_SUCCESS) {
				printf("[x] Failed to get value\n");
			}
		}
		else {
			printf("[!] Not a simple property\n"); // TODO: Handle non-simple properties
		}

		userlen -= len;
		data += len;
	}
}

void CALLBACK OnEvent(PEVENT_RECORD rec)
{
	DisplayGeneralEventInfo(rec);

	ULONG size = 0;
	auto status = ::TdhGetEventInformation(rec, 0, nullptr, nullptr, &size);
	assert(status == ERROR_INSUFFICIENT_BUFFER);

	auto buffer = std::make_unique<BYTE[]>(size);
	if (!buffer) {
		printf("[x] Unable to allocate memory for PTRACE_EVENT_INFO!\n");
		::ExitProcess(1);
	}

	auto info = reinterpret_cast<PTRACE_EVENT_INFO>(buffer.get());
	status = ::TdhGetEventInformation(rec, 0, nullptr, info, &size);
	if (status != ERROR_SUCCESS) {
		printf("[x] Error while processing event!\n");
		return;
	}

	DisplayEventInfo(rec, info);
}

bool RunSession(const std::vector<GUID>& providers)
{
	// {6B260F2C-A001-46B3-ABDE-D095D1F3A3F5}
	static const GUID sessionGuid =
	{ 0x6b260f2c, 0xa001, 0x46b3, { 0xab, 0xde, 0xd0, 0x95, 0xd1, 0xf3, 0xa3, 0xf5 } };
	const WCHAR sessionName[] = L"ETWDemo";

	/*
	*		  LAYOUT OF EVENT_TRACE_PROPERTIES
	*
	*			+------------------------+
	*			|                        |
	*			|      WNODE_HEADER      |
	*			+------------------------+
	*			|                        |
	*			| EVENT_TRACE_PROPERTIES |
	*			+------------------------+
	*			|                        |
	*			|      SESSION NAME      |
	*			+------------------------+
	*			|                        |
	*			|  FILE NAME (OPTIONAL)  |
	*			+------------------------+
	*/

	auto size = sizeof(EVENT_TRACE_PROPERTIES) + sizeof(sessionName);
	TRACEHANDLE hTrace = NULL;

	auto buffer = std::make_unique<BYTE[]>(size);
	if (!buffer) {
		return false;
	}

	// EVENT_TRACE_PROPERTIES
	auto props = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(buffer.get());
	ULONG status;

	do {
		::ZeroMemory(buffer.get(), size);

		props->Wnode.BufferSize = (ULONG)size;
		props->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
		props->Wnode.ClientContext = 1;
		props->Wnode.Guid = sessionGuid;
		props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
		props->MaximumFileSize = 100;	// in MB
		props->LoggerNameOffset = sizeof(*props);
		props->LogFileNameOffset = 0;

		// SESSION NAME
		::wcscpy_s((PWSTR)(props + 1), ::wcslen(sessionName) + 1, sessionName);

		// NO FILE NAME!

		status = ::StartTrace(&hTrace, sessionName, props);
		if (status == ERROR_ALREADY_EXISTS) {
			status = ::ControlTrace(hTrace, sessionName, props, EVENT_TRACE_CONTROL_STOP);
			continue;
		}
		break;
	} while (true);

	if (status != ERROR_SUCCESS) {
		return false;
	}

	TRACEHANDLE hParse = 0;
	HANDLE hThread = nullptr;
	
	g_hStop = ::CreateEvent(nullptr, TRUE, FALSE, nullptr);

	EVENT_TRACE_LOGFILE etl{};
	etl.LoggerName = (PWSTR)sessionName;
	etl.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_REAL_TIME;
	etl.EventRecordCallback = OnEvent;
	hParse = ::OpenTrace(&etl);
	if (hParse == INVALID_PROCESSTRACE_HANDLE) {
		printf("Failed to open a read-time session\n");
	}
	else {
		hThread = ::CreateThread(nullptr, 0, [](auto param) -> DWORD {
			FILETIME now;
			::GetSystemTimeAsFileTime(&now);
			::ProcessTrace(static_cast<TRACEHANDLE*>(param), 1, &now, nullptr);
			return 0;
		}, &hParse, 0, nullptr);
	}

	for (auto& guid : providers) {
		status = ::EnableTraceEx(&guid, nullptr, hTrace, TRUE, TRACE_LEVEL_INFORMATION, 0, 0, 0, nullptr);
		if (status != ERROR_SUCCESS) {
			::StopTrace(hTrace, sessionName, props);
			return false;
		}
	}

	::SetConsoleCtrlHandler([](auto code) {
		if (code == CTRL_C_EVENT) {
			::SetEvent(g_hStop);
			return TRUE;
		}
		return FALSE;
		}, TRUE);
	::WaitForSingleObject(g_hStop, INFINITE);
	::CloseTrace(hParse);
	::WaitForSingleObject(hThread, INFINITE);
	::CloseHandle(g_hStop);
	::CloseHandle(hThread);

	printf("[!] Session running... press ENTER to stop\n");

	::StopTrace(hTrace, sessionName, props);

	return true;
}