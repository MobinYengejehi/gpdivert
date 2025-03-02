#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <Windows.h>

namespace Process
{
	using ProcessId = DWORD;
	using ProcessName = std::string;
	using ProcessInfoMap = std::unordered_map<ProcessName, struct ProcessInfo>;
	using ProcessProtocolInfoList = std::vector<struct ProcessProtocolInfo>;

	struct ProcessProtocolInfo
	{
		std::string name;
		UINT        id;
		std::string serverHost;
		USHORT      serverPort;
	};

	struct ProcessInfo
	{
		ProcessName name;
		std::string description;
		std::string displayName;
		std::string displayDescription;

		ProcessProtocolInfoList protocols;
	};

	void Initialize();
	void Uninitialize();

	bool IsReady();
	void WaitTillBeReady();

	void   UpdateSnapshotHelper();
	HANDLE GetSnapshotTool();

	ProcessId FindProcessIdByName(std::string processName);

	void         AddProcessInfo(ProcessName processName, std::string description = "", std::string displayName = "", std::string displayDescription = "", ProcessProtocolInfoList protocols = ProcessProtocolInfoList());
	void         DeleteProcessInfo(ProcessName processName);
	ProcessInfo* GetProcessInfo(ProcessName processName);
	bool         ExistsProcessInfo(ProcessName processName);
	
	ProcessInfoMap& GetProcessInfoMap();
	void            ClearProcessInfoMap();
};