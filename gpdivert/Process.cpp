#include "Process.h"

#include <TlHelp32.h>

#include "Utils.h"

HANDLE SnapshotTool = NULL;
bool   ProcessIsReady = false;

Process::ProcessInfoMap ProcessInfos;

void Process::Initialize()
{
    SnapshotTool = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    ProcessIsReady = true;

    L_INFO << "Process manager is started and ready to work." << L_END;
}

void Process::Uninitialize()
{
    if (SnapshotTool)
    {
        CloseHandle(SnapshotTool);
    }

    SnapshotTool = NULL;

    ClearProcessInfoMap();

    ProcessIsReady = false;

    L_INFO << "Process Manager Stopped." << L_END;
}

bool Process::IsReady()
{
    return ProcessIsReady;
}

void Process::WaitTillBeReady()
{
    while (!ProcessIsReady);

    Sleep(100);
}

void Process::UpdateSnapshotHelper()
{
    if (SnapshotTool)
    {
        CloseHandle(SnapshotTool);
    }

    SnapshotTool = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
}

HANDLE Process::GetSnapshotTool()
{
    return SnapshotTool;
}

Process::ProcessId Process::FindProcessIdByName(std::string processName)
{
    Process::ProcessId selectedProcess = NULL;
    
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(SnapshotTool, &entry) == TRUE)
    {
        while (Process32Next(SnapshotTool, &entry) == TRUE)
        {
            std::string pName = Utils::ConvertWStringToString(entry.szExeFile);

            if (pName == processName)
            {
                selectedProcess = entry.th32ProcessID;
                
                break;
            }
        }
    }

    return selectedProcess;
}

void Process::AddProcessInfo(ProcessName processName, std::string description, std::string displayName, std::string displayDescription, ProcessProtocolInfoList protocols)
{
    if (ExistsProcessInfo(processName))
    {
        return;
    }

    ProcessInfo info;
    info.name = processName;
    info.description = description;
    info.displayName = displayName;
    info.displayDescription = displayDescription;
    info.protocols = protocols;

    ProcessInfos[processName] = info;
}

void Process::DeleteProcessInfo(ProcessName processName)
{
    if (!ExistsProcessInfo(processName))
    {
        return;
    }

    ProcessInfos.erase(processName);
}

bool Process::ExistsProcessInfo(ProcessName processName)
{
    return ProcessInfos.find(processName) != ProcessInfos.end();
}

Process::ProcessInfo* Process::GetProcessInfo(ProcessName processName)
{
    if (!ExistsProcessInfo(processName))
    {
        return NULL;
    }

    return &ProcessInfos[processName];
}

Process::ProcessInfoMap& Process::GetProcessInfoMap()
{
    return ProcessInfos;
}

void Process::ClearProcessInfoMap()
{
    ProcessInfos.clear();
}