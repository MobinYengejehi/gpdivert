#include "Utils.h"

#include <thread>

#include "Network.h"
#include "Process.h"

#pragma comment(lib, "WinDivert.lib")
#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "Ws2_32.lib")

#include "SharedNetwork.h"

int main(int argc, char** argv)
{
    if (argc > 1)
    {
        Network::SetServerHost(argv[1]);
    }

    //char buffer[100];
    //memset(buffer, 0, sizeof(buffer));

    //char random[20];
    //memcpy(random, "gpdv", sizeof("gpdv") - 1);
    //memset(random + (sizeof("gpdv") - 1), 34, sizeof(random) - (sizeof("gpdv") - 1));
    //random[19] = 'f';

    ////const char* data = "gpdvsalam chetori khgpdvobi gpdv mobinam man?";

    //std::string randomStr(random, 20);

    //std::string data;
    //data += randomStr;
    //data += randomStr;
    //data += "salam chetori khobi?";
    //data += randomStr;

    //memcpy(buffer, data.data(), data.length());
    //
    //size_t trashSize = strlen(buffer);
    //size_t realSize = Network::ClearGPDivertHeaders((UINT8*)buffer, trashSize);

    //L_INFO << "size is : " << std::string(buffer, realSize) << " | " << trashSize << " | " << realSize << L_END;

    //return 0;

    std::cout <<
        "------------------------------------------------------------------------------------\n"
        "----   ######    ########  ########  #### ##     ## ######## ########  ########\n"
        "----   ##    ##  ##     ## ##     ##  ##  ##     ## ##       ##     ##    ##\n"
        "----   ##        ##     ## ##     ##  ##  ##     ## ##       ##     ##    ##\n"
        "----   ##   #### ########  ##     ##  ##  ##     ## ######   ########     ##\n"
        "----   ##    ##  ##        ##     ##  ##   ##   ##  ##       ##   ##      ##\n"
        "----   ##    ##  ##        ##     ##  ##    ## ##   ##       ##    ##     ##\n"
        "----   ######    ##        ########  ####    ###    ######## ##     ##    ##\n"
        "-----------------------------------------------------------------------------------\n\n"
        << std::endl;

    L_INFO << "Starting services..." << L_END;
    
    /*int i = 0;

    while (true)
    {
        L_INFO << "is window focues : " << i++ << LOGGER_FLUSH;
        Sleep(10);
        LOGGER_CLEAR_LAST_LINE;
    }*/

    std::thread processThread(Process::Initialize);
    std::thread networkThread(Network::Initialize);

    processThread.join();
    networkThread.join();

    Network::Uninitialize();
    Process::Uninitialize();

    Utils::WaitToPressEnter();

    return EXIT_SUCCESS;
}

/*#include <iostream>
#include <string>
#include <vector>
#include <thread>

#define WIN32_LEAN_AND_MEAN

#include <Windows.h>
#include <TlHelp32.h>
#include <WS2tcpip.h>
#include <iphlpapi.h>

#include "windivert.h"

#include "Network.h"
#include "Process.h"

#pragma comment(lib, "WinDivert.lib")
#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "Ws2_32.lib")

//#define CSGO_2_PROCESS_NAME "cs2.exe"
#define CSGO_2_PROCESS_NAME "cod.exe"

struct NetworkInfo
{
    std::string localAddress;
    std::string remoteAddress;
    USHORT      localPort;
    USHORT      remotePort;
    bool        isUDP;
};

std::string IpAddressToString(DWORD ipAddress)
{
    char address[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &ipAddress, address, INET_ADDRSTRLEN);

    return std::string(address);
}

std::string GetWinDivertErrorMessage(DWORD error)
{
    switch (error) {
        case ERROR_ACCESS_DENIED:
            return "Error: Access denied. Run the program as Administrator.";
        case ERROR_FILE_NOT_FOUND:
            return "Error: WinDivert driver not found. Make sure it is installed.";
        case ERROR_SERVICE_DOES_NOT_EXIST:
            return "Error: WinDivert driver not installed. Install it first.";
        default:
            break;
    }

    return std::string("Unknown error occurred. [Code: ") + std::to_string(error) + "]";
}

std::string ConvertWStringToString(std::wstring wstr)
{
    size_t size = wstr.size() + 1;

    char* result = (char*)malloc(size);
    
    sprintf_s(result, size, "%ws", wstr.c_str());

    std::string resultStr = result;
    
    free(result);

    return resultStr;
}

DWORD FindProcessIdByName(std::string processName)
{
    DWORD selectedProcess = NULL;

    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (Process32First(snapshot, &entry) == TRUE)
    {
        while (Process32Next(snapshot, &entry) == TRUE)
        {
            std::string pName = ConvertWStringToString(entry.szExeFile);

            if (pName == processName)
            {
                selectedProcess = entry.th32ProcessID;

                goto Result;
            }
        }
    }

Result:
    CloseHandle(snapshot);

    return selectedProcess;
}

std::vector<NetworkInfo> GetProcessPorts(DWORD processId)
{
    std::vector<NetworkInfo> networks;

    PMIB_TCPTABLE_OWNER_PID tcpTable = NULL;
    DWORD                   tcpSize = 0;

    GetExtendedTcpTable(tcpTable, &tcpSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);

    tcpTable = (PMIB_TCPTABLE_OWNER_PID)malloc(tcpSize);

    if (GetExtendedTcpTable(tcpTable, &tcpSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR)
    {
        for (DWORD i = 0; i < tcpTable->dwNumEntries; i++)
        {
            if (tcpTable->table[i].dwOwningPid == processId)
            {
                NetworkInfo info;

                char localAddress[INET_ADDRSTRLEN];
                char remoteAddress[INET_ADDRSTRLEN];

                inet_ntop(AF_INET, &tcpTable->table[i].dwLocalAddr, localAddress, INET_ADDRSTRLEN);
                inet_ntop(AF_INET, &tcpTable->table[i].dwRemoteAddr, remoteAddress, INET_ADDRSTRLEN);

                info.localPort = ntohs((USHORT)tcpTable->table[i].dwLocalPort);
                info.remotePort = ntohs((USHORT)tcpTable->table[i].dwRemotePort);

                info.isUDP = false;

                networks.push_back(info);
            }
        }
    }

    free(tcpTable);

    PMIB_UDPTABLE_OWNER_PID udpTable = NULL;
    DWORD                   udpSize = 0;

    GetExtendedUdpTable(udpTable, &udpSize, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0);

    udpTable = (PMIB_UDPTABLE_OWNER_PID)malloc(udpSize);

    if (GetExtendedUdpTable(udpTable, &udpSize, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0) == NO_ERROR)
    {
        for (DWORD i = 0; i < udpTable->dwNumEntries; i++)
        {
            if (udpTable->table[i].dwOwningPid == processId)
            {
                NetworkInfo info;

                char localAddress[INET_ADDRSTRLEN];

                inet_ntop(AF_INET, &udpTable->table[i].dwLocalAddr, localAddress, INET_ADDRSTRLEN);

                info.localAddress = localAddress;
                info.remoteAddress = "";

                info.localPort = ntohs((USHORT)udpTable->table[i].dwLocalPort);
                info.remotePort = 0;

                info.isUDP = true;

                networks.push_back(info);
            }
        }
    }

    free(udpTable);

    return networks;
}

bool PortExists(const std::vector<NetworkInfo>& networks, USHORT port)
{
    for (const NetworkInfo& network : networks)
    {
        if (port == network.localPort || port == network.remotePort)
        {
            return true;
        }
    }

    return false;
}

std::string BuildMatchFormat(const std::vector<NetworkInfo>& networks)
{
    if (networks.empty())
    {
        return "";
    }

    std::string format;
    std::string OrDevider = " || ";

    for (const NetworkInfo& info : networks)
    {
        if (info.isUDP)
        {
            //format += "(udp.SrcPort == " + std::to_string(info.localPort) + " && ip.SrcAddr == " + info.localAddress + ")" + OrDevider;
            format += "(udp.SrcPort == " + std::to_string(info.localPort) + OrDevider + "udp.DstPort == " + std::to_string(info.localPort) + ")" + OrDevider;
        }
        else
        {
            format += (
                "(tcp.SrcPort == " + std::to_string(info.localPort) + OrDevider +
                "tcp.DstPort == " + std::to_string(info.localPort) + ")" + OrDevider
            );
        }
    }

    if (!format.empty())
    {
        format = format.substr(0, format.length() - OrDevider.length());
    }

    format = std::string("(ip || ipv6) && (") + format + ")";

    return format;
}

void PacketListenerThread(DWORD cs2ProcessId)
{
    std::vector<NetworkInfo> networks = GetProcessPorts(cs2ProcessId);

    for (const NetworkInfo& network : networks)
    {
        std::cout << "network is : " << network.isUDP << " | " << network.localAddress << ":" << network.localPort << " | " << network.remoteAddress << ":" << network.remotePort << std::endl;
    }

    std::cout << "network size : " << networks.size() << std::endl;

    //return;

    std::string matchFormat = BuildMatchFormat(networks);

    if (matchFormat.empty())
    {
        std::cout << "Couldn't find any network packet to listen on!" << std::endl;
        exit(EXIT_FAILURE);
    }

    //matchFormat = std::string("(socket.ProcessId == ") + std::to_string(cs2ProcessId) + ") && (socket.Protocol == 6 || socket.Protocol == 17)";
    matchFormat = "ip && (tcp || udp)";

    std::cout << "WinDivert filter is : '" << matchFormat << "'" << std::endl;

    HANDLE winDivert = WinDivertOpen(matchFormat.c_str(), WINDIVERT_LAYER_NETWORK, 0, 0);

    if (winDivert == INVALID_HANDLE_VALUE)
    {
        std::cout << "WinDivert ERROR: " << GetWinDivertErrorMessage(GetLastError()) << std::endl;
        exit(EXIT_FAILURE);
    }

    char              packet[65536];
    UINT              packetLength;
    UINT              sendLength;
    WINDIVERT_ADDRESS address;

    std::cout << "WinDivert listening for packets..." << std::endl;

    ULONG64 tcpLength = 0;
    ULONG64 udpLength = 0;

    while (true)
    {
        //system("cls");

        if (!WinDivertRecv(winDivert, packet, sizeof(packet), &packetLength, &address))
        {
            std::cout << "WinDivertRecv ERROR: " << GetWinDivertErrorMessage(GetLastError()) << std::endl;
            continue;
        }

        std::string chunk = std::string(packet, 20) + "\0";
        chunk = std::to_string(packetLength);

        //GetProcessPorts(cs2ProcessId);
        //std::cout << "new packet here : '" << chunk << "'" << " | " << address.Socket.ProcessId << std::endl;

        WINDIVERT_IPHDR*  ipHeader;
        WINDIVERT_TCPHDR* tcpHeader;
        WINDIVERT_UDPHDR* udpHeader;

        WinDivertHelperParsePacket(packet, packetLength, &ipHeader, NULL, NULL, NULL, NULL, &tcpHeader, &udpHeader, NULL, NULL, NULL, NULL);

        USHORT tcpSrcPort = 0;
        USHORT tcpDstPort = 0;
        USHORT udpSrcPort = 0;
        USHORT udpDstPort = 0;

        if (GetAsyncKeyState('R') & 0x8000)
        {
            if (ipHeader != NULL && !tcpHeader)
            {
                bool outbound = address.Outbound == 1;

                if (outbound)
                {
                    std::cout
                        << "new packet here : '"
                        << chunk
                        << "' Addresses : "
                        << IpAddressToString(ipHeader->SrcAddr)
                        << " / "
                        << IpAddressToString(ipHeader->DstAddr)
                        << " is outbound : " << outbound
                        << " ports : ";

                    if (tcpHeader)
                    {
                        tcpSrcPort = ntohs(tcpHeader->SrcPort);
                        tcpDstPort = ntohs(tcpHeader->DstPort);

                        std::cout
                            << tcpSrcPort
                            << "(" << PortExists(networks, tcpSrcPort) << ")"
                            << ", "
                            << tcpDstPort
                            << "(" << PortExists(networks, tcpDstPort) << ")";
                    }
                    else
                    {
                        std::cout << "notcp";
                    }

                    std::cout << " | ";

                    if (udpHeader)
                    {
                        udpSrcPort = ntohs(udpHeader->SrcPort);
                        udpDstPort = ntohs(udpHeader->DstPort);

                        std::cout
                            << udpSrcPort
                            << "(" << PortExists(networks, udpSrcPort) << ")"
                            << ", "
                            << udpDstPort
                            << "(" << PortExists(networks, udpDstPort) << ")";
                    }
                    else
                    {
                        std::cout << "noudp";
                    }

                    std::cout << std::endl;
                }
            }
        }

        if (tcpHeader)
        {
            if (PortExists(networks, tcpSrcPort) || PortExists(networks, tcpDstPort))
                tcpLength += packetLength;
        }
        else if (udpHeader)
        {
            if (PortExists(networks, udpSrcPort) || PortExists(networks, udpDstPort))
                udpLength += packetLength;
        }

        if (GetAsyncKeyState('H') & 0x8000)
        {
            //system("clr");
            std::cout << "total tcp packet length : " << tcpLength << " (" << ((double)tcpLength / 1024 / 1024) << ") | " << udpLength << " (" << ((double)udpLength / 1024 / 1024) << ")" << std::endl;
        }
        
        if (!WinDivertSend(winDivert, packet, packetLength, &sendLength, &address))
        {
            std::cout << "WinDivertSend ERROR: " << GetWinDivertErrorMessage(GetLastError()) << std::endl;
            continue;
        }

        //std::cout << "packet sent!" << std::endl;
    }

    WinDivertClose(winDivert);
}

int main()
{
    DWORD cs2ProcessId = FindProcessIdByName(CSGO_2_PROCESS_NAME);

    if (cs2ProcessId == NULL)
    {
        std::cout << "game is not open! [couldn't find process '" CSGO_2_PROCESS_NAME "']" << std::endl;
        return EXIT_FAILURE;
    }
    
    std::thread packetListenerThread(PacketListenerThread, cs2ProcessId);

    packetListenerThread.join();

    return EXIT_SUCCESS;
}*/