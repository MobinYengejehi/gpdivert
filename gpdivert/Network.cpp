#define WIN32_LEAN_AND_MEAN

#include <WinSock2.h>

#include "Network.h"
#include "Utils.h"
#include "PropertyUtils.h"

#include "windivert.h"

#include <iphlpapi.h>

#include <thread>
#include <sstream>

#define PROCESS_NETWORK_INFO_UPDATE_DURATION (1000) // miliseconds

//#include <WS2tcpip.h>

/*
driver install commands:

start windivert:   "sc start WinDivert"
check windivert:   "sc query WinDivert"
delete winDivert:  "sc delete WinDivert"
install winDivert: "sc create WinDivert binPath= "C:\WinDivert\x64\WinDivert64.sys" type= kernel start= demand"

*/

#include <boost/asio.hpp>

Network::NetworkInfoMap NetworkInfos;
bool                    NetworkIsReady = false;

std::string ServerHost = "localhost:38309";

Network::MacAddress ServerMacAddress;

std::string         HttpServerHost = "localhost";
Network::PortNumber HttpServerPort = 38309;

std::string         TcpSocketHost = "";
Network::PortNumber TcpSocketPort = 0;
std::string         UdpSocketHost = "";
Network::PortNumber UdpSocketPort = 0;

std::vector<std::string> LocalAddresses;

HANDLE WinDivertHandle = INVALID_HANDLE_VALUE;

bool IsLocalAddress(std::string address)
{
	for (const std::string& addr : LocalAddresses)
	{
		if (addr == address)
		{
			return true;
		}
	}

	return false;
}

Network::Info::Info()
{
	m_strLocalAddress = "";
	m_strRemoteAddress = "";
	m_nLocalPort = 0;
	m_nRemotePort = 0;
}

Network::Info::Info(std::string localAddress, std::string remoteAddress, PortNumber localPort, PortNumber remotePort, NetworkLayer layer)
{
	m_strLocalAddress = localAddress;
	m_strRemoteAddress = remoteAddress;
	m_nLocalPort = localPort;
	m_nRemotePort = remotePort;

	m_eNetworkLayer = layer;
}

Network::Info::Info(DWORD localAddress, DWORD remoteAddress, DWORD localPort, DWORD remotePort, NetworkLayer layer)
{
	m_strLocalAddress = ConvertIntegerAddressToString(localAddress);
	m_strRemoteAddress = ConvertIntegerAddressToString(remoteAddress);
	m_nLocalPort = ExtractPort(localPort);
	m_nRemotePort = ExtractPort(remotePort);

	m_eNetworkLayer = layer;
}

Network::Info::~Info()
{

}

std::string& Network::Info::GetLocalAddress()
{
	return m_strLocalAddress;
}

const std::string& Network::Info::GetLocalAddress() const
{
	return m_strLocalAddress;
}

std::string& Network::Info::GetRemoteAddress()
{
	return m_strRemoteAddress;
}

const std::string& Network::Info::GetRemoteAddress() const
{
	return m_strRemoteAddress;
}

Network::PortNumber& Network::Info::GetLocalPort()
{
	return m_nLocalPort;
}

const Network::PortNumber& Network::Info::GetLocalPort() const
{
	return m_nLocalPort;
}

Network::PortNumber& Network::Info::GetRemotePort()
{
	return m_nRemotePort;
}

const Network::PortNumber& Network::Info::GetRemotePort() const
{
	return m_nRemotePort;
}

Network::NetworkLayer& Network::Info::GetNetworkLayer()
{
	return m_eNetworkLayer;
}

const Network::NetworkLayer& Network::Info::GetNetworkLayer() const
{
	return m_eNetworkLayer;
}

bool Network::Info::IsLocalVaild() const
{
	return m_nLocalPort != 0;
}

bool Network::Info::IsRemoteValid() const
{
	return m_nRemotePort != 0;
}

bool Network::Info::IsUDP() const
{
	return m_eNetworkLayer == NetworkLayer::UDP;
}

Network::Info::operator std::string() const
{
	std::string result;

	result += "(";
	result += IsUDP() ? "UDP" : "TCP";
	result += ") ";
	result += m_strLocalAddress;
	result += ":";
	result += std::to_string(m_nLocalPort);
	result += " -> ";
	result += m_strRemoteAddress;
	result += ":";
	result += std::to_string(m_nRemotePort);

	return result;
}

std::string Network::Http::Fetch(std::string host, std::string path, std::string method, FetchProgressHandler progressHandler)
{
	if (host.empty() || path.empty() || method.empty())
	{
		return "";
	}

	try
	{
		ClientRequest request(host);

		auto response = request.request(method, path);

		size_t contentLength = 0;

		auto found = response->header.find("Content-Length");

		if (found != response->header.end())
		{
			contentLength = std::stoul(found->second);
		}

		std::ostringstream result;

		constexpr size_t packetBufferSize = 4096;

		char packetBuffer[packetBufferSize];

		size_t totalBytesRead = 0;

		while (response->content.read(packetBuffer, packetBufferSize) || response->content.gcount())
		{
			std::streamsize bytesRead = response->content.gcount();

			result.write(packetBuffer, bytesRead);

			totalBytesRead += bytesRead;

			if (progressHandler)
			{
				progressHandler(
					contentLength > 0 ?
					((double)totalBytesRead / (double)contentLength) * 100 :
					0,
					totalBytesRead,
					contentLength
				);
			}
		}

		return result.str();
	}
	catch (const std::exception&) {}

	return "";
}

void Network::PacketManager::Initialize()
{
	WinDivertHandle = WinDivertOpen("ip && (tcp || udp)", WINDIVERT_LAYER_NETWORK, 0, 0);

	if (WinDivertHandle == INVALID_HANDLE_VALUE)
	{
		L_ERROR << "Couldn't open WinDivert handle. [Code: " << GetLastError() << "]" << L_END;

		Sleep(5000);

		exit(EXIT_FAILURE);

		return;
	}

	L_INFO << "Packet manager started and ready to work." << L_END;
	
	PacketListener();
}

void Network::PacketManager::Uninitialize()
{
	if (WinDivertHandle != INVALID_HANDLE_VALUE)
	{
		WinDivertClose(WinDivertHandle);
	}

	WinDivertHandle = INVALID_HANDLE_VALUE;
}

void Network::PacketManager::PacketListener()
{
	char              packet[NETWORK_MAX_PACKET_SIZE];
	UINT              packetLength = 0;
	UINT              sendLength = 0;
	WINDIVERT_ADDRESS address;

	ULONG64 tcpLength = 0;
	ULONG64 udpLength = 0;

	memset(packet, 0, sizeof(packet));

	while (true)
	{
		if (!WinDivertRecv(WinDivertHandle, packet, sizeof(packet), &packetLength, &address))
		{
			L_ERROR << "Packet couldn't receive from WinDivert. [Code: " << GetLastError() << "]" << L_END;
			continue;
		}

		{
			WINDIVERT_IPHDR* ipHeader = NULL;
			WINDIVERT_TCPHDR* tcpHeader = NULL;
			WINDIVERT_UDPHDR* udpHeader = NULL;

			UINT8* payload = NULL;
			UINT   payloadLength = 0;

			if (!WinDivertHelperParsePacket(packet, packetLength, &ipHeader, NULL, NULL, NULL, NULL, &tcpHeader, &udpHeader, (PVOID*)&payload, &payloadLength, NULL, NULL))
			{
				goto PacketInject;
			}

			if (ipHeader == NULL)
			{
				goto PacketInject;
			}

			if (payload == NULL)
			{
				goto PacketInject;
			}

			USHORT sourcePort = 0;
			USHORT destinationPort = 0;

			if (tcpHeader != NULL)
			{
				sourcePort = ExtractPort(tcpHeader->SrcPort);
				destinationPort = ExtractPort(tcpHeader->DstPort);
			}

			if (udpHeader != NULL)
			{
				sourcePort = ExtractPort(udpHeader->SrcPort);
				destinationPort = ExtractPort(udpHeader->DstPort);
			}

			Process::ProcessName sourceProcess = FindPortProcess(sourcePort);
			Process::ProcessName destinationProcess = FindPortProcess(destinationPort);

			if (sourceProcess.empty() && destinationProcess.empty())
			{
				goto PacketInject;
			}

			L_INFO << "packet process is : " << sourceProcess << " | " << destinationProcess << L_END;

			constexpr size_t extraHeaderSize = sizeof(PacketExtraHeader);

			PacketExtraHeader payloadExtraHeader;
			memcpy(&payloadExtraHeader, payload, extraHeaderSize);

			bool hasGpDivertHeader = payloadExtraHeader.identifier == GP_DIVERT_HEADER;

			if (address.Outbound)
			{
				if (hasGpDivertHeader)
				{
					goto InboundPacketCaptured;
					//goto PacketInject;
				}

				std::string socketHost = "";
				PortNumber  socketPort = 0;

				Process::ProcessInfo* processInfo = Process::GetProcessInfo(sourceProcess.empty() ? destinationProcess : sourceProcess);

				if (processInfo == NULL)
				{
					goto PacketInject;
				}

				for (const auto& protocol : processInfo->protocols)
				{
					if (
						(protocol.id == NETWORK_TCP_PROTOCOL_ID && tcpHeader != NULL) ||
						(protocol.id == NETWORK_UDP_PROTOCOL_ID && udpHeader != NULL)
						)
					{
						socketHost = protocol.serverHost;
						socketPort = protocol.serverPort;

						break;
					}
				}

				if (socketHost.empty() || socketPort == 0)
				{
					goto PacketInject;
				}

				UINT totalHeaderLength = ipHeader->HdrLength * 4 + (
					tcpHeader ?
					(tcpHeader->HdrLength >> 4) * 4 :
					(
						udpHeader ?
						sizeof(WINDIVERT_UDPHDR) :
						0
						)
					);

				if (packetLength + extraHeaderSize > NETWORK_MAX_PACKET_SIZE)
				{
					goto PacketInject;
				}

				memmove(packet + totalHeaderLength + extraHeaderSize, packet + totalHeaderLength, payloadLength);

				PacketExtraHeader extraInfo;
				extraInfo.identifier = GP_DIVERT_HEADER;
				extraInfo.originalIp = ipHeader->DstAddr;
				extraInfo.originalPort = destinationPort;
				extraInfo.socketPort = socketPort;

				inet_pton(AF_INET, socketHost.c_str(), &extraInfo.socketHost);

				memcpy(packet + totalHeaderLength, &extraInfo, extraHeaderSize);

				USHORT oldIpLength = ntohs(ipHeader->Length);

				ipHeader->Length = htons(oldIpLength + extraHeaderSize);

				if (udpHeader != NULL)
				{
					USHORT oldUdpLength = ntohs(udpHeader->Length);

					udpHeader->Length = htons(oldUdpLength + extraHeaderSize);
				}

				packetLength += extraHeaderSize;

				inet_pton(AF_INET, socketHost.c_str(), &ipHeader->DstAddr);

				if (tcpHeader != NULL)
				{
					tcpHeader->DstPort = htons(socketPort);
				}
				else if (udpHeader != NULL)
				{
					udpHeader->DstPort = htons(socketPort);
				}

				L_INFO << "sending outbound game packet '" << destinationProcess << "' to '" << socketHost << ":" << socketPort << "' | orig : '" << ConvertIntegerAddressToString(extraInfo.originalIp) << ":" << extraInfo.originalPort << "'" << L_END;
			}
			else
			{
				if (hasGpDivertHeader)
				{
					goto InboundPacketCaptured;
				}
			}

			goto PacketInject;

		InboundPacketCaptured:
			{
				//memmove(payload, payload + extraHeaderSize, payloadLength - extraHeaderSize);

				//UDP : udp_header->Length = htons(ntohs(udp_header->Length) - sizeof(CustomHeader))

				//payloadLength -= extraHeaderSize;
				//packetLength -= extraHeaderSize;

				size_t clearedPayloadLength = Network::ClearGPDivertHeaders((UINT8*)payload, payloadLength);

				size_t distanceLength = payloadLength - clearedPayloadLength;

				payloadLength -= distanceLength;
				packetLength -= distanceLength;

				ipHeader->Length = htons(ntohs(ipHeader->Length) - distanceLength);

				if (udpHeader != NULL)
				{
					udpHeader->Length = htons(ntohs(udpHeader->Length) - distanceLength);
				}

				inet_pton(AF_INET, ConvertIntegerAddressToString(payloadExtraHeader.originalIp).c_str(), &ipHeader->SrcAddr);

				if (tcpHeader != NULL)
				{
					tcpHeader->SrcPort = htons(payloadExtraHeader.originalPort);
				}
				else if (udpHeader != NULL)
				{
					udpHeader->SrcPort = htons(payloadExtraHeader.originalPort);
				}

				L_INFO << "inbound payload is : " << ConvertIntegerAddressToString(ipHeader->SrcAddr) << " | " << ConvertIntegerAddressToString(ipHeader->DstAddr) << " | " << std::string((char*)payload, 4) << " | " << std::string((char*)(payload + extraHeaderSize), 4) << " | " << payloadLength << L_END;
			}
		}

	PacketInject:
		{
			WinDivertHelperCalcChecksums(packet, packetLength, &address, 0);

			if (!WinDivertSend(WinDivertHandle, packet, packetLength, &sendLength, &address))
			{
				L_ERROR << "Couldn't inject packet. [Code: " << GetLastError() << "]" << L_END;
				continue;
			}
		}
	}
}

void Network::Initialize()
{
	Process::WaitTillBeReady();
	
	ClearNetworkInfoMap();

	memset(ServerMacAddress, 0, sizeof(ServerMacAddress));

	{
		L_INFO << "Sending request to host '" << ServerHost << "'..." << L_END;

		std::string content = Http::Fetch(ServerHost, "/serverinfo");

		if (content.empty())
		{
			L_ERROR << "Failed to communicate with host '" << ServerHost << "'." << std::endl;

			Sleep(5000);

			exit(EXIT_FAILURE);

			return;
		}

		Utils::PropertyTree serverInfo;

		Utils::PTreeReadJson(serverInfo, content);

		if (!Utils::PTreeGetItem<bool>(serverInfo, "success", false))
		{
			L_ERROR << "Request failed. [Message: " << Utils::PTreeGetItem<std::string>(serverInfo, "message", "UNKNOWN") << "]" << L_END;

			Sleep(5000);

			exit(EXIT_FAILURE);

			return;
		}

		L_INFO << "Connected to host '" << Utils::PTreeGetItem<std::string>(serverInfo, "host_name", ServerHost) << "'." << L_END;

		HttpServerHost = Utils::PTreeGetItem<std::string>(serverInfo, "http_host", HttpServerHost);
		HttpServerPort = Utils::PTreeGetItem<Network::PortNumber>(serverInfo, "http_port", HttpServerPort);

		ServerHost = HttpServerHost + ":" + std::to_string(HttpServerPort);

		TcpSocketHost = Utils::PTreeGetItem<std::string>(serverInfo, "tcp_socket_host", HttpServerHost);
		TcpSocketPort = Utils::PTreeGetItem<Network::PortNumber>(serverInfo, "tcp_socket_port", 38310);
		UdpSocketHost = Utils::PTreeGetItem<std::string>(serverInfo, "udp_socket_host", HttpServerHost);
		UdpSocketPort = Utils::PTreeGetItem<Network::PortNumber>(serverInfo, "udp_socket_port", 38311);

		{
			std::string macAddress = Utils::PTreeGetItem<std::string>(serverInfo, "host_mac_address", "00-00-00-00-00-00");

			if (!macAddress.empty())
			{
				std::vector<std::string> chunks;

				size_t count = Utils::SplitString(macAddress, "-", chunks);

				for (size_t i = 0; i < count && i < sizeof(ServerMacAddress); i++)
				{
					ServerMacAddress[i] = static_cast<BYTE>(std::stoul(chunks[i], nullptr, 16));
				}
			}
		}

		std::string appListRaw = Http::Fetch(ServerHost, "/applist");

		if (!appListRaw.empty())
		{
			Utils::PropertyTree appList;

			Utils::PTreeReadJson(appList, appListRaw);

			if (Utils::PTreeGetItem(appList, "success", false))
			{
				Utils::PropertyTree& list = appList.get_child("applications");

				for (const auto& item : list)
				{
					Process::ProcessProtocolInfoList protocolList;

 					Utils::PropertyTree protocols = item.second.get_child("protocols");

					for (const auto& pItem : protocols)
					{
						Process::ProcessProtocolInfo protocol;
						protocol.name = Utils::PTreeGetItem<std::string>(pItem.second, "name", "");
						protocol.id = Utils::PTreeGetItem<PortNumber>(pItem.second, "id", 0);
						protocol.serverHost = Utils::PTreeGetItem<std::string>(
							pItem.second,
							"server_host",
							protocol.id == IPPROTO_TCP ? TcpSocketHost : protocol.id == IPPROTO_UDP ? UdpSocketHost : HttpServerHost
						);
						protocol.serverPort = Utils::PTreeGetItem<PortNumber>(
							pItem.second,
							"server_port",
							protocol.id == IPPROTO_TCP ? TcpSocketPort : protocol.id == IPPROTO_UDP ? UdpSocketPort : 38310
						);

						if (protocol.serverHost.empty())
						{
							protocol.serverHost = HttpServerHost;
						}

						protocolList.push_back(protocol);
					}

					Process::AddProcessInfo(
						Utils::PTreeGetItem<std::string>(item.second, "name", ""),
						Utils::PTreeGetItem<std::string>(item.second, "description", ""),
						Utils::PTreeGetItem<std::string>(item.second, "display_name", ""),
						Utils::PTreeGetItem<std::string>(item.second, "display_description", ""),
						protocolList
					);
				}
			}
		}

		try
		{
			boost::asio::io_context ioContext;

			std::string hostname = boost::asio::ip::host_name();

			boost::asio::ip::tcp::resolver               resolver(ioContext);
			boost::asio::ip::tcp::resolver::results_type endpoints = resolver.resolve(hostname, "");

			for (const auto& endpoint : endpoints)
			{
				LocalAddresses.push_back(endpoint.endpoint().address().to_string());
			}
		}
		catch (const std::exception& exception)
		{
			L_ERROR << "Couldn't resolve hostname ip addresses. [MESSAGE: " << exception.what() << "]" << L_END;
		}
	}

	NetworkIsReady = true;

	std::thread processNetworkInfoUpdaterThread(ProcessNetworkInfoUpdater);

	L_INFO << "Network manager is started and ready to work." << L_END;

	PacketManager::Initialize();

	processNetworkInfoUpdaterThread.join();
}

void Network::Uninitialize()
{
	ClearNetworkInfoMap();

	PacketManager::Uninitialize();

	NetworkIsReady = false;

	L_INFO << "Network Manager Stopped." << L_END;
}

bool Network::IsReady()
{
	return NetworkIsReady;
}

void Network::WaitTillBeReady()
{
	while (!NetworkIsReady);
}

void Network::ProcessNetworkInfoUpdater()
{
	while (NetworkIsReady)
	{
		Process::UpdateSnapshotHelper();

		for (const auto& item : Process::GetProcessInfoMap())
		{
			if (Process::FindProcessIdByName(item.second.name) == NULL)
			{
				if (ExistsNetworkInfoMap(item.second.name))
				{
					DeleteNetworkInfoList(item.second.name);

					L_INFO << "Application '" << item.second.displayName << " (" << item.second.displayDescription << ")' has been closed. Stopped listening to packets." << L_END;
				}

				continue;
			}

			if (!ExistsNetworkInfoMap(item.second.name))
			{
				L_INFO << "Appication '" << item.second.displayName << " (" << item.second.displayDescription << ")' detected. Started listening to packets." << L_END;
			}

			UpdateNetworkInfoList(item.second.name);
		}

		Sleep(PROCESS_NETWORK_INFO_UPDATE_DURATION);
	}
}

Network::NetworkInfoMap& Network::GetNetworkInfoMap()
{
	return NetworkInfos;
}

void Network::UpdateNetworkInfoList(Process::ProcessName processName, Process::ProcessId processId)
{
	if (processName.empty())
	{
		return;
	}

	if (processId == NULL)
	{
		processId = Process::FindProcessIdByName(processName);
	}

	if (processId == NULL)
	{
		return;
	}

	if (!ExistsNetworkInfoMap(processName))
	{
		NetworkInfos[processName] = new InfoList();
	}

	InfoList* list = NetworkInfos[processName];
	
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
				Info networkInfo(
					tcpTable->table[i].dwLocalAddr,
					tcpTable->table[i].dwRemoteAddr,
					tcpTable->table[i].dwLocalPort,
					tcpTable->table[i].dwRemotePort,
					NetworkLayer::TCP
				);

				bool found = false;

				for (const Info& network : *list)
				{
					if (network.IsUDP())
					{
						continue;
					}

					if (
						ExtractPort(tcpTable->table[i].dwLocalPort) == network.GetLocalPort() ||
						ExtractPort(tcpTable->table[i].dwRemotePort) == network.GetRemotePort()
					)
					{
						found = true;
						break;
					}
				}

				if (!found) list->push_back(networkInfo);
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
				Info networkInfo(
					udpTable->table[i].dwLocalAddr,
					0,
					udpTable->table[i].dwLocalPort,
					0,
					NetworkLayer::UDP
				);

				bool found = false;

				for (const Info& network : *list)
				{
					if (!network.IsUDP())
					{
						continue;
					}

					if (ExtractPort(udpTable->table[i].dwLocalPort) == network.GetLocalPort())
					{
						found = true;
						break;
					}
				}

				if (!found) list->push_back(networkInfo);
			}
		}
	}

	free(udpTable);
}

void Network::ClearNetworkInfoList(Process::ProcessName processName)
{
	if (!ExistsNetworkInfoMap(processName))
	{
		return;
	}

	NetworkInfos[processName]->clear();
}

void Network::DeleteNetworkInfoList(Process::ProcessName processName)
{
	if (!ExistsNetworkInfoMap(processName))
	{
		return;
	}

	InfoList* list = NetworkInfos[processName];
	
	list->clear();

	delete list;

	NetworkInfos.erase(processName);
}

bool Network::ExistsNetworkInfoMap(Process::ProcessName processName)
{
	return NetworkInfos.find(processName) != NetworkInfos.end();
}

Network::InfoList* Network::GetNetworkInfoList(Process::ProcessName processName)
{
	if (!ExistsNetworkInfoMap(processName))
	{
		return NULL;
	}

	return NetworkInfos[processName];
}

Process::ProcessName Network::FindPortProcess(PortNumber port, NetworkLayer* layer)
{
	for (const auto& item : NetworkInfos)
	{
		size_t count = item.second->size();

		for (int i = 0; i < count; i++)
		{
			Info& networkInfo = item.second->at(i);

			if (networkInfo.GetLocalPort() == port || networkInfo.GetRemotePort() == port)
			{
				if (layer != NULL)
				{
					*layer = networkInfo.GetNetworkLayer();
				}

				return item.first;
			}
		}
	}

	return "";
}

bool Network::DoesProcessOwnPort(Process::ProcessName processName, PortNumber port, NetworkLayer* layer)
{
	if (!ExistsNetworkInfoMap(processName))
	{
		return false;
	}

	for (const Info& info : *NetworkInfos[processName])
	{
		if (info.GetLocalPort() == port || info.GetRemotePort() == port)
		{
			if (layer != NULL)
			{
				*layer = info.GetNetworkLayer();
			}

			return true;
		}
	}

	return false;
}

void Network::ClearNetworkInfoMap()
{
	for (const auto& item : NetworkInfos)
	{
		item.second->clear();

		delete item.second;
	}

	NetworkInfos.clear();
}

void Network::SetServerHost(std::string host)
{
	ServerHost = host;
}