#include "SocketServer.h"

#include <thread>
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <iphlpapi.h>

#include "Config.h"
#include "HttpServer.h"

#include "SharedNetwork.h"

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

SOCKET TcpServerSocket = INVALID_SOCKET;
SOCKET UdpServerSocket = INVALID_SOCKET;

Network::MacAddress ServerMacAddress = { 0, 0, 0, 0, 0, 0 };

void TcpServerProcess()
{

}

void UdpServerProcess()
{
	char        packet[NETWORK_MAX_PACKET_SIZE];
	sockaddr_in clientAddress;
	int         clientAddressLength;

	memset(packet, 0, sizeof(packet));

	while (true)
	{
		clientAddressLength = sizeof(clientAddress);

		int receivedBytes = recvfrom(UdpServerSocket, packet, sizeof(packet), 0, (sockaddr*)&clientAddress, &clientAddressLength);

		if (receivedBytes <= 0)
		{
			continue;
		}

		Network::PacketExtraHeader extraInfo;
		ZeroMemory(&extraInfo, sizeof(extraInfo));

		char* originalPayload = packet;
		int   originalPayloadLength = receivedBytes;

		if (receivedBytes >= sizeof(extraInfo))
		{
			memcpy(&extraInfo, packet, sizeof(extraInfo));

			originalPayloadLength = Network::ClearGPDivertHeaders((UINT8*)originalPayload, originalPayloadLength);
		}

		UINT32 originalServerIp = extraInfo.originalIp;
		USHORT originalServerPort = extraInfo.originalPort;

		if (originalServerIp == 0 || originalServerPort == 0)
		{
			continue;
		}

		L_INFO << "packet is : " << packet << L_END;
		L_INFO << "original payload : " << originalPayload << L_END;

		sockaddr_in originalAddress;
		originalAddress.sin_family = AF_INET;
		originalAddress.sin_port = htons(originalServerPort);

		inet_pton(AF_INET, Network::ConvertIntegerAddressToString(originalServerIp).c_str(), &originalAddress.sin_addr);

		sendto(UdpServerSocket, originalPayload, originalPayloadLength, 0, (sockaddr*)&originalAddress, sizeof(originalAddress));

		sockaddr_in originalResponseAddress;
		int         originalResponseAddressLength = sizeof(originalResponseAddress);

		char originalResponseBuffer[sizeof(packet)];
		memset(originalResponseBuffer, 0, sizeof(originalResponseBuffer));

		int responseReceivedBytes = recvfrom(UdpServerSocket, originalResponseBuffer, sizeof(originalResponseBuffer), 0, (sockaddr*)&originalResponseAddress, &originalResponseAddressLength);

		if (responseReceivedBytes < 1)
		{
			continue;
		}
		
		char* filteredOriginalResponseBuffer = originalResponseBuffer;
		int   filteredOriginalResponseBufferLength = responseReceivedBytes;

		if (filteredOriginalResponseBufferLength > sizeof(extraInfo))
		{
			filteredOriginalResponseBufferLength = Network::ClearGPDivertHeaders((UINT8*)filteredOriginalResponseBuffer, filteredOriginalResponseBufferLength);
		}

		L_INFO << "original response before change : " << filteredOriginalResponseBuffer << L_END;

		memmove(filteredOriginalResponseBuffer + sizeof(extraInfo), filteredOriginalResponseBuffer, filteredOriginalResponseBufferLength);
		memcpy(filteredOriginalResponseBuffer, &extraInfo, sizeof(extraInfo));

		L_INFO << "original response after change : " << filteredOriginalResponseBuffer << L_END;

		sendto(UdpServerSocket, filteredOriginalResponseBuffer, filteredOriginalResponseBufferLength, 0, (sockaddr*)&clientAddress, clientAddressLength);

		L_INFO << "payload came from client and original host is : " << Network::ConvertIntegerAddressToString(extraInfo.socketHost) << ":" << extraInfo.socketPort << " | " << Network::ConvertIntegerAddressToString(extraInfo.originalIp) << ":" << extraInfo.originalPort << L_END;
		L_INFO << "sending data to client: " << filteredOriginalResponseBuffer << " | " << filteredOriginalResponseBufferLength << L_END;
	}
}

void Network::SocketServer::Initialize()
{
	UpdateMacAddress();

	WSADATA wsaData;

	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
	{
		L_ERROR << "`WSA` failed to start." << L_END;
		goto Failed;
	}

	{
		TcpServerSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

		if (TcpServerSocket == SOCKET_ERROR)
		{
			L_ERROR << "Couldn't create TCP server socket." << L_END;
			goto Failed;
		}

		sockaddr_in address;
		address.sin_family = AF_INET;
		address.sin_port = htons(Config::GetTcpSocketPort());

		inet_pton(AF_INET, Config::GetTcpSocketHost().c_str(), &address.sin_addr);

		if (bind(TcpServerSocket, (SOCKADDR*)&address, sizeof(address)) == SOCKET_ERROR)
		{
			L_ERROR << "Couldn't bind TCP server socket on '" << Config::GetTcpSocketHost() << ":" << Config::GetTcpSocketPort() << "'." << L_END;
			goto Failed;
		}

		if (listen(TcpServerSocket, SOMAXCONN) == SOCKET_ERROR)
		{
			L_ERROR << "TCP server failed to listen on '" << Config::GetTcpSocketHost() << ":" << Config::GetTcpSocketPort() << "'." << L_END;
			goto Failed;
		}

		L_INFO << "TCP server socket started to listening on '" << Config::GetTcpSocketHost() << ":" << Config::GetTcpSocketPort() << "'." << L_END;
	}

	{
		UdpServerSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

		if (UdpServerSocket == SOCKET_ERROR)
		{
			L_ERROR << "Couldn't create UDP server socket." << L_END;
			goto Failed;
		}

		sockaddr_in address;
		address.sin_family = AF_INET;
		address.sin_port = htons(Config::GetUdpSocketPort());

		inet_pton(AF_INET, Config::GetUdpSocketHost().c_str(), &address.sin_addr);

		if (bind(UdpServerSocket, (SOCKADDR*)&address, sizeof(address)) == SOCKET_ERROR)
		{
			L_ERROR << "Couldn't bind UDP server socket on '" << Config::GetUdpSocketHost() << ":" << Config::GetUdpSocketPort() << "'." << L_END;
			goto Failed;
		}

		L_INFO << "UDP server socket started to listening on '" << Config::GetUdpSocketHost() << ":" << Config::GetUdpSocketPort() << "'." << L_END;
	}

	goto Succeed;

Failed:
	{
		Uninitialize();

		Sleep(5000);

		exit(EXIT_FAILURE);
	}

Succeed:
	{
		std::thread tcpServerProcessThread(TcpServerProcess);
		std::thread udpServerProcessThread(UdpServerProcess);

		tcpServerProcessThread.join();
		udpServerProcessThread.join();
	}
}

void Network::SocketServer::Uninitialize()
{
	if (TcpServerSocket != INVALID_SOCKET)
	{
		closesocket(TcpServerSocket);
	}

	if (UdpServerSocket != INVALID_SOCKET)
	{
		closesocket(UdpServerSocket);
	}

	TcpServerSocket = INVALID_SOCKET;
	UdpServerSocket = INVALID_SOCKET;

	WSACleanup();
}

void Network::UpdateMacAddress()
{
	std::string ipAddress = GetIpAddress();

	if (ipAddress.empty())
	{
		return;
	}

	IPAddr sourceIP = 0;
	ULONG  ipAddressNumber = 0;

	inet_pton(AF_INET, ipAddress.c_str(), &ipAddressNumber);

	MacAddress macAddress;
	ULONG      macAddressLength = sizeof(macAddress);

	memset(macAddress, 0, sizeof(macAddress));

	DWORD result = SendARP(ipAddressNumber, sourceIP, macAddress, &macAddressLength);

	if (result == NO_ERROR)
	{
		memcpy(ServerMacAddress, macAddress, macAddressLength);
		return;
	}

	memset(ServerMacAddress, 0, macAddressLength);
}

std::string Network::GetMacAddress(MacAddress* outMacAddress)
{
	char macStr[20];
	memset(macStr, 0, sizeof(macStr));
	
	sprintf_s(
		macStr,
		"%02x-%02x-%02x-%02x-%02x-%02x",
		ServerMacAddress[0],
		ServerMacAddress[1],
		ServerMacAddress[2],
		ServerMacAddress[3],
		ServerMacAddress[4],
		ServerMacAddress[5]
	);

	if (outMacAddress != NULL)
	{
		memcpy(outMacAddress, ServerMacAddress, sizeof(ServerMacAddress));
	}

	return std::string(macStr);
}