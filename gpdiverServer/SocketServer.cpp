#include "SocketServer.h"

#include <thread>
#include <mutex>
#include <atomic>
#include <unordered_map>
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <iphlpapi.h>
#include <sstream>
#include <iomanip>

#include "Config.h"
#include "HttpServer.h"
#include "SharedNetwork.h"

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

SOCKET TcpServerSocket = INVALID_SOCKET;
SOCKET UdpServerSocket = INVALID_SOCKET; // Main UDP socket for receiving client packets

Network::MacAddress ServerMacAddress = { 0, 0, 0, 0, 0, 0 };

// Global session mapping: sessionId -> client address.
std::mutex g_sessionMutex;
std::unordered_map<uint32_t, sockaddr_in> g_sessionMap;
std::atomic<uint32_t> g_nextSessionId{ 1 };

void TcpServerProcess()
{
    // Not implemented in this example.
}

// Helper function: dump hex for debugging.
std::string HexDump(const char* data, int length)
{
    std::ostringstream oss;
    for (int i = 0; i < length; i++) {
        oss << std::hex << std::setw(2) << std::setfill('0')
            << (static_cast<unsigned int>(static_cast<unsigned char>(data[i]))) << " ";
    }
    return oss.str();
}
void HandleClientUdpSession(const sockaddr_in& clientAddr, const Network::PacketExtraHeader& header, const char* payload, int payloadLength)
{
    // Use the sessionId provided by the client (convert to host order for logging).
    uint32_t sessionId = ntohl(header.sessionId);
    if (sessionId == 0) {
        L_ERROR << "Client did not provide a valid sessionId." << L_END;
        return;
    }
    L_INFO << "Session " << sessionId << ": Using sessionId from client." << L_END;

    // Create a new UDP socket for this session.
    SOCKET sessionSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sessionSocket == INVALID_SOCKET)
    {
        L_ERROR << "Session " << sessionId << ": Failed to create session socket." << L_END;
        return;
    }

    // Bind session socket to an ephemeral port.
    sockaddr_in localAddr = {};
    localAddr.sin_family = AF_INET;
    localAddr.sin_port = 0; // let OS assign a port.
    inet_pton(AF_INET, Config::GetUdpSocketHost().c_str(), &localAddr.sin_addr);
    if (bind(sessionSocket, (sockaddr*)&localAddr, sizeof(localAddr)) == SOCKET_ERROR)
    {
        L_ERROR << "Session " << sessionId << ": Failed to bind session socket." << L_END;
        closesocket(sessionSocket);
        return;
    }

    // (Optionally, store the client address in a session map if needed for later lookups.)
    {
        std::lock_guard<std::mutex> lock(g_sessionMutex);
        g_sessionMap[sessionId] = clientAddr;
    }

    // At this point, the payload already does NOT contain the extra header.
    // (It was removed in the main UDP process loop before spawning the session thread.)

    // Build the destination server address from the header.
    sockaddr_in destAddr = {};
    destAddr.sin_family = AF_INET;
    destAddr.sin_port = header.originalPort;  // already in network order
    inet_pton(AF_INET, Network::ConvertIntegerAddressToString(header.originalIp).c_str(), &destAddr.sin_addr);

    // Forward the original payload (without header) to the destination server.
    int sent = sendto(sessionSocket, payload, payloadLength, 0, (sockaddr*)&destAddr, sizeof(destAddr));
    if (sent != payloadLength)
    {
        L_ERROR << "Session " << sessionId << ": Failed to send complete payload to destination server." << L_END;
        closesocket(sessionSocket);
        return;
    }
    L_INFO << "Session " << sessionId << ": Forwarded payload (" << sent << " bytes) to destination server." << L_END;

    // Wait for a response from the destination server (with a timeout).
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(sessionSocket, &readfds);
    timeval tv = { 2, 0 }; // 2-second timeout.
    int sel = select(sessionSocket + 1, &readfds, NULL, NULL, &tv);
    if (sel <= 0)
    {
        L_INFO << "Session " << sessionId << ": Timeout waiting for response." << L_END;
        closesocket(sessionSocket);
        return;
    }

    char responseBuffer[NETWORK_MAX_PACKET_SIZE];
    memset(responseBuffer, 0, sizeof(responseBuffer));
    sockaddr_in respAddr = {};
    int respAddrLen = sizeof(respAddr);
    int respLen = recvfrom(sessionSocket, responseBuffer, sizeof(responseBuffer), 0, (sockaddr*)&respAddr, &respAddrLen);
    if (respLen < 1)
    {
        L_ERROR << "Session " << sessionId << ": Failed to receive response." << L_END;
        closesocket(sessionSocket);
        return;
    }
    L_INFO << "Session " << sessionId << ": Received response (" << respLen << " bytes) from destination server." << L_END;
    L_INFO << "Session " << sessionId << ": Response hex dump: " << HexDump(responseBuffer, respLen) << L_END;

    // Prepend the stored extra header (mark it as a server response).
    Network::PacketExtraHeader modifiedHeader = header;
    modifiedHeader.identifier = Network::GP_SERVER_HEADER; // mark as server response
    // Do NOT change modifiedHeader.sessionId – echo the same value (still in network order).

    if ((size_t)respLen + sizeof(modifiedHeader) > sizeof(responseBuffer))
    {
        L_ERROR << "Session " << sessionId << ": Response too large to prepend header, aborting." << L_END;
        closesocket(sessionSocket);
        return;
    }
    memmove(responseBuffer + sizeof(modifiedHeader), responseBuffer, respLen);
    memcpy(responseBuffer, &modifiedHeader, sizeof(modifiedHeader));
    int totalRespLen = respLen + sizeof(modifiedHeader);

    // Retrieve the client address from our mapping.
    sockaddr_in clientToSend;
    {
        std::lock_guard<std::mutex> lock(g_sessionMutex);
        clientToSend = g_sessionMap[sessionId];
        g_sessionMap.erase(sessionId);
    }

    // Send the complete packet (header + response payload) back to the client using the main UDP socket.
    int sentBack = sendto(UdpServerSocket, responseBuffer, totalRespLen, 0,
        (sockaddr*)&clientToSend, sizeof(clientToSend));
    if (sentBack != totalRespLen)
    {
        L_ERROR << "Session " << sessionId << ": Failed to send complete response back to client." << L_END;
    }
    else
    {
        L_INFO << "Session " << sessionId << ": Successfully forwarded response to client." << L_END;
    }

    closesocket(sessionSocket);
}

void UdpServerProcess()
{
    char packet[NETWORK_MAX_PACKET_SIZE];
    sockaddr_in clientAddress;
    int clientAddressLength = sizeof(clientAddress);
    memset(packet, 0, sizeof(packet));

    while (true)
    {
        std::cout << "-----------------------------------------------------------------------------------" << std::endl;
        clientAddressLength = sizeof(clientAddress);
        int receivedBytes = recvfrom(UdpServerSocket, packet, sizeof(packet), 0,
            (sockaddr*)&clientAddress, &clientAddressLength);
        if (receivedBytes <= 0)
        {
            continue;
        }
        L_INFO << "Received packet (" << receivedBytes << " bytes) from "
            << Network::ConvertIntegerAddressToString(*(DWORD*)&clientAddress.sin_addr)
            << ":" << Network::ExtractPort(clientAddress.sin_port) << L_END;
        L_INFO << "[DEBUG] Packet hex dump: " << HexDump(packet, receivedBytes) << L_END;

        constexpr size_t extraHeaderSize = sizeof(Network::PacketExtraHeader);
        if (receivedBytes < (int)extraHeaderSize)
        {
            L_INFO << "[DEBUG] Packet too short (" << receivedBytes << " bytes), skipping." << L_END;
            continue;
        }
        Network::PacketExtraHeader extraInfo;
        ZeroMemory(&extraInfo, extraHeaderSize);
        memcpy(&extraInfo, packet, extraHeaderSize);
        // Verify the identifier.
        if (extraInfo.identifier != Network::GP_DIVERT_HEADER)
        {
            L_INFO << "[DEBUG] Header identifier mismatch, skipping." << L_END;
            continue;
        }
        // Remove the header from the packet so that the payload passed to the session is header-free.
        char* originalPayload = packet + extraHeaderSize;
        int originalPayloadLength = receivedBytes - (int)extraHeaderSize;
        if (originalPayloadLength < 1)
        {
            L_INFO << "[DEBUG] No payload in packet, skipping." << L_END;
            continue;
        }

        // Spawn a thread to handle this UDP session.
        std::thread sessionThread(HandleClientUdpSession, clientAddress, extraInfo, originalPayload, originalPayloadLength);
        sessionThread.detach();
    }
}



void Network::SocketServer::Initialize()
{
    UpdateMacAddress();
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
    {
        L_ERROR << "WSA failed to start." << L_END;
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
            L_ERROR << "Couldn't bind TCP server socket on '"
                << Config::GetTcpSocketHost() << ":" << Config::GetTcpSocketPort() << "'." << L_END;
            goto Failed;
        }
        if (listen(TcpServerSocket, SOMAXCONN) == SOCKET_ERROR)
        {
            L_ERROR << "TCP server failed to listen on '"
                << Config::GetTcpSocketHost() << ":" << Config::GetTcpSocketPort() << "'." << L_END;
            goto Failed;
        }
        L_INFO << "TCP server socket listening on '"
            << Config::GetTcpSocketHost() << ":" << Config::GetTcpSocketPort() << "'." << L_END;
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
            L_ERROR << "Couldn't bind UDP server socket on '"
                << Config::GetUdpSocketHost() << ":" << Config::GetUdpSocketPort() << "'." << L_END;
            goto Failed;
        }
        L_INFO << "UDP server socket listening on '"
            << Config::GetUdpSocketHost() << ":" << Config::GetUdpSocketPort() << "'." << L_END;
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
    ULONG ipAddressNumber = 0;
    inet_pton(AF_INET, ipAddress.c_str(), &ipAddressNumber);
    MacAddress macAddress;
    ULONG macAddressLength = sizeof(macAddress);
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














//#include "SocketServer.h"
//
//#include <thread>
//#include <WinSock2.h>
//#include <WS2tcpip.h>
//#include <iphlpapi.h>
//
//#include "Config.h"
//#include "HttpServer.h"
//
//#include "SharedNetwork.h"
//
//#pragma comment(lib, "Ws2_32.lib")
//#pragma comment(lib, "iphlpapi.lib")
//
//SOCKET TcpServerSocket = INVALID_SOCKET;
//SOCKET UdpServerSocket = INVALID_SOCKET;
//
//Network::MacAddress ServerMacAddress = { 0, 0, 0, 0, 0, 0 };
//
//void TcpServerProcess()
//{
//
//}
//
//void UdpServerProcess()
//{
//	char        packet[NETWORK_MAX_PACKET_SIZE];
//	sockaddr_in clientAddress;
//	int         clientAddressLength;
//
//	memset(packet, 0, sizeof(packet));
//
//	while (true)
//	{
//		std::cout << "-----------------------------------------------------------------------------------" << std::endl;
//
//		clientAddressLength = sizeof(clientAddress);
//
//		int receivedBytes = recvfrom(UdpServerSocket, packet, sizeof(packet), 0, (sockaddr*)&clientAddress, &clientAddressLength);
//
//		if (receivedBytes <= 0)
//		{
//			continue;
//		}
//
//		L_INFO << "total packet is : " << std::string(packet, receivedBytes) << " | " << receivedBytes << L_END;
//		L_INFO << "client address is : " << Network::ConvertIntegerAddressToString(*(DWORD*)&clientAddress.sin_addr) << ":" << Network::ExtractPort(clientAddress.sin_port) << L_END;
//
//		constexpr size_t extraHeaderSize = sizeof(Network::PacketExtraHeader);
//
//		Network::PacketExtraHeader extraInfo;
//		ZeroMemory(&extraInfo, extraHeaderSize);
//
//		char* originalPayload = NULL;
//		int   originalPayloadLength = 0;
//
//		if (receivedBytes >= extraHeaderSize)
//		{
//			memcpy(&extraInfo, packet, extraHeaderSize);
//
//			originalPayload = packet + extraHeaderSize;
//			originalPayloadLength = receivedBytes - extraHeaderSize;
//		}
//
//		if (!originalPayload || originalPayloadLength < 1)
//		{
//			continue;
//		}
//
//		if (extraInfo.identifier != GP_DIVERT_HEADER)
//		{
//			continue;
//		}
//
//		decltype(extraInfo.originalIp)   originalIpAddress = extraInfo.originalIp;
//		decltype(extraInfo.originalPort) originalPort = extraInfo.originalPort;
//
//		L_INFO << "came packet is : " << std::string(originalPayload, originalPayloadLength) << " | " << originalPayloadLength << L_END;
//		L_INFO << "send payload to : " << Network::ConvertIntegerAddressToString(originalIpAddress) << ":" << originalPort << " | " << Network::ConvertIntegerAddressToString(extraInfo.socketHost) << ":" << extraInfo.socketPort << L_END;
//
//		if (originalIpAddress == 0 || originalPort == 0)
//		{
//			continue;
//		}
//
//		sockaddr_in originalServerAddress;
//		originalServerAddress.sin_family = AF_INET;
//		originalServerAddress.sin_port = htons(originalPort);
//
//		inet_pton(originalServerAddress.sin_family, Network::ConvertIntegerAddressToString(originalIpAddress).c_str(), &originalServerAddress.sin_addr);
//
//		sendto(UdpServerSocket, originalPayload, originalPayloadLength, 0, (sockaddr*)&originalServerAddress, sizeof(originalServerAddress));
//
//		sockaddr_in originalResponseAddress;
//		int         originalResponseAddressLength = sizeof(originalResponseAddress);
//
//		char originalResponse[sizeof(packet)];
//
//		int originalResponseLength = recvfrom(UdpServerSocket, originalResponse, sizeof(originalResponse), 0, (sockaddr*)&originalResponseAddress, &originalResponseAddressLength);
//
//		if (originalResponseLength < 1)
//		{
//			continue;
//		}
//
//		extraInfo.identifier = GP_SERVER_HEADER;
//
//		memmove(originalResponse + extraHeaderSize, originalResponse, originalResponseLength);
//		memcpy(originalResponse, &extraInfo, extraHeaderSize);
//
//		originalResponseLength += extraHeaderSize;
//
//		L_INFO << "original response is : " << std::string(originalResponse, originalResponseLength) << " | " << originalResponseLength << L_END;
//
//		sendto(UdpServerSocket, originalResponse, originalResponseLength, 0, (sockaddr*)&clientAddress, clientAddressLength);
//
//		//L_INFO << "proxy packet done. " << originalResponseLength << " | " << originalPayloadLength << L_END;
//	}
//}
//
//void Network::SocketServer::Initialize()
//{
//	UpdateMacAddress();
//
//	WSADATA wsaData;
//
//	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
//	{
//		L_ERROR << "`WSA` failed to start." << L_END;
//		goto Failed;
//	}
//
//	{
//		TcpServerSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
//
//		if (TcpServerSocket == SOCKET_ERROR)
//		{
//			L_ERROR << "Couldn't create TCP server socket." << L_END;
//			goto Failed;
//		}
//
//		sockaddr_in address;
//		address.sin_family = AF_INET;
//		address.sin_port = htons(Config::GetTcpSocketPort());
//
//		inet_pton(AF_INET, Config::GetTcpSocketHost().c_str(), &address.sin_addr);
//
//		if (bind(TcpServerSocket, (SOCKADDR*)&address, sizeof(address)) == SOCKET_ERROR)
//		{
//			L_ERROR << "Couldn't bind TCP server socket on '" << Config::GetTcpSocketHost() << ":" << Config::GetTcpSocketPort() << "'." << L_END;
//			goto Failed;
//		}
//
//		if (listen(TcpServerSocket, SOMAXCONN) == SOCKET_ERROR)
//		{
//			L_ERROR << "TCP server failed to listen on '" << Config::GetTcpSocketHost() << ":" << Config::GetTcpSocketPort() << "'." << L_END;
//			goto Failed;
//		}
//
//		L_INFO << "TCP server socket started to listening on '" << Config::GetTcpSocketHost() << ":" << Config::GetTcpSocketPort() << "'." << L_END;
//	}
//
//	{
//		UdpServerSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
//
//		if (UdpServerSocket == SOCKET_ERROR)
//		{
//			L_ERROR << "Couldn't create UDP server socket." << L_END;
//			goto Failed;
//		}
//
//		sockaddr_in address;
//		address.sin_family = AF_INET;
//		address.sin_port = htons(Config::GetUdpSocketPort());
//
//		inet_pton(AF_INET, Config::GetUdpSocketHost().c_str(), &address.sin_addr);
//
//		if (bind(UdpServerSocket, (SOCKADDR*)&address, sizeof(address)) == SOCKET_ERROR)
//		{
//			L_ERROR << "Couldn't bind UDP server socket on '" << Config::GetUdpSocketHost() << ":" << Config::GetUdpSocketPort() << "'." << L_END;
//			goto Failed;
//		}
//
//		L_INFO << "UDP server socket started to listening on '" << Config::GetUdpSocketHost() << ":" << Config::GetUdpSocketPort() << "'." << L_END;
//	}
//
//	goto Succeed;
//
//Failed:
//	{
//		Uninitialize();
//
//		Sleep(5000);
//
//		exit(EXIT_FAILURE);
//	}
//
//Succeed:
//	{
//		std::thread tcpServerProcessThread(TcpServerProcess);
//		std::thread udpServerProcessThread(UdpServerProcess);
//
//		tcpServerProcessThread.join();
//		udpServerProcessThread.join();
//	}
//}
//
//void Network::SocketServer::Uninitialize()
//{
//	if (TcpServerSocket != INVALID_SOCKET)
//	{
//		closesocket(TcpServerSocket);
//	}
//
//	if (UdpServerSocket != INVALID_SOCKET)
//	{
//		closesocket(UdpServerSocket);
//	}
//
//	TcpServerSocket = INVALID_SOCKET;
//	UdpServerSocket = INVALID_SOCKET;
//
//	WSACleanup();
//}
//
//void Network::UpdateMacAddress()
//{
//	std::string ipAddress = GetIpAddress();
//
//	if (ipAddress.empty())
//	{
//		return;
//	}
//
//	IPAddr sourceIP = 0;
//	ULONG  ipAddressNumber = 0;
//
//	inet_pton(AF_INET, ipAddress.c_str(), &ipAddressNumber);
//
//	MacAddress macAddress;
//	ULONG      macAddressLength = sizeof(macAddress);
//
//	memset(macAddress, 0, sizeof(macAddress));
//
//	DWORD result = SendARP(ipAddressNumber, sourceIP, macAddress, &macAddressLength);
//
//	if (result == NO_ERROR)
//	{
//		memcpy(ServerMacAddress, macAddress, macAddressLength);
//		return;
//	}
//
//	memset(ServerMacAddress, 0, macAddressLength);
//}
//
//std::string Network::GetMacAddress(MacAddress* outMacAddress)
//{
//	char macStr[20];
//	memset(macStr, 0, sizeof(macStr));
//	
//	sprintf_s(
//		macStr,
//		"%02x-%02x-%02x-%02x-%02x-%02x",
//		ServerMacAddress[0],
//		ServerMacAddress[1],
//		ServerMacAddress[2],
//		ServerMacAddress[3],
//		ServerMacAddress[4],
//		ServerMacAddress[5]
//	);
//
//	if (outMacAddress != NULL)
//	{
//		memcpy(outMacAddress, ServerMacAddress, sizeof(ServerMacAddress));
//	}
//
//	return std::string(macStr);
//}