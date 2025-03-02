#pragma once

#include <string>
#include <Windows.h>

#define NETWORK_INET_ADDRESS_LENGTH (22)
#define NETWORK_INET6_ADDRESS_LENGTH (65)

#define NETWORK_MAX_PACKET_SIZE (0xffff)

#define NETWORK_TCP_PROTOCOL_ID 6
#define NETWORK_UDP_PROTOCOL_ID 17

#define GP_DIVERT_HEADER (unsigned int)(0x76647067)
#define GP_SERVER_HEADER (unsigned int)(0x76647367)

namespace Network
{
	using PortNumber = USHORT;
	
	struct PacketExtraHeader
	{
		UINT   identifier;
		UINT   originalIp;
		USHORT originalPort;
		UINT   socketHost;
		USHORT socketPort;
	};

	size_t ClearGPDivertHeaders(UINT8* buffer, size_t bufferLength);

	std::string ConvertIntegerAddressToString(const DWORD& addressNumber);
	PortNumber  ExtractPort(const DWORD& port);
};