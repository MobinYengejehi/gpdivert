#pragma once

#include <string>
#include <Windows.h>

#define NETWORK_INET_ADDRESS_LENGTH (22)
#define NETWORK_INET6_ADDRESS_LENGTH (65)

#define NETWORK_MAX_PACKET_SIZE (0xffff)

#define NETWORK_TCP_PROTOCOL_ID 6
#define NETWORK_UDP_PROTOCOL_ID 17

namespace Network
{
	using PortNumber = USHORT;

	constexpr uint32_t GP_DIVERT_HEADER = 0x44495645;  // 'DIVE'
	constexpr uint32_t GP_SERVER_HEADER = 0x53455645;   // 'SEVE'

#pragma pack(push, 1)
	struct PacketExtraHeader
	{
		uint32_t   identifier;
		uint32_t   originalIp;
		uint16_t   originalPort;
		uint32_t   socketHost;
		uint16_t   socketPort;
		uint32_t   sessionId;
	};
#pragma pack(pop)

	size_t ClearGPDivertHeaders(UINT8* buffer, size_t bufferLength);

	std::string ConvertIntegerAddressToString(const DWORD& addressNumber);
	PortNumber  ExtractPort(const DWORD& port);
};

/*#pragma once

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

#pragma pack(push, 1)
	struct PacketExtraHeader
	{
		uint32_t   identifier;
		uint32_t   originalIp;
		uint16_t   originalPort;
		uint32_t   socketHost;
		uint16_t   socketPort;
		uint32_t   sessionId;
	};
#pragma pack(pop)

	size_t ClearGPDivertHeaders(UINT8* buffer, size_t bufferLength);

	std::string ConvertIntegerAddressToString(const DWORD& addressNumber);
	PortNumber  ExtractPort(const DWORD& port);
};*/