#include "SharedNetwork.h"

#include <iostream>
#include <memory>

size_t Network::ClearGPDivertHeaders(UINT8* buffer, size_t bufferLength)
{
	if (buffer == NULL)
	{
		return 0;
	}

	constexpr size_t headerSize = sizeof(PacketExtraHeader);

	while (bufferLength > headerSize)
	{
		PacketExtraHeader* gpHeader = (PacketExtraHeader*)buffer;

		if (gpHeader->identifier != GP_DIVERT_HEADER)
		{
			return bufferLength;
		}

		memmove(buffer, buffer + headerSize, bufferLength - headerSize);

		bufferLength -= headerSize;
	}

	return bufferLength;
}

std::string Network::ConvertIntegerAddressToString(const DWORD& addressNumber)
{
	char address[NETWORK_INET_ADDRESS_LENGTH];
	memset(address, 0, sizeof(address));

	DWORD addr = ntohl(addressNumber);

	int written = snprintf(
		address,
		sizeof(address),
		"%u.%u.%u.%u",
		(addr >> 24) & 0xff,
		(addr >> 16) & 0xff,
		(addr >> 8) & 0xff,
		addr & 0xff
	);

	if (written < 0 || (size_t)written >= sizeof(address))
	{
		return "";
	}

	std::string addressStr = address;

	return addressStr;
}

Network::PortNumber Network::ExtractPort(const DWORD& port)
{
	return (PortNumber)ntohs((PortNumber)port);
}