#pragma once

#include "Utils.h"

namespace Network
{
	using MacAddress = BYTE[6];

	namespace SocketServer
	{

		void Initialize();
		void Uninitialize();
	}

	void        UpdateMacAddress();
	std::string GetMacAddress(MacAddress* outMacAddress = NULL);
}