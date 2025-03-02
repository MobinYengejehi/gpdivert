#pragma once

#include <vector>
#include <string>

#include "PropertyUtils.h"

#include "ws2def.h"

#include "SharedNetwork.h"

#define DEFAULT_CONFIG_FILE_NAME "config.json"

namespace Config
{
	constexpr const char* DefaultConfigData = (
		"{"
			"\"http_host\" : \"0.0.0.0\","
			"\"http_port\" : 38309,"
			"\"tcp_socket_host\" : \"0.0.0.0\","
			"\"tcp_socket_port\" : 38310,"
			"\"udp_socket_host\" : \"0.0.0.0\","
			"\"udp_socket_port\" : 38311,"
			"\"applications\" : ["
				"{"
					"\"name\" : \"cs2.exe\","
					"\"description\" : \"Counter-Strike 2\","
					"\"display_name\" : \"Counter Strike 2\","
					"\"display_description\" : \"Counter Strike 2 (VALVE)\","
					"\"protocols\" : ["
						"{"
							"\"name\" : \"tcp\","
							"\"id\" : " C_TO_STRING(NETWORK_TCP_PROTOCOL_ID) ","
							"\"server_host\" : \"\","
							"\"server_port\" : 38310"
						"},"
						"{"
							"\"name\" : \"udp\","
							"\"id\" : " C_TO_STRING(NETWORK_UDP_PROTOCOL_ID) ","
							"\"server_host\" : \"\","
							"\"server_port\" : 38311"
						"}"
					"]"
				"},"
				"{"
					"\"name\" : \"cod.exe\","
					"\"description\" : \"Call Of Duty\","
					"\"display_name\" : \"Call Of Duty Warzone\","
					"\"display_description\" : \"Call Of Duty Black OPS 6 (WARZONE)\","
					"\"protocols\" : ["
						"{"
							"\"name\" : \"tcp\","
							"\"id\" : " C_TO_STRING(NETWORK_TCP_PROTOCOL_ID) ","
							"\"server_host\" : \"\","
							"\"server_port\" : 38310"
						"},"
						"{"
							"\"name\" : \"udp\","
							"\"id\" : " C_TO_STRING(NETWORK_UDP_PROTOCOL_ID) ","
							"\"server_host\" : \"\","
							"\"server_port\" : 38311"
						"}"
					"]"
				"}"
			"]"
		"}"
	);

	void Initialize();
	void Uninitialize();

	void ReadConfigFile();
	void WriteConfigFile(std::string content);

	Utils::PropertyTree& GetConfig();

	std::string GetHttpHost();
	USHORT      GetHttpPort();
	
	std::string GetTcpSocketHost();
	USHORT      GetTcpSocketPort();

	std::string GetUdpSocketHost();
	USHORT      GetUdpSocketPort();
};