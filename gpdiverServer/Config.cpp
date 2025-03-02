#include "Utils.h"

#include <filesystem>

#include "Config.h"

Utils::PropertyTree ConfigTree;

void Config::Initialize()
{
	L_INFO << "Config initlaizing..." << L_END;

	ReadConfigFile();

	L_INFO << "Config initialized" << L_END;
}

void Config::Uninitialize()
{
	L_INFO << "Config Uninitialized" << L_END;
}

void Config::ReadConfigFile()
{
	std::string currentDirectory = Utils::Path::GetApplicationDirectory();
	std::string filePath = Utils::Path::Join(currentDirectory, { DEFAULT_CONFIG_FILE_NAME });

	if (!Utils::File::Exists(filePath))
	{
		Utils::PTreeReadJson(ConfigTree, DefaultConfigData);

		WriteConfigFile(DefaultConfigData);

		return;
	}

	std::string data = Utils::File::Read(filePath);

	ConfigTree.clear();

	Utils::PTreeReadJson(ConfigTree, data);
}

void Config::WriteConfigFile(std::string data)
{
	std::string currentDirectory = Utils::Path::GetApplicationDirectory();
	std::string filePath = Utils::Path::Join(currentDirectory, { DEFAULT_CONFIG_FILE_NAME });

	Utils::File::Write(filePath, data, true);
}

Utils::PropertyTree& Config::GetConfig()
{
	return ConfigTree;
}

std::string Config::GetHttpHost()
{
	return Utils::PTreeGetItem<std::string>(ConfigTree, "http_host", "0.0.0.0");
}

USHORT Config::GetHttpPort()
{
	return Utils::PTreeGetItem<USHORT>(ConfigTree, "http_port", 38309);
}

std::string Config::GetTcpSocketHost()
{
	return Utils::PTreeGetItem<std::string>(ConfigTree, "tcp_socket_host", "0.0.0.0");
}

USHORT Config::GetTcpSocketPort()
{
	return Utils::PTreeGetItem<USHORT>(ConfigTree, "tcp_socket_port", 38310);
}

std::string Config::GetUdpSocketHost()
{
	return Utils::PTreeGetItem<std::string>(ConfigTree, "udp_socket_host", "0.0.0.0");
}

USHORT Config::GetUdpSocketPort()
{
	return Utils::PTreeGetItem<USHORT>(ConfigTree, "udp_socket_port", 38311);
}