#include "HttpServer.h"

#include "Utils.h"
#include "Config.h"
#include "SocketServer.h"

#include <sstream>

#include <boost/asio.hpp>

Network::Http::ServerBase* Server = NULL;

void Network::Http::Initialize()
{
	L_INFO << "Starting HTTP Server..." << L_END;

	Server = new Network::Http::ServerBase();

	Server->config.address = Config::GetHttpHost();
	Server->config.port = Config::GetHttpPort();

	SetupHandlers();

	L_INFO << "HTTP server started on 'http://" << Server->config.address << ":" << Server->config.port << "/'." << L_END;

	Server->start();
}

void Network::Http::Unintialize()
{
	if (Server)
	{
		delete Server;
	}

	Server = NULL;
}

void Network::Http::SetupHandlers()
{
	Server->default_resource["GET"] = Handlers::NotFound;

	Server->resource["^/serverinfo$"]["GET"] = Handlers::ServerInfo;
	Server->resource["^/applist$"]["GET"] = Handlers::AppList;
}

#define H Network::Http::Handlers::

#define H_CODE SimpleWeb::StatusCode

void H NotFound(Response response, Request request)
{
	std::ostringstream result;

	result << "Not Found";

	response->write(H_CODE::client_error_not_found, result.str());
}

void H ServerInfo(Response response, Request request)
{
	Utils::PropertyTree  tree;

	H_CODE             resultCode = H_CODE::success_ok;
	std::ostringstream result;

	Utils::PTreeSetItem<std::string, bool>(tree, "success", true);
	
	try
	{
		std::string hostname = "";
		std::string ipv4Address = GetIpAddress(&hostname);

		if (ipv4Address.empty())
		{
			throw std::exception("Couldn't find IPv4 address.");
		}

		Utils::PTreeSetItem<std::string, std::string>(tree, "host_name", hostname);
		Utils::PTreeSetItem<std::string, std::string>(tree, "host_mac_address", GetMacAddress());
		Utils::PTreeSetItem<std::string, std::string>(tree, "http_host", ipv4Address);
		Utils::PTreeSetItem<std::string, USHORT>(tree, "http_port", Config::GetHttpPort());
		Utils::PTreeSetItem<std::string, std::string>(tree, "tcp_socket_host", ipv4Address);
		Utils::PTreeSetItem<std::string, std::string>(tree, "tcp_choosen_socket_host", Config::GetTcpSocketHost());
		Utils::PTreeSetItem<std::string, USHORT>(tree, "tcp_socket_port", Config::GetTcpSocketPort());
		Utils::PTreeSetItem<std::string, std::string>(tree, "udp_socket_host", ipv4Address);
		Utils::PTreeSetItem<std::string, std::string>(tree, "udp_choosen_socket_host", Config::GetUdpSocketHost());
		Utils::PTreeSetItem<std::string, USHORT>(tree, "udp_socket_port", Config::GetUdpSocketPort());
	}
	catch (const std::exception& exception)
	{
		Utils::PTreeSetItem<std::string, bool>(tree, "success", false);
		Utils::PTreeSetItem<std::string, std::string>(tree, "message", exception.what());
	}

	result << Utils::PTreeToJson(tree);

	response->write(resultCode, result.str());
}

void H AppList(Response response, Request request)
{
	Utils::PropertyTree& configTree = Config::GetConfig();
	Utils::PropertyTree  tree;

	std::ostringstream result;

	Utils::PTreeSetItem<std::string, bool>(tree, "success", true);

	tree.put_child("applications", configTree.get_child("applications"));

	result << Utils::PTreeToJson(tree);

	response->write(H_CODE::success_ok, result.str());
}

std::string Network::GetIpAddress(std::string* hostName)
{
	boost::asio::io_context ioContext;

	std::string hostname = boost::asio::ip::host_name();

	if (hostName != NULL)
	{
		*hostName = hostname;
	}

	boost::asio::ip::tcp::resolver               resolver(ioContext);
	boost::asio::ip::tcp::resolver::results_type endpoints = resolver.resolve(hostname, "");

	std::string ipv4Address = "";

	for (const auto& endpoint : endpoints)
	{
		auto address = endpoint.endpoint().address();

		if (address.is_v4())
		{
			ipv4Address = address.to_string();
			break;
		}
	}

	return ipv4Address;
}

#undef H_CODE

#undef H