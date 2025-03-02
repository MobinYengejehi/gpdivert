#pragma once

#define _WIN32_WINNT 0x0600

#include <SimpleWebServer/server_http.hpp>

namespace Network
{
	namespace Http
	{
		using ServerBase = SimpleWeb::Server<SimpleWeb::HTTP>;

		using Request = std::shared_ptr<ServerBase::Request>;
		using Response = std::shared_ptr<ServerBase::Response>;

		void Initialize();
		void Unintialize();

		void SetupHandlers();

		namespace Handlers
		{
#define H_HANDLER(handler) void handler(Response response, Request request)

			H_HANDLER(NotFound);
			H_HANDLER(ServerInfo);
			H_HANDLER(AppList);

#undef H_HANDLER
		}
	};

	std::string GetIpAddress(std::string* hostName = NULL);
};