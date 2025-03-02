#include "Utils.h"

#include <thread>

#include "Config.h"
#include "HttpServer.h"
#include "SocketServer.h"

int main(int argc, char** argv)
{
	std::cout <<
		" d888b  d8888b. .d8888 .d88888b d8888b. db    db d88888b d8888b. \n"
		"88' Y8b 88  `8D 88'  YP 88'     88  `8D 88    88 88'     88  `8D \n"
		"88      88oodD' `8bo.   88ooooo 88oobY' Y8    8P 88ooooo 88oobY' \n"
		"88  ooo 88~~~     `Y8b. 88~~~~~ 88`8b   `8b  d8' 88~~~~~ 88`8b   \n"
		"88. ~8~ 88      db   8D 88.     88 `88.  `8bd8'  88.     88 `88. \n"
		" Y888P  88      `8888Y' Y88888P 88   YD    YP    Y88888P 88   YD \n"
		<< std::endl;

	Config::Initialize();

	std::thread httpServerThread(Network::Http::Initialize);

	Sleep(100);

	std::thread socketServerThread(Network::SocketServer::Initialize);

	httpServerThread.join();
	socketServerThread.join();

	Network::SocketServer::Uninitialize();
	Network::Http::Unintialize();

	Config::Uninitialize();

	return EXIT_SUCCESS;
}