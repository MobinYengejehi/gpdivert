#pragma once

#define _WIN32_WINNT 0x0600

#include <string>
#include <vector>
#include <unordered_map>

#include <Windows.h>

#include <SimpleWebServer/client_http.hpp>

#include "Process.h"

#include "SharedNetwork.h"

namespace Network
{
	using InfoList = std::vector<class Info>;
	using NetworkInfoMap = std::unordered_map<Process::ProcessName, InfoList*>;

	using MacAddress = BYTE[6];

	enum NetworkLayer : BYTE
	{
		Unknown,
		TCP,
		UDP
	};

	class Info
	{
	public:
		Info();
		Info(std::string localAddress, std::string remoteAddress, PortNumber localPort, PortNumber remotePort, NetworkLayer layer = NetworkLayer::TCP);
		Info(DWORD localAddress, DWORD remoteAddress, DWORD localPort, DWORD remotePort, NetworkLayer layer = NetworkLayer::TCP);
		~Info();

		std::string&       GetLocalAddress();
		const std::string& GetLocalAddress() const;

		std::string& GetRemoteAddress();
		const std::string& GetRemoteAddress() const;

		PortNumber&       GetLocalPort();
		const PortNumber& GetLocalPort() const;

		PortNumber&       GetRemotePort();
		const PortNumber& GetRemotePort() const;

		NetworkLayer& GetNetworkLayer();
		const NetworkLayer& GetNetworkLayer() const;

		bool IsLocalVaild() const;
		bool IsRemoteValid() const;
		bool IsUDP() const;

		operator std::string() const;

	private:
		std::string m_strLocalAddress;
		std::string m_strRemoteAddress;
		PortNumber  m_nLocalPort;
		PortNumber  m_nRemotePort;
		
		NetworkLayer m_eNetworkLayer;
	};

	namespace Http
	{
		using ClientRequest = SimpleWeb::Client<SimpleWeb::HTTP>;

		using FetchProgressHandler = void (*)(double progress, size_t bytesRecieved, size_t totalBytes);

		std::string Fetch(std::string host, std::string path = "/", std::string method = "GET", FetchProgressHandler progressHandler = NULL);
	}
	
	namespace PacketManager
	{
		void Initialize();
		void Uninitialize();

		void PacketListener();
	};

	void Initialize();
	void Uninitialize();

	bool IsReady();
	void WaitTillBeReady();

	void ProcessNetworkInfoUpdater();

	NetworkInfoMap& GetNetworkInfoMap();

	void      UpdateNetworkInfoList(Process::ProcessName processName, Process::ProcessId processId = NULL);
	void      ClearNetworkInfoList(Process::ProcessName processName);
	void      DeleteNetworkInfoList(Process::ProcessName processName);
	bool      ExistsNetworkInfoMap(Process::ProcessName processName);
	InfoList* GetNetworkInfoList(Process::ProcessName processName);

	Process::ProcessName FindPortProcess(PortNumber port, NetworkLayer* layer = NULL);
	bool                 DoesProcessOwnPort(Process::ProcessName processName, PortNumber port, NetworkLayer* layer = NULL);
	
	void ClearNetworkInfoMap();

	void SetServerHost(std::string host);
};