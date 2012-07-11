#include "stdio.h"
#include <iostream>
#include <string>
#include <vector>

#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <boost/make_shared.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/enable_shared_from_this.hpp>
#include <boost/thread.hpp>
#include <boost/timer.hpp>
#include <boost/program_options/parsers.hpp>
#include <boost/program_options/variables_map.hpp>
#include <boost/lexical_cast.hpp>

#include "shared/silkroad_security.h"
#include "shared/stream_utility.h"

boost::shared_ptr<boost::asio::io_service> io_service;
std::string server = "";
uint16_t port = 15779;
uint16_t connections = 50;

#define DATA_MAX_SIZE 4096

boost::asio::ip::tcp::resolver::iterator resolve(const std::string & ip, const std::string & port)
{
	boost::system::error_code ec;

	//Resolve IPv6 first
	boost::asio::ip::tcp::resolver resolver(*io_service);
	boost::asio::ip::tcp::resolver::query query(boost::asio::ip::tcp::v6(), ip, port);
	boost::asio::ip::tcp::resolver::iterator result = resolver.resolve(query, ec);

	if(ec)
	{
		//IPv4
		boost::asio::ip::tcp::resolver::query query(boost::asio::ip::tcp::v4(), ip, port);
		result = resolver.resolve(query, ec);
	}

	return result;
}

class SilkroadClient : public boost::enable_shared_from_this<SilkroadClient>
{
private:

	boost::shared_ptr<boost::asio::ip::tcp::socket> s;
	std::vector<uint8_t> data;
	boost::asio::strand strand;
	SilkroadSecurity security;

	boost::shared_ptr<boost::asio::deadline_timer> timer;

	void Close()
	{
		boost::system::error_code ec;

		if(s)
		{
			std::cout << "Connection closed" << std::endl;

			s->shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
			s->close(ec);
			s.reset();
		}
	}

	void HandleRead(size_t bytes_transferred, const boost::system::error_code & error)
	{
		if(error)
		{
			Close();
		}
		else
		{
			security.Recv(&data[0], bytes_transferred);
			PostRead();
		}
	}

	void PostRead()
	{
		s->async_read_some(boost::asio::buffer(&data[0], DATA_MAX_SIZE), strand.wrap(boost::bind(&SilkroadClient::HandleRead, shared_from_this(), boost::asio::placeholders::bytes_transferred, boost::asio::placeholders::error)));
	}

	bool Send(boost::shared_ptr<boost::asio::ip::tcp::socket> socket, std::vector<uint8_t> packet)
	{
		if(!socket) return false;

		boost::system::error_code ec;
		boost::asio::write(*socket, boost::asio::buffer(&packet[0], packet.size()), boost::asio::transfer_all(), ec);

		if(ec)
		{
			strand.post(boost::bind(&SilkroadClient::Close, shared_from_this()));
			return false;
		}

		return true;
	}

	void OnTimer(const boost::system::error_code & error)
	{
		if(!error && s)
		{
			security.Send(0x6101, 0, 0, 1, 0);

			timer->expires_from_now(boost::posix_time::seconds(1));
			timer->async_wait(strand.wrap(boost::bind(&SilkroadClient::OnTimer, shared_from_this(), boost::asio::placeholders::error)));
		}
	}

public:

	//Constructor
	SilkroadClient() : strand(*io_service)
	{
	}

	//Destructor
	~SilkroadClient()
	{
	}

	//Initializes the class
	bool Initialize()
	{
		//Initialize data
		data.resize(DATA_MAX_SIZE + 1);

		//Create a new socket
		s = boost::make_shared<boost::asio::ip::tcp::socket>(*io_service);

		//Connect to the server
		boost::system::error_code ec;
		s->connect(*resolve(server, boost::lexical_cast<std::string>(port)), ec);
		if(ec) return false;

		//Disable nagle
		s->set_option(boost::asio::ip::tcp::no_delay(true));

		PostRead();

		return true;
	}

	bool Process()
	{
		if(!s) return false;

		while(security.HasPacketToRecv())
		{
			PacketContainer packet = security.GetPacketToRecv();
			const uint16_t & opcode = packet.opcode;
			StreamUtility & r = packet.data;

			/*std::cout << "[Joymax][" << std::hex << std::setfill('0') << std::setw(4) << packet.opcode << "][" << std::dec << packet.data.GetReadStreamSize() << "]" << std::endl;
			std::cout << DumpToString(packet.data) << std::endl << std::endl;*/

			if(opcode == 0x2001)
			{
				StreamUtility w;
				w.Write<uint8_t>(22);
				w.Write<uint16_t>(9);
				w.Write_Ascii("SR_Client");
				w.Write<uint32_t>(123);
				security.Send(0x6100, w, 1, 0);
			}
			else if(opcode == 0xA100)
			{
				if(r.Read<uint8_t>() != 1)
				{
					std::cout << "Version is out of date" << std::endl;
				}

				security.Send(0x6101, 0, 0, 1, 0);

				timer = boost::make_shared<boost::asio::deadline_timer>(*io_service);
				timer->expires_from_now(boost::posix_time::seconds(1));
				timer->async_wait(strand.wrap(boost::bind(&SilkroadClient::OnTimer, shared_from_this(), boost::asio::placeholders::error)));
			}
		}

		while(security.HasPacketToSend())
			Send(s, security.GetPacketToSend());

		return true;
	}
};
std::vector<boost::shared_ptr<SilkroadClient> > clients;

void Timer(boost::shared_ptr<boost::asio::deadline_timer> timer, const boost::system::error_code & error)
{
	if(!error)
	{
		//Iterate all clients
		std::vector<boost::shared_ptr<SilkroadClient> >::iterator itr = clients.begin();
		while(itr != clients.end())
		{
			//Process packets
			if(!(*itr)->Process())
				//Client is no longer connected so remove it from the vector
				itr = clients.erase(itr);
			else
				++itr;
		}

		timer->expires_from_now(boost::posix_time::milliseconds(10));
		timer->async_wait(boost::bind(&Timer, timer, boost::asio::placeholders::error));
	}
}

void WorkerThread(boost::shared_ptr<boost::asio::io_service> io_service)
{
	boost::system::error_code ec;

	while(true)
	{
		try
		{
			io_service->run(ec);

			if(ec)
			{
				std::cout << "[" << __FUNCTION__ << "]" << "[" << __LINE__ << "] " << ec.message() << std::endl;
			}
			else
			{
				break;
			}
			
			//Prevent high CPU usage
			boost::this_thread::sleep(boost::posix_time::milliseconds(1));
		}
		catch(std::exception & e)
		{
			std::cout << "[" << __FUNCTION__ << "][" << __LINE__ << "] " << e.what() << std::endl;
		}
	}
}

int main(int argc, char* argv[])
{
	io_service = boost::make_shared<boost::asio::io_service>();
	int32_t threads = static_cast<int32_t>(boost::thread::hardware_concurrency()) - 1;

	//Command line args
	boost::program_options::options_description desc;
	desc.add_options()
		("help", "Displays help menu")
		("server", boost::program_options::value<std::string>(), "Sets the gateway IP")
		("port", boost::program_options::value<uint16_t>(), "Sets the gateway port")
		("connections", boost::program_options::value<uint16_t>(), "Sets the number of connections")
		("threads", boost::program_options::value<int32_t>(), "Sets the thread count");

	boost::program_options::variables_map vm;
	boost::program_options::store(boost::program_options::command_line_parser(argc, argv).options(desc).allow_unregistered().run(), vm);
	boost::program_options::notify(vm);

	if(vm.count("help"))
	{
		std::cout << desc;
		return 0;
	}

	if(!vm.count("server") || !vm.count("port"))
	{
		std::cout << "Missing --server and --port" << std::endl << "Run with --help for a list of arguments" << std::endl;
		return 0;
	}

	if(vm.count("threads"))
		threads = vm["threads"].as<int32_t>() - 1;
	if(vm.count("connections"))
		connections = vm["connections"].as<uint16_t>();

	server = vm["server"].as<std::string>();
	port = vm["port"].as<uint16_t>();

	//Create worker threads
	for(int32_t x = 0; x < threads; ++x)
	{
		boost::thread(boost::bind(&WorkerThread, io_service));
	}

	//Packet processing timer
	boost::shared_ptr<boost::asio::deadline_timer> timer = boost::make_shared<boost::asio::deadline_timer>(*io_service);
	timer->expires_from_now(boost::posix_time::milliseconds(10));
	timer->async_wait(boost::bind(&Timer, timer, boost::asio::placeholders::error));

	for(uint16_t x = 0; x < connections; ++x)
	{
		boost::shared_ptr<SilkroadClient> client(boost::make_shared<SilkroadClient>());
		if(!client->Initialize()) return 1;
		clients.push_back(client);

		boost::this_thread::sleep(boost::posix_time::milliseconds(1));
	}

	WorkerThread(io_service);
	return 0;
}