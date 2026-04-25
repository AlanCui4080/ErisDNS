#pragma once

#include "dns_recursive.hpp"

#include <boost/asio.hpp>

#include <array>
#include <vector>

namespace erisdns {

namespace asio = boost::asio;

class DnsServer
{
public:
    DnsServer(asio::io_context& io, uint16_t port, RecursiveResolver& resolver);

    void start();
    void stop();

private:
    void do_receive_udp();
    void do_accept_tcp();
    void handle_tcp_session(asio::ip::tcp::socket sock);

    void send_udp_response(std::vector<uint8_t> response,
                           asio::ip::udp::endpoint sender);

    void send_tcp_response(std::vector<uint8_t> response,
                           asio::ip::tcp::socket& sock);

    asio::io_context&          io_;
    uint16_t                   port_;
    RecursiveResolver&         resolver_;
    asio::ip::udp::socket      udp_socket_;
    asio::ip::tcp::acceptor    tcp_acceptor_;
    std::array<uint8_t, 4096>  udp_recv_buf_;
};

} // namespace erisdns
