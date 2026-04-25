#include "erisdns/dns_server.hpp"
#include "erisdns/dns_parser.hpp"

#include <iostream>
#include <thread>

namespace erisdns {

DnsServer::DnsServer(asio::io_context& io, uint16_t port, RecursiveResolver& resolver)
    : io_(io)
    , port_(port)
    , resolver_(resolver)
    , udp_socket_(io, asio::ip::udp::endpoint(asio::ip::udp::v4(), port))
    , tcp_acceptor_(io, asio::ip::tcp::endpoint(asio::ip::tcp::v4(), port))
{
}

void DnsServer::start()
{
    do_receive_udp();
    do_accept_tcp();
    std::cout << "ErisDNS recursive resolver listening on UDP/TCP port " << port_ << std::endl;
}

void DnsServer::stop()
{
    boost::system::error_code ec;
    udp_socket_.close(ec);
    tcp_acceptor_.close(ec);
}

// ─── UDP ───────────────────────────────────────────────────────────

void DnsServer::do_receive_udp()
{
    auto sender = std::make_shared<asio::ip::udp::endpoint>();
    udp_socket_.async_receive_from(
        asio::buffer(udp_recv_buf_),
        *sender,
        [this, sender](std::error_code ec, size_t n)
        {
            if (!ec && n >= 12)
            {
                Parser  p({udp_recv_buf_.data(), n});
                Message query = p.parse();

                if (query.parse_error)
                {
                    Message err_resp{};
                    err_resp.header.id    = query.header.id;
                    err_resp.header.qr    = true;
                    err_resp.header.rcode = RCode::FORMERR;
                    Serializer ser;
                    send_udp_response(ser.serialize(err_resp), *sender);
                }
                else
                {
                    auto ep = std::make_shared<asio::ip::udp::endpoint>(*sender);
                    resolver_.resolve(std::move(query),
                                      [this, ep](Message resp)
                                      {
                                          Serializer ser;
                                          auto       wire = ser.serialize(resp);
                                          if (wire.size() > 512)
                                          {
                                              resp.header.tc = true;
                                              resp.answers.clear();
                                              resp.authorities.clear();
                                              resp.additionals.clear();
                                              resp.header.ancount = 0;
                                              resp.header.nscount = 0;
                                              resp.header.arcount = 0;
                                              wire = ser.serialize(resp);
                                          }
                                          send_udp_response(std::move(wire), *ep);
                                      });
                }
            }
            do_receive_udp();
        });
}

void DnsServer::send_udp_response(std::vector<uint8_t> response,
                                  asio::ip::udp::endpoint sender)
{
    auto buf = std::make_shared<std::vector<uint8_t>>(std::move(response));
    auto ep  = std::make_shared<asio::ip::udp::endpoint>(std::move(sender));
    udp_socket_.async_send_to(
        asio::buffer(*buf), *ep,
        [buf, ep](std::error_code, size_t) {});
}

// ─── TCP ───────────────────────────────────────────────────────────

void DnsServer::do_accept_tcp()
{
    tcp_acceptor_.async_accept(
        [this](std::error_code ec, asio::ip::tcp::socket peer)
        {
            if (!ec)
            {
                std::thread([this, sock = std::move(peer)]() mutable
                            {
                                handle_tcp_session(std::move(sock));
                            }).detach();
            }
            do_accept_tcp();
        });
}

void DnsServer::handle_tcp_session(asio::ip::tcp::socket sock)
{
    for (;;)
    {
        std::array<uint8_t, 2> len_buf{};
        boost::system::error_code ec;
        asio::read(sock, asio::buffer(len_buf), ec);
        if (ec) break;

        uint16_t msg_len = (static_cast<uint16_t>(len_buf[0]) << 8) | len_buf[1];
        if (msg_len > 65535) break;

        std::vector<uint8_t> msg_buf(msg_len);
        asio::read(sock, asio::buffer(msg_buf), ec);
        if (ec) break;

        Parser  p(msg_buf);
        Message query = p.parse();

        if (query.parse_error)
        {
            Message err_resp{};
            err_resp.header.id    = query.header.id;
            err_resp.header.qr    = true;
            err_resp.header.rcode = RCode::FORMERR;
            Serializer ser;
            send_tcp_response(ser.serialize(err_resp), sock);
        }
        else
        {
            std::promise<Message> prom;
            auto                 fut = prom.get_future();

            resolver_.resolve(std::move(query),
                              [&prom](Message resp)
                              {
                                  prom.set_value(std::move(resp));
                              });

            Message resp = fut.get();
            Serializer ser;
            send_tcp_response(ser.serialize(resp), sock);
        }
    }

    boost::system::error_code ec;
    sock.shutdown(asio::ip::tcp::socket::shutdown_both, ec);
    sock.close(ec);
}

void DnsServer::send_tcp_response(std::vector<uint8_t> response,
                                  asio::ip::tcp::socket& sock)
{
    uint16_t len = static_cast<uint16_t>(response.size());
    std::vector<uint8_t> frame;
    frame.push_back(static_cast<uint8_t>(len >> 8));
    frame.push_back(static_cast<uint8_t>(len & 0xFF));
    frame.insert(frame.end(), response.begin(), response.end());

    asio::write(sock, asio::buffer(frame));
}

} // namespace erisdns
