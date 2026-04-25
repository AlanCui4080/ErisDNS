#include "erisdns/dns_upstream.hpp"
#include "erisdns/dns_parser.hpp"

#include <boost/asio.hpp>

namespace erisdns {

namespace asio = boost::asio;

UpstreamResult UpstreamClient::query(const Message& query,
                                     const std::string& server_addr,
                                     uint16_t port,
                                     std::chrono::milliseconds timeout)
{
    Serializer            ser;
    std::vector<uint8_t>  wire = ser.serialize(query);

    auto result = udp_query(wire, server_addr, port, timeout);

    if (result.truncated)
    {
        auto tcp_result = tcp_query(wire, server_addr, port, timeout);
        if (tcp_result.success) return tcp_result;
    }

    return result;
}

UpstreamResult UpstreamClient::udp_query(const std::vector<uint8_t>& wire,
                                         const std::string& server_addr,
                                         uint16_t port,
                                         std::chrono::milliseconds timeout)
{
    UpstreamResult result;
    boost::system::error_code ec;

    try
    {
        asio::io_context io;

        asio::ip::udp::resolver resolver(io);
        auto endpoints = resolver.resolve(server_addr, std::to_string(port), ec);
        if (ec)
        {
            result.error = "resolve failed: " + ec.message();
            return result;
        }

        asio::ip::udp::socket sock(io);
        sock.open(asio::ip::udp::v4());

        // Send
        for (auto& ep : endpoints)
        {
            sock.send_to(asio::buffer(wire), ep, 0, ec);
            if (!ec) break;
        }
        if (ec)
        {
            result.error = "send failed: " + ec.message();
            return result;
        }

        // Receive with timeout
        std::vector<uint8_t>  buf(65535);
        asio::ip::udp::endpoint from;

        sock.async_receive_from(
            asio::buffer(buf),
            from,
            [&](boost::system::error_code e, size_t n)
            {
                ec = e;
                buf.resize(n);
            });

        io.run_for(timeout);

        if (!io.stopped())
        {
            sock.cancel();
            io.run();
            result.error = "timeout";
            return result;
        }

        if (ec)
        {
            result.error = "recv failed: " + ec.message();
            return result;
        }

        Parser p(buf);
        result.msg = p.parse();

        if (result.msg.parse_error)
        {
            result.error = "parse error: " + result.msg.error_msg;
            return result;
        }

        result.success   = true;
        result.truncated = result.msg.header.tc;
    }
    catch (std::exception& e)
    {
        result.error = std::string("exception: ") + e.what();
    }

    return result;
}

UpstreamResult UpstreamClient::tcp_query(const std::vector<uint8_t>& wire,
                                         const std::string& server_addr,
                                         uint16_t port,
                                         std::chrono::milliseconds timeout)
{
    UpstreamResult result;
    boost::system::error_code ec;

    try
    {
        asio::io_context io;

        asio::ip::tcp::resolver resolver(io);
        auto endpoints = resolver.resolve(server_addr, std::to_string(port), ec);
        if (ec)
        {
            result.error = "TCP resolve failed: " + ec.message();
            return result;
        }

        asio::ip::tcp::socket sock(io);
        bool connected = false;

        for (auto& ep : endpoints)
        {
            sock.async_connect(ep, [&](boost::system::error_code e)
                               { ec = e; connected = true; });
            io.run_for(timeout);
            if (!io.stopped()) { sock.cancel(); io.run(); result.error = "TCP connect timeout"; return result; }
            if (!ec) break;
            sock.close();
            sock = asio::ip::tcp::socket(io);
        }

        if (ec)
        {
            result.error = "TCP connect failed: " + ec.message();
            return result;
        }

        // Send 2-byte length prefix + message
        uint16_t len = static_cast<uint16_t>(wire.size());
        std::vector<uint8_t> frame;
        frame.push_back(static_cast<uint8_t>(len >> 8));
        frame.push_back(static_cast<uint8_t>(len & 0xFF));
        frame.insert(frame.end(), wire.begin(), wire.end());

        {
            size_t sent = 0;
            bool   done = false;
            sock.async_send(asio::buffer(frame), [&](boost::system::error_code e, size_t n)
                            { ec = e; sent = n; done = true; });
            io.restart(); io.run_for(timeout);
            if (!io.stopped()) { sock.cancel(); io.run(); result.error = "TCP send timeout"; return result; }
            if (ec) { result.error = "TCP send failed: " + ec.message(); return result; }
        }

        // Read 2-byte length prefix
        uint8_t lb[2];
        {
            bool done = false;
            asio::async_read(sock, asio::buffer(lb), [&](boost::system::error_code e, size_t)
                             { ec = e; done = true; });
            io.restart(); io.run_for(timeout);
            if (!io.stopped()) { sock.cancel(); io.run(); result.error = "TCP recv len timeout"; return result; }
            if (ec) { result.error = "TCP recv len failed: " + ec.message(); return result; }
        }

        uint16_t resp_len = (static_cast<uint16_t>(lb[0]) << 8) | lb[1];
        if (resp_len > 65535) { result.error = "TCP invalid response length"; return result; }

        std::vector<uint8_t> resp(resp_len);
        {
            bool done = false;
            asio::async_read(sock, asio::buffer(resp), [&](boost::system::error_code e, size_t)
                             { ec = e; done = true; });
            io.restart(); io.run_for(timeout);
            if (!io.stopped()) { sock.cancel(); io.run(); result.error = "TCP recv data timeout"; return result; }
            if (ec) { result.error = "TCP recv data failed: " + ec.message(); return result; }
        }

        sock.close();

        Parser p(resp);
        result.msg     = p.parse();
        result.success = !result.msg.parse_error;
        if (!result.success) result.error = "TCP parse error: " + result.msg.error_msg;
    }
    catch (std::exception& e)
    {
        result.error = std::string("TCP exception: ") + e.what();
    }

    return result;
}

} // namespace erisdns
