#include "erisdns/dns_parser.hpp"
#include "erisdns/dns_resolver.hpp"
#include "erisdns/dns_server.hpp"

#include <boost/asio.hpp>

#include <csignal>
#include <iostream>
#include <string>
#include <vector>

using namespace erisdns;

int main(int argc, char* argv[])
{
    uint16_t port = 5353;
    if (argc > 1)
    {
        port = static_cast<uint16_t>(std::stoi(argv[1]));
    }

    asio::io_context io;

    RecursiveResolver resolver(io);

    // ═══ Root Hints (IANA root servers, authoritative for ".") ═══
    resolver.set_root_hints({
        {"a.root-servers.net", "198.41.0.4"},
        {"b.root-servers.net", "170.247.170.2"},
        {"c.root-servers.net", "192.33.4.12"},
        {"d.root-servers.net", "199.7.91.13"},
        {"e.root-servers.net", "192.203.230.10"},
        {"f.root-servers.net", "192.5.5.241"},
        {"g.root-servers.net", "192.112.36.4"},
        {"h.root-servers.net", "198.97.190.53"},
        {"i.root-servers.net", "192.36.148.17"},
        {"j.root-servers.net", "192.58.128.30"},
        {"k.root-servers.net", "193.0.14.129"},
        {"l.root-servers.net", "199.7.83.42"},
        {"m.root-servers.net", "202.12.27.33"},
    });

    // ═══ Upstream Forwarder (bypass root recursion) ═══
    // Specify via command line: erisdns <port> <upstream_ip>
    std::string upstream_ip = "192.168.5.252";
    if (argc > 2)
    {
        upstream_ip = argv[2];
    }
    resolver.set_forwarder(upstream_ip);

    // ═══ Optional: local authoritative zones ═══
    resolver.add_zone("example.local", QType::A, 300, std::vector<uint8_t>{192, 168, 1, 100});
    resolver.add_zone("example6.local", QType::AAAA, 300,
                      std::vector<uint8_t>{0xfd, 0x00, 0,0,0,0,0,0, 0,0,0,0,0,0,0,1});

    DnsServer server(io, port, resolver);
    server.start();

    asio::signal_set signals(io, SIGINT, SIGTERM);
    signals.async_wait([&](std::error_code, int)
                       {
                           std::cout << "\nShutting down..." << std::endl;
                           server.stop();
                           io.stop();
                       });

    io.run();

    return 0;
}
