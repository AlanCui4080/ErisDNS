#pragma once

#include "dns_types.hpp"

#include <chrono>
#include <string>
#include <vector>

namespace erisdns {

struct UpstreamResult
{
    Message         msg;
    bool            success = false;
    std::string     error;
    bool            truncated = false;
};

class UpstreamClient
{
public:
    UpstreamClient() = default;

    // Send a DNS query to a remote server, wait for response
    // Each call uses its own internal io_context (no shared state)
    UpstreamResult query(const Message& query,
                         const std::string& server_addr,
                         uint16_t port = 53,
                         std::chrono::milliseconds timeout = std::chrono::seconds(5));

private:
    UpstreamResult udp_query(const std::vector<uint8_t>& wire,
                             const std::string& server_addr,
                             uint16_t port,
                             std::chrono::milliseconds timeout);

    UpstreamResult tcp_query(const std::vector<uint8_t>& wire,
                             const std::string& server_addr,
                             uint16_t port,
                             std::chrono::milliseconds timeout);
};

} // namespace erisdns
