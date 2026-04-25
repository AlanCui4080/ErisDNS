#pragma once

#include "dns_cache.hpp"
#include "dns_types.hpp"
#include "dns_upstream.hpp"

#include <boost/asio.hpp>

#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace erisdns {

namespace asio = boost::asio;

struct NameserverInfo
{
    std::string name;
    std::string addr;
};

class RecursiveResolver
{
public:
    explicit RecursiveResolver(asio::io_context& io);

    void set_root_hints(std::vector<NameserverInfo> roots);

    // Set a single upstream forwarder (bypass root-hint recursion)
    void set_forwarder(const std::string& addr, uint16_t port = 53);

    // Async recursive resolve
    void resolve(Message query, std::function<void(Message)> callback);

    // Sync wrapper for tests
    Message resolve_sync(const Message& query);

    // Add local authoritative zone data
    void add_zone(const std::string& name, QType type, QClass qclass, uint32_t ttl,
                  std::span<const uint8_t> rdata);
    void add_zone(const std::string& name, QType type, uint32_t ttl,
                  std::span<const uint8_t> rdata);

private:
    struct ResolutionState
    {
        Message                                 original_query;
        std::function<void(Message)>            callback;
        std::string                             current_qname;
        QType                                   current_qtype;
        std::vector<ResourceRecord>             cname_chain;
        std::vector<NameserverInfo>             nameservers;
        size_t                                  ns_index = 0;
        int                                     iteration = 0;
        static constexpr int                    MAX_ITERATIONS = 30;
        std::chrono::milliseconds               timeout = std::chrono::seconds(5);
    };

    void continue_resolution(std::shared_ptr<ResolutionState> state);
    void handle_response(std::shared_ptr<ResolutionState> state, UpstreamResult result);
    void follow_cname(std::shared_ptr<ResolutionState> state, const std::string& target);
    void start_from_root(std::shared_ptr<ResolutionState> state);
    Message build_response(std::shared_ptr<ResolutionState> state, RCode rcode);
    static void extract_nameserver_ips(const std::vector<ResourceRecord>& rrs,
                                       std::vector<NameserverInfo>& out);

    asio::io_context&           io_;
    UpstreamClient              upstream_;
    DnsCache                    cache_;
    std::vector<NameserverInfo> root_hints_;
    std::map<std::string, std::vector<ResourceRecord>> zones_;
    bool                        use_forwarder_ = false;
    NameserverInfo              forwarder_;
};

} // namespace erisdns
