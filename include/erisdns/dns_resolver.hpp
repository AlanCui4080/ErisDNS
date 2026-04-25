#pragma once

#include "dns_types.hpp"

#include <map>
#include <string>
#include <vector>

namespace erisdns {

class Resolver
{
public:
    void add_record(const std::string& name, QType type, QClass qclass, uint32_t ttl,
                    std::span<const uint8_t> rdata);
    void add_record(const std::string& name, QType type, uint32_t ttl, std::span<const uint8_t> rdata);

    Message resolve(const Message& query);

    void set_authoritative(bool v) { authoritative_ = v; }

private:
    using RecordKey = std::pair<std::string, QType>;
    std::map<RecordKey, std::vector<ResourceRecord>> records_;
    bool authoritative_ = true;
};

} // namespace erisdns
