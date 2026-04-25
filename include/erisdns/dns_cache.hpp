#pragma once

#include "dns_types.hpp"

#include <chrono>
#include <map>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <string>
#include <vector>

namespace erisdns {

using Clock = std::chrono::steady_clock;

struct CacheEntry
{
    std::vector<ResourceRecord> answers;
    std::vector<ResourceRecord> authorities;
    std::vector<ResourceRecord> additionals;
    bool                        nxdomain = false;
    Clock::time_point           expires;
};

class DnsCache
{
public:
    // Store a set of RRs from an authoritative answer
    void put(const std::string& name, QType type, std::vector<ResourceRecord> answers,
             std::vector<ResourceRecord> authorities, std::vector<ResourceRecord> additionals);

    // Store a negative (NXDOMAIN) cache entry
    void put_nxdomain(const std::string& name, uint32_t ttl = 300);

    // Store NS referral information
    void put_ns(const std::string& zone, std::vector<ResourceRecord> ns_rrs,
                std::vector<ResourceRecord> glue);

    // Retrieve cached answer for (name, type)
    std::optional<CacheEntry> get(const std::string& name, QType type);

    // Retrieve cached NS records for a zone
    std::optional<CacheEntry> get_ns(const std::string& zone);

    // Check if a domain name is known to not exist
    bool is_nxdomain(const std::string& name);

    // Check if we have authoritative NS info for a zone (or its parent)
    std::optional<CacheEntry> find_closest_ns(const std::string& name);

    // Clean expired entries
    void cleanup();

private:
    struct Key
    {
        std::string name;
        QType       type;
        auto operator<=>(const Key&) const = default;
    };

    void put_internal(const std::string& name, QType type, std::vector<ResourceRecord> answers,
                      std::vector<ResourceRecord> authorities, std::vector<ResourceRecord> additionals,
                      uint32_t min_ttl);

    mutable std::shared_mutex mutex_;
    std::map<Key, CacheEntry> entries_;
};

} // namespace erisdns
