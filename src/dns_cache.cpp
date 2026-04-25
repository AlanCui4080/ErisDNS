#include "erisdns/dns_cache.hpp"

#include <algorithm>
#include <ranges>

namespace erisdns {

static std::string lower(std::string s)
{
    std::ranges::transform(s, s.begin(),
                           [](unsigned char c)
                           { return static_cast<char>(std::tolower(c)); });
    return s;
}

static uint32_t min_ttl_of(const std::vector<ResourceRecord>& rrs)
{
    uint32_t t = 0;
    for (auto& rr : rrs)
    {
        if (t == 0 || rr.ttl < t) t = rr.ttl;
    }
    return t;
}

void DnsCache::put(const std::string& name, QType type,
                   std::vector<ResourceRecord> answers,
                   std::vector<ResourceRecord> authorities,
                   std::vector<ResourceRecord> additionals)
{
    uint32_t ttl = min_ttl_of(answers);
    if (ttl == 0) ttl = 300;
    if (auto a_ttl = min_ttl_of(authorities); a_ttl > 0 && a_ttl < ttl) ttl = a_ttl;
    if (auto ad_ttl = min_ttl_of(additionals); ad_ttl > 0 && ad_ttl < ttl) ttl = ad_ttl;
    put_internal(name, type, std::move(answers), std::move(authorities), std::move(additionals), ttl);
}

void DnsCache::put_nxdomain(const std::string& name, uint32_t ttl)
{
    put_internal(name, QType::A, {}, {}, {}, ttl);
}

void DnsCache::put_ns(const std::string& zone, std::vector<ResourceRecord> ns_rrs,
                      std::vector<ResourceRecord> glue)
{
    uint32_t ttl = min_ttl_of(ns_rrs);
    if (ttl == 0) ttl = 3600;
    if (auto g_ttl = min_ttl_of(glue); g_ttl > 0 && g_ttl < ttl) ttl = g_ttl;
    put_internal(zone, QType::NS, std::move(ns_rrs), {}, std::move(glue), ttl);
}

void DnsCache::put_internal(const std::string& name, QType type,
                            std::vector<ResourceRecord> answers,
                            std::vector<ResourceRecord> authorities,
                            std::vector<ResourceRecord> additionals,
                            uint32_t min_ttl)
{
    CacheEntry e;
    e.answers     = std::move(answers);
    e.authorities = std::move(authorities);
    e.additionals = std::move(additionals);
    e.nxdomain    = e.answers.empty() && e.authorities.empty();
    e.expires     = Clock::now() + std::chrono::seconds(min_ttl);

    Key key{lower(name), type};
    std::unique_lock lock(mutex_);
    entries_[key] = std::move(e);
}

std::optional<CacheEntry> DnsCache::get(const std::string& name, QType type)
{
    Key key{lower(name), type};
    std::shared_lock lock(mutex_);
    auto it = entries_.find(key);
    if (it == entries_.end()) return std::nullopt;
    if (Clock::now() > it->second.expires)
    {
        lock.unlock();
        std::unique_lock wlock(mutex_);
        entries_.erase(key);
        return std::nullopt;
    }
    return it->second;
}

std::optional<CacheEntry> DnsCache::get_ns(const std::string& zone)
{
    return get(zone, QType::NS);
}

bool DnsCache::is_nxdomain(const std::string& name)
{
    for (auto t : {QType::A, QType::AAAA})
    {
        auto e = get(name, t);
        if (e && e->nxdomain) return true;
    }
    return false;
}

std::optional<CacheEntry> DnsCache::find_closest_ns(const std::string& name)
{
    std::string key = lower(name);
    for (;;)
    {
        auto ns = get_ns(key);
        if (ns) return ns;

        auto dot = key.find('.');
        if (dot == std::string::npos) break;
        key = key.substr(dot + 1);
    }
    return std::nullopt;
}

void DnsCache::cleanup()
{
    std::unique_lock lock(mutex_);
    auto now = Clock::now();
    std::erase_if(entries_, [now](const auto& kv)
                  { return kv.second.expires <= now; });
}

} // namespace erisdns
