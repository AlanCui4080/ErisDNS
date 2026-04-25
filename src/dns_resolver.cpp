#include "erisdns/dns_resolver.hpp"

#include <algorithm>
#include <cstring>

namespace erisdns {

static std::string lower(std::string s)
{
    std::ranges::transform(s, s.begin(), [](unsigned char c)
                           { return static_cast<char>(std::tolower(c)); });
    return s;
}

void Resolver::add_record(const std::string& name, QType type, QClass qclass, uint32_t ttl,
                          std::span<const uint8_t> rdata)
{
    ResourceRecord rr;
    rr.name   = lower(name);
    rr.type   = type;
    rr.qclass = qclass;
    rr.ttl    = ttl;
    rr.rdata.assign(rdata.begin(), rdata.end());
    records_[{lower(name), type}].push_back(std::move(rr));
}

void Resolver::add_record(const std::string& name, QType type, uint32_t ttl,
                          std::span<const uint8_t> rdata)
{
    add_record(name, type, QClass::IN, ttl, rdata);
}

Message Resolver::resolve(const Message& query)
{
    Message resp{};
    resp.header.id      = query.header.id;
    resp.header.qr      = true;
    resp.header.opcode  = query.header.opcode;
    resp.header.rd      = query.header.rd;
    resp.header.ra      = false;
    resp.header.aa      = authoritative_;
    resp.header.rcode   = RCode::NOERROR;
    resp.header.qdcount = 0;
    resp.header.ancount = 0;

    if (query.header.opcode != Opcode::QUERY)
    {
        resp.header.rcode = RCode::NOTIMP;
        return resp;
    }

    resp.questions = query.questions;
    resp.header.qdcount = static_cast<uint16_t>(resp.questions.size());

    for (const auto& q : query.questions)
    {
        auto key = std::make_pair(lower(q.qname), q.qtype);
        auto it  = records_.find(key);

        if (it != records_.end())
        {
            for (const auto& rr : it->second)
                resp.answers.push_back(rr);
        }
        else if (q.qtype == QType::ANY)
        {
            auto lb = records_.lower_bound({lower(q.qname), static_cast<QType>(0)});
            while (lb != records_.end() && lb->first.first == lower(q.qname))
            {
                for (const auto& rr : lb->second)
                    resp.answers.push_back(rr);
                ++lb;
            }
        }
    }

    if (resp.answers.empty() && !query.questions.empty())
        resp.header.rcode = RCode::NXDOMAIN;

    resp.header.ancount = static_cast<uint16_t>(resp.answers.size());
    resp.header.nscount = static_cast<uint16_t>(resp.authorities.size());
    resp.header.arcount = static_cast<uint16_t>(resp.additionals.size());

    return resp;
}

} // namespace erisdns
