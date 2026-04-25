#include "erisdns/dns_recursive.hpp"
#include "erisdns/dns_parser.hpp"

#include <algorithm>
#include <boost/asio/post.hpp>
#include <thread>

namespace erisdns {

static std::string lower(std::string s)
{
    std::ranges::transform(s, s.begin(), [](unsigned char c)
                           { return static_cast<char>(std::tolower(c)); });
    return s;
}

static std::string label_to_name(const std::vector<uint8_t>& raw)
{
    std::string result;
    size_t      pos = 0;
    while (pos < raw.size())
    {
        uint8_t len = raw[pos++];
        if (len == 0) break;
        if (len > 63) break;
        if (!result.empty()) result += '.';
        result.append(reinterpret_cast<const char*>(raw.data() + pos), len);
        pos += len;
    }
    return result;
}

RecursiveResolver::RecursiveResolver(asio::io_context& io)
    : io_(io)
{
}

void RecursiveResolver::set_root_hints(std::vector<NameserverInfo> roots)
{
    root_hints_ = std::move(roots);
}

void RecursiveResolver::set_forwarder(const std::string& addr, uint16_t port)
{
    use_forwarder_ = true;
    forwarder_     = {"forwarder", addr};
    forwarder_.addr = addr; // use addr directly
    (void)port;
}

void RecursiveResolver::add_zone(const std::string& name, QType type, QClass qclass, uint32_t ttl,
                                 std::span<const uint8_t> rdata)
{
    ResourceRecord rr;
    rr.name   = lower(name);
    rr.type   = type;
    rr.qclass = qclass;
    rr.ttl    = ttl;
    rr.rdata.assign(rdata.begin(), rdata.end());
    zones_[lower(name)].push_back(std::move(rr));
}

void RecursiveResolver::add_zone(const std::string& name, QType type, uint32_t ttl,
                                 std::span<const uint8_t> rdata)
{
    add_zone(name, type, QClass::IN, ttl, rdata);
}

void RecursiveResolver::resolve(Message query, std::function<void(Message)> callback)
{
    auto state     = std::make_shared<ResolutionState>();
    state->original_query = std::move(query);
    state->callback       = std::move(callback);
    state->current_qname  = state->original_query.questions.empty()
                                ? ""
                                : lower(state->original_query.questions[0].qname);
    state->current_qtype  = state->original_query.questions.empty()
                                ? QType::A
                                : state->original_query.questions[0].qtype;

    if (state->current_qname.empty())
    {
        state->callback(build_response(state, RCode::NOERROR));
        return;
    }

    // 1. Check local zones
    auto z_it = zones_.find(state->current_qname);
    if (z_it != zones_.end())
    {
        Message resp = build_response(state, RCode::NOERROR);
        resp.header.aa = true;
        for (auto& rr : z_it->second)
            if (rr.type == state->current_qtype)
                resp.answers.push_back(rr);
        resp.header.ancount = static_cast<uint16_t>(resp.answers.size());
        if (resp.answers.empty()) resp.header.rcode = RCode::NXDOMAIN;
        state->callback(resp);
        return;
    }

    // 2. Check NXDOMAIN cache
    if (cache_.is_nxdomain(state->current_qname))
    {
        state->callback(build_response(state, RCode::NXDOMAIN));
        return;
    }

    // 3. Check answer cache
    auto cached = cache_.get(state->current_qname, state->current_qtype);
    if (cached && !cached->answers.empty())
    {
        Message resp = build_response(state, RCode::NOERROR);
        resp.answers = cached->answers;
        resp.header.ancount = static_cast<uint16_t>(resp.answers.size());
        state->callback(resp);
        return;
    }

    // Check CNAME cache
    auto cname_cached = cache_.get(state->current_qname, QType::CNAME);
    if (cname_cached && !cname_cached->answers.empty())
    {
        Message resp = build_response(state, RCode::NOERROR);
        resp.answers = cname_cached->answers;
        resp.header.ancount = static_cast<uint16_t>(resp.answers.size());
        state->callback(resp);
        return;
    }

    // 4. Forwarder mode: send directly to configured upstream
    if (use_forwarder_)
    {
        state->nameservers = {forwarder_};
        state->ns_index    = 0;
        continue_resolution(state);
        return;
    }

    // 4. Find closest cached NS
    auto ns_cached = cache_.find_closest_ns(state->current_qname);
    if (ns_cached)
    {
        state->nameservers.clear();
        for (auto& rr : ns_cached->answers)
        {
            std::string ns_name = label_to_name(rr.rdata);
            bool        found   = false;
            for (auto& add_rr : ns_cached->additionals)
            {
                if (lower(add_rr.name) == lower(ns_name))
                {
                    std::string ip;
                    if (add_rr.type == QType::A && add_rr.rdata.size() >= 4)
                    {
                        ip = std::to_string(add_rr.rdata[0]) + "." +
                             std::to_string(add_rr.rdata[1]) + "." +
                             std::to_string(add_rr.rdata[2]) + "." +
                             std::to_string(add_rr.rdata[3]);
                    }
                    if (!ip.empty())
                    {
                        state->nameservers.push_back({ns_name, ip});
                        found = true;
                        break;
                    }
                }
            }
        }
        if (!state->nameservers.empty())
        {
            continue_resolution(state);
            return;
        }
    }

    // 5. Start from root
    start_from_root(state);
}

void RecursiveResolver::continue_resolution(std::shared_ptr<ResolutionState> state)
{
    if (state->ns_index >= state->nameservers.size())
        state->ns_index = 0;

    if (state->iteration++ > ResolutionState::MAX_ITERATIONS)
    {
        state->callback(build_response(state, RCode::SERVFAIL));
        return;
    }

    auto& ns = state->nameservers[state->ns_index];

    Message q{};
    q.header.id      = static_cast<uint16_t>(state->iteration);
    q.header.rd      = use_forwarder_;
    q.header.qdcount = 1;

    Question qq;
    qq.qname  = state->current_qname;
    qq.qtype  = state->current_qtype;
    qq.qclass = QClass::IN;
    q.questions.push_back(qq);

    state->ns_index++;

    std::thread([this, state, ns, q]() mutable
                {
                    UpstreamResult r = upstream_.query(q, ns.addr, 53, state->timeout);
                    asio::post(io_, [this, state, r = std::move(r)]() mutable
                               {
                                   handle_response(state, std::move(r));
                               });
                }).detach();
}

void RecursiveResolver::handle_response(std::shared_ptr<ResolutionState> state,
                                        UpstreamResult result)
{
    if (!result.success)
    {
        if (state->ns_index < state->nameservers.size())
        {
            continue_resolution(state);
            return;
        }
        state->callback(build_response(state, RCode::SERVFAIL));
        return;
    }

    auto& msg = result.msg;

    // Got answers
    if (!msg.answers.empty())
    {
        bool has_target_answer = false;
        for (auto& rr : msg.answers)
        {
            if (rr.type == state->current_qtype)
            {
                has_target_answer = true;
                break;
            }
        }

        if (has_target_answer)
        {
            cache_.put(state->current_qname, state->current_qtype,
                       msg.answers, msg.authorities, msg.additionals);

            Message resp = build_response(state, RCode::NOERROR);
            resp.header.ra      = true;
            resp.answers        = msg.answers;
            resp.header.ancount = static_cast<uint16_t>(resp.answers.size());
            resp.authorities    = msg.authorities;
            resp.header.nscount = static_cast<uint16_t>(resp.authorities.size());
            resp.additionals    = msg.additionals;
            resp.header.arcount = static_cast<uint16_t>(resp.additionals.size());
            state->callback(resp);
            return;
        }

        // CNAME only — follow the chain
        bool has_cname = false;
        for (auto& rr : msg.answers)
        {
            if (rr.type == QType::CNAME)
            {
                std::string target = label_to_name(rr.rdata);
                state->cname_chain.push_back(rr);
                cache_.put(state->current_qname, QType::CNAME,
                           std::vector<ResourceRecord>{rr}, {}, {});
                follow_cname(state, target);
                has_cname = true;
                break;
            }
        }

        if (!has_cname)
        {
            cache_.put(state->current_qname, state->current_qtype,
                       msg.answers, msg.authorities, msg.additionals);

            Message resp = build_response(state, RCode::NOERROR);
            resp.header.ra          = true;
            resp.answers            = msg.answers;
            resp.header.ancount     = static_cast<uint16_t>(resp.answers.size());
            resp.authorities        = msg.authorities;
            resp.header.nscount     = static_cast<uint16_t>(resp.authorities.size());
            resp.additionals        = msg.additionals;
            resp.header.arcount     = static_cast<uint16_t>(resp.additionals.size());
            state->callback(resp);
            return;
        }
        return;
    }

    // NXDOMAIN
    if (msg.header.rcode == RCode::NXDOMAIN)
    {
        uint32_t ttl = 300;
        if (!msg.authorities.empty() && msg.authorities[0].ttl > 0)
            ttl = msg.authorities[0].ttl;
        cache_.put_nxdomain(state->current_qname, ttl);
        state->callback(build_response(state, RCode::NXDOMAIN));
        return;
    }

    // Referral: NS records in authority
    if (!msg.authorities.empty())
    {
        for (auto& rr : msg.authorities)
        {
            if (rr.type == QType::NS)
            {
                std::string ns_zone = lower(rr.name);
                cache_.put_ns(ns_zone, msg.authorities, msg.additionals);

                state->nameservers.clear();
                for (auto& auth_rr : msg.authorities)
                {
                    if (auth_rr.type == QType::NS)
                    {
                        std::string ns_name = label_to_name(auth_rr.rdata);
                        for (auto& add_rr : msg.additionals)
                        {
                            if (lower(add_rr.name) == lower(ns_name))
                            {
                                std::string ip;
                                if (add_rr.type == QType::A && add_rr.rdata.size() >= 4)
                                {
                                    ip = std::to_string(add_rr.rdata[0]) + "." +
                                         std::to_string(add_rr.rdata[1]) + "." +
                                         std::to_string(add_rr.rdata[2]) + "." +
                                         std::to_string(add_rr.rdata[3]);
                                }
                                else if (add_rr.type == QType::AAAA && add_rr.rdata.size() >= 16)
                                {
                                    char buf[40];
                                    snprintf(buf, sizeof(buf),
                                             "%02x%02x:%02x%02x:%02x%02x:%02x%02x:"
                                             "%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                                             add_rr.rdata[0], add_rr.rdata[1],
                                             add_rr.rdata[2], add_rr.rdata[3],
                                             add_rr.rdata[4], add_rr.rdata[5],
                                             add_rr.rdata[6], add_rr.rdata[7],
                                             add_rr.rdata[8], add_rr.rdata[9],
                                             add_rr.rdata[10], add_rr.rdata[11],
                                             add_rr.rdata[12], add_rr.rdata[13],
                                             add_rr.rdata[14], add_rr.rdata[15]);
                                    ip = buf;
                                }
                                if (!ip.empty())
                                    state->nameservers.push_back({ns_name, ip});
                            }
                        }
                    }
                }

                if (!state->nameservers.empty())
                {
                    state->ns_index = 0;
                    continue_resolution(state);
                    return;
                }
                break;
            }
        }

        state->callback(build_response(state, RCode::SERVFAIL));
        return;
    }

    // Nothing useful - try next NS
    if (state->ns_index < state->nameservers.size())
    {
        continue_resolution(state);
        return;
    }

    state->callback(build_response(state, RCode::SERVFAIL));
}

void RecursiveResolver::follow_cname(std::shared_ptr<ResolutionState> state,
                                     const std::string& target)
{
    state->current_qname = lower(target);

    auto cached = cache_.get(state->current_qname, state->current_qtype);
    if (cached && !cached->answers.empty())
    {
        Message resp = build_response(state, RCode::NOERROR);
        resp.header.ra = true;
        resp.answers   = state->cname_chain;
        resp.answers.insert(resp.answers.end(), cached->answers.begin(), cached->answers.end());
        resp.header.ancount = static_cast<uint16_t>(resp.answers.size());
        state->callback(resp);
        return;
    }

    state->nameservers.clear();

    if (use_forwarder_)
    {
        state->nameservers = {forwarder_};
        state->ns_index    = 0;
        continue_resolution(state);
        return;
    }

    start_from_root(state);
}

void RecursiveResolver::start_from_root(std::shared_ptr<ResolutionState> state)
{
    if (root_hints_.empty())
    {
        state->callback(build_response(state, RCode::SERVFAIL));
        return;
    }
    state->nameservers = root_hints_;
    state->ns_index    = 0;
    continue_resolution(state);
}

void RecursiveResolver::extract_nameserver_ips(const std::vector<ResourceRecord>& rrs,
                                               std::vector<NameserverInfo>& out)
{
    for (auto& rr : rrs)
    {
        if (rr.type == QType::A && rr.rdata.size() >= 4)
        {
            std::string ip = std::to_string(rr.rdata[0]) + "." +
                             std::to_string(rr.rdata[1]) + "." +
                             std::to_string(rr.rdata[2]) + "." +
                             std::to_string(rr.rdata[3]);
            out.push_back({rr.name, ip});
        }
    }
}

Message RecursiveResolver::build_response(std::shared_ptr<ResolutionState> state, RCode rcode)
{
    Message resp{};
    resp.header.id      = state->original_query.header.id;
    resp.header.qr      = true;
    resp.header.opcode  = state->original_query.header.opcode;
    resp.header.rd      = state->original_query.header.rd;
    resp.header.ra      = true;
    resp.header.rcode   = rcode;
    resp.questions      = state->original_query.questions;
    resp.header.qdcount = static_cast<uint16_t>(resp.questions.size());
    return resp;
}

Message RecursiveResolver::resolve_sync(const Message& query)
{
    std::promise<Message> prom;
    auto                 fut = prom.get_future();

    // Copy query for async operation
    Message q = query;
    resolve(std::move(q), [&prom](Message resp)
            {
                prom.set_value(std::move(resp));
            });

    return fut.get();
}

} // namespace erisdns
