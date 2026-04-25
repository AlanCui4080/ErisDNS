#pragma once

#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace erisdns {

// RFC 1035 QTYPE values
enum class QType : uint16_t
{
    A          = 1,
    NS         = 2,
    CNAME      = 5,
    SOA        = 6,
    PTR        = 12,
    MX         = 15,
    TXT        = 16,
    AAAA       = 28,
    OPT        = 41,
    AXFR       = 252,
    ANY        = 255,
};

// RFC 1035 QCLASS values
enum class QClass : uint16_t
{
    IN = 1,
};

// RFC 1035 RCODE values
enum class RCode : uint8_t
{
    NOERROR   = 0,
    FORMERR   = 1,
    SERVFAIL  = 2,
    NXDOMAIN  = 3,
    NOTIMP    = 4,
    REFUSED   = 5,
};

// RFC 1035 Opcode values
enum class Opcode : uint8_t
{
    QUERY  = 0,
    IQUERY = 1,
    STATUS = 2,
};

// RFC 1035 4.1.1 — DNS Header (12 bytes)
struct Header
{
    uint16_t id;
    bool     qr;     // 0=query, 1=response
    Opcode   opcode;
    bool     aa;     // authoritative answer
    bool     tc;     // truncated
    bool     rd;     // recursion desired
    bool     ra;     // recursion available
    uint8_t  z;      // reserved
    RCode    rcode;
    uint16_t qdcount; // question count
    uint16_t ancount; // answer RR count
    uint16_t nscount; // authority RR count
    uint16_t arcount; // additional RR count

    static constexpr size_t WIRE_SIZE = 12;
};

// RFC 1035 4.1.2 — Question section
struct Question
{
    std::string qname;  // original dotted name for display
    QType       qtype;
    QClass      qclass;

    // Wire bytes of the encoded name (labels or pointers)
    std::vector<uint8_t> raw_name;
};

// RFC 1035 4.1.3 — Resource Record
struct ResourceRecord
{
    std::string name;   // owner name (uncompressed)
    QType       type;
    QClass      qclass;
    uint32_t    ttl;
    std::vector<uint8_t> rdata;

    // Wire bytes for the NAME field (may include pointers internally
    // but resolved here to canonical form for comparison)
    std::vector<uint8_t> raw_name;
};

// RFC 1035 4.1 — Full DNS Message
struct Message
{
    Header                 header;
    std::vector<Question>       questions;
    std::vector<ResourceRecord> answers;
    std::vector<ResourceRecord> authorities;
    std::vector<ResourceRecord> additionals;

    bool parse_error = false;
    std::string error_msg;
};

// Helper: convert QType to human readable string
constexpr std::string_view qtype_name(QType t)
{
    using enum QType;
    switch (t)
    {
    case A:     return "A";
    case NS:    return "NS";
    case CNAME: return "CNAME";
    case SOA:   return "SOA";
    case PTR:   return "PTR";
    case MX:    return "MX";
    case TXT:   return "TXT";
    case AAAA:  return "AAAA";
    case OPT:   return "OPT";
    case AXFR:  return "AXFR";
    case ANY:   return "ANY";
    default:    return "UNKNOWN";
    }
}

constexpr std::string_view rcode_name(RCode r)
{
    using enum RCode;
    switch (r)
    {
    case NOERROR:  return "NOERROR";
    case FORMERR:  return "FORMERR";
    case SERVFAIL: return "SERVFAIL";
    case NXDOMAIN: return "NXDOMAIN";
    case NOTIMP:   return "NOTIMP";
    case REFUSED:  return "REFUSED";
    default:       return "UNKNOWN";
    }
}

} // namespace erisdns
