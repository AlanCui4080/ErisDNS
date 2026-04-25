#define BOOST_TEST_MODULE test_parser
#include <boost/test/unit_test.hpp>

#include "erisdns/dns_parser.hpp"
#include "erisdns/dns_resolver.hpp"

#include <cstring>

using namespace erisdns;

namespace {

// Helper: build a simple DNS query wire-format message
std::vector<uint8_t> build_query(uint16_t id, const std::string& name, QType qtype)
{
    std::vector<uint8_t> wire;

    // Header: ID
    wire.push_back(static_cast<uint8_t>(id >> 8));
    wire.push_back(static_cast<uint8_t>(id & 0xFF));

    // Flags: standard query, RD=1
    wire.push_back(0x01); // QR=0, Opcode=0, AA=0, TC=0, RD=1
    wire.push_back(0x00); // RA=0, Z=0, RCODE=0

    // QDCOUNT = 1
    wire.push_back(0x00);
    wire.push_back(0x01);

    // ANCOUNT = 0
    wire.push_back(0x00);
    wire.push_back(0x00);

    // NSCOUNT = 0
    wire.push_back(0x00);
    wire.push_back(0x00);

    // ARCOUNT = 0
    wire.push_back(0x00);
    wire.push_back(0x00);

    // Question: encode name
    size_t start = 0;
    while (start < name.size())
    {
        size_t dot = name.find('.', start);
        if (dot == std::string::npos) dot = name.size();
        size_t len = dot - start;
        wire.push_back(static_cast<uint8_t>(len));
        for (size_t i = 0; i < len; ++i)
            wire.push_back(static_cast<uint8_t>(name[start + i]));
        start = dot + 1;
    }
    wire.push_back(0x00); // root label

    // QTYPE
    wire.push_back(static_cast<uint8_t>(static_cast<uint16_t>(qtype) >> 8));
    wire.push_back(static_cast<uint8_t>(static_cast<uint16_t>(qtype) & 0xFF));

    // QCLASS = IN (1)
    wire.push_back(0x00);
    wire.push_back(0x01);

    return wire;
}

// Helper: build a DNS response wire-format message with one A record
std::vector<uint8_t> build_a_response(uint16_t id, const std::string& name,
                                       uint8_t a, uint8_t b, uint8_t c, uint8_t d)
{
    std::vector<uint8_t> wire;

    // ID
    wire.push_back(static_cast<uint8_t>(id >> 8));
    wire.push_back(static_cast<uint8_t>(id & 0xFF));

    // Flags: QR=1, Opcode=0, AA=0, TC=0, RD=1, RA=0, RCODE=0
    wire.push_back(0x81); // QR=1, RD=1
    wire.push_back(0x80); // RA=1

    // QDCOUNT = 1, ANCOUNT = 1, NSCOUNT = 0, ARCOUNT = 0
    wire.push_back(0x00); wire.push_back(0x01); // QDCOUNT
    wire.push_back(0x00); wire.push_back(0x01); // ANCOUNT
    wire.push_back(0x00); wire.push_back(0x00); // NSCOUNT
    wire.push_back(0x00); wire.push_back(0x00); // ARCOUNT

    // Encode QNAME
    size_t start = 0;
    while (start < name.size())
    {
        size_t dot = name.find('.', start);
        if (dot == std::string::npos) dot = name.size();
        size_t len = dot - start;
        wire.push_back(static_cast<uint8_t>(len));
        for (size_t i = 0; i < len; ++i)
            wire.push_back(static_cast<uint8_t>(name[start + i]));
        start = dot + 1;
    }
    wire.push_back(0x00);
    // QTYPE=A, QCLASS=IN
    wire.push_back(0x00); wire.push_back(0x01); // A
    wire.push_back(0x00); wire.push_back(0x01); // IN

    // Answer: name as pointer to QNAME at offset 12
    wire.push_back(0xC0);
    wire.push_back(0x0C); // Pointer to byte 12

    // TYPE=A, CLASS=IN, TTL=300, RDLENGTH=4
    wire.push_back(0x00); wire.push_back(0x01);
    wire.push_back(0x00); wire.push_back(0x01);
    wire.push_back(0x00); wire.push_back(0x00); wire.push_back(0x01); wire.push_back(0x2C); // TTL=300
    wire.push_back(0x00); wire.push_back(0x04); // RDLENGTH=4

    // RDATA: A.B.C.D
    wire.push_back(a); wire.push_back(b); wire.push_back(c); wire.push_back(d);

    return wire;
}

} // anonymous namespace

// ─── Header Parsing ─────────────────────────────────────────────────────────────

BOOST_AUTO_TEST_CASE(parse_empty)
{
    std::vector<uint8_t> data;
    Parser               p(data);
    Message              msg = p.parse();
    BOOST_CHECK(msg.parse_error);
}

BOOST_AUTO_TEST_CASE(parse_header_only)
{
    // Minimal 12-byte header with all zeros
    std::vector<uint8_t> data(12, 0);
    Parser               p(data);
    Message              msg = p.parse();
    BOOST_CHECK(!msg.parse_error);
    BOOST_CHECK_EQUAL(msg.header.id, 0);
    BOOST_CHECK_EQUAL(msg.header.qr, false);
    BOOST_CHECK(static_cast<uint8_t>(msg.header.opcode) == 0);
    BOOST_CHECK_EQUAL(msg.header.aa, false);
    BOOST_CHECK_EQUAL(msg.header.tc, false);
    BOOST_CHECK_EQUAL(msg.header.rd, false);
    BOOST_CHECK_EQUAL(msg.header.ra, false);
    BOOST_CHECK_EQUAL(msg.header.z, 0);
    BOOST_CHECK(static_cast<uint8_t>(msg.header.rcode) == 0);
    BOOST_CHECK_EQUAL(msg.header.qdcount, 0);
    BOOST_CHECK_EQUAL(msg.header.ancount, 0);
    BOOST_CHECK_EQUAL(msg.header.nscount, 0);
    BOOST_CHECK_EQUAL(msg.header.arcount, 0);
}

BOOST_AUTO_TEST_CASE(parse_simple_query)
{
    auto    data = build_query(0x1234, "www.example.com", QType::A);
    Parser  p(data);
    Message msg = p.parse();

    BOOST_CHECK(!msg.parse_error);
    BOOST_CHECK_EQUAL(msg.header.id, 0x1234);
    BOOST_CHECK_EQUAL(msg.header.qr, false);
    BOOST_CHECK_EQUAL(msg.header.rd, true);
    BOOST_CHECK_EQUAL(msg.header.qdcount, 1);
    BOOST_REQUIRE_EQUAL(msg.questions.size(), 1);
    BOOST_CHECK_EQUAL(msg.questions[0].qname, "www.example.com");
    BOOST_CHECK(msg.questions[0].qtype == QType::A);
    BOOST_CHECK(msg.questions[0].qclass == QClass::IN);
}

BOOST_AUTO_TEST_CASE(parse_query_aaaa)
{
    auto    data = build_query(0x0001, "ipv6.test.local", QType::AAAA);
    Parser  p(data);
    Message msg = p.parse();

    BOOST_CHECK(!msg.parse_error);
    BOOST_REQUIRE_EQUAL(msg.questions.size(), 1);
    BOOST_CHECK(msg.questions[0].qtype == QType::AAAA);
    BOOST_CHECK_EQUAL(msg.questions[0].qname, "ipv6.test.local");
}

// ─── Response Parsing ────────────────────────────────────────────────────────────

BOOST_AUTO_TEST_CASE(parse_a_response)
{
    auto    data = build_a_response(0xABCD, "example.com", 10, 0, 0, 1);
    Parser  p(data);
    Message msg = p.parse();

    BOOST_CHECK(!msg.parse_error);
    BOOST_CHECK_EQUAL(msg.header.id, 0xABCD);
    BOOST_CHECK_EQUAL(msg.header.qr, true);
    BOOST_CHECK_EQUAL(msg.header.ancount, 1);
    BOOST_REQUIRE_EQUAL(msg.questions.size(), 1);
    BOOST_CHECK_EQUAL(msg.questions[0].qname, "example.com");
    BOOST_REQUIRE_EQUAL(msg.answers.size(), 1);
    BOOST_CHECK(msg.answers[0].type == QType::A);
    BOOST_CHECK_EQUAL(msg.answers[0].name, "example.com");
    BOOST_REQUIRE_EQUAL(msg.answers[0].rdata.size(), 4);
    BOOST_CHECK_EQUAL(msg.answers[0].rdata[0], 10);
    BOOST_CHECK_EQUAL(msg.answers[0].rdata[1], 0);
    BOOST_CHECK_EQUAL(msg.answers[0].rdata[2], 0);
    BOOST_CHECK_EQUAL(msg.answers[0].rdata[3], 1);
}

BOOST_AUTO_TEST_CASE(parse_with_multiple_questions)
{
    // Build a message with 2 questions
    auto q1 = build_query(0x0001, "foo.com", QType::A);
    auto q2 = build_query(0x0001, "bar.com", QType::AAAA);

    std::vector<uint8_t> data;
    // Header (12 bytes)
    data.resize(12, 0);
    data[0] = 0x00; data[1] = 0x01;         // ID
    data[5] = 0x02;                         // QDCOUNT = 2

    // Append questions from both (skip their headers)
    data.insert(data.end(), q1.begin() + 12, q1.end());
    data.insert(data.end(), q2.begin() + 12, q2.end());

    Parser  p(data);
    Message msg = p.parse();

    BOOST_CHECK(!msg.parse_error);
    BOOST_REQUIRE_EQUAL(msg.questions.size(), 2);
    BOOST_CHECK_EQUAL(msg.questions[0].qname, "foo.com");
    BOOST_CHECK_EQUAL(msg.questions[1].qname, "bar.com");
}

// ─── Serialize then Parse (round-trip) ──────────────────────────────────────────

BOOST_AUTO_TEST_CASE(roundtrip_query)
{
    auto    orig_data = build_query(0xBEEF, "round.trip.test", QType::TXT);
    Parser  p1(orig_data);
    Message msg = p1.parse();
    BOOST_REQUIRE(!msg.parse_error);

    Serializer            ser;
    std::vector<uint8_t>  new_data = ser.serialize(msg);

    Parser  p2(new_data);
    Message msg2 = p2.parse();

    BOOST_CHECK(!msg2.parse_error);
    BOOST_CHECK_EQUAL(msg2.header.id, msg.header.id);
    BOOST_CHECK_EQUAL(msg2.header.qdcount, msg.header.qdcount);
    BOOST_REQUIRE_EQUAL(msg2.questions.size(), msg.questions.size());
    BOOST_CHECK_EQUAL(msg2.questions[0].qname, msg.questions[0].qname);
    BOOST_CHECK(msg2.questions[0].qtype == msg.questions[0].qtype);
}

BOOST_AUTO_TEST_CASE(roundtrip_response)
{
    auto    orig_data = build_a_response(0xCAFE, "response.test", 192, 168, 1, 1);
    Parser  p1(orig_data);
    Message msg = p1.parse();
    BOOST_REQUIRE(!msg.parse_error);

    Serializer            ser;
    std::vector<uint8_t>  new_data = ser.serialize(msg);

    Parser  p2(new_data);
    Message msg2 = p2.parse();

    BOOST_CHECK(!msg2.parse_error);
    BOOST_CHECK_EQUAL(msg2.header.id, msg.header.id);
    BOOST_CHECK_EQUAL(msg2.answers.size(), 1);
    BOOST_CHECK_EQUAL(msg2.answers[0].name, "response.test");
}

// ─── Resolver ────────────────────────────────────────────────────────────────────

BOOST_AUTO_TEST_CASE(resolver_a_record)
{
    Resolver resolver;
    std::vector<uint8_t> ip = {10, 20, 30, 40};
    resolver.add_record("test.local", QType::A, 300, ip);

    auto    query_wire = build_query(0x0001, "test.local", QType::A);
    Parser  p(query_wire);
    Message query = p.parse();

    Message resp = resolver.resolve(query);

    BOOST_CHECK_EQUAL(resp.header.id, 0x0001);
    BOOST_CHECK_EQUAL(resp.header.qr, true);
    BOOST_CHECK(static_cast<uint8_t>(resp.header.rcode) == 0);
    BOOST_REQUIRE_EQUAL(resp.answers.size(), 1);
    BOOST_CHECK(resp.answers[0].type == QType::A);
    BOOST_REQUIRE_EQUAL(resp.answers[0].rdata.size(), 4);
    BOOST_CHECK_EQUAL(resp.answers[0].rdata[0], 10);
    BOOST_CHECK_EQUAL(resp.answers[0].rdata[1], 20);
    BOOST_CHECK_EQUAL(resp.answers[0].rdata[2], 30);
    BOOST_CHECK_EQUAL(resp.answers[0].rdata[3], 40);
}

BOOST_AUTO_TEST_CASE(resolver_nxdomain)
{
    Resolver resolver;
    std::vector<uint8_t> ip = {1, 2, 3, 4};
    resolver.add_record("exists.local", QType::A, 300, ip);

    auto    query_wire = build_query(0x0002, "nonexist.local", QType::A);
    Parser  p(query_wire);
    Message query = p.parse();
    Message resp  = resolver.resolve(query);

    BOOST_CHECK(static_cast<uint8_t>(resp.header.rcode) == static_cast<uint8_t>(RCode::NXDOMAIN));
    BOOST_CHECK_EQUAL(resp.answers.size(), 0);
}

BOOST_AUTO_TEST_CASE(resolver_case_insensitive)
{
    Resolver resolver;
    std::vector<uint8_t> ip = {1, 1, 1, 1};
    resolver.add_record("CamelCase.Local", QType::A, 300, ip);

    auto    query_wire = build_query(0x0042, "camelcase.local", QType::A);
    Parser  p(query_wire);
    Message query = p.parse();
    Message resp  = resolver.resolve(query);

    BOOST_REQUIRE_EQUAL(resp.answers.size(), 1);
    BOOST_CHECK(resp.answers[0].type == QType::A);
}

BOOST_AUTO_TEST_CASE(resolver_notimpl)
{
    Resolver resolver;

    // Build a query with opcode = IQUERY (1)
    std::vector<uint8_t> wire(12, 0);
    wire[0] = 0x00; wire[1] = 0x01; // ID=1
    wire[2] = 0x08; wire[3] = 0x00; // QR=0, OPCODE=1 (IQUERY), RD=0
    wire[5] = 0x01;                 // QDCOUNT=1

    Parser  p(wire);
    Message msg = p.parse();
    BOOST_REQUIRE(msg.parse_error); // No question data, but opcode parsed
    // The parser will return error because QDCOUNT=1 but no question
    // Let's instead build a proper IQUERY
    auto q = build_query(0x0001, "test.local", QType::A);
    // Set opcode to IQUERY (1)
    q[2] = 0x08; // QR=0, OPCODE=1

    Parser  p2(q);
    Message query2 = p2.parse();
    BOOST_REQUIRE(!query2.parse_error);
    BOOST_CHECK(query2.header.opcode == Opcode::IQUERY);

    Message resp2 = resolver.resolve(query2);
    BOOST_CHECK(resp2.header.rcode == RCode::NOTIMP);
}

// ─── Serializer correctness ─────────────────────────────────────────────────────

BOOST_AUTO_TEST_CASE(serialize_simple_query)
{
    auto    data = build_query(0x5678, "my.test.name.com", QType::NS);
    Parser  p(data);
    Message msg = p.parse();
    BOOST_REQUIRE(!msg.parse_error);

    Serializer            ser;
    std::vector<uint8_t>  wire = ser.serialize(msg);

    // Wire should be exactly the same as input (no name compression in questions)
    BOOST_CHECK_EQUAL(wire.size(), data.size());
    BOOST_CHECK(std::equal(wire.begin(), wire.end(), data.begin()));
}

BOOST_AUTO_TEST_CASE(qtype_enum_values)
{
    BOOST_CHECK(static_cast<uint16_t>(QType::A) == 1);
    BOOST_CHECK(static_cast<uint16_t>(QType::NS) == 2);
    BOOST_CHECK(static_cast<uint16_t>(QType::CNAME) == 5);
    BOOST_CHECK(static_cast<uint16_t>(QType::SOA) == 6);
    BOOST_CHECK(static_cast<uint16_t>(QType::PTR) == 12);
    BOOST_CHECK(static_cast<uint16_t>(QType::MX) == 15);
    BOOST_CHECK(static_cast<uint16_t>(QType::TXT) == 16);
    BOOST_CHECK(static_cast<uint16_t>(QType::AAAA) == 28);
    BOOST_CHECK(static_cast<uint16_t>(QType::OPT) == 41);
    BOOST_CHECK(static_cast<uint16_t>(QType::AXFR) == 252);
    BOOST_CHECK(static_cast<uint16_t>(QType::ANY) == 255);
}

BOOST_AUTO_TEST_CASE(qtype_name_converts)
{
    BOOST_CHECK(qtype_name(QType::A) == "A");
    BOOST_CHECK(qtype_name(QType::AAAA) == "AAAA");
    BOOST_CHECK(qtype_name(QType::MX) == "MX");
}

BOOST_AUTO_TEST_CASE(rcode_name_converts)
{
    BOOST_CHECK(rcode_name(RCode::NOERROR) == "NOERROR");
    BOOST_CHECK(rcode_name(RCode::NXDOMAIN) == "NXDOMAIN");
    BOOST_CHECK(rcode_name(RCode::FORMERR) == "FORMERR");
}

// ─── TCP response serialization (regression test for correct sizes) ───────────

BOOST_AUTO_TEST_CASE(serialize_full_response)
{
    Resolver resolver;
    std::vector<uint8_t> ip1 = {10, 0, 0, 1};
    std::vector<uint8_t> ip2 = {10, 0, 0, 2};
    resolver.add_record("multi.local", QType::A, 300, ip1);
    resolver.add_record("multi.local", QType::A, 300, ip2);

    auto    query_wire = build_query(0x0001, "multi.local", QType::A);
    Parser  p(query_wire);
    Message query = p.parse();

    Message resp = resolver.resolve(query);
    BOOST_REQUIRE_EQUAL(resp.answers.size(), 2);

    Serializer            ser;
    std::vector<uint8_t>  wire = ser.serialize(resp);

    // Re-parse to verify
    Parser  p2(wire);
    Message msg2 = p2.parse();
    BOOST_CHECK(!msg2.parse_error);
    BOOST_REQUIRE_EQUAL(msg2.answers.size(), 2);
}
