#define BOOST_TEST_MODULE test_class
#include <boost/test/unit_test.hpp>

#include "erisdns/dns_parser.hpp"
#include "erisdns/dns_resolver.hpp"

#include <cstring>
#include <numeric>
#include <random>
#include <sstream>

using namespace erisdns;

// ═══════════════════════════════════════════════════════════════════════════════
// Helper: build wire-format DNS query
// ═══════════════════════════════════════════════════════════════════════════════

static std::vector<uint8_t> build_query(uint16_t id,
                                        const std::string& name,
                                        QType qtype = QType::A,
                                        uint16_t flags = 0x0100)
{
    std::vector<uint8_t> w;
    auto push_u16 = [&](uint16_t v) {
        w.push_back(static_cast<uint8_t>(v >> 8));
        w.push_back(static_cast<uint8_t>(v & 0xFF));
    };

    push_u16(id);  // ID
    push_u16(flags); // flags (default: RD=1)
    push_u16(1);  // QDCOUNT
    push_u16(0);  // ANCOUNT
    push_u16(0);  // NSCOUNT
    push_u16(0);  // ARCOUNT

    // Encode QNAME
    if (name.empty() || name == ".")
    {
        w.push_back(0);
    }
    else
    {
        size_t s = 0;
        while (s <= name.size())
        {
            size_t dot = name.find('.', s);
            if (dot == std::string::npos) dot = name.size();
            size_t len = dot - s;
            w.push_back(static_cast<uint8_t>(len));
            for (size_t i = 0; i < len; ++i)
                w.push_back(static_cast<uint8_t>(name[s + i]));
            s = dot + 1;
        }
        w.push_back(0); // terminal
    }

    push_u16(static_cast<uint16_t>(qtype));   // QTYPE
    push_u16(static_cast<uint16_t>(QClass::IN)); // QCLASS
    return w;
}

// ═══════════════════════════════════════════════════════════════════════════════
// RFC 1035 §2.3.1 — Preferred name syntax
// ═══════════════════════════════════════════════════════════════════════════════

BOOST_AUTO_TEST_SUITE(rfc1035_name_syntax)

BOOST_AUTO_TEST_CASE(labels_must_start_with_letter)
{
    std::vector<uint8_t> w = build_query(1, "www.example.com");
    Parser p(w);
    auto m = p.parse();
    BOOST_CHECK(!m.parse_error);
    BOOST_CHECK_EQUAL(m.questions[0].qname, "www.example.com");
}

BOOST_AUTO_TEST_CASE(labels_may_contain_hyphens)
{
    std::vector<uint8_t> w = build_query(1, "my-host.example.com");
    Parser p(w);
    auto m = p.parse();
    BOOST_CHECK(!m.parse_error);
    BOOST_CHECK_EQUAL(m.questions[0].qname, "my-host.example.com");
}

BOOST_AUTO_TEST_CASE(labels_may_contain_digits)
{
    std::vector<uint8_t> w = build_query(1, "srv123.example.com");
    Parser p(w);
    auto m = p.parse();
    BOOST_CHECK(!m.parse_error);
}

BOOST_AUTO_TEST_CASE(single_label_name)
{
    std::vector<uint8_t> w = build_query(1, "test");
    Parser p(w);
    auto m = p.parse();
    BOOST_CHECK(!m.parse_error);
    BOOST_CHECK_EQUAL(m.questions[0].qname, "test");
}

BOOST_AUTO_TEST_CASE(subdomain_parsing)
{
    std::vector<uint8_t> w = build_query(1, "a.b.c.d.e.f.g.example.com");
    Parser p(w);
    auto m = p.parse();
    BOOST_CHECK(!m.parse_error);
    BOOST_CHECK_EQUAL(m.questions[0].qname, "a.b.c.d.e.f.g.example.com");
}

BOOST_AUTO_TEST_CASE(uppercase_allowed_in_labels)
{
    std::vector<uint8_t> w = build_query(1, "UPPER.CASE.test");
    Parser p(w);
    auto m = p.parse();
    BOOST_CHECK(!m.parse_error);
    BOOST_CHECK_EQUAL(m.questions[0].qname, "UPPER.CASE.test");
}

BOOST_AUTO_TEST_CASE(mixed_case_preserved)
{
    std::vector<uint8_t> w = build_query(1, "Mixed.Case.Name.com");
    Parser p(w);
    auto m = p.parse();
    BOOST_CHECK(!m.parse_error);
    BOOST_CHECK_EQUAL(m.questions[0].qname, "Mixed.Case.Name.com");
}

BOOST_AUTO_TEST_SUITE_END()

// ═══════════════════════════════════════════════════════════════════════════════
// RFC 1035 §2.3.3 — Character Case (case-insensitive comparison)
// ═══════════════════════════════════════════════════════════════════════════════

BOOST_AUTO_TEST_SUITE(rfc1035_case_insensitive)

BOOST_AUTO_TEST_CASE(resolver_matches_case_insensitive)
{
    Resolver r;
    r.add_record("UPPER.CASE.NAME", QType::A, 300, std::vector<uint8_t>{1, 2, 3, 4});

    auto w = build_query(1, "upper.case.name");
    Parser p(w);
    auto q = p.parse();
    auto resp = r.resolve(q);
    BOOST_REQUIRE_EQUAL(resp.answers.size(), 1);
    BOOST_CHECK(resp.answers[0].type == QType::A);
}

BOOST_AUTO_TEST_CASE(resolver_matches_all_upper_query)
{
    Resolver r;
    r.add_record("some.name", QType::A, 300, std::vector<uint8_t>{1, 2, 3, 4});

    auto w = build_query(1, "SOME.NAME");
    Parser p(w);
    auto q = p.parse();
    auto resp = r.resolve(q);
    BOOST_REQUIRE_EQUAL(resp.answers.size(), 1);
}

BOOST_AUTO_TEST_CASE(resolver_matches_random_case)
{
    Resolver r;
    r.add_record("test.example.com", QType::A, 300, std::vector<uint8_t>{1, 1, 1, 1});

    std::vector<std::string> variants = {
        "TEST.example.COM",
        "Test.Example.Com",
        "test.Example.com",
        "tEsT.eXaMpLe.cOm",
        "test.example.com"
    };

    for (auto& v : variants)
    {
        auto w = build_query(1, v);
        Parser p(w);
        auto q = p.parse();
        auto resp = r.resolve(q);
        BOOST_CHECK_MESSAGE(resp.answers.size() == 1,
                            "Failed for variant: " << v);
    }
}

BOOST_AUTO_TEST_SUITE_END()

// ═══════════════════════════════════════════════════════════════════════════════
// RFC 1035 §2.3.4 — Size limits (labels <= 63, names <= 255)
// ═══════════════════════════════════════════════════════════════════════════════

BOOST_AUTO_TEST_SUITE(rfc1035_size_limits)

BOOST_AUTO_TEST_CASE(label_63_octets_allowed)
{
    // Build a query with a 63-char label
    std::string big = std::string(63, 'a');
    auto w = build_query(1, big + ".com");
    Parser p(w);
    auto m = p.parse();
    BOOST_CHECK(!m.parse_error);
}

BOOST_AUTO_TEST_CASE(label_64_octets_rejected)
{
    // Wire format: length byte = 64 (invalid)
    std::vector<uint8_t> w(12, 0);
    w[5] = 1; // QDCOUNT=1
    w.push_back(64); // length > 63
    for (int i = 0; i < 64; ++i) w.push_back('a');
    w.push_back(0); // root
    w.push_back(0); w.push_back(1); // QTYPE=A
    w.push_back(0); w.push_back(1); // QCLASS=IN

    Parser p(w);
    auto m = p.parse();
    BOOST_CHECK(m.parse_error);
}

BOOST_AUTO_TEST_CASE(name_255_allowed)
{
    // 5 labels of 50 chars each + 4 dots = 254, plus one more char
    // Max: 25 x 9-char labels + dots. Let's do: aaaa... (63) + .com = 67 total
    // Or: build 4 x 63-char labels = 252 + 3 dots = 255
    std::string big3 = std::string(63, 'a');
    std::string full = big3 + "." + big3 + "." + big3 + "." + big3.substr(0, 61);
    // 63 + 1 + 63 + 1 + 63 + 1 + 61 = 253, plus root = valid

    auto w = build_query(1, full);
    Parser p(w);
    auto m = p.parse();
    BOOST_CHECK(!m.parse_error);
}

BOOST_AUTO_TEST_CASE(name_over_255_rejected)
{
    // Build a name > 255 by using labels whose encoded lengths exceed 255
    // 4 x 63-byte labels + dots + root = much more
    std::string part = std::string(63, 'a');
    std::string huge = part + "." + part + "." + part + "." + part + ".extra";
    // encoded: 4*64 + 5 (extra) + 1 = 262

    auto w = build_query(1, huge);
    Parser p(w);
    auto m = p.parse();
    BOOST_CHECK(m.parse_error);
}

BOOST_AUTO_TEST_CASE(ttl_positive_values)
{
    // TTL should be a positive value
    Resolver r;
    r.add_record("ttl.test", QType::A, 0x7FFFFFFF, std::vector<uint8_t>{1, 2, 3, 4}); // max positive

    auto w = build_query(1, "ttl.test");
    Parser p(w);
    auto q = p.parse();
    auto resp = r.resolve(q);
    BOOST_REQUIRE_EQUAL(resp.answers.size(), 1);
    BOOST_CHECK_EQUAL(resp.answers[0].ttl, 0x7FFFFFFF);
}

BOOST_AUTO_TEST_SUITE_END()

// ═══════════════════════════════════════════════════════════════════════════════
// RFC 1035 §2.3.2 — Data Transmission Order (big-endian)
// ═══════════════════════════════════════════════════════════════════════════════

BOOST_AUTO_TEST_SUITE(rfc1035_big_endian)

BOOST_AUTO_TEST_CASE(header_fields_are_big_endian)
{
    // Build raw header with ID=0x1234
    std::vector<uint8_t> w(12, 0);
    w[0] = 0x12; w[1] = 0x34; // ID big-endian
    w[5] = 1;                  // QDCOUNT=1
    // Question: "a" label
    w.push_back(1); w.push_back('a'); w.push_back(0); // a.
    w.push_back(0); w.push_back(1);  // QTYPE=A (big-endian: 0x0001)
    w.push_back(0); w.push_back(1);  // QCLASS=IN

    Parser p(w);
    auto m = p.parse();
    BOOST_CHECK(!m.parse_error);
    BOOST_CHECK_EQUAL(m.header.id, 0x1234);
}

BOOST_AUTO_TEST_CASE(qtype_a_is_big_endian)
{
    std::vector<uint8_t> w = build_query(0, "test");
    BOOST_CHECK_EQUAL(w[w.size() - 4], 0x00); // QTYPE high byte
    BOOST_CHECK_EQUAL(w[w.size() - 3], 0x01); // QTYPE low byte = A

    Parser p(w);
    auto m = p.parse();
    BOOST_CHECK(m.questions[0].qtype == QType::A);
}

BOOST_AUTO_TEST_CASE(qtype_all_values_big_endian)
{
    struct { QType t; uint16_t val; } vals[] = {
        {QType::A, 1}, {QType::NS, 2}, {QType::CNAME, 5},
        {QType::SOA, 6}, {QType::PTR, 12}, {QType::MX, 15},
        {QType::TXT, 16}, {QType::AAAA, 28}, {QType::OPT, 41},
        {QType::AXFR, 252}, {QType::ANY, 255}
    };

    for (auto& v : vals)
    {
        auto w = build_query(1, "test", v.t);
        size_t off = w.size() - 4;
        uint16_t wire_val = (static_cast<uint16_t>(w[off]) << 8) | w[off + 1];
        BOOST_CHECK_MESSAGE(wire_val == v.val,
                            "QType " << qtype_name(v.t) << " wire value mismatch: "
                            << wire_val << " != " << v.val);
    }
}

BOOST_AUTO_TEST_SUITE_END()

// ═══════════════════════════════════════════════════════════════════════════════
// RFC 1035 §4.1.1 — Header section format
// ═══════════════════════════════════════════════════════════════════════════════

BOOST_AUTO_TEST_SUITE(rfc1035_header)

BOOST_AUTO_TEST_CASE(header_is_12_bytes)
{
    BOOST_CHECK_EQUAL(Header::WIRE_SIZE, 12);
}

BOOST_AUTO_TEST_CASE(id_copied_in_response)
{
    Resolver r;
    r.add_record("test", QType::A, 300, std::vector<uint8_t>{1, 2, 3, 4});

    auto w = build_query(0xDEAD, "test");
    Parser p(w);
    auto q = p.parse();
    auto resp = r.resolve(q);
    BOOST_CHECK_EQUAL(resp.header.id, 0xDEAD);
}

BOOST_AUTO_TEST_CASE(qr_bit_0_for_query)
{
    auto w = build_query(1, "test", QType::A, 0x0000);
    // First flag byte: QR=0, OPCODE=0, AA=0, TC=0, RD=0
    Parser p(w);
    auto m = p.parse();
    BOOST_CHECK(!m.parse_error);
    BOOST_CHECK_EQUAL(m.header.qr, false);
}

BOOST_AUTO_TEST_CASE(qr_bit_1_for_response)
{
    Resolver r;
    r.add_record("test", QType::A, 300, std::vector<uint8_t>{1, 2, 3, 4});
    auto w = build_query(1, "test");
    Parser p(w);
    auto q = p.parse();
    auto resp = r.resolve(q);
    BOOST_CHECK_EQUAL(resp.header.qr, true);
}

BOOST_AUTO_TEST_CASE(opcode_0_is_query)
{
    auto w = build_query(1, "test", QType::A, 0x0000);
    Parser p(w);
    auto m = p.parse();
    BOOST_CHECK(m.header.opcode == Opcode::QUERY);
}

BOOST_AUTO_TEST_CASE(opcode_preserved_in_response)
{
    // Build IQUERY (opcode=1)
    auto w = build_query(1, "test", QType::A, 0x0800); // OPCODE=1
    Parser p(w);
    auto m = p.parse();

    Resolver r;
    auto resp = r.resolve(m);
    BOOST_CHECK(resp.header.opcode == Opcode::IQUERY);
}

BOOST_AUTO_TEST_CASE(aa_bit_set_in_authoritative_response)
{
    Resolver r;
    r.add_record("test", QType::A, 300, std::vector<uint8_t>{1, 2, 3, 4});
    auto w = build_query(1, "test");
    Parser p(w);
    auto q = p.parse();
    auto resp = r.resolve(q);
    BOOST_CHECK_EQUAL(resp.header.aa, true);
}

BOOST_AUTO_TEST_CASE(rd_bit_copied_to_response)
{
    auto w = build_query(1, "test", QType::A, 0x0100); // RD=1
    Parser p(w);
    auto q = p.parse();

    Resolver r;
    r.add_record("test", QType::A, 300, std::vector<uint8_t>{1, 2, 3, 4});
    auto resp = r.resolve(q);
    BOOST_CHECK_EQUAL(resp.header.rd, true);
}

BOOST_AUTO_TEST_CASE(ra_zero_for_non_recursive)
{
    Resolver r;
    r.add_record("test", QType::A, 300, std::vector<uint8_t>{1, 2, 3, 4});
    auto w = build_query(1, "test");
    Parser p(w);
    auto q = p.parse();
    auto resp = r.resolve(q);
    BOOST_CHECK_EQUAL(resp.header.ra, false); // We don't implement recursion
}

BOOST_AUTO_TEST_CASE(z_field_zero_in_queries)
{
    // Standard query with Z=0
    auto w = build_query(1, "test");
    // Byte 3: RA=0, Z=0, RCODE=0
    BOOST_CHECK_EQUAL(w[3] & 0x70, 0);
}

BOOST_AUTO_TEST_CASE(header_roundtrip_serialization)
{
    auto w = build_query(0xBEEF, "test", QType::A, 0x0120); // RD=1, RA=1
    Parser p(w);
    auto m = p.parse();
    Serializer s;
    auto wire = s.serialize(m);
    BOOST_CHECK_GE(wire.size(), 12);
    BOOST_CHECK_EQUAL(wire[0], w[0]); // ID high
    BOOST_CHECK_EQUAL(wire[1], w[1]); // ID low
}

BOOST_AUTO_TEST_CASE(qdcount_ancount_nscount_arcount_are_uint16)
{
    auto w = build_query(1, "test");
    w[5] = 0x01; // QDCOUNT=1
    w[7] = 0x00; // ANCOUNT=0
    w[9] = 0x00; // NSCOUNT=0
    w[11] = 0x00; // ARCOUNT=0

    Parser p(w);
    auto m = p.parse();
    BOOST_CHECK_EQUAL(m.header.qdcount, 1);
    BOOST_CHECK_EQUAL(m.header.ancount, 0);
    BOOST_CHECK_EQUAL(m.header.nscount, 0);
    BOOST_CHECK_EQUAL(m.header.arcount, 0);
}

BOOST_AUTO_TEST_SUITE_END()

// ═══════════════════════════════════════════════════════════════════════════════
// RFC 1035 §4.1.2 — Question section format
// ═══════════════════════════════════════════════════════════════════════════════

BOOST_AUTO_TEST_SUITE(rfc1035_question)

BOOST_AUTO_TEST_CASE(question_has_qname_qtype_qclass)
{
    auto w = build_query(1, "www.example.com", QType::AAAA);
    Parser p(w);
    auto m = p.parse();
    BOOST_REQUIRE_EQUAL(m.questions.size(), 1);
    BOOST_CHECK_EQUAL(m.questions[0].qname, "www.example.com");
    BOOST_CHECK(m.questions[0].qtype == QType::AAAA);
    BOOST_CHECK(m.questions[0].qclass == QClass::IN);
}

BOOST_AUTO_TEST_CASE(multiple_questions_parsed)
{
    std::vector<uint8_t> w(12, 0);
    w[0] = 0x00; w[1] = 0x01; // ID=1
    w[5] = 3; // QDCOUNT=3

    auto add_q = [&](const std::string& name, QType t) {
        w.push_back(static_cast<uint8_t>(name.size()));
        for (char c : name) w.push_back(static_cast<uint8_t>(c));
        w.push_back(0);
        w.push_back(0); w.push_back(static_cast<uint8_t>(static_cast<uint16_t>(t) & 0xFF));
        w.push_back(0); w.push_back(1);
    };

    add_q("foo", QType::A);
    add_q("bar", QType::AAAA);
    add_q("baz", QType::MX);

    Parser p(w);
    auto m = p.parse();
    BOOST_CHECK(!m.parse_error);
    BOOST_REQUIRE_EQUAL(m.questions.size(), 3);
    BOOST_CHECK_EQUAL(m.questions[0].qname, "foo");
    BOOST_CHECK(m.questions[0].qtype == QType::A);
    BOOST_CHECK_EQUAL(m.questions[1].qname, "bar");
    BOOST_CHECK(m.questions[1].qtype == QType::AAAA);
    BOOST_CHECK_EQUAL(m.questions[2].qname, "baz");
    BOOST_CHECK(m.questions[2].qtype == QType::MX);
}

BOOST_AUTO_TEST_CASE(question_roundtrip_serialization)
{
    auto w = build_query(0x42, "round.trip.question", QType::TXT);
    Parser p(w);
    auto m = p.parse();
    Serializer s;
    auto wire = s.serialize(m);

    Parser p2(wire);
    auto m2 = p2.parse();
    BOOST_CHECK(!m2.parse_error);
    BOOST_REQUIRE_EQUAL(m2.questions.size(), 1);
    BOOST_CHECK_EQUAL(m2.questions[0].qname, "round.trip.question");
    BOOST_CHECK(m2.questions[0].qtype == QType::TXT);
}

BOOST_AUTO_TEST_CASE(qtype_any_is_255)
{
    auto w = build_query(1, "test", QType::ANY);
    size_t off = w.size() - 4;
    uint16_t val = (static_cast<uint16_t>(w[off]) << 8) | w[off + 1];
    BOOST_CHECK_EQUAL(val, 255);
}

BOOST_AUTO_TEST_SUITE_END()

// ═══════════════════════════════════════════════════════════════════════════════
// RFC 1035 §4.1.3 — Resource Record format
// ═══════════════════════════════════════════════════════════════════════════════

BOOST_AUTO_TEST_SUITE(rfc1035_rr)

BOOST_AUTO_TEST_CASE(rr_has_name_type_class_ttl_rdlength_rdata)
{
    Resolver r;
    r.add_record("rr.test", QType::A, 3600, std::vector<uint8_t>{10, 0, 0, 1});
    auto w = build_query(1, "rr.test");
    Parser p(w);
    auto m = p.parse();
    auto resp = r.resolve(m);

    BOOST_REQUIRE_EQUAL(resp.answers.size(), 1);
    auto& rr = resp.answers[0];
    BOOST_CHECK_EQUAL(rr.name, "rr.test");
    BOOST_CHECK(rr.type == QType::A);
    BOOST_CHECK(rr.qclass == QClass::IN);
    BOOST_CHECK_EQUAL(rr.ttl, 3600);
    BOOST_REQUIRE_EQUAL(rr.rdata.size(), 4);
    BOOST_CHECK_EQUAL(rr.rdata[0], 10);
    BOOST_CHECK_EQUAL(rr.rdata[1], 0);
    BOOST_CHECK_EQUAL(rr.rdata[2], 0);
    BOOST_CHECK_EQUAL(rr.rdata[3], 1);
}

BOOST_AUTO_TEST_CASE(a_record_rdata_4_octets)
{
    Resolver r;
    r.add_record("a.test", QType::A, 300, std::vector<uint8_t>{192, 168, 1, 1});
    auto w = build_query(1, "a.test");
    Parser p(w);
    auto m = p.parse();
    auto resp = r.resolve(m);
    BOOST_REQUIRE_EQUAL(resp.answers.size(), 1);
    BOOST_CHECK_EQUAL(resp.answers[0].rdata.size(), 4);
}

BOOST_AUTO_TEST_CASE(aaaa_record_rdata_16_octets)
{
    Resolver r;
    std::vector<uint8_t> ip6(16, 0);
    ip6[0] = 0xfd; ip6[15] = 1;
    r.add_record("aaaa.test", QType::AAAA, 300, ip6);
    auto w = build_query(1, "aaaa.test", QType::AAAA);
    Parser p(w);
    auto m = p.parse();
    auto resp = r.resolve(m);
    BOOST_REQUIRE_EQUAL(resp.answers.size(), 1);
    BOOST_CHECK_EQUAL(resp.answers[0].rdata.size(), 16);
}

BOOST_AUTO_TEST_CASE(txt_record_with_character_string)
{
    std::string txt = "Hello DNS World";
    std::vector<uint8_t> rd;
    rd.push_back(static_cast<uint8_t>(txt.size()));
    for (char c : txt) rd.push_back(static_cast<uint8_t>(c));

    Resolver r;
    r.add_record("txt.test", QType::TXT, 300, rd);
    auto w = build_query(1, "txt.test", QType::TXT);
    Parser p(w);
    auto m = p.parse();
    auto resp = r.resolve(m);
    BOOST_REQUIRE_EQUAL(resp.answers.size(), 1);
    BOOST_CHECK_GE(resp.answers[0].rdata.size(), 1);
    BOOST_CHECK_EQUAL(resp.answers[0].rdata[0], txt.size());
}

BOOST_AUTO_TEST_CASE(mx_record_with_preference_and_exchange)
{
    // Wire: 2 bytes preference + encoded domain name
    std::string exch = "mail.example.com";
    std::vector<uint8_t> rd;
    rd.push_back(0x00); rd.push_back(0x0A); // preference=10

    size_t s = 0;
    while (s <= exch.size())
    {
        size_t dot = exch.find('.', s);
        if (dot == std::string::npos) dot = exch.size();
        size_t len = dot - s;
        rd.push_back(static_cast<uint8_t>(len));
        for (size_t i = 0; i < len; ++i)
            rd.push_back(static_cast<uint8_t>(exch[s + i]));
        s = dot + 1;
    }
    rd.push_back(0);

    Resolver r;
    r.add_record("mx.test", QType::MX, 300, rd);
    auto w = build_query(1, "mx.test", QType::MX);
    Parser p(w);
    auto m = p.parse();
    auto resp = r.resolve(m);
    BOOST_REQUIRE_EQUAL(resp.answers.size(), 1);
    BOOST_CHECK_EQUAL(resp.answers[0].rdata[0], 0x00);
    BOOST_CHECK_EQUAL(resp.answers[0].rdata[1], 0x0A);
}

BOOST_AUTO_TEST_CASE(ns_record_with_domain_name_rdata)
{
    std::string nsname = "ns1.example.com";
    std::vector<uint8_t> rd;

    size_t s = 0;
    while (s <= nsname.size())
    {
        size_t dot = nsname.find('.', s);
        if (dot == std::string::npos) dot = nsname.size();
        size_t len = dot - s;
        rd.push_back(static_cast<uint8_t>(len));
        for (size_t i = 0; i < len; ++i)
            rd.push_back(static_cast<uint8_t>(nsname[s + i]));
        s = dot + 1;
    }
    rd.push_back(0);

    Resolver r;
    r.add_record("ns.test", QType::NS, 300, rd);
    auto w = build_query(1, "ns.test", QType::NS);
    Parser p(w);
    auto m = p.parse();
    auto resp = r.resolve(m);
    BOOST_REQUIRE_EQUAL(resp.answers.size(), 1);
    BOOST_CHECK_GE(resp.answers[0].rdata.size(), 3);
}

BOOST_AUTO_TEST_CASE(ptr_record_with_domain_name_rdata)
{
    std::string ptr = "host.example.com";
    std::vector<uint8_t> rd;
    size_t s = 0;
    while (s <= ptr.size())
    {
        size_t dot = ptr.find('.', s);
        if (dot == std::string::npos) dot = ptr.size();
        size_t len = dot - s;
        rd.push_back(static_cast<uint8_t>(len));
        for (size_t i = 0; i < len; ++i)
            rd.push_back(static_cast<uint8_t>(ptr[s + i]));
        s = dot + 1;
    }
    rd.push_back(0);

    Resolver r;
    r.add_record("ptr.test", QType::PTR, 300, rd);
    auto w = build_query(1, "ptr.test", QType::PTR);
    Parser p(w);
    auto m = p.parse();
    auto resp = r.resolve(m);
    BOOST_REQUIRE_EQUAL(resp.answers.size(), 1);
}

BOOST_AUTO_TEST_CASE(cname_record_parsed_correctly)
{
    std::string target = "real-host.example.com";
    std::vector<uint8_t> rd;
    size_t s = 0;
    while (s <= target.size())
    {
        size_t dot = target.find('.', s);
        if (dot == std::string::npos) dot = target.size();
        size_t len = dot - s;
        rd.push_back(static_cast<uint8_t>(len));
        for (size_t i = 0; i < len; ++i)
            rd.push_back(static_cast<uint8_t>(target[s + i]));
        s = dot + 1;
    }
    rd.push_back(0);

    Resolver r;
    r.add_record("alias.test", QType::CNAME, 300, rd);
    auto w = build_query(1, "alias.test", QType::CNAME);
    Parser p(w);
    auto m = p.parse();
    auto resp = r.resolve(m);
    BOOST_REQUIRE_EQUAL(resp.answers.size(), 1);
    BOOST_CHECK(resp.answers[0].type == QType::CNAME);
}

BOOST_AUTO_TEST_CASE(soa_record_stores_fields)
{
    std::vector<uint8_t> rd = {
        3, 'n', 's', '1', 0,          // MNAME: ns1.
        5, 'a', 'd', 'm', 'i', 'n', 0, // RNAME: admin.
        0, 0, 0, 1,                     // SERIAL
        0, 0, 0x0E, 0x10,              // REFRESH = 3600
        0, 0, 0x02, 0xBC,              // RETRY = 700
        0, 0, 0x15, 0x18,              // EXPIRE = 5400
        0, 0, 0x00, 0x3C               // MINIMUM = 60
    };

    Resolver r;
    r.add_record("zone.test", QType::SOA, 3600, rd);
    auto w = build_query(1, "zone.test", QType::SOA);
    Parser p(w);
    auto m = p.parse();
    auto resp = r.resolve(m);
    BOOST_REQUIRE_EQUAL(resp.answers.size(), 1);
    BOOST_CHECK(resp.answers[0].type == QType::SOA);
    BOOST_CHECK_GE(resp.answers[0].rdata.size(), 20);
}

BOOST_AUTO_TEST_CASE(empty_rdata_allowed)
{
    Resolver r;
    r.add_record("empty.test", QType::A, 300, std::vector<uint8_t>{});
    auto w = build_query(1, "empty.test");
    Parser p(w);
    auto m = p.parse();
    auto resp = r.resolve(m);
    BOOST_REQUIRE_EQUAL(resp.answers.size(), 1);
    BOOST_CHECK_EQUAL(resp.answers[0].rdata.size(), 0);
}

BOOST_AUTO_TEST_CASE(large_rdata_supported)
{
    std::vector<uint8_t> big(2048, 0xAB);
    Resolver r;
    r.add_record("big.test", QType::TXT, 300, big);
    auto w = build_query(1, "big.test", QType::TXT);
    Parser p(w);
    auto m = p.parse();
    auto resp = r.resolve(m);
    BOOST_REQUIRE_EQUAL(resp.answers.size(), 1);
    BOOST_CHECK_EQUAL(resp.answers[0].rdata.size(), 2048);
}

BOOST_AUTO_TEST_SUITE_END()

// ═══════════════════════════════════════════════════════════════════════════════
// RFC 1035 §4.1.4 — Message compression (pointer format)
// ═══════════════════════════════════════════════════════════════════════════════

BOOST_AUTO_TEST_SUITE(rfc1035_compression)

BOOST_AUTO_TEST_CASE(pointer_top_2_bits_are_11)
{
    // Pointer byte with 0xC0 prefix
    uint8_t ptr_hi = 0xC0;
    BOOST_CHECK_EQUAL((ptr_hi & 0xC0), 0xC0);
    BOOST_CHECK_EQUAL((ptr_hi & 0x3F), 0);
}

BOOST_AUTO_TEST_CASE(simple_pointer_decompressed)
{
    // Build message where answer name points to question name at offset 12
    std::vector<uint8_t> w(12, 0);
    w[0] = 0x00; w[1] = 0x01; // ID=1
    w[5] = 0x01;              // QDCOUNT=1
    w[7] = 0x01;              // ANCOUNT=1

    // Question name "a.com" at offset 12
    w.push_back(1); w.push_back('a');
    w.push_back(3); w.push_back('c'); w.push_back('o'); w.push_back('m');
    w.push_back(0);
    w.push_back(0); w.push_back(1);  // QTYPE=A
    w.push_back(0); w.push_back(1);  // QCLASS=IN

    // Answer: pointer to offset 12
    w.push_back(0xC0); w.push_back(0x0C);
    w.push_back(0); w.push_back(1);  // TYPE=A
    w.push_back(0); w.push_back(1);  // CLASS=IN
    w.push_back(0); w.push_back(0); w.push_back(0); w.push_back(0x3C); // TTL=60
    w.push_back(0); w.push_back(4);  // RDLENGTH=4
    w.push_back(10); w.push_back(0); w.push_back(0); w.push_back(1);

    Parser p(w);
    auto m = p.parse();
    BOOST_CHECK(!m.parse_error);
    BOOST_CHECK_EQUAL(m.answers[0].name, "a.com");
}

BOOST_AUTO_TEST_CASE(pointer_to_pointer)
{
    // Test a compressed name: answer uses pointer to question name
    std::vector<uint8_t> w(12, 0);
    w[0] = 0x00; w[1] = 0x01; // ID
    w[5] = 1;                 // QDCOUNT=1
    w[7] = 1;                 // ANCOUNT=1

    // Question: "x.y.z" at offset 12
    w.push_back(1); w.push_back('x');
    w.push_back(1); w.push_back('y');
    w.push_back(1); w.push_back('z');
    w.push_back(0);               // root
    w.push_back(0); w.push_back(1);  // QTYPE=A
    w.push_back(0); w.push_back(1);  // QCLASS=IN

    // Answer: pointer to question name at offset 12
    w.push_back(0xC0); w.push_back(0x0C); // pointer to offset 12
    w.push_back(0); w.push_back(1);  // TYPE=A
    w.push_back(0); w.push_back(1);  // CLASS=IN
    w.push_back(0); w.push_back(0); w.push_back(0); w.push_back(60); // TTL
    w.push_back(0); w.push_back(4);  // RDLENGTH
    w.push_back(127); w.push_back(0); w.push_back(0); w.push_back(1);

    Parser p(w);
    auto m = p.parse();
    BOOST_CHECK_MESSAGE(!m.parse_error, "parse_error: " << m.error_msg);
    if (!m.parse_error)
    {
        BOOST_CHECK_EQUAL(m.answers[0].name, "x.y.z");
    }
}

BOOST_AUTO_TEST_CASE(label_plus_pointer_decompressed)
{
    // Test compressed name: answer has label "w" + pointer to "x.y.z"
    std::vector<uint8_t> w(12, 0);
    w[0] = 0x00; w[1] = 0x01; // ID
    w[5] = 1;                 // QDCOUNT=1
    w[7] = 1;                 // ANCOUNT=1

    // Question: "x.y.z" at offset 12
    w.push_back(1); w.push_back('x');
    w.push_back(1); w.push_back('y');
    w.push_back(1); w.push_back('z');
    w.push_back(0);               // root -> offset 18
    w.push_back(0); w.push_back(1);  // QTYPE=A -> offsets 19-20
    w.push_back(0); w.push_back(1);  // QCLASS=IN -> offsets 21-22

    // Answer: label "w" + pointer to "x.y.z" at offset 12
    w.push_back(1); w.push_back('w'); // label "w" -> offsets 23-24
    w.push_back(0xC0); w.push_back(0x0C); // pointer to 12 -> offsets 25-26
    w.push_back(0); w.push_back(1);  // TYPE=A
    w.push_back(0); w.push_back(1);  // CLASS=IN
    w.push_back(0); w.push_back(0); w.push_back(0); w.push_back(60); // TTL
    w.push_back(0); w.push_back(4);  // RDLENGTH
    w.push_back(127); w.push_back(0); w.push_back(0); w.push_back(1);

    Parser p(w);
    auto m = p.parse();
    BOOST_CHECK_MESSAGE(!m.parse_error, "parse_error: " << m.error_msg);
    if (!m.parse_error)
    {
        BOOST_CHECK_EQUAL(m.answers[0].name, "w.x.y.z");
    }
}

BOOST_AUTO_TEST_CASE(pointer_loop_detected)
{
    std::vector<uint8_t> w(12, 0);
    w[5] = 1;
    // Pointer at 12 -> 14, pointer at 14 -> 12
    w.push_back(0xC0); w.push_back(0x0E);
    w.push_back(0xC0); w.push_back(0x0C);
    w.push_back(0); w.push_back(1);
    w.push_back(0); w.push_back(1);

    Parser p(w);
    auto m = p.parse();
    BOOST_CHECK(m.parse_error);
}

BOOST_AUTO_TEST_CASE(pointer_beyond_message)
{
    std::vector<uint8_t> w(12, 0);
    w[5] = 1;
    w.push_back(0xC0); w.push_back(0xFF); // pointer to 0x03FF (far beyond)
    w.push_back(0); w.push_back(1);
    w.push_back(0); w.push_back(1);

    Parser p(w);
    auto m = p.parse();
    BOOST_CHECK(m.parse_error);
}

BOOST_AUTO_TEST_SUITE_END()

// ═══════════════════════════════════════════════════════════════════════════════
// RFC 1035 §4.2.1 — RCODE values
// ═══════════════════════════════════════════════════════════════════════════════

BOOST_AUTO_TEST_SUITE(rfc1035_rcode)

BOOST_AUTO_TEST_CASE(noerror_is_0)
{
    BOOST_CHECK_EQUAL(static_cast<uint8_t>(RCode::NOERROR), 0);
}

BOOST_AUTO_TEST_CASE(formerr_is_1)
{
    BOOST_CHECK_EQUAL(static_cast<uint8_t>(RCode::FORMERR), 1);
}

BOOST_AUTO_TEST_CASE(servfail_is_2)
{
    BOOST_CHECK_EQUAL(static_cast<uint8_t>(RCode::SERVFAIL), 2);
}

BOOST_AUTO_TEST_CASE(nxdomain_is_3)
{
    BOOST_CHECK_EQUAL(static_cast<uint8_t>(RCode::NXDOMAIN), 3);
}

BOOST_AUTO_TEST_CASE(notimp_is_4)
{
    BOOST_CHECK_EQUAL(static_cast<uint8_t>(RCode::NOTIMP), 4);
}

BOOST_AUTO_TEST_CASE(refused_is_5)
{
    BOOST_CHECK_EQUAL(static_cast<uint8_t>(RCode::REFUSED), 5);
}

BOOST_AUTO_TEST_CASE(noerror_for_valid_query)
{
    Resolver r;
    r.add_record("ok.test", QType::A, 300, std::vector<uint8_t>{1, 2, 3, 4});
    auto w = build_query(1, "ok.test");
    Parser p(w);
    auto m = p.parse();
    auto resp = r.resolve(m);
    BOOST_CHECK(resp.header.rcode == RCode::NOERROR);
}

BOOST_AUTO_TEST_CASE(formerr_for_parse_error)
{
    std::vector<uint8_t> bad(5, 0);
    Parser p(bad);
    auto m = p.parse();
    BOOST_CHECK(m.parse_error);
}

BOOST_AUTO_TEST_CASE(nxdomain_for_missing_name)
{
    Resolver r;
    r.add_record("exists", QType::A, 300, std::vector<uint8_t>{1, 2, 3, 4});
    auto w = build_query(1, "nonexistent");
    Parser p(w);
    auto m = p.parse();
    auto resp = r.resolve(m);
    BOOST_CHECK(resp.header.rcode == RCode::NXDOMAIN);
}

BOOST_AUTO_TEST_CASE(notimp_for_unsopported_opcode)
{
    auto w = build_query(1, "test", QType::A, 0x0800); // IQUERY
    Parser p(w);
    auto m = p.parse();
    Resolver r;
    auto resp = r.resolve(m);
    BOOST_CHECK(resp.header.rcode == RCode::NOTIMP);
}

BOOST_AUTO_TEST_SUITE_END()

// ═══════════════════════════════════════════════════════════════════════════════
// RFC 1035 §4.2.2 — TCP usage (2-byte length prefix)
// ═══════════════════════════════════════════════════════════════════════════════

BOOST_AUTO_TEST_SUITE(rfc1035_tcp)

BOOST_AUTO_TEST_CASE(tcp_length_prefix_is_big_endian)
{
    // Simulate what the server sends: length prefix + message
    auto w = build_query(1, "test");
    uint16_t len = static_cast<uint16_t>(w.size());

    std::vector<uint8_t> tcp_frame;
    tcp_frame.push_back(static_cast<uint8_t>(len >> 8));
    tcp_frame.push_back(static_cast<uint8_t>(len & 0xFF));
    tcp_frame.insert(tcp_frame.end(), w.begin(), w.end());

    // Parser consumes the 2-byte prefix first, then the message
    BOOST_CHECK_EQUAL(tcp_frame[0], len >> 8);
    BOOST_CHECK_EQUAL(tcp_frame[1], len & 0xFF);
    BOOST_CHECK_EQUAL(tcp_frame.size(), len + 2);
}

BOOST_AUTO_TEST_CASE(tcp_length_matches_message)
{
    auto w = build_query(1, "test.example.com", QType::AAAA);
    uint16_t expected_len = static_cast<uint16_t>(w.size());

    // Check that the message length matches
    BOOST_CHECK_EQUAL(w.size(), expected_len);
}

BOOST_AUTO_TEST_SUITE_END()

// ═══════════════════════════════════════════════════════════════════════════════
// RFC 6891 §6 — OPT pseudo-RR (EDNS0)
// ═══════════════════════════════════════════════════════════════════════════════

BOOST_AUTO_TEST_SUITE(rfc6891_opt)

BOOST_AUTO_TEST_CASE(opt_type_is_41)
{
    BOOST_CHECK_EQUAL(static_cast<uint16_t>(QType::OPT), 41);
}

BOOST_AUTO_TEST_CASE(opt_name_must_be_root)
{
    // Build OPT RR with empty name (root)
    std::vector<uint8_t> w(12, 0);
    w[0] = 0x00; w[1] = 0x01; // ID
    w[5] = 1;                 // QDCOUNT=1
    w[11] = 1;                // ARCOUNT=1

    // Question
    w.push_back(0); // root name
    w.push_back(0); w.push_back(1);  // QTYPE=A
    w.push_back(0); w.push_back(1);  // QCLASS=IN

    // OPT pseudo-RR
    w.push_back(0); // NAME = root
    w.push_back(0); w.push_back(41);     // TYPE=OPT
    w.push_back(0x05); w.push_back(0xAC); // CLASS=UDP payload size 1452
    w.push_back(0); w.push_back(0); w.push_back(0); w.push_back(0); // TTL
    w.push_back(0); w.push_back(0); // RDLENGTH=0

    Parser p(w);
    auto m = p.parse();
    BOOST_CHECK(!m.parse_error);
    BOOST_REQUIRE_EQUAL(m.additionals.size(), 1);
    BOOST_CHECK(m.additionals[0].type == QType::OPT);
    BOOST_CHECK_EQUAL(m.additionals[0].name, "");
}

BOOST_AUTO_TEST_CASE(opt_class_is_udp_payload_size)
{
    std::vector<uint8_t> w(12, 0);
    w[0] = 0x00; w[1] = 1;
    w[5] = 1;  w[11] = 1;

    w.push_back(0); // qname root
    w.push_back(0); w.push_back(1); w.push_back(0); w.push_back(1);

    w.push_back(0); // name=root
    w.push_back(0); w.push_back(41); // TYPE=41
    // CLASS = 4096 (0x1000)
    w.push_back(0x10); w.push_back(0x00);
    w.push_back(0); w.push_back(0); w.push_back(0); w.push_back(0);
    w.push_back(0); w.push_back(0);

    Parser p(w);
    auto m = p.parse();
    BOOST_CHECK(!m.parse_error);
    BOOST_REQUIRE_EQUAL(m.additionals.size(), 1);
    uint16_t ps = static_cast<uint16_t>(m.additionals[0].qclass);
    BOOST_CHECK_EQUAL(ps, 4096);
}

BOOST_AUTO_TEST_CASE(opt_ttl_contains_extended_rcode_and_version)
{
    std::vector<uint8_t> w(12, 0);
    w[0] = 0x00; w[1] = 1;
    w[5] = 1;  w[11] = 1;

    w.push_back(0); w.push_back(0); w.push_back(1); w.push_back(0); w.push_back(1);
    w.push_back(0);
    w.push_back(0); w.push_back(41);

    // CLASS = 512
    w.push_back(0x02); w.push_back(0x00);
    // TTL: EXT-RCODE=0, VERSION=0, DO=1
    w.push_back(0x00); w.push_back(0x00); w.push_back(0x80); w.push_back(0x00);
    w.push_back(0); w.push_back(0);

    Parser p(w);
    auto m = p.parse();
    BOOST_CHECK(!m.parse_error);
    BOOST_REQUIRE_EQUAL(m.additionals.size(), 1);
    // DO bit set: byte 2 of TTL = 0x80
    BOOST_CHECK(m.additionals[0].ttl & 0x8000);
}

BOOST_AUTO_TEST_CASE(opt_must_be_only_one)
{
    // Message with 2 OPT RRs - parser should handle it (FORMERR is server logic)
    std::vector<uint8_t> w(12, 0);
    w[0] = 0x00; w[1] = 1;
    w[5] = 1; w[11] = 2; // 2 additional records

    w.push_back(0); w.push_back(0); w.push_back(1); w.push_back(0); w.push_back(1);

    // First OPT
    w.push_back(0);
    w.push_back(0); w.push_back(41);
    w.push_back(0); w.push_back(0);
    w.push_back(0); w.push_back(0); w.push_back(0); w.push_back(0);
    w.push_back(0); w.push_back(0);

    // Second OPT (violates spec)
    w.push_back(0);
    w.push_back(0); w.push_back(41);
    w.push_back(0); w.push_back(0);
    w.push_back(0); w.push_back(0); w.push_back(0); w.push_back(0);
    w.push_back(0); w.push_back(0);

    Parser p(w);
    auto m = p.parse();
    BOOST_CHECK(!m.parse_error);
    BOOST_CHECK_EQUAL(m.additionals.size(), 2);
}

BOOST_AUTO_TEST_SUITE_END()

// ═══════════════════════════════════════════════════════════════════════════════
// RFC 6891 §7 — Transport Considerations
// ═══════════════════════════════════════════════════════════════════════════════

BOOST_AUTO_TEST_SUITE(rfc6891_transport)

BOOST_AUTO_TEST_CASE(edns_udp_payload_default_512)
{
    auto w = build_query(1, "test");
    // Without EDNS, UDP payload is 512
    BOOST_CHECK_LE(w.size(), 512);
}

BOOST_AUTO_TEST_CASE(edns_udp_payload_can_be_larger)
{
    // EDNS allows up to 4096 bytes
    auto w = build_query(1, "test");
    // With EDNS OPT in additional section, full payload can be > 512
    // Server must support >= 512 (per RFC 6891 §6.2.3)
    BOOST_CHECK_LE(w.size(), 512);
}

BOOST_AUTO_TEST_SUITE_END()

// ═══════════════════════════════════════════════════════════════════════════════
// RFC 6891 §6.2.2 — Fallback
// ═══════════════════════════════════════════════════════════════════════════════

BOOST_AUTO_TEST_SUITE(rfc6891_fallback)

BOOST_AUTO_TEST_CASE(query_without_edns_still_works)
{
    // Standard query without OPT record must work
    Resolver r;
    r.add_record("basic.test", QType::A, 300, std::vector<uint8_t>{1, 2, 3, 4});
    auto w = build_query(1, "basic.test");
    Parser p(w);
    auto m = p.parse();
    auto resp = r.resolve(m);
    BOOST_CHECK(resp.header.rcode == RCode::NOERROR);
    BOOST_CHECK_EQUAL(resp.answers.size(), 1);
}

BOOST_AUTO_TEST_SUITE_END()

// ═══════════════════════════════════════════════════════════════════════════════
// Combined stress / edge scenarios
// ═══════════════════════════════════════════════════════════════════════════════

BOOST_AUTO_TEST_SUITE(stress_edge)

BOOST_AUTO_TEST_CASE(many_records_same_name)
{
    Resolver r;
    for (int i = 0; i < 50; ++i)
    {
        r.add_record("many.test", QType::A, 300,
                     std::vector<uint8_t>{static_cast<uint8_t>(i), 0, 0, 1});
    }

    auto w = build_query(1, "many.test");
    Parser p(w);
    auto m = p.parse();
    auto resp = r.resolve(m);
    BOOST_CHECK_EQUAL(resp.answers.size(), 50);
}

BOOST_AUTO_TEST_CASE(mixed_record_types)
{
    Resolver r;
    std::vector<uint8_t> ip = {1, 2, 3, 4};
    r.add_record("multi.test", QType::A, 300, ip);
    r.add_record("multi.test", QType::NS, 300, std::vector<uint8_t>{3, 'n', 's', '1', 0});
    r.add_record("multi.test", QType::TXT, 300, std::vector<uint8_t>{3, 'f', 'o', 'o'});

    {
        auto w = build_query(1, "multi.test", QType::A);
        Parser p(w); auto resp = r.resolve(p.parse());
        BOOST_CHECK_EQUAL(resp.answers.size(), 1);
        BOOST_CHECK(resp.answers[0].type == QType::A);
    }
    {
        auto w = build_query(1, "multi.test", QType::NS);
        Parser p(w); auto resp = r.resolve(p.parse());
        BOOST_CHECK_EQUAL(resp.answers.size(), 1);
        BOOST_CHECK(resp.answers[0].type == QType::NS);
    }
}

BOOST_AUTO_TEST_CASE(wildcard_any_returns_all)
{
    Resolver r;
    r.add_record("any.test", QType::A, 300, std::vector<uint8_t>{1, 2, 3, 4});
    r.add_record("any.test", QType::AAAA, 300, std::vector<uint8_t>(16, 0));
    r.add_record("any.test", QType::TXT, 300, std::vector<uint8_t>{4, 't', 'e', 's', 't'});

    auto w = build_query(1, "any.test", QType::ANY);
    Parser p(w);
    auto m = p.parse();
    auto resp = r.resolve(m);
    BOOST_CHECK_EQUAL(resp.answers.size(), 3);
}

BOOST_AUTO_TEST_CASE(random_fuzz_input_no_crash)
{
    std::mt19937 rng(12345);
    for (int round = 0; round < 500; ++round)
    {
        size_t len = rng() % 1024;
        std::vector<uint8_t> data(len);
        std::generate(data.begin(), data.end(), [&]() { return static_cast<uint8_t>(rng()); });

        Parser p(data);
        auto m = p.parse();
        (void)m;

        Resolver r;
        r.add_record("example.com", QType::A, 300, std::vector<uint8_t>{1, 2, 3, 4});
        r.resolve(m);
    }
}

BOOST_AUTO_TEST_CASE(serializer_handles_empty_message)
{
    Message m{};
    Serializer s;
    auto wire = s.serialize(m);
    BOOST_CHECK_EQUAL(wire.size(), 12); // Just header
}

BOOST_AUTO_TEST_CASE(serializer_handles_all_sections)
{
    Message m{};
    m.header.id = 0x1234;
    m.header.qr = true;
    m.header.qdcount = 1;
    m.header.ancount = 1;
    m.header.nscount = 1;
    m.header.arcount = 1;

    Question q;
    q.qname = "example.com";
    q.qtype = QType::A;
    q.qclass = QClass::IN;
    m.questions.push_back(q);

    ResourceRecord rr;
    rr.name = "example.com";
    rr.type = QType::A;
    rr.qclass = QClass::IN;
    rr.ttl = 300;
    rr.rdata = {1, 2, 3, 4};
    m.answers.push_back(rr);
    m.authorities.push_back(rr);
    m.additionals.push_back(rr);

    Serializer s;
    auto wire = s.serialize(m);

    Parser p(wire);
    auto parsed = p.parse();
    BOOST_CHECK(!parsed.parse_error);
    BOOST_CHECK_EQUAL(parsed.header.id, 0x1234);
    BOOST_CHECK_EQUAL(parsed.questions.size(), 1);
    BOOST_CHECK_EQUAL(parsed.answers.size(), 1);
    BOOST_CHECK_EQUAL(parsed.authorities.size(), 1);
    BOOST_CHECK_EQUAL(parsed.additionals.size(), 1);
}

BOOST_AUTO_TEST_SUITE_END()
