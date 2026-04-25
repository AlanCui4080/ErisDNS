#define BOOST_TEST_MODULE test_product
#include <boost/test/unit_test.hpp>

#include "erisdns/dns_parser.hpp"
#include "erisdns/dns_recursive.hpp"

#include <boost/asio.hpp>

#include <memory>
#include <thread>

using namespace erisdns;
namespace asio = boost::asio;

static std::vector<uint8_t> build_query(uint16_t id, const std::string& name,
                                        QType qtype = QType::A, uint16_t flags = 0x0100)
{
    std::vector<uint8_t> w;
    auto p16 = [&](uint16_t v) {
        w.push_back(static_cast<uint8_t>(v >> 8)); w.push_back(static_cast<uint8_t>(v & 0xFF));
    };
    p16(id); p16(flags); p16(1); p16(0); p16(0); p16(0);
    if (name == "." || name.empty()) { w.push_back(0); return w; }
    size_t s = 0;
    while (s <= name.size()) {
        size_t d = name.find('.', s);
        if (d == std::string::npos) d = name.size();
        size_t len = d - s;
        w.push_back(static_cast<uint8_t>(len));
        for (size_t i = 0; i < len; ++i) w.push_back(static_cast<uint8_t>(name[s + i]));
        s = d + 1;
    }
    w.push_back(0);
    p16(static_cast<uint16_t>(qtype)); p16(static_cast<uint16_t>(QClass::IN));
    return w;
}

static Message parse_wire(const std::vector<uint8_t>& wire)
{
    Parser p(wire); return p.parse();
}

// ─── Shared resolver instance ─────────────────────────────────────────

static std::unique_ptr<asio::io_context>  g_io;
static std::unique_ptr<RecursiveResolver> g_resolver;

struct GlobalFix
{
    GlobalFix()
    {
        g_io       = std::make_unique<asio::io_context>();
        g_resolver = std::make_unique<RecursiveResolver>(*g_io);

        g_resolver->add_zone("www.test.local", QType::A, 300, std::vector<uint8_t>{192, 168, 1, 100});
        g_resolver->add_zone("www.test.local", QType::A, 300, std::vector<uint8_t>{192, 168, 1, 101});
        g_resolver->add_zone("ipv6.test.local", QType::AAAA, 300,
                             std::vector<uint8_t>{0xfd, 0x00, 0,0,0,0,0,0, 0,0,0,0,0,0,0,1});
        g_resolver->add_zone("alias.test.local", QType::CNAME, 300,
                             std::vector<uint8_t>{3, 'w','w','w', 4,'t','e','s','t', 4,'l','o','c','a','l', 0});
        g_resolver->add_zone("txt.test.local", QType::TXT, 300,
                             std::vector<uint8_t>{13,'H','e','l','l','o',' ','D','N','S',' ','W','o','r','l','d'});
        g_resolver->add_zone("mx.test.local", QType::MX, 300,
                             std::vector<uint8_t>{0,10, 4,'m','a','i','l', 4,'t','e','s','t', 4,'l','o','c','a','l', 0});
        g_resolver->add_zone("soa.test.local", QType::SOA, 3600,
                             std::vector<uint8_t>{3,'n','s','1',0, 5,'a','d','m','i','n',0,
                                                   0,0,0,1, 0,0,0x0E,0x10, 0,0,0x02,0xBC,
                                                   0,0,0x15,0x18, 0,0,0,0x3C});
    }
    ~GlobalFix() = default;
};

BOOST_TEST_GLOBAL_FIXTURE(GlobalFix);

// ─── Recursive resolver API tests ─────────────────────────────────────

BOOST_AUTO_TEST_SUITE(local_zone_resolve)

BOOST_AUTO_TEST_CASE(a_record)
{
    auto wire = build_query(0x0001, "www.test.local");
    auto q    = parse_wire(wire);
    auto resp = g_resolver->resolve_sync(q);
    BOOST_CHECK(resp.header.qr);
    BOOST_CHECK(resp.header.aa);
    BOOST_CHECK(resp.header.rcode == RCode::NOERROR);
    BOOST_CHECK_GE(resp.answers.size(), 1);
    BOOST_CHECK(resp.answers[0].type == QType::A);
    BOOST_CHECK_EQUAL(resp.answers[0].rdata.size(), 4);
}

BOOST_AUTO_TEST_CASE(aaaa_record)
{
    auto wire = build_query(0x0002, "ipv6.test.local", QType::AAAA);
    auto q    = parse_wire(wire);
    auto resp = g_resolver->resolve_sync(q);
    BOOST_CHECK(resp.header.rcode == RCode::NOERROR);
    BOOST_REQUIRE_GE(resp.answers.size(), 1);
    BOOST_CHECK(resp.answers[0].type == QType::AAAA);
    BOOST_CHECK_EQUAL(resp.answers[0].rdata.size(), 16);
}

BOOST_AUTO_TEST_CASE(cname_record)
{
    auto wire = build_query(0x0003, "alias.test.local", QType::CNAME);
    auto q    = parse_wire(wire);
    auto resp = g_resolver->resolve_sync(q);
    BOOST_CHECK(resp.header.rcode == RCode::NOERROR);
    BOOST_REQUIRE_GE(resp.answers.size(), 1);
    BOOST_CHECK(resp.answers[0].type == QType::CNAME);
}

BOOST_AUTO_TEST_CASE(txt_record)
{
    auto wire = build_query(0x0004, "txt.test.local", QType::TXT);
    auto q    = parse_wire(wire);
    auto resp = g_resolver->resolve_sync(q);
    BOOST_CHECK(resp.header.rcode == RCode::NOERROR);
    BOOST_REQUIRE_GE(resp.answers.size(), 1);
    BOOST_CHECK(resp.answers[0].type == QType::TXT);
}

BOOST_AUTO_TEST_CASE(mx_record)
{
    auto wire = build_query(0x0005, "mx.test.local", QType::MX);
    auto q    = parse_wire(wire);
    auto resp = g_resolver->resolve_sync(q);
    BOOST_CHECK(resp.header.rcode == RCode::NOERROR);
    BOOST_REQUIRE_GE(resp.answers.size(), 1);
    BOOST_CHECK(resp.answers[0].type == QType::MX);
}

BOOST_AUTO_TEST_CASE(soa_record)
{
    auto wire = build_query(0x0006, "soa.test.local", QType::SOA);
    auto q    = parse_wire(wire);
    auto resp = g_resolver->resolve_sync(q);
    BOOST_CHECK(resp.header.rcode == RCode::NOERROR);
    BOOST_REQUIRE_GE(resp.answers.size(), 1);
    BOOST_CHECK(resp.answers[0].type == QType::SOA);
}

BOOST_AUTO_TEST_CASE(id_preserved)
{
    for (uint16_t id : {0x0001, 0x5555, 0xAAAA, 0xFFFF, 0x1234})
    {
        auto wire = build_query(id, "www.test.local");
        auto q    = parse_wire(wire);
        auto resp = g_resolver->resolve_sync(q);
        BOOST_CHECK_MESSAGE(resp.header.id == id, "ID " << id);
    }
}

BOOST_AUTO_TEST_CASE(case_insensitive_lookup)
{
    for (auto name : {"WWW.TEST.LOCAL", "Www.Test.Local", "www.test.local", "wWw.TeSt.LoCaL"})
    {
        auto wire = build_query(0x0099, name);
        auto q    = parse_wire(wire);
        auto resp = g_resolver->resolve_sync(q);
        BOOST_CHECK_MESSAGE(resp.header.rcode == RCode::NOERROR, name);
        BOOST_CHECK_MESSAGE(resp.answers.size() >= 1, name);
    }
}

BOOST_AUTO_TEST_CASE(serialize_response_valid)
{
    auto wire = build_query(0x0100, "www.test.local");
    auto q    = parse_wire(wire);
    auto resp = g_resolver->resolve_sync(q);

    BOOST_REQUIRE_GE(resp.answers.size(), 1);
    // Debug: print response state
    printf("DBG: qdcount=%u ancount=%u qr=%d aa=%d ra=%d rcode=%d\n",
           resp.header.qdcount, resp.header.ancount,
           resp.header.qr, resp.header.aa, resp.header.ra, (int)resp.header.rcode);
    printf("DBG: questions=%zu answers=%zu\n",
           resp.questions.size(), resp.answers.size());
    printf("DBG: ans[0] name=[%s] type=%d rdata_sz=%zu\n",
           resp.answers[0].name.c_str(), (int)resp.answers[0].type,
           resp.answers[0].rdata.size());

    Serializer ser;
    auto resp_wire = ser.serialize(resp);

    printf("DBG: wire sz=%zu first16:", resp_wire.size());
    for (size_t i = 0; i < std::min(resp_wire.size(), size_t(16)); ++i)
        printf(" %02X", resp_wire[i]);
    printf("\n");

    Parser p(resp_wire);
    auto m = p.parse();
    BOOST_CHECK_MESSAGE(!m.parse_error, "parse error: " << m.error_msg);
    BOOST_CHECK_EQUAL(m.header.id, 0x0100);
    BOOST_CHECK_GE(m.answers.size(), 1);
}

BOOST_AUTO_TEST_CASE(question_echoed_in_response)
{
    auto wire = build_query(0x0200, "soa.test.local", QType::SOA);
    auto q    = parse_wire(wire);
    auto resp = g_resolver->resolve_sync(q);
    BOOST_REQUIRE_GE(resp.questions.size(), 1);
    BOOST_CHECK_EQUAL(resp.questions[0].qname, "soa.test.local");
    BOOST_CHECK(resp.questions[0].qtype == QType::SOA);
}

BOOST_AUTO_TEST_CASE(edns_opt_in_query_preserves_response)
{
    // Build query with EDNS OPT in additional section
    auto base = build_query(0x6000, "www.test.local", QType::A, 0x0120);
    base[11] = 1; // ARCOUNT=1
    base.push_back(0); // NAME=root
    base.push_back(0); base.push_back(41); // TYPE=OPT
    base.push_back(0x05); base.push_back(0xAC); // UDP=1452
    base.push_back(0); base.push_back(0); base.push_back(0); base.push_back(0); // TTL
    base.push_back(0); base.push_back(0); // RDLENGTH=0

    auto q    = parse_wire(base);
    auto resp = g_resolver->resolve_sync(q);
    BOOST_CHECK(!resp.parse_error || resp.header.rcode == RCode::NOERROR);
    // OPT RR should be parsed
    BOOST_REQUIRE_EQUAL(q.additionals.size(), 1);
    BOOST_CHECK(q.additionals[0].type == QType::OPT);
}

BOOST_AUTO_TEST_SUITE_END()
