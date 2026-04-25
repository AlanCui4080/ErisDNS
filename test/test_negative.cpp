#define BOOST_TEST_MODULE test_negative
#include <boost/test/unit_test.hpp>

#include "erisdns/dns_parser.hpp"

#include <cstring>
#include <random>

using namespace erisdns;

// ─── Edge cases and malformed input ─────────────────────────────────────────

BOOST_AUTO_TEST_CASE(empty_input)
{
    std::vector<uint8_t> data;
    Parser               p(data);
    Message              msg = p.parse();
    BOOST_CHECK(msg.parse_error);
}

BOOST_AUTO_TEST_CASE(truncated_header)
{
    for (size_t len = 0; len < 12; ++len)
    {
        std::vector<uint8_t> data(len, 0);
        Parser               p(data);
        Message              msg = p.parse();
        BOOST_CHECK_MESSAGE(msg.parse_error,
                            "Truncated at " << len << " bytes should fail");
    }
}

BOOST_AUTO_TEST_CASE(truncated_question)
{
    // 14 bytes: 12 header + 2 label (no root)
    std::vector<uint8_t> data(12, 0);
    data[5] = 0x01; // QDCOUNT = 1
    // Add a partial label: length byte + incomplete label
    data.push_back(0x05);      // label length 5
    data.push_back('h');
    data.push_back('e');
    data.push_back('l');       // only 3 bytes of 5-byte label

    Parser  p(data);
    Message msg = p.parse();
    BOOST_CHECK(msg.parse_error);
}

BOOST_AUTO_TEST_CASE(invalid_label_length)
{
    std::vector<uint8_t> data(12, 0);
    data[5] = 0x01; // QDCOUNT = 1
    // Label with length > 63 (invalid per RFC 1035)
    data.push_back(0x40); // length = 64

    for (int i = 0; i < 64; ++i)
        data.push_back('x');

    data.push_back(0x00); // root
    data.push_back(0x00);
    data.push_back(0x01); // QTYPE=A
    data.push_back(0x00);
    data.push_back(0x01); // QCLASS=IN

    Parser  p(data);
    Message msg = p.parse();
    BOOST_CHECK(msg.parse_error);
}

BOOST_AUTO_TEST_CASE(name_too_long)
{
    // Build a name with a single label of 255 bytes
    std::vector<uint8_t> data(12, 0);
    data[5] = 0x01; // QDCOUNT = 1

    data.push_back(0xFF); // label length 255
    for (int i = 0; i < 255; ++i)
        data.push_back('a');

    data.push_back(0x00); // root
    data.push_back(0x00);
    data.push_back(0x01);
    data.push_back(0x00);
    data.push_back(0x01);

    Parser  p(data);
    Message msg = p.parse();
    BOOST_CHECK(msg.parse_error); // Name too long > 255
}

BOOST_AUTO_TEST_CASE(total_name_too_long_with_children)
{
    // Build name: 250-byte-label.parent (total > 255)
    std::vector<uint8_t> data(12, 0);
    data[5] = 0x01;

    data.push_back(0xFA); // 250 bytes
    for (int i = 0; i < 250; ++i)
        data.push_back('a');

    data.push_back(0x06); // 6 bytes
    for (int i = 0; i < 6; ++i)
        data.push_back('b');

    data.push_back(0x00); // root
    data.push_back(0x00);
    data.push_back(0x01);
    data.push_back(0x00);
    data.push_back(0x01);

    Parser  p(data);
    Message msg = p.parse();
    BOOST_CHECK(msg.parse_error);
}

BOOST_AUTO_TEST_CASE(pointer_loop)
{
    std::vector<uint8_t> data(12, 0);
    data[5] = 0x01; // QDCOUNT = 1

    // Put a pointer at offset 12 pointing to offset 14
    data.push_back(0xC0);
    data.push_back(0x0E); // pointer to byte 14
    // At offset 14, pointer back to offset 12
    data.push_back(0xC0);
    data.push_back(0x0C); // pointer to byte 12

    // Fill remaining question fields
    data.push_back(0x00); data.push_back(0x01);
    data.push_back(0x00); data.push_back(0x01);

    Parser  p(data);
    Message msg = p.parse();
    BOOST_CHECK(msg.parse_error);
}

BOOST_AUTO_TEST_CASE(pointer_out_of_bounds)
{
    std::vector<uint8_t> data(12, 0);
    data[5] = 0x01;

    // Pointer to offset 9999 (way beyond message)
    data.push_back(0xC0 | (9999 >> 8));
    data.push_back(9999 & 0xFF);

    data.push_back(0x00); data.push_back(0x01);
    data.push_back(0x00); data.push_back(0x01);

    Parser  p(data);
    Message msg = p.parse();
    BOOST_CHECK(msg.parse_error);
}

BOOST_AUTO_TEST_CASE(excessive_rr_count)
{
    std::vector<uint8_t> data(12, 0);
    data[5] = 0xFF; // QDCOUNT = 65535 (too many)

    Parser  p(data);
    Message msg = p.parse();
    BOOST_CHECK(msg.parse_error);
}

BOOST_AUTO_TEST_CASE(truncated_rdata)
{
    // Build a valid 12-byte header + question and an answer with truncated rdlen
    std::vector<uint8_t> data(12, 0);
    data[0] = 0x00; data[1] = 0x01; // ID=1
    data[5] = 0x01;                 // QDCOUNT = 1
    data[7] = 0x01;                 // ANCOUNT = 1

    // Question: single label "a" + root
    data.push_back(0x01); data.push_back('a'); data.push_back(0x00); // name: a.
    data.push_back(0x00); data.push_back(0x01); // QTYPE=A
    data.push_back(0x00); data.push_back(0x01); // QCLASS=IN

    // Answer: pointer to name
    data.push_back(0xC0); data.push_back(0x0C); // pointer to offset 12 (name "a")
    data.push_back(0x00); data.push_back(0x01); // TYPE=A
    data.push_back(0x00); data.push_back(0x01); // CLASS=IN
    data.push_back(0x00); data.push_back(0x00); data.push_back(0x00); data.push_back(0x3C); // TTL=60
    data.push_back(0x00); data.push_back(0x10); // RDLENGTH=16 (but no RDATA follows)

    Parser  p(data);
    Message msg = p.parse();
    BOOST_CHECK(msg.parse_error);
}

BOOST_AUTO_TEST_CASE(no_questions_but_qdcount)
{
    std::vector<uint8_t> data(12, 0);
    data[5] = 0x01; // QDCOUNT = 1, but no question data

    Parser  p(data);
    Message msg = p.parse();
    BOOST_CHECK(msg.parse_error);
}

BOOST_AUTO_TEST_CASE(random_malformed_data)
{
    std::mt19937 rng(42);
    for (int round = 0; round < 100; ++round)
    {
        size_t len = rng() % 512;
        std::vector<uint8_t> data(len);
        for (size_t i = 0; i < len; ++i)
            data[i] = static_cast<uint8_t>(rng());

        Parser  p(data);
        Message msg = p.parse();

        (void)msg; // Should not crash
    }
}

BOOST_AUTO_TEST_CASE(valid_query_with_random_tail)
{
    // A valid query followed by random junk
    std::vector<uint8_t> data = {
        // Header
        0x00, 0x01,                   // ID
        0x01, 0x00,                   // RD=1
        0x00, 0x01,                   // QDCOUNT=1
        0x00, 0x00,                   // ANCOUNT=0
        0x00, 0x00,                   // NSCOUNT=0
        0x00, 0x00,                   // ARCOUNT=0
        // Question: "t.est" + root (note: 1-byte label "t", then "est")
        0x01, 't', 0x03, 'e', 's', 't', 0x00,
        0x00, 0x01,                   // QTYPE=A
        0x00, 0x01,                   // QCLASS=IN
        // Random tail
        0xFF, 0x00, 0xAB, 0xCD
    };

    Parser  p(data);
    Message msg = p.parse();
    // Should parse successfully - extra bytes after message are ignored
    BOOST_CHECK(!msg.parse_error);
    BOOST_REQUIRE_EQUAL(msg.questions.size(), 1);
    BOOST_CHECK_EQUAL(msg.questions[0].qname, "t.est");
}

BOOST_AUTO_TEST_CASE(too_many_total_rr)
{
    std::vector<uint8_t> data(12, 0);
    // Set all RR counts to 100 (total 400)
    data[5] = 0x64; // QDCOUNT=100
    data[7] = 0x64; // ANCOUNT=100
    data[9] = 0x64; // NSCOUNT=100
    data[11] = 0x64; // ARCOUNT=100

    Parser  p(data);
    Message msg = p.parse();
    BOOST_CHECK(msg.parse_error);
}

BOOST_AUTO_TEST_CASE(too_short_for_question_with_count)
{
    // 12 bytes + 1 byte (no room for full question)
    std::vector<uint8_t> data(12, 0);
    data[5] = 0x01; // QDCOUNT=1
    data.push_back(0x00); // root label only (empty name)

    Parser  p(data);
    Message msg = p.parse();
    BOOST_CHECK(msg.parse_error); // not enough bytes for QTYPE+QCLASS
}
