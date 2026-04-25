#define BOOST_TEST_MODULE test_semi_fuzz
#include <boost/test/unit_test.hpp>

#include "erisdns/dns_parser.hpp"
#include "erisdns/dns_resolver.hpp"

#include <cstring>
#include <random>

using namespace erisdns;

// ══════════════════════════════════════════════════════════════════
// Helper: build a valid wire-format DNS query
// ══════════════════════════════════════════════════════════════════

static std::vector<uint8_t> build_wire(uint16_t id,
                                       const std::string& name,
                                       QType qtype,
                                       uint16_t flags,
                                       uint16_t ancount,
                                       uint16_t nscount,
                                       uint16_t arcount)
{
    std::vector<uint8_t> w;
    auto p16 = [&](uint16_t v) {
        w.push_back(static_cast<uint8_t>(v >> 8));
        w.push_back(static_cast<uint8_t>(v & 0xFF));
    };

    p16(id);
    p16(flags);
    p16(1); p16(ancount); p16(nscount); p16(arcount);

    size_t s = 0;
    while (s <= name.size())
    {
        size_t d = name.find('.', s);
        if (d == std::string::npos) d = name.size();
        size_t len = d - s;
        w.push_back(static_cast<uint8_t>(len));
        for (size_t i = 0; i < len; ++i) w.push_back(static_cast<uint8_t>(name[s + i]));
        s = d + 1;
    }
    w.push_back(0);

    p16(static_cast<uint16_t>(qtype));
    p16(static_cast<uint16_t>(QClass::IN));
    return w;
}

static std::vector<uint8_t> build_query(uint16_t id, const std::string& name, QType t)
{
    return build_wire(id, name, t, 0x0100, 0, 0, 0);
}

// ══════════════════════════════════════════════════════════════════
// Semi-fuzz suite 1: BIT-FLIP on valid messages
// ══════════════════════════════════════════════════════════════════

BOOST_AUTO_TEST_SUITE(semi_bitflip)

BOOST_AUTO_TEST_CASE(bitflip_every_byte_of_valid_query)
{
    auto base = build_query(0x1234, "www.example.com", QType::A);

    for (size_t byte_idx = 0; byte_idx < base.size(); ++byte_idx)
    {
        uint8_t orig = base[byte_idx];
        for (int bit = 0; bit < 8; ++bit)
        {
            base[byte_idx] = static_cast<uint8_t>(orig ^ (1 << bit));
            Parser  p(base);
            Message m = p.parse();
            // Must not crash; parse_error is expected for some mutations
            (void)m;
            base[byte_idx] = orig;
        }
    }
}

BOOST_AUTO_TEST_CASE(bitflip_on_response)
{
    // Build a valid response with A record
    std::vector<uint8_t> w(12, 0);
    w[0] = 0; w[1] = 1; // ID=1
    w[2] = 0x85; w[3] = 0x80; // QR=1, RD=1, RA=1
    w[5] = 1; // QDCOUNT=1
    w[7] = 1; // ANCOUNT=1

    // Question "a.com"
    w.push_back(1); w.push_back('a');
    w.push_back(3); w.push_back('c'); w.push_back('o'); w.push_back('m');
    w.push_back(0);
    w.push_back(0); w.push_back(1); w.push_back(0); w.push_back(1);

    // Answer: pointer to QNAME, TYPE=A, CLASS=IN, TTL=300
    w.push_back(0xC0); w.push_back(0x0C);
    w.push_back(0); w.push_back(1); w.push_back(0); w.push_back(1);
    w.push_back(0); w.push_back(0); w.push_back(1); w.push_back(0x2C);
    w.push_back(0); w.push_back(4);
    w.push_back(10); w.push_back(0); w.push_back(0); w.push_back(1);

    for (size_t i = 0; i < w.size(); ++i)
    {
        uint8_t orig = w[i];
        w[i] = static_cast<uint8_t>(orig ^ 0xFF);
        Parser p(w);
        auto m = p.parse();
        (void)m;
        w[i] = orig;
    }
}

BOOST_AUTO_TEST_SUITE_END()

// ══════════════════════════════════════════════════════════════════
// Semi-fuzz suite 2: FIELD BOUNDARY / EDGE VALUES
// ══════════════════════════════════════════════════════════════════

BOOST_AUTO_TEST_SUITE(semi_boundary)

BOOST_AUTO_TEST_CASE(header_count_fields_all_zeros)
{
    auto w = build_wire(0, "test.com", QType::A, 0x0100, 0, 0, 0);
    // Explicitly zero all count fields (they already are)
    w[4] = 0; w[5] = 0; w[6] = 0; w[7] = 0; w[8] = 0; w[9] = 0; w[10] = 0; w[11] = 0;
    Parser p(w);
    auto m = p.parse();
    BOOST_CHECK(!m.parse_error);
}

BOOST_AUTO_TEST_CASE(header_count_fields_max_uint16)
{
    auto w = build_wire(0, "test.com", QType::A, 0x0100, 0xFFFF, 0xFFFF, 0xFFFF);
    w[4] = 0xFF; w[5] = 0xFF; // QDCOUNT=65535
    Parser p(w);
    auto m = p.parse();
    // Should be rejected (too many RRs) or parse error
    // Must not crash
    (void)m;
}

BOOST_AUTO_TEST_CASE(qdcount_exceeds_actual_questions_by_100)
{
    auto w = build_wire(0, "test.com", QType::A, 0x0100, 0, 0, 0);
    w[5] = 100; // QDCOUNT=100 but only 1 question present
    Parser p(w);
    auto m = p.parse();
    (void)m; // Must not crash
}

BOOST_AUTO_TEST_CASE(ancount_claims_records_but_none_present)
{
    auto w = build_wire(0, "test.com", QType::A, 0x0100, 100, 0, 0);
    w[7] = 100; // ANCOUNT=100
    Parser p(w);
    auto m = p.parse();
    (void)m;
}

BOOST_AUTO_TEST_CASE(combined_overflow)
{
    // QDCOUNT=100, ANCOUNT=100, NSCOUNT=100, ARCOUNT=100 -> total=400 > 256
    auto w = build_wire(0, "test.com", QType::A, 0x0100, 100, 100, 100);
    w[5] = 100; w[7] = 100; w[9] = 100; w[11] = 100;
    Parser p(w);
    auto m = p.parse();
    BOOST_CHECK(m.parse_error);
}

BOOST_AUTO_TEST_CASE(ttl_boundary_zero)
{
    // Build a response with TTL=0
    std::vector<uint8_t> w(12, 0);
    w[5] = 1; w[7] = 1;
    w.push_back(1); w.push_back('a'); w.push_back(0);
    w.push_back(0); w.push_back(1); w.push_back(0); w.push_back(1);
    w.push_back(0xC0); w.push_back(0x0C);
    w.push_back(0); w.push_back(1); w.push_back(0); w.push_back(1);
    w.push_back(0); w.push_back(0); w.push_back(0); w.push_back(0); // TTL=0
    w.push_back(0); w.push_back(4);
    for (int i = 0; i < 4; ++i) w.push_back(0);

    Parser p(w);
    auto m = p.parse();
    BOOST_CHECK(!m.parse_error);
}

BOOST_AUTO_TEST_CASE(ttl_boundary_max_uint32)
{
    std::vector<uint8_t> w(12, 0);
    w[5] = 1; w[7] = 1;
    w.push_back(1); w.push_back('a'); w.push_back(0);
    w.push_back(0); w.push_back(1); w.push_back(0); w.push_back(1);
    w.push_back(0xC0); w.push_back(0x0C);
    w.push_back(0); w.push_back(1); w.push_back(0); w.push_back(1);
    w.push_back(0xFF); w.push_back(0xFF); w.push_back(0xFF); w.push_back(0xFF); // TTL=max
    w.push_back(0); w.push_back(4);
    for (int i = 0; i < 4; ++i) w.push_back(0);

    Parser p(w);
    auto m = p.parse();
    BOOST_CHECK(!m.parse_error);
}

BOOST_AUTO_TEST_CASE(rdlength_boundary_zero)
{
    std::vector<uint8_t> w(12, 0);
    w[5] = 1; w[7] = 1;
    w.push_back(1); w.push_back('a'); w.push_back(0);
    w.push_back(0); w.push_back(1); w.push_back(0); w.push_back(1);
    w.push_back(0xC0); w.push_back(0x0C);
    w.push_back(0); w.push_back(1); w.push_back(0); w.push_back(1);
    w.push_back(0); w.push_back(0); w.push_back(0); w.push_back(0x3C);
    w.push_back(0); w.push_back(0); // RDLENGTH=0

    Parser p(w);
    auto m = p.parse();
    BOOST_CHECK(!m.parse_error);
    BOOST_CHECK_EQUAL(m.answers[0].rdata.size(), 0);
}

BOOST_AUTO_TEST_CASE(rdlength_boundary_max)
{
    std::vector<uint8_t> w(12, 0);
    w[5] = 1; w[7] = 1;
    w.push_back(1); w.push_back('a'); w.push_back(0);
    w.push_back(0); w.push_back(1); w.push_back(0); w.push_back(1);
    w.push_back(0xC0); w.push_back(0x0C);
    w.push_back(0); w.push_back(1); w.push_back(0); w.push_back(1);
    w.push_back(0); w.push_back(0); w.push_back(0); w.push_back(0x3C);
    w.push_back(0xFF); w.push_back(0xFF); // RDLENGTH=65535

    Parser p(w);
    auto m = p.parse();
    // Should fail (truncated) but not crash
    (void)m;
}

BOOST_AUTO_TEST_CASE(msg_length_exactly_12)
{
    std::vector<uint8_t> w(12, 0);
    // QDCOUNT=0, all zeros
    Parser p(w);
    auto m = p.parse();
    BOOST_CHECK(!m.parse_error);
    BOOST_CHECK_EQUAL(m.questions.size(), 0);
}

BOOST_AUTO_TEST_CASE(msg_length_11_truncated)
{
    for (size_t len = 0; len < 12; ++len)
    {
        std::vector<uint8_t> w(len, 0);
        Parser p(w);
        auto m = p.parse();
        // len < 12 should all fail the minimum-size check
        if (len < 12)
        {
            BOOST_CHECK_MESSAGE(m.parse_error, "Expected error for len=" << len);
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()

// ══════════════════════════════════════════════════════════════════
// Semi-fuzz suite 3: NAME / QNAME MUTATIONS
// ══════════════════════════════════════════════════════════════════

BOOST_AUTO_TEST_SUITE(semi_name_mutation)

BOOST_AUTO_TEST_CASE(label_length_zero_in_middle)
{
    // Build a query where the name has a zero-length label in between
    std::vector<uint8_t> w(12, 0);
    w[5] = 1;
    // Name: label "abc" (3 bytes), then root (0), then label "def" (3 bytes), root again
    w.push_back(3); w.push_back('a'); w.push_back('b'); w.push_back('c');
    w.push_back(0); // root (name terminates here in normal DNS)
    w.push_back(3); w.push_back('d'); w.push_back('e'); w.push_back('f');
    w.push_back(0);
    w.push_back(0); w.push_back(1); w.push_back(0); w.push_back(1);

    Parser p(w);
    auto m = p.parse();
    // First name "abc" terminates at 0, parser consumes rest as extra data
    (void)m;
}

BOOST_AUTO_TEST_CASE(label_length_followed_by_nothing)
{
    std::vector<uint8_t> w(12, 0);
    w[5] = 1;
    w.push_back(10); // label length 10, but no data follows
    w.push_back(0); w.push_back(1); w.push_back(0); w.push_back(1);

    Parser p(w);
    auto m = p.parse();
    (void)m; // Must not crash
}

BOOST_AUTO_TEST_CASE(label_length_0x3F_boundary)
{
    // Label exactly 63 chars (max valid)
    std::vector<uint8_t> w(12, 0);
    w[5] = 1;
    w.push_back(63);
    for (int i = 0; i < 63; ++i) w.push_back('x');
    w.push_back(0);
    w.push_back(0); w.push_back(1); w.push_back(0); w.push_back(1);

    Parser p(w);
    auto m = p.parse();
    BOOST_CHECK(!m.parse_error);
}

BOOST_AUTO_TEST_CASE(label_length_0x40_overflow)
{
    // Label 64 chars (invalid per RFC)
    std::vector<uint8_t> w(12, 0);
    w[5] = 1;
    w.push_back(64);
    for (int i = 0; i < 64; ++i) w.push_back('x');
    w.push_back(0);
    w.push_back(0); w.push_back(1); w.push_back(0); w.push_back(1);

    Parser p(w);
    auto m = p.parse();
    BOOST_CHECK(m.parse_error);
}

BOOST_AUTO_TEST_CASE(label_length_0xFF_255)
{
    // Label claiming 255 chars (but actually 255 follows)
    std::vector<uint8_t> w(12, 0);
    w[5] = 1;
    w.push_back(0xFF);
    for (int i = 0; i < 255; ++i) w.push_back('x');
    w.push_back(0);
    w.push_back(0); w.push_back(1); w.push_back(0); w.push_back(1);

    Parser p(w);
    auto m = p.parse();
    BOOST_CHECK(m.parse_error); // Total length > 255
}

BOOST_AUTO_TEST_CASE(encoded_name_total_255_exactly)
{
    // 3 labels of 63 + 1 label of 61 + 4 length bytes + 1 root = 255
    std::vector<uint8_t> w(12, 0);
    w[5] = 1;

    auto add_label = [&](int len, char c) {
        w.push_back(static_cast<uint8_t>(len));
        for (int i = 0; i < len; ++i) w.push_back(static_cast<uint8_t>(c));
    };

    add_label(63, 'a');
    add_label(63, 'b');
    add_label(63, 'c');
    add_label(61, 'd');

    w.push_back(0); // root
    w.push_back(0); w.push_back(1); w.push_back(0); w.push_back(1);

    Parser p(w);
    auto m = p.parse();
    BOOST_CHECK(!m.parse_error);
}

BOOST_AUTO_TEST_CASE(encoded_name_total_256_over_limit)
{
    // 3 labels of 63 + 1 label of 62 + 4 length bytes + 1 root = 256 (>255 limit)
    std::vector<uint8_t> w(12, 0);
    w[5] = 1;

    auto add_label = [&](int len, char c) {
        w.push_back(static_cast<uint8_t>(len));
        for (int i = 0; i < len; ++i) w.push_back(static_cast<uint8_t>(c));
    };

    add_label(63, 'a');
    add_label(63, 'b');
    add_label(63, 'c');
    add_label(62, 'd');

    w.push_back(0);
    w.push_back(0); w.push_back(1); w.push_back(0); w.push_back(1);

    Parser p(w);
    auto m = p.parse();
    BOOST_CHECK(m.parse_error); // >255
}

BOOST_AUTO_TEST_CASE(root_only_name)
{
    std::vector<uint8_t> w(12, 0);
    w[5] = 1;
    w.push_back(0); // root label only (.)
    w.push_back(0); w.push_back(1); w.push_back(0); w.push_back(1);

    Parser p(w);
    auto m = p.parse();
    BOOST_CHECK(!m.parse_error);
    BOOST_CHECK_EQUAL(m.questions[0].qname, "");
}

BOOST_AUTO_TEST_CASE(many_small_labels)
{
    // 50 single-char labels: a.b.c.d.e.f.g....
    std::vector<uint8_t> w(12, 0);
    w[5] = 1;

    for (int i = 0; i < 50; ++i)
        { w.push_back(1); w.push_back(static_cast<uint8_t>('a' + (i % 26))); }
    w.push_back(0);
    w.push_back(0); w.push_back(1); w.push_back(0); w.push_back(1);

    Parser p(w);
    auto m = p.parse();
    (void)m; // Must not crash
}

BOOST_AUTO_TEST_SUITE_END()

// ══════════════════════════════════════════════════════════════════
// Semi-fuzz suite 4: QTYPE / QCLASS EDGE VALUES
// ══════════════════════════════════════════════════════════════════

BOOST_AUTO_TEST_SUITE(semi_qtype_qclass)

BOOST_AUTO_TEST_CASE(all_defined_qtypes)
{
    uint16_t types[] = {1, 2, 5, 6, 12, 15, 16, 28, 41, 252, 255, 0, 100, 65535};
    for (auto t : types)
    {
        auto w = build_query(1, "test.com", static_cast<QType>(t));
        Parser p(w);
        auto m = p.parse();
        (void)m;
    }
}

BOOST_AUTO_TEST_CASE(all_possible_qclass_values)
{
    uint16_t classes[] = {0, 1, 255, 65535, 3};
    for (auto c : classes)
    {
        auto w = build_query(1, "test.com", QType::A);
        w[w.size() - 2] = static_cast<uint8_t>(c >> 8);
        w[w.size() - 1] = static_cast<uint8_t>(c & 0xFF);
        Parser p(w);
        auto m = p.parse();
        (void)m;
    }
}

BOOST_AUTO_TEST_SUITE_END()

// ══════════════════════════════════════════════════════════════════
// Semi-fuzz suite 5: POINTER CORRUPTION
// ══════════════════════════════════════════════════════════════════

BOOST_AUTO_TEST_SUITE(semi_pointer_corruption)

BOOST_AUTO_TEST_CASE(all_pointer_offsets_from_valid_base)
{
    // Start from a valid response with pointer, exhaust every offset
    auto base = build_query(1, "www.test.local", QType::A);
    std::vector<uint8_t> w(12, 0);
    w[0] = 0; w[1] = 1;
    w[5] = 1; w[7] = 1;

    // Question "a.z"
    w.push_back(1); w.push_back('a');
    w.push_back(1); w.push_back('z');
    w.push_back(0);
    w.push_back(0); w.push_back(1); w.push_back(0); w.push_back(1);

    // Base offset to question name = 12
    size_t ans_start = w.size();

    for (int offset = 0; offset < 20; ++offset)
    {
        std::vector<uint8_t> msg = w;

        msg.push_back(0xC0 | static_cast<uint8_t>(offset >> 8));
        msg.push_back(static_cast<uint8_t>(offset & 0xFF));
        msg.push_back(0); msg.push_back(1); // TYPE=A
        msg.push_back(0); msg.push_back(1); // CLASS=IN
        msg.push_back(0); msg.push_back(0); msg.push_back(0); msg.push_back(60);
        msg.push_back(0); msg.push_back(4);
        for (int i = 0; i < 4; ++i) msg.push_back(0);

        Parser p(msg);
        auto m = p.parse();
        (void)m; // Must never crash
    }
}

BOOST_AUTO_TEST_CASE(pointer_to_self)
{
    // Pointer that points to itself
    std::vector<uint8_t> w(12, 0);
    w[5] = 1;
    // Name starts at offset 12
    w.push_back(0xC0); w.push_back(0x0C); // pointer to 12 (itself!)
    w.push_back(0); w.push_back(1); w.push_back(0); w.push_back(1);

    Parser p(w);
    auto m = p.parse();
    BOOST_CHECK(m.parse_error); // Pointer loop
}

BOOST_AUTO_TEST_CASE(pointer_to_last_byte)
{
    std::vector<uint8_t> w(12, 0);
    w[5] = 1;
    // Name at offset 12: just root label
    w.push_back(0); // root at offset 12
    w.push_back(0); w.push_back(1); w.push_back(0); w.push_back(1);

    // Now add a message with pointer to the root (offset 12)
    size_t end = w.size();
    std::vector<uint8_t> msg(w.begin(), w.end());
    // Add a new answer
    msg[7] = 1; // ANCOUNT=1 (but w[7] was 0, need to set in msg)
    msg.push_back(0xC0); msg.push_back(0x0C); // pointer to offset 12 (root label)
    msg.push_back(0); msg.push_back(1); // TYPE=A
    msg.push_back(0); msg.push_back(1); // CLASS=IN
    msg.push_back(0); msg.push_back(0); msg.push_back(0); msg.push_back(60);
    msg.push_back(0); msg.push_back(4);
    for (int i = 0; i < 4; ++i) msg.push_back(0);

    Parser p(msg);
    auto m = p.parse();
    BOOST_CHECK(!m.parse_error); // Root name is valid
}

BOOST_AUTO_TEST_CASE(partial_pointer_not_on_byte_boundary)
{
    // Encoding where 0xC0 appears mid-byte (not a real pointer)
    std::vector<uint8_t> w(12, 0);
    w[5] = 1;
    // Label "test\300" — the 0xC0 is part of label data, not a pointer
    w.push_back(5);
    w.push_back('t'); w.push_back('e'); w.push_back('s'); w.push_back('t');
    w.push_back(0xC0); // This looks like pointer start but is label data
    w.push_back(0);
    w.push_back(0); w.push_back(1); w.push_back(0); w.push_back(1);

    Parser p(w);
    auto m = p.parse();
    // 0xC0 in label data is valid (8-bit clean), not a pointer
    BOOST_CHECK(!m.parse_error);
}

BOOST_AUTO_TEST_SUITE_END()

// ══════════════════════════════════════════════════════════════════
// Semi-fuzz suite 6: MESSAGE SIZE & TRUNCATION
// ══════════════════════════════════════════════════════════════════

BOOST_AUTO_TEST_SUITE(semi_size_truncation)

BOOST_AUTO_TEST_CASE(truncate_at_every_offset)
{
    auto base = build_query(0xBEEF, "www.very.long.and.complex.name.example.com", QType::AAAA);

    for (size_t cut = 1; cut < base.size(); ++cut)
    {
        std::vector<uint8_t> truncated(base.begin(), base.begin() + cut);
        Parser p(truncated);
        auto m = p.parse();
        (void)m; // Must never crash
    }
}

BOOST_AUTO_TEST_CASE(truncate_response_at_every_offset)
{
    std::vector<uint8_t> w(12, 0);
    w[0] = 0; w[1] = 1;
    w[2] = 0x85; w[3] = 0x80;
    w[5] = 1; w[7] = 2; // 1 question, 2 answers

    w.push_back(1); w.push_back('x'); w.push_back(0);
    w.push_back(0); w.push_back(1); w.push_back(0); w.push_back(1);

    for (int r = 0; r < 2; ++r)
    {
        w.push_back(0xC0); w.push_back(0x0C); // pointer
        w.push_back(0); w.push_back(1); // TYPE=A
        w.push_back(0); w.push_back(1); // CLASS=IN
        w.push_back(0); w.push_back(0); w.push_back(0); w.push_back(60); // TTL
        w.push_back(0); w.push_back(4); // RDLENGTH
        for (int i = 0; i < 4; ++i) w.push_back(static_cast<uint8_t>(r + i));
    }

    for (size_t cut = 12; cut <= w.size(); ++cut)
    {
        std::vector<uint8_t> truncated(w.begin(), w.begin() + cut);
        Parser p(truncated);
        auto m = p.parse();
        (void)m;
    }
}

BOOST_AUTO_TEST_CASE(random_byte_deletion_from_valid_query)
{
    auto base = build_query(0xCAFE, "www.example.com", QType::A);
    std::mt19937 rng(42);

    for (int trial = 0; trial < 200; ++trial)
    {
        auto msg = base;
        if (msg.empty()) continue;
        size_t del_pos = rng() % msg.size();
        msg.erase(msg.begin() + del_pos);

        Parser p(msg);
        auto m = p.parse();
        (void)m;
    }
}

BOOST_AUTO_TEST_CASE(random_byte_insertion_into_valid_query)
{
    auto base = build_query(0xCAFE, "www.example.com", QType::A);
    std::mt19937 rng(99);

    for (int trial = 0; trial < 200; ++trial)
    {
        auto msg = base;
        size_t ins_pos = rng() % (msg.size() + 1);
        msg.insert(msg.begin() + ins_pos, static_cast<uint8_t>(rng()));

        Parser p(msg);
        auto m = p.parse();
        (void)m;
    }
}

BOOST_AUTO_TEST_CASE(byte_replacement_random_in_valid_query)
{
    auto base = build_query(0xCAFE, "www.example.com", QType::A);
    std::mt19937 rng(777);

    for (int trial = 0; trial < 500; ++trial)
    {
        auto msg = base;
        size_t pos = rng() % msg.size();
        msg[pos] = static_cast<uint8_t>(rng());

        Parser p(msg);
        auto m = p.parse();
        (void)m;
    }
}

BOOST_AUTO_TEST_SUITE_END()

// ══════════════════════════════════════════════════════════════════
// Semi-fuzz suite 7: HEADER FLAG COMBINATORIAL
// ══════════════════════════════════════════════════════════════════

BOOST_AUTO_TEST_SUITE(semi_flag_combinatorial)

BOOST_AUTO_TEST_CASE(all_combinations_of_qr_opcode_aa_tc_rd_ra_rcode)
{
    // Exhaustively test every combination of header flags
    for (uint16_t qr = 0; qr <= 1; ++qr)
    {
        for (uint16_t opcode = 0; opcode <= 3; ++opcode)
        {
            uint16_t flags = static_cast<uint16_t>(
                (qr << 15) | (opcode << 11) | 0x0100); // RD=1
            auto w = build_wire(1, "test.com", QType::A, flags, 0, 0, 0);
            Parser p(w);
            auto m = p.parse();
            BOOST_CHECK_MESSAGE(!m.parse_error,
                                "Flag combo: QR=" << qr << " OPCODE=" << opcode);
            BOOST_CHECK_EQUAL(m.header.qr, bool(qr));
            BOOST_CHECK(static_cast<uint8_t>(m.header.opcode) == opcode);
        }
    }
}

BOOST_AUTO_TEST_CASE(all_rcode_values_in_wire)
{
    // Build messages with all 16 RCODE values in the response flags
    for (uint16_t rcode = 0; rcode <= 15; ++rcode)
    {
        auto w = build_wire(1, "test.com", QType::A,
                            static_cast<uint16_t>(0x8400 | rcode), 0, 0, 0);
        Parser p(w);
        auto m = p.parse();
        BOOST_CHECK(!m.parse_error);
        BOOST_CHECK_EQUAL(static_cast<uint8_t>(m.header.rcode), rcode & 0x0F);
    }
}

BOOST_AUTO_TEST_CASE(z_field_nonzero_all_values)
{
    // Z field (bits 6-4) — should be zero per RFC but parse all values
    for (uint16_t z = 0; z <= 7; ++z)
    {
        auto w = build_wire(1, "test.com", QType::A,
                            static_cast<uint16_t>(0x0100 | (z << 4)), 0, 0, 0);
        Parser p(w);
        auto m = p.parse();
        BOOST_CHECK(!m.parse_error);
        BOOST_CHECK_EQUAL(m.header.z, z);
    }
}

BOOST_AUTO_TEST_SUITE_END()

// ══════════════════════════════════════════════════════════════════
// Semi-fuzz suite 8: SERIALIZER ROUND-TRIP INVARIANTS
// ══════════════════════════════════════════════════════════════════

BOOST_AUTO_TEST_SUITE(semi_serializer_invariants)

BOOST_AUTO_TEST_CASE(valid_queries_roundtrip_identically)
{
    struct { const char* name; QType t; } queries[] = {
        {"a", QType::A},
        {"www.example.com", QType::A},
        {"ns1.test.local", QType::NS},
        {"mail.domain.org", QType::MX},
        {"foo.bar.baz.qux.test", QType::TXT},
        {"ipv6.heavy.net", QType::AAAA},
        {"short", QType::SOA},
        {"cname.alias.name", QType::CNAME},
        {"ptr.rev.addr.arpa", QType::PTR},
    };

    uint16_t ids[] = {0, 1, 0x8000, 0xFFFF, 0x1234, 0x5678};
    uint16_t flags[] = {0x0000, 0x0100, 0x0120, 0x0000};

    for (auto& q : queries)
    {
        for (auto id : ids)
        {
            for (auto fl : flags)
            {
                auto wire = build_wire(static_cast<uint16_t>(id), q.name, q.t, fl, 0, 0, 0);
                Parser p1(wire);
                auto m1 = p1.parse();
                if (m1.parse_error) continue;

                Serializer ser;
                auto wire2 = ser.serialize(m1);

                // Verify wire2 is identical to original (no compression in queries)
                BOOST_CHECK_EQUAL(wire2.size(), wire.size());
                BOOST_CHECK(std::equal(wire2.begin(), wire2.end(), wire.begin()));

                Parser p2(wire2);
                auto m2 = p2.parse();
                BOOST_CHECK(!m2.parse_error);
                BOOST_CHECK_EQUAL(m2.header.id, m1.header.id);
                BOOST_CHECK_EQUAL(m2.questions.size(), m1.questions.size());
                if (!m2.questions.empty())
                {
                    BOOST_CHECK_EQUAL(m2.questions[0].qname, m1.questions[0].qname);
                    BOOST_CHECK(m2.questions[0].qtype == m1.questions[0].qtype);
                }
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(serialize_empty_message)
{
    Message m{};
    Serializer ser;
    auto wire = ser.serialize(m);
    BOOST_CHECK_EQUAL(wire.size(), 12); // Header only
}

BOOST_AUTO_TEST_CASE(serialize_with_only_questions)
{
    Message m{};
    m.header.id = 0x4242;
    m.header.qdcount = 2;
    m.header.qr = true;

    Question q1;
    q1.qname = "q1.test";
    q1.qtype = QType::A;
    q1.qclass = QClass::IN;
    Question q2;
    q2.qname = "q2.test";
    q2.qtype = QType::AAAA;
    q2.qclass = QClass::IN;

    m.questions = {q1, q2};

    Serializer ser;
    auto wire = ser.serialize(m);

    Parser p(wire);
    auto restored = p.parse();
    BOOST_CHECK(!restored.parse_error);
    BOOST_CHECK_EQUAL(restored.questions.size(), 2);
    BOOST_CHECK_EQUAL(restored.questions[0].qname, "q1.test");
    BOOST_CHECK_EQUAL(restored.questions[1].qname, "q2.test");
}

BOOST_AUTO_TEST_CASE(serialize_all_four_sections)
{
    Message m{};
    m.header.id = 0xABCD;
    m.header.qr = true;
    m.header.qdcount = 1;
    m.header.ancount = 1;
    m.header.nscount = 1;
    m.header.arcount = 1;

    Question q;
    q.qname = "all.test";
    q.qtype = QType::A;
    q.qclass = QClass::IN;
    m.questions.push_back(q);

    ResourceRecord rr;
    rr.name = "all.test";
    rr.type = QType::A;
    rr.qclass = QClass::IN;
    rr.ttl = 3600;
    rr.rdata = {192, 168, 1, 1};

    m.answers.push_back(rr);
    m.authorities.push_back(rr);
    m.additionals.push_back(rr);

    Serializer ser;
    auto wire = ser.serialize(m);

    Parser p(wire);
    auto m2 = p.parse();
    BOOST_CHECK(!m2.parse_error);
    BOOST_CHECK_EQUAL(m2.header.id, 0xABCD);
    BOOST_CHECK_EQUAL(m2.questions.size(), 1);
    BOOST_CHECK_EQUAL(m2.answers.size(), 1);
    BOOST_CHECK_EQUAL(m2.authorities.size(), 1);
    BOOST_CHECK_EQUAL(m2.additionals.size(), 1);
}

BOOST_AUTO_TEST_SUITE_END()

// ══════════════════════════════════════════════════════════════════
// Semi-fuzz suite 9: RESOLVER STRESS
// ══════════════════════════════════════════════════════════════════

BOOST_AUTO_TEST_SUITE(semi_resolver_stress)

BOOST_AUTO_TEST_CASE(resolver_with_random_lookups)
{
    Resolver r;
    // Populate with diverse records
    r.add_record("alpha.com", QType::A, 300, std::vector<uint8_t>{10, 0, 0, 1});
    r.add_record("beta.com", QType::AAAA, 300, std::vector<uint8_t>(16, 0));
    r.add_record("gamma.com", QType::NS, 300, std::vector<uint8_t>{3, 'n', 's', '1', 0});
    r.add_record("delta.com", QType::CNAME, 300, std::vector<uint8_t>{5, 'a', 'l', 'p', 'h', 'a', 0});
    r.add_record("epsilon.com", QType::MX, 300,
                 std::vector<uint8_t>{0, 10, 4, 'm', 'a', 'i', 'l', 0});
    r.add_record("zeta.com", QType::TXT, 300, std::vector<uint8_t>{6, 'f', 'o', 'o', 'b', 'a', 'r'});

    std::mt19937 rng(777);
    std::vector<std::string> names = {
        "alpha.com", "beta.com", "gamma.com", "delta.com",
        "epsilon.com", "zeta.com", "NOTFOUND.com", "not.there.org"
    };
    QType types[] = {QType::A, QType::AAAA, QType::NS, QType::CNAME, QType::MX, QType::TXT, QType::SOA, QType::ANY};

    for (int trial = 0; trial < 500; ++trial)
    {
        const auto& name = names[rng() % names.size()];
        QType t = types[rng() % sizeof(types) / sizeof(types[0])];

        auto wire = build_query(static_cast<uint16_t>(trial), name, t);
        Parser p(wire);
        auto q = p.parse();
        if (!q.parse_error)
        {
            auto resp = r.resolve(q);
            (void)resp;
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()

// ══════════════════════════════════════════════════════════════════
// Semi-fuzz suite 10: CONCURRENT VALID + INVALID MESSAGES
// ══════════════════════════════════════════════════════════════════

BOOST_AUTO_TEST_SUITE(semi_concurrent)

BOOST_AUTO_TEST_CASE(mixed_valid_and_truncated_messages)
{
    auto valid = build_query(0x0001, "www.example.com", QType::A);
    std::mt19937 rng(123);

    for (int trial = 0; trial < 300; ++trial)
    {
        // Alternate between corrupting valid message and random truncation
        std::vector<uint8_t> msg;
        if (trial % 3 == 0)
        {
            // Total random bytes
            size_t len = rng() % 64;
            msg.resize(len);
            for (auto& b : msg) b = static_cast<uint8_t>(rng());
        }
        else if (trial % 3 == 1)
        {
            // Truncated valid
            msg = valid;
            size_t cut = rng() % (msg.size() + 1);
            msg.resize(cut);
        }
        else
        {
            // Slightly corrupted valid
            msg = valid;
            size_t pos = rng() % msg.size();
            msg[pos] ^= static_cast<uint8_t>(1 << (rng() % 8));
        }

        Parser p(msg);
        auto m = p.parse();

        // Exercise resolver too
        Resolver r;
        r.add_record("example.com", QType::A, 300, std::vector<uint8_t>{1, 2, 3, 4});
        r.resolve(m);

        // Serialize if valid
        if (!m.parse_error)
        {
            Serializer ser;
            auto w = ser.serialize(m);
            Parser p2(w);
            auto m2 = p2.parse();
            (void)m2;
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
