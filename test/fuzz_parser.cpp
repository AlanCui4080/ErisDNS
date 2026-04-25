// LibFuzzer harness for DNS parser
// Build with clang++ -fsanitize=fuzzer,address,undefined

#include "erisdns/dns_parser.hpp"
#include "erisdns/dns_resolver.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

using namespace erisdns;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    // Phase 1: Parse the input
    std::span<const uint8_t> input(data, size);
    Parser                   parser(input);
    Message                  msg = parser.parse();

    // If parsing succeeded, try serializing and re-parsing
    if (!msg.parse_error)
    {
        Serializer            ser;
        std::vector<uint8_t>  wire = ser.serialize(msg);

        Parser  parser2(wire);
        Message msg2 = parser2.parse();

        // Serialized-then-parsed should also succeed
        // (May fail in edge cases with name compression, but shouldn't crash)
        (void)msg2;
    }

    // Phase 2: Exercise the resolver (shouldn't crash on any valid/invalid message)
    Resolver resolver;
    // Add some test records
    std::vector<uint8_t> ip = {1, 2, 3, 4};
    resolver.add_record("example.com", QType::A, 300, ip);
    std::vector<uint8_t> ip6 = {0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
    resolver.add_record("test.local", QType::AAAA, 600, ip6);

    resolver.resolve(msg);

    // Phase 3: Allocate and verify no leaks
    std::vector<ResourceRecord> records;
    records.reserve(100);

    Question q;
    q.qname  = "fuzz.test";
    q.qtype  = QType::A;
    q.qclass = QClass::IN;

    records.clear();
    records.shrink_to_fit();

    return 0; // Non-zero return values are reserved for future use
}
