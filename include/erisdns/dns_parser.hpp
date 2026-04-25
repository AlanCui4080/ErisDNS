#pragma once

#include "dns_types.hpp"

#include <span>
#include <string_view>

namespace erisdns {

class Parser
{
public:
    explicit Parser(std::span<const uint8_t> data);

    Message parse();

private:
    const uint8_t* begin_;
    const uint8_t* end_;
    const uint8_t* pos_;
    Message        msg_;

    // Read helpers
    uint8_t  read_u8();
    uint16_t read_u16();
    uint32_t read_u32();

    // Parse sub-structures
    Header           parse_header();
    Question         parse_question();
    ResourceRecord   parse_rr();

    // Name decoding: returns the uncompressed name string
    // raw_name_out gets the wire bytes (labels only, pointers resolved)
    std::string decode_name(std::vector<uint8_t>& raw_name_out);

    // Name decoding without recording wire bytes
    std::string decode_name();

    // Decode a label length or pointer from the current position,
    // advancing pos_ if appropriate. Returns the decoded label.
    struct NameResult {
        std::vector<uint8_t> labels; // the label bytes
        size_t               bytes_read;
        bool                 is_pointer;
        const uint8_t*       jump_target;
    };
    NameResult read_label_or_pointer();
};

// Serialize a Message back to wire format
class Serializer
{
public:
    std::vector<uint8_t> serialize(const Message& msg);

private:
    std::vector<uint8_t> buf_;

    void write_u8(uint8_t v);
    void write_u16(uint16_t v);
    void write_u32(uint32_t v);
    void write_bytes(std::span<const uint8_t> data);

    void write_header(const Header& h);
    void write_question(const Question& q);
    void write_rr(const ResourceRecord& rr);
    void write_name(const std::string& name);
};

} // namespace erisdns
