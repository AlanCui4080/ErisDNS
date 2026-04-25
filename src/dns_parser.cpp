#include "erisdns/dns_parser.hpp"

#include <algorithm>
#include <cstring>
#include <stdexcept>

namespace erisdns {

// ─── Parser ───────────────────────────────────────────────────────────────────

Parser::Parser(std::span<const uint8_t> data)
    : begin_(data.data())
    , end_(data.data() + data.size())
    , pos_(data.data())
{
}

uint8_t Parser::read_u8()
{
    if (pos_ >= end_)
    {
        throw std::out_of_range("DNS parse: unexpected end of message (u8)");
    }
    return *pos_++;
}

uint16_t Parser::read_u16()
{
    return static_cast<uint16_t>(read_u8() << 8) | static_cast<uint16_t>(read_u8());
}

uint32_t Parser::read_u32()
{
    return static_cast<uint32_t>(read_u16() << 16) | static_cast<uint32_t>(read_u16());
}

Header Parser::parse_header()
{
    Header h{};
    h.id = read_u16();

    uint16_t flags  = read_u16();
    h.qr            = (flags >> 15) & 0x01;
    h.opcode        = static_cast<Opcode>((flags >> 11) & 0x0F);
    h.aa            = (flags >> 10) & 0x01;
    h.tc            = (flags >> 9) & 0x01;
    h.rd            = (flags >> 8) & 0x01;
    h.ra            = (flags >> 7) & 0x01;
    h.z             = (flags >> 4) & 0x07;
    h.rcode         = static_cast<RCode>(flags & 0x0F);

    h.qdcount = read_u16();
    h.ancount = read_u16();
    h.nscount = read_u16();
    h.arcount = read_u16();

    return h;
}

Parser::NameResult Parser::read_label_or_pointer()
{
    NameResult result{};
    const uint8_t* start = pos_;

    if (pos_ >= end_)
    {
        throw std::out_of_range("DNS parse: unexpected end reading label");
    }

    uint8_t b = *pos_;

    // Check for pointer (top 2 bits = 11)
    if ((b & 0xC0) == 0xC0)
    {
        if (pos_ + 1 >= end_)
        {
            throw std::out_of_range("DNS parse: truncated pointer");
        }
        uint16_t offset = static_cast<uint16_t>(read_u16() & 0x3FFF);
        result.is_pointer   = true;
        result.jump_target  = begin_ + offset;
        result.bytes_read   = 2;
        return result;
    }

    // Regular label
    uint8_t  len   = b;
    pos_++;

    if (len > 63)
    {
        throw std::runtime_error("DNS parse: invalid label length > 63");
    }

    if (pos_ + len > end_)
    {
        throw std::out_of_range("DNS parse: truncated label");
    }

    result.labels.reserve(len + 1);
    result.labels.push_back(len);
    for (uint8_t i = 0; i < len; ++i)
    {
        result.labels.push_back(*pos_++);
    }

    result.bytes_read = pos_ - start;
    return result;
}

std::string Parser::decode_name()
{
    std::vector<uint8_t> dummy;
    return decode_name(dummy);
}

std::string Parser::decode_name(std::vector<uint8_t>& raw_name_out)
{
    raw_name_out.clear();
    const uint8_t* saved_pos = pos_;
    bool            jumped   = false;

    // Max 10 pointer jumps to prevent infinite loops
    int jump_count = 0;
    int total_len  = 0;

    std::string name;

    for (;;)
    {
        if (pos_ >= end_)
        {
            throw std::out_of_range("DNS parse: truncated name");
        }

        auto result = read_label_or_pointer();

        if (result.is_pointer)
        {
            if (++jump_count > 10)
            {
                throw std::runtime_error("DNS parse: pointer loop detected");
            }
            if (result.jump_target < begin_ || result.jump_target >= end_)
            {
                throw std::runtime_error("DNS parse: pointer out of bounds");
            }
            if (!jumped)
            {
                // Record uncompressed wire bytes up to the pointer
                size_t consumed = pos_ - saved_pos;
                raw_name_out.insert(raw_name_out.end(), saved_pos, saved_pos + consumed);
                jumped = true;
            }
            pos_ = result.jump_target;
            continue;
        }

        uint8_t len = result.labels[0];
        total_len += len + 1;
        if (total_len > 255)
        {
            throw std::runtime_error("DNS parse: name too long (>255)");
        }

        if (len == 0)
        {
            break;
        }

        // Build dotted name
        if (!name.empty())
        {
            name += '.';
        }
        name.append(reinterpret_cast<const char*>(result.labels.data() + 1), len);
    }

    if (!jumped)
    {
        // No pointer was encountered: record all raw bytes
        raw_name_out.insert(raw_name_out.end(), saved_pos, pos_);
    }
    else
    {
        pos_ = saved_pos + raw_name_out.size();
    }

    return name;
}

Question Parser::parse_question()
{
    Question q;
    q.qname  = decode_name(q.raw_name);
    q.qtype  = static_cast<QType>(read_u16());
    q.qclass = static_cast<QClass>(read_u16());
    return q;
}

ResourceRecord Parser::parse_rr()
{
    ResourceRecord rr;
    rr.name   = decode_name(rr.raw_name);
    rr.type   = static_cast<QType>(read_u16());
    rr.qclass = static_cast<QClass>(read_u16());
    rr.ttl    = read_u32();
    uint16_t rdlen = read_u16();

    if (pos_ + rdlen > end_)
    {
        throw std::out_of_range("DNS parse: truncated RDATA");
    }

    rr.rdata.assign(pos_, pos_ + rdlen);
    pos_ += rdlen;

    return rr;
}

Message Parser::parse()
{
    msg_ = Message{};

    try
    {
        // Minimum DNS message: 12 byte header
        if (end_ - pos_ < 12)
        {
            msg_.parse_error = true;
            msg_.error_msg   = "Message too short (< 12 bytes)";
            return msg_;
        }

        msg_.header = parse_header();

        uint16_t total_rr = msg_.header.qdcount
                          + msg_.header.ancount
                          + msg_.header.nscount
                          + msg_.header.arcount;

        // Quick sanity: reject obviously too-large counts
        if (total_rr > 256)
        {
            msg_.parse_error = true;
            msg_.error_msg   = "Too many RRs (>" + std::to_string(256) + ")";
            return msg_;
        }

        for (uint16_t i = 0; i < msg_.header.qdcount; ++i)
        {
            msg_.questions.push_back(parse_question());
        }
        for (uint16_t i = 0; i < msg_.header.ancount; ++i)
        {
            msg_.answers.push_back(parse_rr());
        }
        for (uint16_t i = 0; i < msg_.header.nscount; ++i)
        {
            msg_.authorities.push_back(parse_rr());
        }
        for (uint16_t i = 0; i < msg_.header.arcount; ++i)
        {
            msg_.additionals.push_back(parse_rr());
        }
    }
    catch (const std::exception& e)
    {
        msg_.parse_error = true;
        msg_.error_msg   = e.what();
    }

    return msg_;
}

// ─── Serializer ────────────────────────────────────────────────────────────────

void Serializer::write_u8(uint8_t v)
{
    buf_.push_back(v);
}

void Serializer::write_u16(uint16_t v)
{
    buf_.push_back(static_cast<uint8_t>(v >> 8));
    buf_.push_back(static_cast<uint8_t>(v & 0xFF));
}

void Serializer::write_u32(uint32_t v)
{
    buf_.push_back(static_cast<uint8_t>(v >> 24));
    buf_.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
    buf_.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
    buf_.push_back(static_cast<uint8_t>(v & 0xFF));
}

void Serializer::write_bytes(std::span<const uint8_t> data)
{
    buf_.insert(buf_.end(), data.begin(), data.end());
}

void Serializer::write_name(const std::string& name)
{
    if (name.empty())
    {
        write_u8(0);
        return;
    }

    size_t start = 0;
    while (start < name.size())
    {
        size_t dot = name.find('.', start);
        if (dot == std::string::npos)
        {
            dot = name.size();
        }
        size_t len = dot - start;
        if (len > 63)
        {
            len = 63; // truncate, shouldn't happen with valid names
        }
        write_u8(static_cast<uint8_t>(len));
        for (size_t i = 0; i < len; ++i)
        {
            write_u8(static_cast<uint8_t>(name[start + i]));
        }
        start = dot + 1;
    }
    write_u8(0); // root label
}

void Serializer::write_header(const Header& h)
{
    write_u16(h.id);

    uint16_t flags = 0;
    if (h.qr)  flags |= 0x8000;
    flags |= (static_cast<uint8_t>(h.opcode) & 0x0F) << 11;
    if (h.aa)  flags |= 0x0400;
    if (h.tc)  flags |= 0x0200;
    if (h.rd)  flags |= 0x0100;
    if (h.ra)  flags |= 0x0080;
    flags |= (h.z & 0x07) << 4;
    flags |= static_cast<uint8_t>(h.rcode) & 0x0F;
    write_u16(flags);

    write_u16(static_cast<uint16_t>(h.qdcount));
    write_u16(static_cast<uint16_t>(h.ancount));
    write_u16(static_cast<uint16_t>(h.nscount));
    write_u16(static_cast<uint16_t>(h.arcount));
}

void Serializer::write_question(const Question& q)
{
    write_name(q.qname);
    write_u16(static_cast<uint16_t>(q.qtype));
    write_u16(static_cast<uint16_t>(q.qclass));
}

void Serializer::write_rr(const ResourceRecord& rr)
{
    write_name(rr.name);
    write_u16(static_cast<uint16_t>(rr.type));
    write_u16(static_cast<uint16_t>(rr.qclass));
    write_u32(rr.ttl);
    write_u16(static_cast<uint16_t>(rr.rdata.size()));
    write_bytes(rr.rdata);
}

std::vector<uint8_t> Serializer::serialize(const Message& msg)
{
    buf_.clear();

    write_header(msg.header);

    for (const auto& q : msg.questions)
    {
        write_question(q);
    }
    for (const auto& rr : msg.answers)
    {
        write_rr(rr);
    }
    for (const auto& rr : msg.authorities)
    {
        write_rr(rr);
    }
    for (const auto& rr : msg.additionals)
    {
        write_rr(rr);
    }

    return buf_;
}

} // namespace erisdns
