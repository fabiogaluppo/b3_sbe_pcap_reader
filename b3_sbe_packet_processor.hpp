/* -------------------------------------------------------------------------------------------------
*
* B3 SBE PCAP READER 
* ==================
*
* This file:
*    base b3 sbe packet processor
*
* Authors: 
*   Fabio Galuppo
*
* Releases: April 28 2026 - v0.1
*   v0.1 - April 2026 - initial release
*
* The MIT License (MIT)
* Copyright © 2026 Fabio Galuppo
* 
* Permission is hereby granted, free of charge, to any person obtaining a copy of this software
* and associated documentation files (the “Software”), to deal in the Software without
* restriction, including without limitation the rights to use, copy, modify, merge, publish,
* distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the
* Software is furnished to do so, subject to the following conditions:
* 
* The above copyright notice and this permission notice shall be included in all copies or
* substantial portions of the Software.
* 
* THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING
* BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
* NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
* DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
* FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
* 
------------------------------------------------------------------------------------------------- */

#ifndef B3_SBE_PACKET_PROCESSOR_HPP
#define B3_SBE_PACKET_PROCESSOR_HPP

#include <concepts>
#include <cstddef>
#include <cstdint>
#include <span>

#pragma pack(push, 1)
struct b3_sbe_packet_header
{
    std::uint8_t channel_id;
    std::uint8_t reserved;
    std::uint16_t sequence_version;
    std::uint32_t sequence_number;
    std::uint64_t sending_time;
};

struct b3_sbe_message_header
{
    std::uint16_t message_length;
    std::uint16_t encoding_type;
    std::uint16_t block_length;
    std::uint16_t template_id;
    std::uint16_t schema_id;
    std::uint16_t schema_version;
};
#pragma pack(pop)

template<typename P>
concept B3SbePacketProcessor =
    requires(P p, const b3_sbe_packet_header& b3_sbe_packet_header_ref,
             const b3_sbe_message_header& b3_sbe_message_header_ref, 
             std::span<const std::uint8_t> payload)
{
    { p.on_packet_begin(b3_sbe_packet_header_ref) } -> std::same_as<void>;
    { p.on_message(b3_sbe_packet_header_ref, b3_sbe_message_header_ref, payload) } -> std::same_as<void>;
    { p.on_packet_end(b3_sbe_packet_header_ref) } -> std::same_as<void>;
};

namespace detail
{
    template<B3SbePacketProcessor P>
    static inline void unsafe_read_b3_sbe_message(bool can_read, const std::uint8_t* payload, std::size_t payload_size, const b3_sbe_packet_header* ph, P&& processor)
    {
        if (!can_read)
            return;
        const b3_sbe_message_header* h = reinterpret_cast<const b3_sbe_message_header*>(payload);
        processor.on_message(*ph, *h, std::span(payload + 12, h->block_length));
        unsafe_read_b3_sbe_message(payload_size > h->message_length, payload + h->message_length, payload_size - h->message_length, ph, processor);
    }

    template<B3SbePacketProcessor P>
    static inline void unsafe_read_b3_sbe_packet_header(const std::uint8_t* payload, std::size_t payload_size, P&& processor)
    {
        const b3_sbe_packet_header* h = reinterpret_cast<const b3_sbe_packet_header*>(payload);
        processor.on_packet_begin(*h);
        unsafe_read_b3_sbe_message(true, payload + 16, payload_size - 16, h, processor);
        processor.on_packet_end(*h);
    }
}

struct NullProcessor
{
    void on_packet_begin(const b3_sbe_packet_header&) const noexcept {}
    void on_message(const b3_sbe_packet_header&, const b3_sbe_message_header&, std::span<const std::uint8_t>) const noexcept {}
    void on_packet_end(const b3_sbe_packet_header&) const noexcept {}
};

template<B3SbePacketProcessor P>
static inline void read_b3_sbe_packet(std::span<const std::uint8_t> payload, P&& processor)
{
    detail::unsafe_read_b3_sbe_packet_header(payload.data(), payload.size(), processor);
}

#endif // B3_SBE_PACKET_PROCESSOR_HPP