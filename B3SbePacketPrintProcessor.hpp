#ifndef B3_SBE_PACKET_PRINT_PROCESSOR_HPP
#define B3_SBE_PACKET_PRINT_PROCESSOR_HPP

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <span>

#include "b3_sbe_packet_processor.hpp"

struct B3SbePacketPrintProcessor final
{
    std::size_t counter = 0;

    void on_packet_begin(const b3_sbe_packet_header& h) noexcept
    {
        ++counter;
        std::printf("pkt [%d] [%d] [%d] [%d] [%zx]\n", 
            h.channel_id, h.reserved, h.sequence_version, h.sequence_number, h.sending_time);
    }

    void on_message(const b3_sbe_packet_header&, const b3_sbe_message_header& h, std::span<const std::uint8_t> payload) noexcept
    {
        using std::printf;
        printf("msg [%d] [%x]\t| [%d] [%d] [%d] [%d]", 
            h.message_length, h.encoding_type, h.block_length, 
            h.template_id, h.schema_id, h.schema_version);

        std::size_t n = 16;
        bool smaller = payload.size() <= n;
        if (smaller) n = payload.size();
        if (n) printf("\t| [");        
        for (std::size_t i = 0; i < n; ++i)
            printf("%x", payload[i]);
        if (!smaller) std::printf("...");
        if (n) printf("]");
        printf("\n");
    }

    void on_packet_end(const b3_sbe_packet_header&) noexcept
    {
        std::printf("%zd --------\n", counter);
    }
};

#endif // B3_SBE_PACKET_PRINT_PROCESSOR_HPP