/* -------------------------------------------------------------------------------------------------
*
* B3 SBE PCAP READER 
* ==================
*
* This file:
*    print b3 sbe packet processor
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