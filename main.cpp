//g++ 12 (Linux):
//CC=/usr/bin/gcc-12 CXX=/usr/bin/g++-12 cmake -S . -B build-lin -DPCAPPP_BUILD_EXAMPLES=OFF -DPCAPPP_BUILD_TESTS=OFF
//cmake --build build-lin -j --config Release
//./build-lin/b3_sbe_pcap_reader --file 20250929_MBO_072_DRV_SnapshotRecovery.pcap --limit 1000

//Visual C++ (Windows):
//cmake -S . -B build-win -DPCAP_ROOT=%CD%\external\npcap-sdk-1.16 -DPCAPPP_BUILD_EXAMPLES=OFF -DPCAPPP_BUILD_TESTS=OFF
//cmake --build build-win -j --config Release
//.\build-win\Release\b3_sbe_pcap_reader.exe --file 20250929_MBO_072_DRV_SnapshotRecovery.pcap --limit 1000

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <limits>
#include <span>
#include <string>

#include "b3_sbe_packet_processor.hpp"
#include "B3SbePacketPrintProcessor.hpp"

#include "Packet.h"
#include "PcapFileDevice.h"
#include "UdpLayer.h"

struct Args final
{
    std::string filename;
    std::size_t limit;
};

Args parse_args(int argc, char* argv[])
{
    Args args;
    for (int i = 1; i < argc; ++i)
    {
        if ((std::strcmp(argv[i], "-f") == 0 || std::strcmp(argv[i], "--file") == 0) && i + 1 < argc)
        {
            args.filename = argv[++i];
        }
        else if ((std::strcmp(argv[i], "-l") == 0 || std::strcmp(argv[i], "--limit") == 0) && i + 1 < argc)
        {
            const char* val = argv[++i];
            args.limit = std::strcmp(val, "-1") == 0 ? 
                std::numeric_limits<std::size_t>::max() :
                static_cast<std::size_t>(std::strtoull(val, nullptr, 10));
        }
        else
        {
            std::cerr << "Unknown or incomplete argument: " << argv[i] << "\n";
            std::exit(EXIT_FAILURE);
        }
    }

    if (args.filename.empty())
    {
        std::cerr << "Missing required argument: --file <filename>\n";
        std::exit(EXIT_FAILURE);
    }

    return args;
}

int main(int argc, char* argv[])
{
    std::ios::sync_with_stdio(true);
    auto args = parse_args(argc, argv);

    pcpp::PcapFileReaderDevice reader(args.filename); //"20250929_MBO_072_DRV_InstrumentDefinition.pcap" //SBE
	if (!reader.open())
	{
		std::cerr << "Error opening the pcap file: " << args.filename << "\n";
        std::exit(EXIT_FAILURE);
		return 1;
	}

    B3SbePacketPrintProcessor p;
    
    printf("begin --------\n");

    pcpp::RawPacket rawPacket;
	while (reader.getNextPacket(rawPacket))
	{	
        if (args.limit != -1 && p.counter == args.limit)
           break;

        pcpp::Packet parsedPacket(&rawPacket);
        if (parsedPacket.isPacketOfType(pcpp::UDP))
        {
            pcpp::UdpLayer* udpLayerPtr = parsedPacket.getLayerOfType<pcpp::UdpLayer>();            
            read_b3_sbe_packet(std::span(udpLayerPtr->getLayerPayload(), udpLayerPtr->getLayerPayloadSize()), p);
        }
    }

	reader.close();

    printf("end --------\n");    

    return 0;
}