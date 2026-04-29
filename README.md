# B3 SBE PCAP Reader

A reader utility and sample for B3 SBE PCAPs in C++ using [PcapPlusPlus](https://pcapplusplus.github.io/) 

### Build instructions

- Build with CMake for Visual C++ (x64 VS 2022 and Windows SDK version 10.0.26100.0)
```str
cmake -S . -B build-win -DPCAP_ROOT=%CD%\external\npcap-sdk-1.16 -DPCAPPP_BUILD_EXAMPLES=OFF -DPCAPPP_BUILD_TESTS=OFF
cmake --build build-win -j --config Release
```

- Build with CMake for g++ 12
```str
CC=/usr/bin/gcc-12 CXX=/usr/bin/g++-12 cmake -S . -B build-lin -DPCAPPP_BUILD_EXAMPLES=OFF -DPCAPPP_BUILD_TESTS=OFF
cmake --build build-lin -j --config Release
```

### C++ example 

- C++ snippet to read UDP packets with PcapPlusPlus and basic B3 SBE processing

```cpp
pcpp::PcapFileReaderDevice reader(args.filename);
B3SbePacketPrintProcessor p;
pcpp::RawPacket rawPacket;
while (reader.getNextPacket(rawPacket))
{	
    pcpp::Packet parsedPacket(&rawPacket);
    if (parsedPacket.isPacketOfType(pcpp::UDP))
    {
        pcpp::UdpLayer* udpLayerPtr = parsedPacket.getLayerOfType<pcpp::UdpLayer>();            
        read_b3_sbe_packet(std::span(udpLayerPtr->getLayerPayload(), udpLayerPtr->getLayerPayloadSize()), p);
    }
}
reader.close();
```

### Linux screenshot

![B3 SBE PCAP Reader in action](/images/b3_sbe_pcap_reader_linux.png "B3 SBE PCAP Reader in action")

### WSL VSCODE Terminal screenshot

![B3 SBE PCAP Reader in action](/images/b3_sbe_pcap_reader_wsl_vscode.png "B3 SBE PCAP Reader in action")

### Windows screenshot

![B3 SBE PCAP Reader in action](/images/b3_sbe_pcap_reader_windows.png "B3 SBE PCAP Reader in action")

## License

MIT

**Free Software, Hell Yeah!**
