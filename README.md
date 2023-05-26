# C++ Network Packet Analyzer

This is a simple packet analyzer implemented in C++14. It captures and analyzes network packets, extracting information such as source and destination IP addresses and port numbers.

## Features

- Capture and analyze network packets
- Display source and destination IP addresses
- Display source and destination port numbers

## Prerequisites

- C++14 compatible compiler
- libpcap library

## Implementation

### C++14 Implementation

The C++14 implementation of the packet analyzer can be found in the file [packet_analyzer.cpp](packet_analyzer.cpp). It uses the libpcap library to capture packets and processes them to extract IP and TCP header information.

To compile and run the C++14 implementation:

1. Install the libpcap development package.
2. Compile the code using your preferred C++14 compatible compiler:

```bash
g++ -std=c++14 -o packet_analyzer packet_analyzer.cpp -lpcap

