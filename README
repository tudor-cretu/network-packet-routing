# Dataplane Router

## Overview

This project implements a simple software-based router in C, designed to forward IP packets between interfaces according to a static routing table. It is capable of handling ARP resolution, generating ICMP messages for error handling, and performing basic packet forwarding tasks. The router operates on a simple level, making it suitable for educational purposes and as a foundation for more complex routing functionalities.

## Detailed Description

### How It Works

The simple router program operates by continuously receiving and processing Ethernet frames. Each frame is analyzed to determine if it contains an IPv4 packet. If so, the program proceeds to perform several key functions based on the packet's destination IP address and the contents of its routing and ARP tables.

### Key Functionalities

- **Routing Table Management**: The router maintains a static routing table, where each entry specifies a network destination, a subnet mask, the next-hop IP address, and the interface to use for forwarding. Entries in the routing table are sorted by their network prefix and mask length to facilitate efficient route lookup.

- **ARP Table Lookup**: For forwarding a packet, the router consults its ARP table to find the MAC address associated with the next-hop IP. This table is populated with entries mapping IP addresses to their corresponding MAC addresses.

- **ICMP Message Generation**: The router can generate ICMP messages in response to various events, such as TTL expiration or unreachable destinations. These messages are sent back to the source IP address to indicate issues encountered during packet processing.

- **Packet Forwarding**: Upon determining the best route for a packet, the router modifies the packet's Ethernet header with the correct MAC addresses, decrements the TTL, recalculates the IP checksum, and forwards the packet to the appropriate interface.

### Processing Flow

1. **Packet Reception**: The router listens for incoming packets on all its interfaces.

2. **Routing Decision**: If the packet is an IPv4 packet, the router checks its destination IP against the routing table to determine the best route. If the destination IP is the router's IP, it processes the packet locally.

3. **ICMP Handling**: Depending on the packet's contents and state (e.g., TTL value), the router may generate and send ICMP messages.

4. **Forwarding**: The router updates the packet's Ethernet header with the new source and destination MAC addresses, decrements the TTL, updates the IP checksum, and forwards the packet out of the designated interface.


## Conclusion

The simple router project provides a foundational understanding of how routers operate in a network, including packet forwarding, routing table management, and basic network protocol handling. Its straightforward implementation serves as a stepping stone towards more complex network programming and routing solutions.
