# 🛰️ Minimal IPv4 Software Router

This project implements a **minimalist IPv4 software router** in C, designed as an **educational tool** for understanding how packets are processed at the network layer inside a router.  
The router handles the essential responsibilities of an IP forwarding device: making routing decisions, resolving next-hop addresses, generating ICMP control messages, and maintaining an ARP cache for link-layer delivery.  

---

## 📖 Overview

Routers are critical components of the Internet: they interconnect networks, decide how packets should be forwarded, and handle situations where packets cannot be delivered.  
This project aims to capture that **core forwarding logic** in a compact implementation, while remaining clear enough to be studied, modified, and extended.  

At a high level, the router:

- Listens for Ethernet frames on multiple interfaces.
- Distinguishes between IPv4 packets and ARP frames.
- Validates and updates IPv4 headers, including TTL and checksum.
- Uses **Longest-Prefix Match (LPM)** to select the most specific route towards the destination.
- Handles unknown link-layer destinations with ARP resolution and queues pending packets.
- Responds to control-plane events via ICMP (Echo Reply, Destination Unreachable, Time Exceeded).
- Maintains a dynamic ARP table, learned automatically without preloaded files.

The result is a **self-contained router dataplane** that can run inside a lab framework or emulator, forwarding packets between multiple networks and responding intelligently to traffic directed at itself.

---

## 🌐 Core Components

1. **Ethernet Frame Demultiplexing**  
   Frames are inspected by `ethertype`. The router forwards IPv4 packets to the IP processing path and ARP frames to the ARP handler.  

2. **IPv4 Forwarding**  
   - Verifies checksums and TTL values.  
   - If TTL expires, generates an ICMP *Time Exceeded* message.  
   - If the packet is addressed to one of the router’s own interfaces and carries ICMP, it responds with an *Echo Reply*.  
   - Otherwise, it consults the routing table and forwards the packet to the next hop.  

3. **Routing Table (LPM)**  
   - Built automatically from the router’s own interfaces (directly-connected networks).  
   - Optionally extended with a default route.  
   - Lookup is performed with Longest-Prefix Match (linear scan for simplicity).  

4. **ARP Subsystem**  
   - Maintains a cache of IP–MAC mappings learned from ARP traffic.  
   - Sends ARP Requests when forwarding requires a MAC address not yet known.  
   - Holds packets in a pending queue until the ARP Reply arrives, then flushes them immediately.  

5. **ICMP Handling**  
   - **Echo Reply** for ping requests to router IPs.  
   - **Destination Unreachable** when no route exists.  
   - **Time Exceeded** when TTL reaches zero.  

---

## 🎯 Educational Value

This router is intentionally minimalist, prioritizing **clarity over performance**.  
It demonstrates the fundamental algorithms and mechanisms at the heart of real routers, while stripping away kernel-level complexities.  

By reading and experimenting with this code, one can gain practical understanding of:  

- IP header structure and integrity checks.  
- The routing decision process and longest-prefix match.  
- ARP as a bridge between network and link layers.  
- ICMP as the signaling protocol of IP.  
- How a router’s dataplane operates in tight loops, continuously handling packets.  

This makes the project a **hands-on introduction** to computer networking internals, well-suited for students, hobbyists, and anyone curious about how packets move through the Internet.

---

## 🔮 Extensibility

While minimal by design, the router can serve as a foundation for more advanced features:  

- Implementing ARP timeouts and retries.  
- Supporting IPv4 fragmentation and reassembly.  
- Adding IPv6 forwarding.  
- Improving LPM efficiency with prefix tries or binary search.  
- Introducing a control-plane socket or CLI to dynamically install routes.  
- Collecting statistics (e.g., packets forwarded, ARP requests sent, ICMP errors generated).  

---

## 📜 Summary

This project is not a production router, but a **learning-oriented reimplementation** of core forwarding logic.  
It demonstrates how a router:  
- receives frames,  
- processes headers,  
- chooses routes,  
- resolves MAC addresses,  
- and handles errors with ICMP.  

In doing so, it provides an accessible window into the essential mechanics that keep real-world networks running.  
