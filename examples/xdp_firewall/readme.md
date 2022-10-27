# xdp firewall

This example eBPF program utilises XDP (eXpress Data Path) to place our firewall logic directly into the network driver. 

## What is happening within our firewall

For every packet that traverses the nic we will convert into an ethernet frame, inspect the headers to ensure that the frame contains an IPv4 packet. We will then create an IP header (and pop off the top of the ethernet header), allowing us to inspect the details of the IP packet. We confirm the type/protocol of the packet (UDP/TCP/ICMP) and act accordingly.

The go code that creates our application will take pass an IP address into the eBPF map, that is looked up when ever a packet traverses the nic. If that IP address exists within the map then we will act on it, in this example the packet is dropped by returning `XDP_DROP`.

## Running this example

This binary takes two parameters, the first being the adapter that we will bind our eBPF code to and the second being the IP address that we will pass to the eBPF code through the map.

`go run -exec sudo ./examples/xdp_firewall/ ens160 192.168.0.200`

## Next steps

This example contains additional code to enable the understanding of `ICMP/TCP/UDP`, which should enable a potential user to expand this example for blocking both an address and a specific port that the traffic is travelling on.