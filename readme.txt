Group members: Dawson Perron (dperron)
Work Division: I did everything

Known issues: ICMP contains bogus protocol
I'm not sure what it is. Everything else is right. 
The error in wireshark says Bogus protocol version 7.
The checksum is correct. My router has udp traceroute. 
I also copied the ipheader and udp payload into the data portion of icmp.
This is the only thing stopping it from picking up my router.

Unfortunately the solution router does traceroute using icmp so I can't use that to debug :(
Otherwise I would have been able to pinpoint the mismatch and fix it.
Currently it is able to send ICMP packets with correct checksums, codes, and types.

Design: I tried to follow the pseudo code of the instructions as best as I could.
First I made a skeleton deciding what logic to use when certain packets arived.
Then I filled in the logic starting with arp requests, ip packets, arp replies, then icmp.

One thing in my code is that the packets I generate come from a buffer not defined on the heap so it never needs to be freed.

