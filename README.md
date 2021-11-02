# ft_malcolm

This projet is part of 42's schools cursus. The subject only asks to send an ARP request to a target device into the network (it's ip address is an argument), and finally, to send an ARP reply to this target that spoof target's ARP table with an arbitrary IP and MAC address (that also are arguments).

This was interesting but a little bit simple, so i've implemented as bonus a man of the middle logger. This functionality can be activated adding a router IP address and a router MAC address to the arguments. With this bonus functionality, the ARP table of target's device and the router are spoofed with an arbitrary MAC (normally my computer's MAC) at each other IP index. Then, the metadata and payload of packet sent by the target or the router are written in a log file and packets are forwarded. Once targets are poisoned, any attemp of ARP will be spoofed ("bloqued"). The program reset the ARP table of the router and the target on termination. Like nothing has happened ...

I will do a better readme in a future.
