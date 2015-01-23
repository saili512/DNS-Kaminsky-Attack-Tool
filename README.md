# DNS-Kaminsky-Attack-Tool
A Kaminsky Attack (Simulation) tool to alter the the IP address that was resolved for a given host.

This tool sends multiple requests with random non-existing names in the attack-domain and then sends multiple
fake responses for each query in hope of being accepted as valid response by the client machine before the actual response
from th DNS Server arrives.

Files -
1. pacgen.c - Modified pacgen tool to generate packets with spoofed IP address for a given request.
2. DNS Request Packet Payload file
3. DNS Response Packet Payload file
4. IP, UDP and Ethernet Header files.
