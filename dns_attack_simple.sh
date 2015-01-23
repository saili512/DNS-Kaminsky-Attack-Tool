#!/bin/sh
# uncomment the one you want to run

# send fake dns query and responses for each query
./pacgen -p payload_query2_new -t udp_header_query -i ip_header_query -e eth_header_query_new

