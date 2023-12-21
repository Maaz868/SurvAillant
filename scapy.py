# from scapy.all import *
# from collections import deque
# import csv

# pkt_timestamps_src = {}
# pkt_timestamps_dst = {}

# def process_packet(packet):
#     global pkt_timestamps_src, pkt_timestamps_dst

#     src_ip = packet[IP].src
#     dst_ip = packet[IP].dst
#     src_mac = packet.src
#     dst_mac = packet.dst
#     src_port = packet[TCP].sport
#     dst_port = packet[TCP].dport
#     tcp_flags = packet[TCP].flags
#     payload_size = len(packet[TCP].payload) 
#     protocol = packet[IP].proto
#     timestamp = packet.time
#     window_size = packet[TCP].window
    
#     pkt_timestamps_src.setdefault(src_ip, deque())
#     pkt_timestamps_dst.setdefault(dst_ip, deque())
#     pkt_timestamps_src[src_ip].append(timestamp)
#     pkt_timestamps_dst[dst_ip].append(timestamp)

#     while pkt_timestamps_src[src_ip] and timestamp - pkt_timestamps_src[src_ip][0] > 2:
#         pkt_timestamps_src[src_ip].popleft()
#     # print(timestamp - pkt_timestamps_src[src_ip][0])
    
#     while pkt_timestamps_dst[dst_ip] and timestamp - pkt_timestamps_dst[dst_ip][0] > 2:
#         pkt_timestamps_dst[dst_ip].popleft()
#     # print(timestamp - pkt_timestamps_dst[dst_ip][0])
    
#     num_pkts_src = len(pkt_timestamps_src[src_ip])
#     num_pkts_dst = len(pkt_timestamps_dst[dst_ip])
#     # print(num_pkts_dst+num_pkts_src)

#     if packet.haslayer(TCP) and packet.haslayer(Raw):
#         modbus_payload = packet[Raw].load  
#         protocol = "ModbusTCP"
#         modbus_function_code = int.from_bytes(modbus_payload[7:8], byteorder='big')
#         if (modbus_function_code == 1 and len(modbus_payload)==10):
#             byte_count = modbus_payload[9]  
#             coil_values = [(byte_count >> i) & 1 for i in range(0, 6)]
#             # print(coil_values)
#         else:
#             coil_values = [0,0,0,0,0,0]

#         if (modbus_function_code == 3 and len(modbus_payload)==19):
#             holdings = []
#             for i in range(9,19,2):
#                 modbus_value = modbus_payload[i:i+2]
#                 modbus_value_int = int.from_bytes(modbus_value, byteorder='big')
#                 holdings.append(modbus_value_int)
#         else:
#             holdings = [0,0,0,0,0]
#     else:
#         modbus_payload = "-"
#         modbus_function_code = "-"
#         coil_values = ['-','-','-','-','-','-']
#         holdings = ['-','-','-','-','-']
        
#         data = [
#             src_ip,
#             dst_ip,
#             src_mac,
#             dst_mac,
#             src_port,
#             dst_port,
#             tcp_flags,
#             payload_size,
#             protocol,
#             timestamp,
#             window_size,
#             num_pkts_src,
#             num_pkts_dst,
#             modbus_payload,
#             modbus_function_code,
#             coil_values,
#             holdings
#             ]
#         with open('output.csv', mode='a', newline='') as file:
#             writer = csv.writer(file)
#             writer.writerow(data)

        
# pcap_file = "normalbehavior.pcapng"
# packets = rdpcap(pcap_file)
# packets = packets[:5]

# header = [
#     'src_ip',
#     'dst_ip',
#     'src_mac',
#     'dst_mac',
#     'src_port',
#     'dst_port',
#     'tcp_flags',
#     'payload_size',
#     'protocol',
#     'timestamp',
#     'window_size',
#     'num_pkts_src',
#     'num_pkts_dst',
#     'modbus_payload',
#     'modbus_function_code',
#     'coil_values',
#     'holdings'
# ]

# with open('output.csv', mode='w', newline='') as file:
#     writer = csv.writer(file)
#     writer.writerow(header)


# # Process each packet
# for packet in packets:
#     process_packet(packet)



from scapy.all import *
from collections import deque
import csv

pkt_timestamps_src = {}
pkt_timestamps_dst = {}

def process_packet(packet):
    global pkt_timestamps_src, pkt_timestamps_dst

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    src_mac = packet.src
    dst_mac = packet.dst
    src_port = packet[TCP].sport
    dst_port = packet[TCP].dport
    tcp_flags = packet[TCP].flags
    payload_size = len(packet[TCP].payload) 
    protocol = packet[IP].proto
    timestamp = packet.time
    window_size = packet[TCP].window
    
    pkt_timestamps_src.setdefault(src_ip, deque())
    pkt_timestamps_dst.setdefault(dst_ip, deque())
    pkt_timestamps_src[src_ip].append(timestamp)
    pkt_timestamps_dst[dst_ip].append(timestamp)

    while pkt_timestamps_src[src_ip] and timestamp - pkt_timestamps_src[src_ip][0] > 2:
        pkt_timestamps_src[src_ip].popleft()
    
    while pkt_timestamps_dst[dst_ip] and timestamp - pkt_timestamps_dst[dst_ip][0] > 2:
        pkt_timestamps_dst[dst_ip].popleft()
    
    num_pkts_src = len(pkt_timestamps_src[src_ip])
    num_pkts_dst = len(pkt_timestamps_dst[dst_ip])

    if packet.haslayer(TCP) and packet.haslayer(Raw):
        modbus_payload = packet[Raw].load  
        protocol = "ModbusTCP"
        modbus_function_code = int.from_bytes(modbus_payload[7:8], byteorder='big')
        if (modbus_function_code == 1 and len(modbus_payload)==10):
            byte_count = modbus_payload[9]  
            coil_values = [(byte_count >> i) & 1 for i in range(0, 6)]
        else:
            coil_values = [0,0,0,0,0,0]

        if (modbus_function_code == 3 and len(modbus_payload)==19):
            holdings = []
            for i in range(9,19,2):
                modbus_value = modbus_payload[i:i+2]
                modbus_value_int = int.from_bytes(modbus_value, byteorder='big')
                holdings.append(modbus_value_int)
        else:
            holdings = [0,0,0,0,0]
    else:
        modbus_payload = "-"
        modbus_function_code = "-"
        coil_values = ['-','-','-','-','-','-']
        holdings = ['-','-','-','-','-']

    data = [
        src_ip,
        dst_ip,
        src_mac,
        dst_mac,
        src_port,
        dst_port,
        tcp_flags,
        payload_size,
        protocol,
        timestamp,
        window_size,
        num_pkts_src,
        num_pkts_dst,
        modbus_payload,
        modbus_function_code,
        coil_values,
        holdings
    ]

    with open('output.csv', mode='a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(data)

pcap_file = "mitm.pcapng"
packets = rdpcap(pcap_file)

header = [
    'src_ip',
    'dst_ip',
    'src_mac',
    'dst_mac',
    'src_port',
    'dst_port',
    'tcp_flags',
    'payload_size',
    'protocol',
    'timestamp',
    'window_size',
    'num_pkts_src',
    'num_pkts_dst',
    'modbus_payload',
    'modbus_function_code',
    'coil_values',
    'holdings'
]

with open('output.csv', mode='w', newline='') as file:
    writer = csv.writer(file)
    writer.writerow(header)

# Process each packet
for packet in packets:
    process_packet(packet)

