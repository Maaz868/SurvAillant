import json
import asyncio
import random
import time
from collections import deque
from channels.generic.websocket import AsyncWebsocketConsumer
import pandas as pd
from scapy.all import sniff
import joblib
from scapy.all import *
from collections import deque
from sklearn.preprocessing import StandardScaler, LabelEncoder
import csv
import numpy as np
from .models import PacketEntry, NetworkTraffic, ProtocolCount, SecurityTraffic, AnomalyPackets, SecurityPackets
from channels.db import database_sync_to_async

class DashBoardConsumer(AsyncWebsocketConsumer):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.packets = []

    async def connect(self):
        await self.accept()

        def update_packets(packet):
            self.packets.append(packet)

        asyncio.create_task(asyncio.to_thread(sniff, prn=update_packets, store=0))
        asyncio.create_task(self.periodic_task())

    async def disconnect(self, close_code):
        pass

    @database_sync_to_async
    def save_protocol_count(self):
        tcp_count = sum(1 for packet in self.packets if packet.haslayer("TCP"))
        udp_count = sum(1 for packet in self.packets if packet.haslayer("UDP"))
        modbus_count = sum(1 for packet in self.packets if packet.haslayer("Modbus"))
        mqtt_count = sum(1 for packet in self.packets if packet.haslayer("MQTT"))
        others_count = len(self.packets) - (tcp_count + udp_count + modbus_count + mqtt_count)

        ProtocolCount.objects.create(
            tcp_count=tcp_count,
            udp_count=udp_count,
            modbus_count=modbus_count,
            mqtt_count=mqtt_count,
            others_count=others_count
        )

    @database_sync_to_async
    def save_packet_count(self, packet_count):
        PacketEntry.objects.create(number_of_packets=packet_count)

    async def periodic_task(self):
        while True:
            await asyncio.sleep(5)  # Wait for 5 seconds
            packet_count = len(self.packets)
            await self.save_protocol_count()
            self.packets = []
            # Save packet count to the database
            await self.save_packet_count(packet_count)




class PacketConsumer(AsyncWebsocketConsumer):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.packets = []
        
    async def connect(self):
        await self.accept()

        def update_packets(packet):
            self.packets.append(packet)
            asyncio.run(self.handle_packet(packet))

        # def update_packets(packet):
        #     self.packets.append(packet)
        #     filter_value = self.scope.get('filter_value', None)
        #     if filter_value and packet.haslayer("IP"):
        #         ip_src = packet["IP"].src
        #         if ip_src == filter_value:
        #             asyncio.run(self.handle_packet(packet))
        #     elif (filter_value is None or filter_value=='') and packet.haslayer("IP"):
        #         asyncio.run(self.handle_packet(packet))
                
        asyncio.create_task(asyncio.to_thread(sniff, prn=update_packets, store=0))
        asyncio.create_task(self.periodic_task())

    async def disconnect(self, close_code):
        pass  


    async def periodic_task(self):
        while True:
            await asyncio.sleep(5)  # Wait for 5 seconds
            print(len(self.packets))
            # self.packets = [] 
    # async def receive(self, text_data):
    #     data = json.loads(text_data)
    #     self.scope['filter_value'] = data.get('filter', None)
    
        
    async def handle_packet(self, packet):
        if packet.haslayer(IP) and packet.haslayer(TCP):
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            src_mac = packet[Ether].src
            dst_mac = packet[Ether].dst
            protocol = packet[IP].proto
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            window_size = packet[TCP].window

            packet_info = {
                'ip_src': ip_src,
                'ip_dst': ip_dst,
                'src_port': src_port,
                'dst_port': dst_port,
                'src_mac': src_mac,
                'dst_mac': dst_mac,
                'protocol': protocol,
                'timestamp': timestamp,
                'window_size': window_size
            }

            await self.send(text_data=json.dumps({'packet': packet_info}))



class AnomalyPredictionConsumer(AsyncWebsocketConsumer):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.svm_model = joblib.load("C:\\Users\\Maaz Ahmed\\SCADAFYP\\one_class_svm_model.joblib")
        self.packets = []
        self.pkt_timestamps_src = {}
        self.pkt_timestamps_dst = {}

    async def connect(self):
        await self.accept()

        def update_packets(packet):
            # asyncio.run(self.handle_packet(packet))
            # asyncio.run(self.periodic_task(packet))
            self.packets.append(packet)

        asyncio.create_task(asyncio.to_thread(sniff, prn=update_packets, store=0))

        # Periodically process packets and make predictions
        asyncio.create_task(self.periodic_task())

    async def disconnect(self, close_code):
        pass  # You can add cleanup code here if needed

    
    def extract_features(self, packet):
        src_ip = packet[IP].src
        # print(type(src_ip))
        dst_ip = packet[IP].dst
        # if src_ip == "10.7.53.198" or dst_ip_
        src_mac = packet.src
        dst_mac = packet.dst
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        tcp_flags = packet[TCP].flags
        payload_size = len(packet[TCP].payload) 
        protocol = packet[IP].proto
        timestamp = packet.time
        window_size = packet[TCP].window

        self.pkt_timestamps_src.setdefault(src_ip, deque())
        self.pkt_timestamps_dst.setdefault(dst_ip, deque())
        self.pkt_timestamps_src[src_ip].append(timestamp)
        self.pkt_timestamps_dst[dst_ip].append(timestamp)

        while self.pkt_timestamps_src[src_ip] and timestamp - self.pkt_timestamps_src[src_ip][0] > 2:
            self.pkt_timestamps_src[src_ip].popleft()

        while self.pkt_timestamps_dst[dst_ip] and timestamp - self.pkt_timestamps_dst[dst_ip][0] > 2:
            self.pkt_timestamps_dst[dst_ip].popleft()

        num_pkts_src = len(self.pkt_timestamps_src[src_ip])
        num_pkts_dst = len(self.pkt_timestamps_dst[dst_ip])

        modbus_payload = 0
        modbus_function_code = 0
        voltage = 0
        R1, R2, C1, C2, incLoad1, decLoad1, incLoad2, decLoad2, closeLoad1, closeLoad2 = [0] * 10
        coils = [0]*6
        holdings = [0]*10
        if packet.haslayer(TCP) and packet.haslayer(Raw):
            modbus_payload = packet[Raw].load  
            protocol = 7
            modbus_function_code = int.from_bytes(modbus_payload[7:8], byteorder='big')

            if modbus_function_code == 1 and len(modbus_payload) == 10:
                byte_count = modbus_payload[9]
                coils = [(byte_count >> i) & 1 for i in range(0, 6)]

            if modbus_function_code == 3 and len(modbus_payload) == 19:
                holdings = [int.from_bytes(modbus_payload[i:i+2], byteorder='big') for i in range(9, 19, 2)]

        # new_features = new_data[['payload_size', 'protocol',
        #                  'num_pkts_src', 'num_pkts_dst', 'modbus_function_code', 
        #                  'R1', 'R2', 'C1', 'C2', 'incLoad1', 'decLoad1', 'incLoad2', 'decLoad2',
        #                  'closeLoad1', 'closeLoad2']]
        
        # src_ip="1.1.1.1"
        # dst_ip="2.2.2.2"
        # protocol=""
        holdings=[12,1000,3000,4000,5000]
        features = [
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            payload_size,
            protocol,
            num_pkts_src,
            num_pkts_dst,
            modbus_function_code,
            holdings[0],
            holdings[1],
            holdings[2],
            holdings[3],
            holdings[4],
            coils[0],
            coils[1],
            coils[2],
            coils[3],
            coils[4],
            coils[5]
        ]
        data_dict = {
            'payload_size': 19,
            'protocol': 6,
            'num_pkts_src': 5,
            'num_pkts_dst': 5,
            'modbus_function_code': 6,
            'R1': 3900,
            'R2': 950,
            'C1': 3080,
            'C2': 12630,
            'incLoad1': coils[0],
            'decLoad1': 0,
            'incLoad2': coils[2],
            'decLoad2': coils[3],
            'closeLoad1': coils[4],
            'closeLoad2': coils[5]
        }
        data = pd.DataFrame(data_dict, index=[0])
        # print(type(features))
        # print(type(predicted_data[0]))
        return data, features

    def make_prediction(self, features):
        prediction = self.svm_model.predict(features)
        
        prediction_as_int = int(prediction[0]) if prediction[0] != -1 else -1

        return prediction_as_int

    @database_sync_to_async
    def create_network_traffic_entry(self, anomaly_packets, normal_packets):
        NetworkTraffic.objects.create(anomaly_packets=anomaly_packets, normal_packets=normal_packets)

    @database_sync_to_async
    def create_anomaly_entry(self, data):
        AnomalyPackets.objects.create( 
            src_ip = data[0],
            dst_ip = data[1],
            src_port = data[2],
            dst_port = data[3],
            payload_size = data[4],
            protocol =data[5],
            num_pkts_src = data[6],
            num_pkts_dst = data[7],
            modbus_function_code = data[8],
            R1 = data[10],
            R2 = data[11],
            C1 = data[12],
            C2 = data[13],
            incLoad1 = data[14],
            decLoad1 = data[15],
            incLoad2 = data[16],
            decLoad2 = data[17],
            closeLoad1 = data[18],
            closeLoad2 = data[19]
        )

    async def periodic_task(self):
        while True:
            
            print(f'Number of packets num1: {len(self.packets)}')
            if self.packets:
                print('2')
                eligible_packets = [packet for packet in self.packets if packet.haslayer("IP") and packet.haslayer("TCP")]
                if eligible_packets:
                    print('3')
                    random_packet = random.choice(eligible_packets)
                    packet = random_packet
                    if str(packet[IP].src) == "10.7.224.212" or str(packet[IP].dst) == "10.7.224.212":
                        print('4')
                        if packet.haslayer(IP) and packet.haslayer(TCP):
                            print('5')
                            features, data= self.extract_features(packet)
                            scaler = joblib.load('C:\\Users\\Maaz Ahmed\\SCADAFYP\\scalar.joblib')
                            features = scaler.transform(features)
                            
                            prediction = self.make_prediction(features)
                            print(f'Number of packets: {len(self.packets)}')

                            if prediction == -1:
                                await self.send(text_data=json.dumps({'prediction': prediction, 'data': data}))
                                await self.create_network_traffic_entry(anomaly_packets=100, normal_packets=len(self.packets))
                                await self.create_anomaly_entry(data)
                            else:
                                await self.create_network_traffic_entry(anomaly_packets=0, normal_packets=len(self.packets))

                            self.packets = [] 
            await asyncio.sleep(5)  # Wait for 5 seconds







#SECURITY THREAT WALA CONSUMER
                            
class SecurityPredictionConsumer(AsyncWebsocketConsumer):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.rf_classifier = joblib.load("C:\\Users\\Maaz Ahmed\\SCADAFYP\\rfclassifier.joblib")
        self.packets = []
        self.pkt_timestamps_src = {}
        self.pkt_timestamps_dst = {}

    async def connect(self):
        await self.accept()

        def update_packets(packet):
            self.packets.append(packet)

        asyncio.create_task(asyncio.to_thread(sniff, prn=update_packets, store=0))

        asyncio.create_task(self.periodic_task())

    async def disconnect(self, close_code):
        pass  # You can add cleanup code here if needed

    
    def extract_features(self, packet):
        src_ip = packet[IP].src
        # print(type(src_ip))
        dst_ip = packet[IP].dst
        # # if src_ip == "10.7.53.198" or dst_ip_
        # src_mac = packet.src
        # dst_mac = packet.dst
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        # tcp_flags = packet[TCP].flags
        payload_size = len(packet[TCP].payload) 
        protocol = packet[IP].proto
        timestamp = packet.time
        window_size = packet[TCP].window
        ttl_value = packet[IP].ttl


# selected_features = combined_data[['payload_size', 'window_size', 'num_pkts_src', 'num_pkts_dst','modbus_function_code','ttl_value']]


        self.pkt_timestamps_src.setdefault(src_ip, deque())
        self.pkt_timestamps_dst.setdefault(dst_ip, deque())
        self.pkt_timestamps_src[src_ip].append(timestamp)
        self.pkt_timestamps_dst[dst_ip].append(timestamp)

        while self.pkt_timestamps_src[src_ip] and timestamp - self.pkt_timestamps_src[src_ip][0] > 2:
            self.pkt_timestamps_src[src_ip].popleft()

        while self.pkt_timestamps_dst[dst_ip] and timestamp - self.pkt_timestamps_dst[dst_ip][0] > 2:
            self.pkt_timestamps_dst[dst_ip].popleft()

        num_pkts_src = len(self.pkt_timestamps_src[src_ip])
        num_pkts_dst = len(self.pkt_timestamps_dst[dst_ip])

        modbus_payload = 0
        modbus_function_code = 0
        if packet.haslayer(TCP) and packet.haslayer(Raw):
            modbus_payload = packet[Raw].load  
            protocol = 7
            modbus_function_code = int.from_bytes(modbus_payload[7:8], byteorder='big')

        features = [
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            payload_size,
            window_size,
            num_pkts_src,
            num_pkts_dst,
            modbus_function_code,
            ttl_value

        ]
        data_dict = {
            'payload_size': 19,
            'window_size':window_size,
            'num_pkts_src': 20,
            'num_pkts_dst': 20,
            'modbus_function_code': 0,
            'ttl_value':ttl_value,
        }
        predicted_data = pd.DataFrame(data_dict, index=[0])
        # print(type(predicted_data[0]))
        return predicted_data, features

    def make_prediction(self, features):
        prediction = self.rf_classifier.predict(features)
        
        prediction_as_int = int(prediction[0]) #if prediction[0] != -1 else -1

        return prediction_as_int

    @database_sync_to_async
    def create_security_traffic_entry(self, security_packets, normal_packets):
        SecurityTraffic.objects.create(security_packets=security_packets, normal_packets=normal_packets)

    @database_sync_to_async
    def create_security_entry(self, data):
        SecurityPackets.objects.create( 
            src_ip = data[0],
            dst_ip = data[1],
            src_port = data[2],
            dst_port = data[3],
            payload_size = data[4],
            window_size =data[5],
            num_pkts_src = data[6],
            num_pkts_dst = data[7],
            modbus_function_code = data[8],
            ttl_value = data[9],
            )

    async def periodic_task(self):
        while True:
            print(f'Number of packets num1: {len(self.packets)}')
            if self.packets:
                print('2')
                eligible_packets = [packet for packet in self.packets if packet.haslayer("IP") and packet.haslayer("TCP")]
                if eligible_packets:
                    print('3')
                    random_packet = random.choice(eligible_packets)
                    packet = random_packet
                    if str(packet[IP].src) == "10.7.224.212" or str(packet[IP].dst) == "10.7.224.212":
                        print('4')
                        if packet.haslayer(IP) and packet.haslayer(TCP):
                            print('5')
                            features, data = self.extract_features(packet)
                            scaler = joblib.load('C:\\Users\\Maaz Ahmed\\SCADAFYP\\scalarrf.joblib')
                            features = scaler.transform(features)
                            prediction = self.make_prediction(features)
                            print(f'Number of packets: {len(self.packets)}')
                            if prediction == 1:
                                await self.send(text_data=json.dumps({'prediction': prediction, 'data': data}))
                                await self.create_security_traffic_entry(security_packets=100, normal_packets=len(self.packets))
                                await self.create_security_entry(data)
                            else:
                                await self.create_security_traffic_entry(security_packets=0, normal_packets=len(self.packets))

                            # await self.send(text_data=json.dumps({'prediction': prediction}))
                            self.packets = []  # Reset packets for the next round
            await asyncio.sleep(5)  # Wait for 5 seconds    






"""
from scapy.all import *
from collections import deque
import csv

pkt_timestamps_src = {}
pkt_timestamps_dst = {}

# holding1, holding2, holding3, holding4, holding5 = 0
# coil1, coil2, coil3, coil4, coil5, coil6 = 0
holdings =[12, 5000, 1000, 2400,12000]
coils = [0,0,0,0,0,0]


def process_packet(packet):
    global pkt_timestamps_src, pkt_timestamps_dst,holdings, coils

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
    # print(timestamp - pkt_timestamps_src[src_ip][0])


    while pkt_timestamps_dst[dst_ip] and timestamp - pkt_timestamps_dst[dst_ip][0] > 2:
        pkt_timestamps_dst[dst_ip].popleft()
    # print(timestamp - pkt_timestamps_dst[dst_ip][0])
    
    num_pkts_src = len(pkt_timestamps_src[src_ip])
    num_pkts_dst = len(pkt_timestamps_dst[dst_ip])
    # print(num_pkts_dst+num_pkts_src)

    if packet.haslayer(TCP) and packet.haslayer(Raw):
        modbus_payload = packet[Raw].load  
        protocol = 7
        modbus_function_code = int.from_bytes(modbus_payload[7:8], byteorder='big')
        if (modbus_function_code == 1 and len(modbus_payload)==10):
            byte_count = modbus_payload[9]  
            coils = [(byte_count >> i) & 1 for i in range(0, 6)]
            # print(coil_values)
        # else:
        #     coil_values = [0,0,0,0,0,0]

        if (modbus_function_code == 3 and len(modbus_payload)==19):
            holdings = []
            for i in range(9,19,2):
                modbus_value = modbus_payload[i:i+2]
                modbus_value_int = int.from_bytes(modbus_value, byteorder='big')
                holdings.append(modbus_value_int)
        # else:
        #     holdings = [0,0,0,0,0]
    else:
        modbus_payload = 0
        modbus_function_code = 0
        # coil_values = ['-','-','-','-','-','-']
        # holdings = ['-','-','-','-','-']

    
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
        holdings[0],
        holdings[1],
        holdings[2],
        holdings[3],
        holdings[4],
        coils[0],
        coils[1],
        coils[2],
        coils[3],
        coils[4],
        coils[5]
    ]
    # print(data)
    # print(holdings, coil_values)
    if (holdings[0]!=0 and holdings[1]!=0 and holdings[2]!=0 and holdings[3]!=0 and holdings[4]!=0):
        with open('features.csv', mode='a', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(data)
    
        
      
pcap_file = "outfile.pcap"
packets = rdpcap(pcap_file)
# packets = packets[:1000]

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
    'voltage',
    'R1',
    'R2',
    'C1',
    'C2',
    'incLoad1',
    'decLoad1',
    'incLoad2',
    'decLoad2',
    'closeLoad1',
    'closeLoad2'
    
]# Define the ranges to be ignored
# Define the ranges to be ignored
filtered_packets = packets[:52995] + packets[53219:60363] + packets[60521:105000]
# umber of packets before and after filtering
# print(f"Number of packets before filtering: {len(packets)}")
# print(f"Number of packets after filtering: {len(filtered_packets)}")

with open('features.csv', mode='w', newline='') as file:
    writer = csv.writer(file)
    writer.writerow(header)


# Process each packet
for packet in filtered_packets:
    process_packet(packet)

"""