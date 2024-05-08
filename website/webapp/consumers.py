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


        asyncio.create_task(asyncio.to_thread(sniff, prn=update_packets, store=0))
        asyncio.create_task(self.periodic_task())

    async def disconnect(self, close_code):
        pass  


    async def periodic_task(self):
        while True:
            await asyncio.sleep(5)  # Wait for 5 seconds
            # print(len(self.packets))

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
        self.svm_model = joblib.load("C:\\Users\\Maaz Ahmed\\SCADAFYP\\classifier_model.joblib")
        self.packets = []
        self.pkt_timestamps_src = {}
        self.pkt_timestamps_dst = {}
        self.holdings=[12,28,46,47,57,49,68]

    async def connect(self):
        await self.accept()

        def update_packets(packet):
            if packet.haslayer("IP") and packet.haslayer("TCP"):
                if (str(packet[IP].src) == "10.7.224.216" and str(packet[IP].dst) == "10.7.227.15") or (str(packet[IP].src) == "10.7.227.15" and str(packet[IP].dst) == "10.7.224.216"):
                    self.packets.append(packet)

        asyncio.create_task(asyncio.to_thread(sniff, prn=update_packets, store=0))
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
        ttl_value = packet[IP].ttl
    

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
        # R1, R2, C1, C2, incLoad1, decLoad1, incLoad2, decLoad2, closeLoad1, closeLoad2 = [0] * 10
        coils = [1]*2
        # holdings = [0]*7
        if packet.haslayer(TCP) and packet.haslayer(Raw):
            modbus_payload = packet[Raw].load  
            protocol = 7
            modbus_function_code = int.from_bytes(modbus_payload[7:8], byteorder='big')
            if (modbus_function_code == 1 and len(modbus_payload)==10):
                byte_count = modbus_payload[9]  
                coils = [(byte_count >> i) & 1 for i in range(0, 2)]
                # print(coil_values)
            # else:
            #     coil_values = [0,0,0,0,0,0]

            if (modbus_function_code == 3 and len(modbus_payload)==23):
                self.holdings = []
                for i in range(9,23,2):
                    modbus_value = modbus_payload[i:i+2]
                    modbus_value_int = int.from_bytes(modbus_value, byteorder='big')
                    self.holdings.append(modbus_value_int)

        # new_features = new_data[['payload_size', 'protocol',
        #                  'num_pkts_src', 'num_pkts_dst', 'modbus_function_code', 
        #                  'R1', 'R2', 'C1', 'C2', 'incLoad1', 'decLoad1', 'incLoad2', 'decLoad2',
        #                  'closeLoad1', 'closeLoad2']]
        
        # src_ip="1.1.1.1"
        # dst_ip="2.2.2.2"
        # protocol=""
        # holdings=[12,28,46,47,57,49,68]
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
            self.holdings[0],
            self.holdings[1],
            self.holdings[2],
            self.holdings[3],
            self.holdings[4],
            self.holdings[5],
            self.holdings[6],
            coils[0],
            coils[1]
        ]
        data_dict = {
            'payload_size': payload_size,
            'protocol': protocol,
            'num_pkts_src': num_pkts_src,
            'num_pkts_dst': num_pkts_dst,
            'modbus_function_code': modbus_function_code,
            # 'voltage': 12,
            'temperature': self.holdings[1],
            'humidity': self.holdings[2],
            'pwm1': self.holdings[3],
            'pwm2': self.holdings[4],
            'rpm1': self.holdings[5],
            'rpm2': self.holdings[6],
            'motor1': coils[0],
            'motor2': coils[1],
            # 'closeLoad2': coils[5]
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
            voltage = data[9],
            temperature = data[10],
            humidity = data[11],
            pwm1 = data[12],
            pwm2 = data[13],
            rpm1 = data[14],
            rpm2 = data[15],
            motor1 = data[16],
            motor2 = data[17]
        )

    async def periodic_task(self):
        while True:
            
            print(f'Number of packets num1: {len(self.packets)}')
            if self.packets:
                # print('2')
                eligible_packets = []
                for packet in self.packets:
                    if packet.haslayer("IP") and packet.haslayer("TCP") and packet.haslayer(Raw):
                        modbus_payload = packet[Raw].load
                        if len(modbus_payload)==23:
                            eligible_packets.append(packet)
                # print('here')
                if eligible_packets:
                    # print('3')
                    random_packet = random.choice(eligible_packets)
                    packet = random_packet
                    if (str(packet[IP].src) == "10.7.224.216" and str(packet[IP].dst) == "10.7.227.15") or (str(packet[IP].src) == "10.7.227.15" and str(packet[IP].dst) == "10.7.224.216"):
                        # print('4')
                        if packet.haslayer(IP) and packet.haslayer(TCP):
                            # print('5')
                            features, data= self.extract_features(packet)
                            # print(data)
                            scaler = joblib.load('C:\\Users\\Maaz Ahmed\\SCADAFYP\\scalar.joblib')
                            features = scaler.transform(features)
                            
                            prediction = self.make_prediction(features)
                            # print(f'Number of packets: {len(self.packets)}')
                            # print("prediction: ",prediction)
                            if prediction == 1:
                                await self.send(text_data=json.dumps({'prediction': prediction, 'data': data}))
                                await self.create_network_traffic_entry(anomaly_packets=10, normal_packets=len(self.packets))
                                await self.create_anomaly_entry(data)
                                # await asyncio.sleep(15) 
                            else:
                                await self.create_network_traffic_entry(anomaly_packets=0, normal_packets=len(self.packets))
                                # await asyncio.sleep(5) 

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
            'payload_size': payload_size,
            'window_size':window_size,
            'num_pkts_src': num_pkts_src,
            'num_pkts_dst': num_pkts_dst,
            'modbus_function_code': modbus_function_code,
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
            # print(f'Number of packets num1: {len(self.packets)}')
            if self.packets:
                # print('2')
                eligible_packets = [packet for packet in self.packets if packet.haslayer("IP") and packet.haslayer("TCP")]
                if eligible_packets:
                    # print('3')
                    random_packet = random.choice(eligible_packets)
                    packet = random_packet
                    if (str(packet[IP].src) == "10.7.224.216" and str(packet[IP].dst) == "10.7.227.15") or (str(packet[IP].src) == "10.7.227.15" and str(packet[IP].dst) == "10.7.224.216"):
                        # print('4')
                        if packet.haslayer(IP) and packet.haslayer(TCP):
                            # print('5')
                            features, data = self.extract_features(packet)
                            scaler = joblib.load('C:\\Users\\Maaz Ahmed\\SCADAFYP\\scalarrf.joblib')
                            features = scaler.transform(features)
                            prediction = self.make_prediction(features)
                            # print(f'Number of packets: {len(self.packets)}')
                            # print("prediction: ",prediction)
                            if prediction == 1:
                                print('predicted')
                                await self.send(text_data=json.dumps({'prediction': prediction, 'data': data}))
                                await self.create_security_traffic_entry(security_packets=10, normal_packets=len(self.packets))
                                await self.create_security_entry(data)
                            else:
                                await self.create_security_traffic_entry(security_packets=0, normal_packets=len(self.packets))

                            # await self.send(text_data=json.dumps({'prediction': prediction}))
                            self.packets = []  # Reset packets for the next round
            await asyncio.sleep(5)  # Wait for 5 seconds    




