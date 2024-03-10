# webapp/models.py
from django.db import models
from django.contrib.auth.models import AbstractUser
from django.contrib.auth.models import Group, Permission


class CustomUser(AbstractUser):
    is_admin = models.BooleanField(default=False)
    is_user_approved = models.BooleanField(default=False)
    # Add related_name to avoid clashes with auth.User
    groups = models.ManyToManyField(Group, blank=True, related_name='customuser_set', related_query_name='customuser')
    user_permissions = models.ManyToManyField(Permission, blank=True, related_name='customuser_set', related_query_name='customuser')

class ProtocolCount(models.Model):
    timestamp = models.DateTimeField(auto_now_add=True)
    tcp_count = models.IntegerField(default=0)
    udp_count = models.IntegerField(default=0)
    modbus_count = models.IntegerField(default=0)
    mqtt_count = models.IntegerField(default=0)
    others_count = models.IntegerField(default=0)


class PacketEntry(models.Model):
    number_of_packets = models.IntegerField()
    timestamp = models.DateTimeField(auto_now_add=True)

class NetworkTraffic(models.Model):
    timestamp = models.DateTimeField(auto_now_add=True)
    normal_packets = models.IntegerField(default=0)
    anomaly_packets = models.IntegerField(default=0)

class SecurityTraffic(models.Model):
    timestamp = models.DateTimeField(auto_now_add=True)
    normal_packets = models.IntegerField(default=0)
    security_packets = models.IntegerField(default=0)

class Packet(models.Model):
    timestamp = models.DateTimeField(auto_now_add=True)
    source_ip = models.CharField(max_length=15)
    destination_ip = models.CharField(max_length=20)
    protocol = models.CharField(max_length=10, default='')
    # Add more fields as needed


class AnomalyPackets(models.Model):
    src_ip = models.CharField(max_length=30, default="1.1.1.1")
    dst_ip = models.CharField(max_length=30,default="1.1.1.1")
    src_port = models.IntegerField(default=0)
    dst_port = models.IntegerField(default=0)
    payload_size = models.IntegerField()
    protocol = models.IntegerField()
    num_pkts_src = models.IntegerField()
    num_pkts_dst = models.IntegerField()
    modbus_function_code = models.IntegerField()
    R1 = models.IntegerField()
    R2 = models.IntegerField()
    C1 = models.IntegerField()
    C2 = models.IntegerField()
    incLoad1 = models.BooleanField()
    decLoad1 = models.IntegerField()
    incLoad2 = models.BooleanField()
    decLoad2 = models.IntegerField()
    closeLoad1 = models.BooleanField()
    closeLoad2 = models.BooleanField()

class SecurityPackets(models.Model):
    src_ip = models.CharField(max_length=30, default="1.1.1.1")
    dst_ip = models.CharField(max_length=30,default="1.1.1.1")
    src_port = models.IntegerField(default=0)
    dst_port = models.IntegerField(default=0)
    payload_size = models.IntegerField()
    window_size = models.IntegerField()
    # protocol = models.IntegerField()
    num_pkts_src = models.IntegerField()
    num_pkts_dst = models.IntegerField()
    modbus_function_code = models.IntegerField()
    ttl_value = models.IntegerField()
  