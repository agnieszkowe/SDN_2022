#!/usr/bin/env python

from multiprocessing import Process
import random
import sys
from scapy.all import *

random_dport = list(range(49152, 55000))
random_sport = list(range(55000, 60000))
random_sport2 = list(range(49152,54152))
host_ips = ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"]

def get_dest_and_src_ip ():
  src_ip = random.choice(host_ips)
  host_ips.remove(src_ip)
  dst_ip = random.choice(host_ips)
  host_ips.append(src_ip)
  return src_ip, dst_ip

def send_packets (): #to sluzy do generowania randomowego ruchu
  rand_dport = random.choice(random_dport)
  rand_sport = random.choice(random_sport)
  random_dport.remove(rand_dport)
  random_sport.remove(rand_sport)
  src_ip, dst_ip = get_dest_and_src_ip()
  pkt = Ether()/IP(src=src_ip, dst=dst_ip)/UDP(dport=rand_dport, sport=rand_sport)
  a = sendpfast(pkt,pps=100, loop=1000, parse_results=1)
  print(a)

def send_packets_4_tuple (): #to sluzy do generowania ruchu z 4 takimi samymi parametrami
  rand_sport = random.choice(random_sport2)
  random_sport2.remove(rand_sport)
  src_ip, dst_ip = get_dest_and_src_ip()
  pkt = Ether()/IP(src="10.0.0.1", dst="10.0.0.4")/UDP(dport=55123, sport=rand_sport)
  a = sendpfast(pkt,pps=100, loop=1000, parse_results=1)
  print(a)

def send_packets_4_tuple_2 (): 
  rand_sport = random.choice(random_sport2)
  random_sport2.remove(rand_sport)
  src_ip, dst_ip = get_dest_and_src_ip()
  pkt = Ether()/IP(src="10.0.0.1", dst="10.0.0.4")/UDP(dport=56124, sport=rand_sport)
  a = sendpfast(pkt,pps=100, loop=1000, parse_results=1)
  print(a)

def send_packets_4_tuple_4a ():
  rand_sport = random.choice(random_sport2)
  random_sport2.remove(rand_sport)
  src_ip, dst_ip = get_dest_and_src_ip()
  pkt = Ether()/IP(src="10.0.0.1", dst="10.0.0.4")/UDP(dport=57125, sport=rand_sport)
  a = sendpfast(pkt,pps=100, loop=1000, parse_results=1)
  print(a)

def send_packets_4_tuple_4b ():
  rand_sport = random.choice(random_sport2)
  random_sport2.remove(rand_sport)
  src_ip, dst_ip = get_dest_and_src_ip()
  pkt = Ether()/IP(src="10.0.0.1", dst="10.0.0.4")/UDP(dport=58126, sport=rand_sport)
  a = sendpfast(pkt,pps=100, loop=1000, parse_results=1)
  print(a)
  
def send_packets_4_tuple_5 ():
  rand_sport = random.choice(random_sport2)
  random_sport2.remove(rand_sport)
  src_ip, dst_ip = get_dest_and_src_ip()
  pkt = Ether()/IP(src="10.0.0.1", dst="10.0.0.4")/UDP(dport=59127, sport=rand_sport)
  a = sendpfast(pkt,pps=100, loop=1000, parse_results=1)
  print(a)

def send_packets_4_tuple_6 ():
  rand_sport = random.choice(random_sport2)
  random_sport2.remove(rand_sport)
  src_ip, dst_ip = get_dest_and_src_ip()
  pkt = Ether()/IP(src="10.0.0.1", dst="10.0.0.4")/UDP(dport=60128, sport=rand_sport)
  a = sendpfast(pkt,pps=100, loop=1000, parse_results=1)
  print(a)
  
def send_packets_4_tuple_7 (): 
  rand_sport = random.choice(random_sport2)
  random_sport2.remove(rand_sport)
  src_ip, dst_ip = get_dest_and_src_ip()
  pkt = Ether()/IP(src="10.0.0.1", dst="10.0.0.4")/UDP(dport=61129, sport=rand_sport)
  a = sendpfast(pkt,pps=100, loop=1000, parse_results=1)
  print(a)

def send_packets_4_tuple_8 (): 
  rand_sport = random.choice(random_sport2)
  random_sport2.remove(rand_sport)
  src_ip, dst_ip = get_dest_and_src_ip()
  pkt = Ether()/IP(src="10.0.0.1", dst="10.0.0.4")/UDP(dport=62120, sport=rand_sport)
  a = sendpfast(pkt,pps=100, loop=1000, parse_results=1)
  print(a) 

def runInParallel(*fns):
  proc = []
  for fn in fns:
    p = Process(target=fn)
    p.start()
    proc.append(p)
  for p in proc:
    p.join()

runInParallel(send_packets, send_packets)

# 16 in one, 1
runInParallel(send_packets,send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets,send_packets_4_tuple, send_packets_4_tuple, send_packets_4_tuple, send_packets_4_tuple, send_packets_4_tuple, send_packets_4_tuple, send_packets_4_tuple, send_packets_4_tuple, send_packets_4_tuple, send_packets_4_tuple, send_packets_4_tuple, send_packets_4_tuple, send_packets_4_tuple, send_packets_4_tuple, send_packets_4_tuple)

# 8 x 2, 2
runInParallel(send_packets,send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets_4_tuple_2, send_packets_4_tuple_2, send_packets_4_tuple_2, send_packets_4_tuple_2, send_packets_4_tuple_2, send_packets_4_tuple_2, send_packets_4_tuple_2, send_packets_4_tuple_2, send_packets_4_tuple, send_packets_4_tuple, send_packets_4_tuple, send_packets_4_tuple, send_packets_4_tuple, send_packets_4_tuple, send_packets_4_tuple, send_packets_4_tuple,)

# 4 x 4, 4
runInParallel(send_packets,send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets_4_tuple, send_packets_4_tuple, send_packets_4_tuple, send_packets_4_tuple, send_packets_4_tuple_2, send_packets_4_tuple_2, send_packets_4_tuple_2, send_packets_4_tuple_2, send_packets_4_tuple_4a, send_packets_4_tuple_4a, send_packets_4_tuple_4a, send_packets_4_tuple_4a, send_packets_4_tuple_4b, send_packets_4_tuple_4b, send_packets_4_tuple_4b, send_packets_4_tuple_4b,)

# 2 x 8, 8
runInParallel(send_packets,send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets_4_tuple, send_packets_4_tuple, send_packets_4_tuple_2, send_packets_4_tuple_2,send_packets_4_tuple_4a, send_packets_4_tuple_4a, send_packets_4_tuple_4b, send_packets_4_tuple_4b, send_packets_4_tuple_5, send_packets_4_tuple_5, send_packets_4_tuple_6, send_packets_4_tuple_6, send_packets_4_tuple_7, send_packets_4_tuple_7, send_packets_4_tuple_8, send_packets_4_tuple_8,)