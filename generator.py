#!/usr/bin/env python

from multiprocessing import Process
import random
import sys
from scapy.all import *

random_dport = list(range(49152, 55000))
random_sport = list(range(55000, 60000))
host_ips = ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"]

def get_dest_and_src_ip ():
  src_ip = random.choice(host_ips)
  host_ips.remove(src_ip)
  dst_ip = random.choice(host_ips)
  host_ips.append(src_ip)
  return src_ip, dst_ip

def send_packets ():
  rand_dport = random.choice(random_dport)
  rand_sport = random.choice(random_sport)
  random_dport.remove(rand_dport)
  random_sport.remove(rand_sport)
  src_ip, dst_ip = get_dest_and_src_ip()
  pkt = Ether()/IP(src=src_ip, dst=dst_ip)/UDP(dport=rand_dport, sport=rand_sport)
  a = sendpfast(pkt, pps=100, loop=1000, parse_results=1)
  print(a)

def runInParallel(*fns):
  proc = []
  for fn in fns:
    p = Process(target=fn)
    p.start()
    proc.append(p)
  for p in proc:
    p.join()

# 2 times
runInParallel(send_packets, send_packets)

# 50 times
runInParallel(send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets,)

# 100 times
runInParallel(send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets, send_packets,)