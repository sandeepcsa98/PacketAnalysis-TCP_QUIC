from scapy.all import rdpcap, TCP, IP
import numpy as np
from collections import defaultdict

packets = rdpcap("1.pcap")

# Data per flow
flows_rtt = defaultdict(list)
flows_sent_times = defaultdict(dict)
flows_times = defaultdict(list)

for pkt in packets:
    if TCP in pkt and IP in pkt:
        flow = (pkt[IP].src, pkt[TCP].sport, pkt[IP].dst, pkt[TCP].dport)
        rev_flow = (pkt[IP].dst, pkt[TCP].dport, pkt[IP].src, pkt[TCP].sport)
        
        # Save times for RTT calc
        if pkt[TCP].flags & 0x10:  # ACK
            ack_num = pkt[TCP].ack
            if ack_num in flows_sent_times[rev_flow]:
                rtt = float(pkt.time) - flows_sent_times[rev_flow][ack_num]
                flows_rtt[flow].append(rtt)
        
        flows_sent_times[flow][pkt[TCP].seq + len(pkt[TCP].payload)] = float(pkt.time)
        flows_times[flow].append(float(pkt.time))

# Calculate per flow
for flow, times in flows_times.items():
    if len(times) > 1:
        iat = np.diff(times)
        jitter = np.mean(np.abs(iat - np.mean(iat)))
    else:
        jitter = None

    avg_rtt = np.mean(flows_rtt[flow]) if flows_rtt[flow] else None

    print(f"Flow {flow}:")
    if avg_rtt is not None:
        print(f"  Avg RTT   : {avg_rtt:.6f} sec")
    else:
        print("  Avg RTT   : No data")
    if jitter is not None:
        print(f"  Avg Jitter: {jitter:.6f} sec")
    else:
        print("  Avg Jitter: No data")

