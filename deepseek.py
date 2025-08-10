import dpkt
import socket
import sys
from collections import defaultdict, deque
import statistics
import time

def analyze_file_transfer(pcap_file, src_ip=None, dst_ip=None, port=None):
    """
    Analyze a PCAP file for file transfer performance metrics with focus on:
    - Retransmissions
    - Jitter
    - Average RTT
    
    Args:
        pcap_file (str): Path to the PCAP file
        src_ip (str): Optional source IP filter
        dst_ip (str): Optional destination IP filter
        port (int): Optional port filter
        
    Returns:
        dict: Dictionary containing performance metrics
    """
    # Open the PCAP file
    with open(pcap_file, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        
        # Initialize data structures
        flows = defaultdict(lambda: {
            'packets': [],
            'seq_nums': set(),
            'retransmissions': 0,
            'timestamps': [],
            'rtt_samples': [],
            'ack_tracker': {}
        })
        
        total_packets = 0
        
        # Process each packet in the PCAP
        for ts, buf in pcap:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                if not isinstance(eth.data, dpkt.ip.IP):
                    continue
                    
                ip = eth.data
                if not isinstance(ip.data, dpkt.tcp.TCP):
                    continue
                    
                tcp = ip.data
                
                # Get source and destination IP:port pairs
                src = socket.inet_ntoa(ip.src)
                dst = socket.inet_ntoa(ip.dst)
                sport = tcp.sport
                dport = tcp.dport
                
                # Apply filters if provided
                if src_ip and src != src_ip:
                    continue
                if dst_ip and dst != dst_ip:
                    continue
                if port and sport != port and dport != port:
                    continue
                
                # Create flow identifier (bidirectional)
                flow_id = tuple(sorted(((src, sport), (dst, dport))))
                flow = flows[flow_id]
                
                # Track packet count
                total_packets += 1
                
                # For data packets (not ACK-only)
                if len(tcp.data) > 0:
                    seq_num = tcp.seq
                    
                    # Check for retransmissions
                    if seq_num in flow['seq_nums']:
                        flow['retransmissions'] += 1
                    else:
                        flow['seq_nums'].add(seq_num)
                        flow['timestamps'].append(ts)
                        flow['packets'].append((ts, len(buf), seq_num))
                    
                    # Track when we sent data packets for RTT calculation
                    if (tcp.flags & dpkt.tcp.TH_SYN) == 0:  # Ignore SYN packets
                        flow['ack_tracker'][seq_num] = ts
                
                # For ACK packets
                if tcp.ack > 0 and (tcp.flags & dpkt.tcp.TH_ACK):
                    ack_num = tcp.ack
                    
                    # Check if this ACK corresponds to a packet we sent
                    if ack_num in flow['ack_tracker']:
                        sent_time = flow['ack_tracker'].pop(ack_num)
                        rtt = ts - sent_time
                        flow['rtt_samples'].append(rtt)
                        
            except Exception as e:
                print(f"Error processing packet: {e}", file=sys.stderr)
                continue
                
    # If no packets found
    if not flows:
        return None
        
    # Analyze each flow
    results = []
    for flow_id, flow_data in flows.items():
        packets = flow_data['packets']
        if len(packets) < 2:
            continue
            
        # Calculate inter-arrival times (jitter)
        inter_arrivals = []
        prev_ts = packets[0][0]
        for pkt in packets[1:]:
            inter_arrivals.append(pkt[0] - prev_ts)
            prev_ts = pkt[0]
        
        # Calculate metrics
        avg_rtt = statistics.mean(flow_data['rtt_samples']) * 1000 if flow_data['rtt_samples'] else 0
        if len(inter_arrivals) > 1:
            jitter = statistics.stdev(inter_arrivals) * 1000  # in milliseconds
        else:
            jitter = 0
            
        retransmission_rate = (flow_data['retransmissions'] / len(packets)) * 100 if packets else 0
        
        # Calculate throughput (in Mbps)
        first_ts = packets[0][0]
        last_ts = packets[-1][0]
        duration = last_ts - first_ts
        total_bytes = sum(pkt[1] for pkt in packets)
        
        if duration > 0:
            throughput = (total_bytes * 8) / (duration * 1000000)  # Mbps
        else:
            throughput = 0
            
        results.append({
            'flow': flow_id,
            'avg_rtt_ms': avg_rtt,
            'jitter_ms': jitter,
            'retransmission_rate_percent': retransmission_rate,
            'retransmission_count': flow_data['retransmissions'],
            'throughput_mbps': throughput,
            'total_packets': len(packets),
            'total_bytes': total_bytes,
            'duration_sec': duration,
            'rtt_samples': len(flow_data['rtt_samples'])
        })
    
    # Return the flow with most packets (assuming it's the file transfer)
    if not results:
        return None
    return max(results, key=lambda x: x['total_packets'])

def main():
    if len(sys.argv) < 2:
        print("Usage: python pcap_analyzer.py <pcap_file> [src_ip] [dst_ip] [port]")
        print("Example: python pcap_analyzer.py transfer.pcap 192.168.1.100 192.168.1.200 5001")
        sys.exit(1)
        
    pcap_file = sys.argv[1]
    src_ip = sys.argv[2] if len(sys.argv) > 2 else None
    dst_ip = sys.argv[3] if len(sys.argv) > 3 else None
    port = int(sys.argv[4]) if len(sys.argv) > 4 else None
    
    print(f"Analyzing {pcap_file}...")
    if src_ip or dst_ip or port:
        print(f"Filters - Source: {src_ip}, Destination: {dst_ip}, Port: {port}")
    
    start_time = time.time()
    results = analyze_file_transfer(pcap_file, src_ip, dst_ip, port)
    analysis_time = time.time() - start_time
    
    if not results:
        print("No valid TCP file transfer flows found in the PCAP file.")
        sys.exit(1)
        
    print("\nFile Transfer Performance Analysis")
    print("=================================")
    print(f"Flow: {results['flow'][0]} <-> {results['flow'][1]}")
    print(f"Average RTT: {results['avg_rtt_ms']:.2f} ms (from {results['rtt_samples']} samples)")
    print(f"Jitter (packet inter-arrival stdev): {results['jitter_ms']:.2f} ms")
    print(f"Retransmissions: {results['retransmission_count']} packets ({results['retransmission_rate_percent']:.2f}%)")
    print(f"Throughput: {results['throughput_mbps']:.2f} Mbps")
    print(f"Total Packets: {results['total_packets']}")
    print(f"Total Bytes: {results['total_bytes']}")
    print(f"Duration: {results['duration_sec']:.2f} seconds")
    print(f"\nAnalysis completed in {analysis_time:.2f} seconds")

if __name__ == "__main__":
    main()
