#Before you start, make sure to install scapy in your Windows Command Prompt [Open Command Prompt with Administrator Privilege]
#Then type and run: pip install scapy
#Save this python file, named as Packet Capture in a folder. Example: C:\Users\User 1\Desktop\Python Folder
#In CMD that you've opened as administrator, run: cd C:\Users\User 1\Desktop\Python Folder
#After running previous command, run: python Packet Capture.py


from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP

def packet_callback(packet):
    if IP in packet:
        ip_layer = packet[IP]
        protocol = ip_layer.proto
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        # Determine the protocol
        protocol_name = ""
        if protocol == 1:
            protocol_name = "ICMP"
        elif protocol == 6:
            protocol_name = "TCP"
        elif protocol == 17:
            protocol_name = "UDP"
        else:
            protocol_name = "Unknown Protocol"

        # Print packet details
        print(f"Protocol: {protocol_name}")
        print(f"Source IP: {src_ip}")
        print(f"Destination IP: {dst_ip}")

        # Print payload data
        if packet.haslayer(TCP) or packet.haslayer(UDP):
            payload = bytes(packet[TCP].payload) if packet.haslayer(TCP) else bytes(packet[UDP].payload)
            print(f"Payload: {payload}")
        elif packet.haslayer(ICMP):
            payload = bytes(packet[ICMP].payload)
            print(f"Payload: {payload}")
        else:
            print("No payload data available")

        print("-" * 50)

def main():
    # Capture packets on the default network interface
    sniff(prn=packet_callback, filter="ip", store=0)

if __name__ == "__main__":
    main()


#This is the Fifth task assigned by Prodigy InfoTech to Vedish. Task has been completed. 
#In order for the code to run, follow line 1-5
