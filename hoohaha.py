import subprocess 
import os
import matplotlib.pyplot as plt

def pcap_parse(pcap_file, filter_string):
    packet_array = []
    file_name = os.path.splitext(pcap_file)[0]
    number = file_name.split("-")[1]

    for i in number:
        pcap_filter = f"tcp contains \"{number}{filter_string}\""
        tshark_cmd = ['tshark', '-r', pcap_file, '-Y', (pcap_filter), '-T', 'fields', '-e', 'frame.number', '-e', 'frame.time_relative']
        p = subprocess.Popen(tshark_cmd, stdout=subprocess.PIPE)
        output = p.communicate()[0].decode().split('\n')
    
        for line in output:
            if line:
                frame_number, time_relative = line.split('\t')
                packet_array.append({'frame_number': int(frame_number), 'time_relative': float(time_relative)})
        
    for packet in packet_array:
        print(packet)
        
    return packet_array

def calc_average_latency(packet_array):
    if not packet_array:
        print("Packet array is empty.")
        return
    
    total = 0
    prime = packet_array[0]['time_relative']
    for packet in packet_array:
        total += (packet['time_relative'] - prime)
    final = '%.7f'%(total/len(packet_array))
    print("Average latency for input file: ", final, " seconds")
    return final

#pcap_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'chat')

pcap_dir = r"C:\Users\maddy\Code Projects\WireShark\chat"
pcap_files = [f for f in os.listdir(pcap_dir) if f.endswith('.pcap')]
pcap_files_sorted = sorted(pcap_files, key=lambda x: int(x.split("-")[1].split(".")[0]))

data = []
clients = []

for pcap_file in pcap_files_sorted:
    # Count the number of clients
    file_name = os.path.splitext(pcap_file)[0]
    number = file_name.split("-")[1]
    clients.append(int(number))
    print(f"Number of clients in file: {number}")
    
    #Process data from the files
    full_path = os.path.join(pcap_dir, pcap_file)
    print(f"Processing file: {full_path}")
    
    filter_string = "=007bond"
    packet_array = pcap_parse(full_path, filter_string)
    data.append(float(calc_average_latency(packet_array))*1000)


plt.plot(clients, data)
plt.ylabel("Average Latency (ms)")
plt.xlabel("# of Clients")
plt.title('Latency Graph')

plt.show()
