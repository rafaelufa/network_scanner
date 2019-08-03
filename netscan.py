import scapy.all as scapy


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.src(arp_request_broadcast, timeout=1, verbose=False)[0]

    client_list = []
    for element in answered_list:
        client_dist = {'ip': element[1].psrc, 'mac': element[1].hwsrc}
        client_list.append(client_dist)
    return client_list

def print_results(results_list):
    print('IP\t\t\tMAC Address\n--------------------------------------')
    for client in results_list:
        print(client['ip'] + '\t\t' + client['mac'])


scan_results = scan('10.0.2.1/24')
print_results(scan_results)
