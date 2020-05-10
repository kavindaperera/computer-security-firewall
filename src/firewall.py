import ipaddress
import json


# creating a dictionary from ip datagram
def analyse_datagram(datagram_header):
    protocol_dict = {1: 'ICMP', 2: 'IGMP', 6: 'TCP', 17: 'UDP'}
    version_bin = datagram_header[0:4]
    ihl_bin = datagram_header[4:8]
    total_length_bin = datagram_header[16:32]
    protocol_bin = datagram_header[72:80]
    saddress_bin = datagram_header[96:128]
    daddress_bin = datagram_header[128:160]
    ihl = int(ihl_bin, 2) * 32
    protocol = int(protocol_bin, 2)
    protocol = protocol_dict.get(protocol)
    payload = datagram_header[ihl:]
    saddress = ipaddress.ip_address(
        int('.'.join(str(int(x, 2)) for x in saddress_bin.split())))
    daddress = ipaddress.ip_address(
        int('.'.join(str(int(x, 2)) for x in daddress_bin.split())))
    sport = int(payload[:16], 2)
    dport = int(payload[16:32], 2)
    headers = {'saddress': saddress, 'daddress': daddress,
        'sport': sport, 'dport': dport, 'protocol': protocol}
    return (headers)

## ip firewall filter
def filter(headers, interface):
    with open('config.json') as f:
        rules = json.load(f)

    for key in rules:
        if (rules[key][0].get("interface") == interface):
            print(rules[key])


def firewall(interface):
    with open(interface+'.json') as f:
        tests = json.load(f)

    for key in tests:
        headers = analyse_datagram(tests[key])
        #print(headers)
        filter(headers,interface)



firewall('interface_1')