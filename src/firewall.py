import ipaddress
import json

#Considering the two networks 192.168.1.0 and 10.10.10.0
#interface_1 => 192.168.1.0
#interface_2 => 10.10.10.0

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

# ip firewall filter
def filter(headers, interface):
    saddress = str(headers.get("saddress")).split(".")
    daddress = str(headers.get("daddress")).split(".")
    sport = str(headers.get("sport"))
    dport = str(headers.get("dport"))
    protocol = headers.get("protocol")
    print(headers)

    with open('config.json') as f:
        rules = json.load(f)

    for key in rules:
        if (rules[key][0].get("interface") == interface):
            if (rules[key][0].get("saddress") != 'any'):
                r_saddress = rules[key][0].get("saddress").split('.')
                if (r_saddress[0] == saddress[0] and r_saddress[1] == saddress[1] and r_saddress[2] == saddress[2]):
                    if (rules[key][0].get("daddress") != 'any'):
                        r_daddress = rules[key][0].get("daddress").split('.')
                        if (r_daddress[0] == daddress[0] and r_daddress[1] == daddress[1] and r_daddress[2] == daddress[2]):
                            if (rules[key][0].get("dport")!= 'any'):
                                r_dport = rules[key][0].get("dport")
                                if (int(dport)==int(r_dport)):
                                    print(interface)
                                    print(rules[key][0].get("action"))
                                    break
                                else:
                                    continue
                            else:
                                print(interface)
                                print(rules[key][0].get("action"))
                                break
                        else:
                            continue
                    else:
                        print(interface)
                        print(rules[key][0].get("action"))
                        break
                else:
                    continue
            else:
                print(interface)
                print(rules[key][0].get("action"))
                break
        else:
            continue


def firewall(interface):
    with open(interface+'.json') as f:
        tests = json.load(f)

    for key in tests:
        headers = analyse_datagram(tests[key])
        filter(headers, interface)
        print('=================================================================================================================================')


firewall('interface_1')
firewall('interface_2')