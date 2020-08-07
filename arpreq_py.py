#!/usr/bin/env python3
# Michael Barbas 08/06/2020
from scapy.layers.l2 import Ether, ARP
from scapy.sendrecv import srp
from scapy.layers.inet import IP
import socket


def arpReq():
    LAN_address = "192.168.0.1/24"  # INSERT LOCAL ADDRESS HERE

    # ARP packet , pdst = target address
    arp = ARP(pdst=LAN_address)

    # broadcasting packet w//stack
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    result = srp(packet, timeout=2, verbose=0)[0]

    devices = []

    for sent, received in result:
        # for each response, add new ip and mac to devices list
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    f = open("testmac_log.txt", "a")

    num_devices = 0

    print("Active devices in the network:\n")
    f.write("Active devices in the network:\n")

    print("IP" + " "*18 + "MAC\n")
    f.write("IP" + " "*18 + "MAC\n")

    for device in devices:
        num_devices += 1
        if str(device['ip']) == str(socket.gethostbyname(socket.gethostname())):
            # handles ghost-signature of local IP
            num_devices -= 1
            continue
        print("{:16}    {}".format(device['ip'], device['mac']))
        f.write(("{:16}    {}".format(device['ip'], device['mac'] + "\n")))
    # write local IP, prevents ghost
    num_devices += 1
    print("{:16}    {}".format(socket.gethostbyname(socket.gethostname()), Ether().src))
    f.write("{:16}    {}".format(socket.gethostbyname(socket.gethostname()), Ether().src))

    print("\n" + str(num_devices) + " discovered.")
    f.write("\n" + str(num_devices) + " discovered.")

    f.write("\n------------------------------------------------------\n")
    f.close()

    with open('testmac_log.txt', 'r') as file:
        data = file.read().split("------------------------------------------------------")
        # print(data[len(data)-3])
        data2 = data[len(data) - 3].split()
        del data2[:7]
        del data2[len(data2)-2:]

        num_prev_devices = data2[::2]

    if len(num_prev_devices) < num_devices:
        diff_devices = num_devices - len(num_prev_devices)
        print(str(diff_devices) + " changes since last scan")

    elif len(num_prev_devices) > num_devices:
        diff_devices = len(num_prev_devices) - num_devices
        print(str(diff_devices) + " changes since last scan")


if __name__ == "__main__":
    arpReq()
