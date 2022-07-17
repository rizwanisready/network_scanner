from socket import timeout
import scapy.all as scapy

# this below function will provide us the mac address through ip address
# but first we need to know the ip address
#
#def scan(ip):
#    scapy.arping(ip)

# in linux, command to search for our ip address is (route -n)
# the above command will give gateway ip for our system, lets check our mac address
#scan('10.0.2.1') #we entered our ip to know our mac address
#Now, we can know all the ip and mac address connected with our internet network
# the range of the last digit of the ip address starts from 1 and ends at 254
# in linux the command to get all the connected ips (10.0.1.1/24)
#scan('10.0.2.1/24') # this will show all the connected ips with mac addresses

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    # scapy.ls(scapy.ARP()) >> to list all the components
    # for mac address
    # scapy.ls(scapy.Ether()) >> to list all the components
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    # combining both in one variable
    arp_request_broadcast = broadcast/arp_request
    #print summary of arp_request_broadcast
    # function returns 2 values: 2 variables (1.answered_packets,2.unanswered_packets)
    #scapy.srp(arp_request_broadcast) / we will use 2 variables to fetch data from this function
    #answered, unanswered = scapy.srp(arp_request_broadcast)
    #now we will have to put it inside a list so that we can do stuffs with the list elements
    #we will set a timeout in the arguments otherwise we will stuck in this program
    #answered_list, unanswered_list = scapy.srp(arp_request_broadcast, timeout=1)
    #now we can print answered summary{print(answerd.summary())}
    #the above print statement will give answered packets, we can print same for unanswered.summary()
    #we need only answered list to work in our code so will remove unanswered with a [0]index at end
    answered_list = scapy.srp(arp_request_broadcast, timeout=1)[0]
    #for loop to get the elements IP and mac add from the answered_list
    print("IP\t\t\tMac Address\n-------------------------------------")
    for element in answered_list:
        print(element[1].psrc + "\t\t" + element[1].hwsrc)




scan('192.168.0.1/24')
