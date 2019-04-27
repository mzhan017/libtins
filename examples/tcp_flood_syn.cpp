#include <iostream>
#include <iomanip>
#include <vector>
#include <set>
#include <string>
#include <cstdlib>
#include <pthread.h>
#include <unistd.h>
#include <tins/ip.h>
#include <tins/tcp.h>
#include <tins/ip_address.h>
#include <tins/ethernetII.h>
#include <tins/network_interface.h>
#include <tins/sniffer.h>
#include <tins/utils.h>
#include <tins/packet_sender.h>

using std::cout;
using std::endl;
using std::vector;
using std::pair;
using std::setw;
using std::string;
using std::set;
using std::runtime_error;

using namespace Tins;

void scan(int argc, char* argv[]) {
    IPv4Address des_ip(argv[1]);
    NetworkInterface iface(des_ip);
    cout << "Sniffing on interface: " << iface.name() << endl;
    NetworkInterface::Info info = iface.addresses();

    PacketSender sender;
    IP ip = IP(des_ip, info.ip_addr) / TCP();
    TCP& tcp = ip.rfind_pdu<TCP>();
    tcp.set_flag(TCP::SYN, 1);
    tcp.sport(1337);
    cout << "Sending SYNs... to port "<<argv[2] << endl;
    uint16_t dport = atoi (argv[2]);
    tcp.dport(dport);
    int i = 10;
    i = atoi(argv[3]);
    while(i>0)
    {
        tcp.sport(1337+i);
        sender.send(ip);
        i--;
    }
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        cout << "Usage: " <<* argv << " <IPADDR> <port1> <count>" << endl;
        return 1;
    }
    try {
        scan(argc, argv);
    }
    catch(runtime_error& ex) {
        cout << "Error - " << ex.what() << endl;
    }
}
