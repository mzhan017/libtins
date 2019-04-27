#include <tins/tins.h>
#include <iostream>
using namespace Tins;
using namespace std;

void test(const IPv6Address &dst, const IPv6Address &src)
{
	PacketSender sender;
	IPv6 ipv6 = IPv6(dst,src) / ICMPv6();
	ICMPv6 & icmp6 = ipv6.rfind_pdu<ICMPv6>();
	icmp6.type(ICMPv6::Types::PACKET_TOOBIG);
	icmp6.checksum(1);
	icmp6.auto_cksum(false);
	cout<<"icmp.chksum="<<icmp6.checksum()<<endl;
	ipv6.hop_limit(255);
	sender.send(ipv6);
	cout<<"icmp.chksum="<<icmp6.checksum()<<endl;
}

int main()
{
	test("2620:1:3:4::61","2620:1:3:4::6");
	//test("f0ef:1234::1","f000::1");
}
