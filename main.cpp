#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <WS2tcpip.h>
#include "windivert.h"
#include <map>

void print_flag(PWINDIVERT_TCPHDR pf_tcp)
{
	printf("tcp.flag: ");

	if (pf_tcp->Fin)
	{
		fputs("[FIN]", stdout);
	}
	if (pf_tcp->Rst)
	{
		fputs("[RST]", stdout);
	}
	if (pf_tcp->Urg)
	{
		fputs("[URG]", stdout);
	}
	if (pf_tcp->Syn)
	{
		fputs("[SYN]", stdout);
	}
	if (pf_tcp->Psh)
	{
		fputs("[PSH]", stdout);
	}
	if (pf_tcp->Ack)
	{
		fputs("[ACK]", stdout);
	}
	printf("\n");
}

HANDLE handle;
char packet[65535], proxy_packet[65535];
WINDIVERT_ADDRESS recv_addr, send_addr;
UINT packet_len, proxy_packet_len;
int i = 0, j = 0, priority = 0;
PWINDIVERT_IPHDR ip_header;
PWINDIVERT_TCPHDR tcp_header;
UINT origin_src_port, origin_dst_port, src_port, dst_port, flag = 0, payload_len;;
UINT32 proxy_ip, origin_src_ip, origin_dst_ip, src_ip, dst_ip;
UINT16 proxy_port;

struct Matching {
	UINT32 ip;
	UINT16 port;

	bool operator<(const Matching &ep) const { return (ip < ep.ip || (ip == ep.ip && port < ep.port)); }

	Matching() {};

	Matching(UINT32 get_ip, UINT16 get_port) {
		ip = get_ip;
		port = get_port;
	}

};


int main(int argc, char *argv[])
{

	std::map<Matching, Matching> match;

	WinDivertHelperParseIPv4Address(argv[1], &proxy_ip);

	proxy_port = atoi(argv[2]);

	char f[100] = "((outbound and tcp.DstPort == 80) or (inbound and tcp.SrcPort == ";
	strcat(f, argv[2]);
	strcat(f, "))");

	//printf("%s\n", f);

	handle = WinDivertOpen(f, WINDIVERT_LAYER_NETWORK, 0, 0);

	if (handle == INVALID_HANDLE_VALUE)
	{
		printf("WinDivertOpen Error!!!\n");
		return 1;
	}


	while (true)
	{
		WinDivertHelperParsePacket(packet, packet_len, &ip_header, NULL, NULL, NULL, &tcp_header, NULL, NULL, &payload_len);

		if (!WinDivertRecv(handle, packet, sizeof(packet), &recv_addr, &packet_len))
		{
			printf("WinDivertRecv Error!!\n");
			break;
		}

		if (ip_header == NULL || tcp_header == NULL)
			continue;

		if (ntohs(tcp_header->DstPort) == 80)
		{
			printf("클라이언트가 인터넷에 접속함!!");
			print_flag(tcp_header);
			printf("\n\n");

			Matching src_addr(ip_header->SrcAddr, tcp_header->SrcPort);
			Matching dst_addr(ip_header->DstAddr, tcp_header->DstPort);

			match[src_addr] = dst_addr;

			ip_header->DstAddr = htonl(proxy_ip);
			tcp_header->DstPort = htons(proxy_port);

			WinDivertHelperCalcChecksums(packet, packet_len, 0);

			if (!WinDivertSend(handle, packet, packet_len, &recv_addr, NULL))
				printf("여기지? error : don't send\n\n");
		}

		else if (ntohs(tcp_header->SrcPort) == proxy_port)
		{
			Matching dst_addr(ip_header->DstAddr, tcp_header->DstPort);
			Matching origin_addr = match[dst_addr];

			ip_header->SrcAddr = origin_addr.ip;
			tcp_header->SrcPort = origin_addr.port;

			printf("프록시에서 응답이옴!!");
			print_flag(tcp_header);
			printf("\n\n");

			WinDivertHelperCalcChecksums(packet, packet_len, 0);

			if (!WinDivertSend(handle, packet, packet_len, &recv_addr, NULL))
				printf("여기지? error : don't send\n\n");
		}
	}
	WinDivertClose(handle);
	return 0;
}
