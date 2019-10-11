#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/if_ether.h>
#include <linux/in.h>

#define BUFFER_MAX 2048

int main(int argc, char* argv[]) {
	int sock_fd;
	int proto;
	int n_read;
	char buffer[BUFFER_MAX];
	char *eth_head;
	char *ip_head;
	char *tcp_head;
	char *udp_head;
	char *icmp_head;
	unsigned char *p;

	if((sock_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP))) < 0) {
		printf("error create raw socket\n");
		return -1;
	}
	
	int flag = 0;  //用于判断是否为ARP RARP协议
	int count = 1;  //用于计数帧数量

	while(1) {
		n_read = recvfrom(sock_fd, buffer, 2048, 0, NULL, NULL);
		if (n_read < 42) {
			printf("error when recv msg\n");
			return -1;
		}

		eth_head = buffer;
		p = eth_head;

		//采用Wireshark的输出方式进行输出
		printf("NUMBER OF FRAME: %d\nMAC address: Src: %.2x:%02x:%02x:%02x:%02x:%02x Dest: %.2x:%02x:%02x:%02x:%02x:%02x\n",
			count ++,
			p[6], p[7], p[8], p[9], p[10], p[11],
			p[0], p[1], p[2], p[3], p[4], p[5]);

		ip_head = eth_head + 14;
		
		//ARP情况
		if ((p+12)[1] == 0x06 && (p+12)[0] == 0x08) {
			flag = 1;		
			printf("ARP\n");
		}
		//RARP情况
		else if ((p+12)[1] == 0x35 && (p+12)[0] == 0x80) {
			flag = 1;
			printf("RARP\n");
		}

		//两种情况下 输出相同
		if (flag) {
			if ((ip_head+7)[0] == 0x01) {
				p = ip_head + 14;
				printf("Information: Who has %d.%d.%d.%d? Tell %d.%d.%d.%d\n",
					p[10], p[11], p[12], p[13],
					p[0], p[1], p[2], p[3]);
			}
			else {
				p = ip_head + 8;
				printf("Information: %d.%d.%d.%d is at %.2x:%02x:%02x:%02x:%02x:%02x\n",
					p[6], p[7], p[8], p[9],
					p[0], p[1], p[2], p[3], p[4], p[5]);
			}
		}
		else {
			p = ip_head + 12;
			printf("IP address: Src: %d.%d.%d.%d Dest: %d.%d.%d.%d\n",
				p[0], p[1], p[2], p[3],
				p[4], p[5], p[6], p[7]);
			proto = (ip_head+9)[0];
			p = ip_head + 12;
			printf("Protocol:");
			switch(proto) {
				case IPPROTO_ICMP:printf("icmp\n");break;
				case IPPROTO_IGMP:printf("igmp\n");break;
				case IPPROTO_IPIP:printf("ipip\n");break;
				case IPPROTO_TCP:printf("tcp\n");break;
				case IPPROTO_UDP:printf("udp\n");break;
				default:printf("Pls query yourself\n");

			}
			if ((ip_head+20)[0] == 0x0) printf("Information: Echo (ping) reply\n");
			if ((ip_head+20)[0] == 0x08) printf("Information: Echo (ping) request\n");
		}
	}
	return -1;
}
