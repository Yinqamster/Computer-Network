//include必要头文件
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netdb.h>
#include <netinet/in_systm.h>
#include <unistd.h>
#include <signal.h>
#include <arpa/inet.h>
#include <errno.h>

//定义Buffersize为2048
#define BUFFER_MAX 2048

struct sockaddr_in sockadd;
int raw_sock;

void xping();

unsigned short cksum(unsigned short *, int);

void output(char *, int);


int main(int argc, char *argv[]) {
	int size;
	struct timeval now;  //进行计时
	char buffer[BUFFER_MAX];

	//调用程序错误 进行提示
	if(argc != 2) {
		printf("Wrong args");
		return -1;
	}


	//创建rawsocket 错误进行提示
	raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if(raw_sock < 0) {
		printf("error *\n");
		return -1;
	}

	bzero(&sockadd, sizeof(sockadd));
	sockadd.sin_family=AF_INET;
	if(inet_aton(argv[1], &sockadd.sin_addr) < 0) {
		printf("invalid IP address:%s\n", argv[1]);
		return -1;
	}

	signal(SIGALRM, xping);  //进行ping动作
	alarm(1);
	//不断进行发包动作
	while(1) {
		size = read(raw_sock, buffer, BUFFER_MAX);
		if(errno == EINTR && size < 0)
			continue;
		else if(size > 0)
			output(buffer, size);
		else if(size < 0)
			printf("error **\n");
	}
	return 0;
}


void xping() {
	int size, i;
	static unsigned short seq = 0;
	char buff[BUFFER_MAX];
	struct timeval tv; 
        struct icmp *icmph = (struct icmp *)buff;
	long *data = (long *)icmph->icmp_data;

	bzero(buff, BUFFER_MAX);
	gettimeofday(&tv, NULL); 

        icmph->icmp_type = ICMP_ECHO;
	icmph->icmp_code = 0; icmph->icmp_cksum = 0;
	icmph->icmp_id = getpid() & 0xffff;
	icmph->icmp_seq = seq++;

	data[0] = tv.tv_sec;
	data[1] = tv.tv_usec; 

	for(i = 8; i < 64; i++)
		icmph->icmp_data[i] = (unsigned char)i;

	icmph->icmp_cksum = cksum((unsigned short *)buff, 72);
	size = sendto(raw_sock, buff, 72, 0, (struct sockaddr *)&sockadd, sizeof(sockadd));
	alarm(1);
}

//参照网络程序进行ICMP包校验计算
unsigned short cksum(unsigned short *addr, int size) {
	int sum = 0;
	unsigned short res = 0;

	while(size > 1)  {
		sum += *addr++;
		size -= 2;
	}
        if(size == 1) {
		*((unsigned char *)(&res)) = *((unsigned char *)addr);
		sum += res;
        }

	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	return ~sum;
}
//按照ping的格式输出输出发包信息
void output(char *buf, int size) {
	struct ip *ipPack = (struct ip *)buf;
	int i = ipPack->ip_hl * 4;
	struct icmp *icmph = (struct icmp *)&buf[i];
	long *data = (long*)icmph->icmp_data;
	struct timeval tv;

	gettimeofday(&tv, NULL);
	if(icmph->icmp_type != ICMP_ECHOREPLY)
		return;
	if(icmph->icmp_id != (getpid()&0xffff))
		return;
	printf("From %s: ttl=%d seq=%d time=%.2f ms\n",
		inet_ntoa(ipPack->ip_src), ipPack->ip_ttl ,
		icmph->icmp_seq,
		(tv.tv_sec-data[0])*1000.0+(tv.tv_usec-data[1])/1000.0);

}
