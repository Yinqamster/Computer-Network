#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/if_ether.h>
#include <string.h>
#include <errno.h>
#include <netpacket/packet.h>
#include <net/if_arp.h>
#include <linux/sockios.h>
#include <linux/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#define BUFFER_MAX 2048
#define ROUTE_INFO_MAX 20
#define ARP_SIZE_MAX 20
#define DEVICE_MAX 10

struct route_item
{
    char destination[16];
    char gateway[16];
    char netmask[16];
    int interface;
}route_info[ROUTE_INFO_MAX];    
int route_item_index=0;     	

struct arp_table_item
{
    char ip_addr[16];
    char mac_addr[18];
}arp_table[ARP_SIZE_MAX];   	
int arp_item_index=0;   		

struct device_ti
{
    char mac[18];
    int interface;
    int is_entrance;
}device[DEVICE_MAX];    	
int device_index=0;     		

struct sockaddr_ll in_addr;
struct sockaddr_ll out_addr;
struct ifreq ifrq0,ifrq1;
int read_route_table_info()
{
    FILE *fp=fopen("route_table_info","r");
    if(fp==NULL)
    {
        printf("can't open the route_table_info\n");
        return -1;
    }
    char buf[100];
    memset(buf,0,100);
    char *p;
    fgets(buf,100,fp);
    while(!feof(fp))
    {
        if(route_item_index<ROUTE_INFO_MAX)
    	{
            p=strtok(buf," ");
            strcpy(route_info[route_item_index].destination,p);
            p=strtok(NULL," ");
            strcpy(route_info[route_item_index].gateway,p);
            p=strtok(NULL," ");
            strcpy(route_info[route_item_index].netmask,p);
            p=strtok(NULL," ");
            route_info[route_item_index].interface=atoi(p);
            route_item_index++;
    	}
        memset(buf,0,100);
        fgets(buf,100,fp);
    }
    return 1;
}
int read_arp_table_info()
{
    FILE *fp=fopen("arp_table_info","r");
    if(fp==NULL)
    {
        printf("can't open the arp_table_info!\n");
        return -1;
    }
    char buf[50];
    memset(buf,0,50);
    char *p;
    fgets(buf,50,fp);
    while(!feof(fp))
    {
        if(arp_item_index<ARP_SIZE_MAX)
    	{
            p=strtok(buf," ");
            strcpy(arp_table[arp_item_index].ip_addr,p);
            p=strtok(NULL," ");
            strcpy(arp_table[arp_item_index].mac_addr,p);
            arp_item_index++;
    	}
        memset(buf,0,50);
        fgets(buf,50,fp);
    }
    return 1;
}

int read_device_info()
{
    FILE *fp=fopen("device_item_info","r");	
    if(fp==NULL)
    {
        printf("can't open the device_item_info\n");
        return -1;
    }
    char buf[100];
    char *p;
    memset(buf,0,100);
    fgets(buf,100,fp);
    while(!feof(fp))
    {
        if(device_index<DEVICE_MAX)	
    	{
            p=strtok(buf," ");
            strcpy(device[device_index].mac,p);
            p=strtok(NULL," ");
            device[device_index].interface=atoi(p);
            device_index++;
    	}
        memset(buf,0,100);
        fgets(buf,100,fp);
    }
    return 1;
}
int if_des_mac_in_device(char des_mac[18])
{
    int index=0;
    while(index<device_index)
    {
        if(strcmp(device[index].mac,des_mac)==0)
            return 1;
        index++;
    }
    return 0;
}
int check_and_get_in_route_table(char des_ip[16])
{
    int index=-1,i;
    for(i=0;i<route_item_index;i++)
    {
        if(strcmp(route_info[i].destination,des_ip)==0)
    	{
            index=i;
            break;
    	}
    }
    return index;
}
int check_arp_get_next_hop_mac(int gateway_index)
{
    int index=-1;
    int i=0;
    while(i<arp_item_index)
    {
        if(strcmp(arp_table[i].ip_addr,route_info[gateway_index].gateway)==0)
        {   index=i;break;}
        i++;
    }
    return index;
}
void change_18_to_6(char mac[18],unsigned char mac_6[6])
{
    unsigned int temp[6];
    sscanf(mac,"%02x:%02x:%02x:%02x:%02x:%02x",&temp[0],&temp[1],&temp[2],&temp[3],&temp[4],&temp[5]);
    mac_6[0]=(unsigned char)temp[0];
    mac_6[1]=(unsigned char)temp[1];
    mac_6[2]=(unsigned char)temp[2];
    mac_6[3]=(unsigned char)temp[3];
    mac_6[4]=(unsigned char)temp[4];
    mac_6[5]=(unsigned char)temp[5];
}
int decide_type(char des_ip[16])
{   
    char des1[16]="192.168.0.2";
    if(strcmp(des_ip,des1)==0)
    {
            return 1;
    }
    else
    {return -1;}
}
void ncopy(char *p1,char *p2,int n){
    int i=0;
    for (i=0;i<n;i++){
        p1[i]=p2[i];
    }
}
unsigned short csum(unsigned short *buf, int len){
    unsigned long sum;
    for(sum=0;len>0;len--){
        sum+=*buf++;
    }
    sum=(sum>>16)+(sum&0xffff);
    sum+=(sum>>16);
    return ~sum;
}
int repack_packet(char *buffer,char *eth_head,char *des_mac,int sock_fd,int n_read)
{
    char buffer_out[BUFFER_MAX];
    char *vpn_ip_head;
    char *temp;	
    char *repack_eth_head;
    char des_ip[16]="172.0.0.2";
    unsigned char des_mac6[6];
    char src_mac[18];
    unsigned char src_mac6[6];
    int index=-1;
    int arp_index=-1;
    int n = 0xff;
    memset(src_mac,0,18);
    char repacket_ip_head[20];
    memset(repacket_ip_head,0,20);
    struct ip *iph=(struct ip *)repacket_ip_head;
    memset(iph,0,20);
    iph->ip_hl=5;
    iph->ip_v=4;
    iph->ip_tos=0;
    iph->ip_len=htons(20+n_read-14);
    iph->ip_id=htonl(54321);
    iph->ip_off=0;
    iph->ip_ttl=255;
    iph->ip_p=IPPROTO_IP;
    iph->ip_sum=0;
    iph->ip_dst.s_addr=inet_addr("172.0.0.2");
    iph->ip_src.s_addr=inet_addr("192.168.0.2");
    iph->ip_sum=csum((unsigned short *)repacket_ip_head,20>>1);
    printf("length is %d\n",iph->ip_len);

    ncopy(buffer_out+14,repacket_ip_head,20);
    ncopy(buffer_out,buffer,14);
    vpn_ip_head = eth_head+14;
    temp = buffer_out+34;
    ncopy(temp,vpn_ip_head,84);
    repack_eth_head=buffer_out;

    printf("des_ip %s\n",des_ip);
    index = check_and_get_in_route_table(des_ip);
    if(index!=-1)
    {      
        printf("Check and find the vpn_des_ip is in the route item table. index=%d\n",index);
        arp_index=check_arp_get_next_hop_mac(index);
        if(arp_index != -1)
    	{
            printf("check and find that next_hop is in the arp table. index=%d\n",arp_index);
            strcpy(src_mac,des_mac);
            strcpy(des_mac,arp_table[arp_index].mac_addr);
            change_18_to_6(src_mac,src_mac6);	
            change_18_to_6(des_mac,des_mac6);
            memcpy(&(repack_eth_head[6]),src_mac6,6);
            printf("resend data src_mac: %02x:%02x:%02x:%02x:%02x:%02x\n",repack_eth_head[6]&n,repack_eth_head[7]&n,repack_eth_head[8]&n,repack_eth_head[9]&n,repack_eth_head[10]&n,repack_eth_head[11]&n); 									
            memcpy(repack_eth_head,des_mac6,6);
            printf("resend data des_mac: %02x:%02x:%02x:%02x:%02x:%02x\n",repack_eth_head[0]&n,repack_eth_head[1]&n,repack_eth_head[2]&n,repack_eth_head[3]&n,repack_eth_head[4]&n,repack_eth_head[5]&n);   									
    	
            memset(&out_addr,0,sizeof(out_addr));
            strcpy(ifrq0.ifr_name,"eth1");
            ioctl(sock_fd,SIOCGIFINDEX,&ifrq0);
            out_addr.sll_ifindex=ifrq0.ifr_ifindex;
            out_addr.sll_family=PF_PACKET;
    	
            printf("the interface is eth1\n");
            printf("bgein to send data to next_hop.....\n");	
            if((sendto(sock_fd,buffer_out,n_read+20,0,(struct sockaddr*)&out_addr,sizeof(out_addr)))<0)
    		{
                printf("resend data error! errno==%d\n",errno);
    		}
        	else
    		{
                printf("success!!!!!!!!!!\n");
    		}
    		
    	}
        else
    	{
            printf("can not find arp info\n");
    	}
    }
    else
    {
        printf("can not find route table info\n");
    }
    return 0;
}
int unpack_packet(char *buffer,char *eth_head,char *des_mac,int sock_fd,int n_read)
{
    char buffer_in[BUFFER_MAX];
    char vpn_des_ip[16];
    char vpn_src_mac[18];
    char vpn_des_mac[18];
    unsigned char vpn_des_mac6[6];
    unsigned char vpn_src_mac6[6];
    char *vpn_head;
        char *vpn_eth_head;
    char *vpn_ip_head;
    char *p;
    int index=-1;
    int vpn_arp_index=-1;
    int n = 0xff;
    memset(vpn_des_ip,0,16);
    memset(vpn_des_mac,0,18);
    memset(vpn_src_mac,0,18);

    ncopy(buffer_in,buffer,14);
    vpn_head = eth_head+34;
    ncopy(buffer_in+14,vpn_head,84);

    vpn_eth_head = buffer_in;
    vpn_ip_head = vpn_eth_head+14;
    p = vpn_ip_head+12;
    
    sprintf(vpn_des_ip,"%d.%d.%d.%d",(256+p[4])%256,(256+p[5])%256,(256+p[6])%256,(256+p[7])%256);
printf("OK%d %d %d %d %d %d %d %d",p[0],p[1],p[2],p[3],p[4],p[5],p[6],p[7]);
    printf("the vpn_des_ip is: %s\n",vpn_des_ip);
    index = check_and_get_in_route_table(vpn_des_ip);
    if(index!=-1)
    {      
        printf("Check and find the vpn_des_ip is in the route item table. index=%d\n",index);
        vpn_arp_index=check_arp_get_next_hop_mac(index);
        if(vpn_arp_index != -1)
    	{
            printf("check and find that next_hop is in the arp table. index=%d\n",vpn_arp_index);
            strcpy(vpn_src_mac,des_mac);
            strcpy(vpn_des_mac,arp_table[vpn_arp_index].mac_addr);
            change_18_to_6(vpn_src_mac,vpn_src_mac6);	
            change_18_to_6(vpn_des_mac,vpn_des_mac6);	
            memcpy(&(vpn_eth_head[6]),vpn_src_mac6,6);
            printf("resend data vpn_src_mac: %02x:%02x:%02x:%02x:%02x:%02x\n",vpn_eth_head[6]&n,vpn_eth_head[7]&n,vpn_eth_head[8]&n,vpn_eth_head[9]&n,vpn_eth_head[10]&n,vpn_eth_head[11]&n);   									
            memcpy(vpn_eth_head,vpn_des_mac6,6);
            printf("resend data vpn_des_mac: %02x:%02x:%02x:%02x:%02x:%02x\n",vpn_eth_head[0]&n,vpn_eth_head[1]&n,vpn_eth_head[2]&n,vpn_eth_head[3]&n,vpn_eth_head[4]&n,vpn_eth_head[5]&n); 									
    		
            memset(&in_addr,0,sizeof(in_addr));			
            strcpy(ifrq1.ifr_name,"eth0");
            ioctl(sock_fd,SIOCGIFINDEX,&ifrq1);
            in_addr.sll_ifindex=ifrq1.ifr_ifindex;
            in_addr.sll_family=PF_PACKET;
    		
            printf("the interface is eth0\n");
            printf("bgein to send data to next_hop.....\n");			
            if((sendto(sock_fd,buffer_in,n_read-20,0,(struct sockaddr*)&in_addr,sizeof(in_addr)))<0)
    		{
                printf("resend data error! errno==%d\n",errno);
    		}
        	else
    		{
                printf("success!!!!!!!!!!\n");
        	}	
    	}
        else
    	{
            printf("can not find arp info\n");
    	}
    }
    else
    {
        printf("can not find route table info\n");
    }
    return 0;
}
int main(int argc, char* argv[])
{
    if(read_route_table_info()==-1)
        return -1;
    if(read_arp_table_info()==-1)
        return -1;
    if(read_device_info()==-1)
        return -1;
    int sock_fd;
    int n_read;
    char buffer[BUFFER_MAX];
    char *eth_head;
    char *ip_head;
    char *p;
    char type[4];
    char des_ip[16];
    char des_mac[18];
    char src_mac[18];
    int dec_type=-1;
    memset(des_ip,0,16);
    memset(des_mac,0,18);
    memset(src_mac,0,18);
    if ((sock_fd = socket(PF_PACKET,SOCK_RAW,htons(ETH_P_IP)))<0)
    {
        printf("create raw socket error!\n");
        return -1;
    }
    while (1)
    {   printf("sock_fd=%d\n",sock_fd);
        n_read = recvfrom(sock_fd,buffer,BUFFER_MAX, 0, NULL, NULL);
        printf("n_read=%d\n",n_read);
        if (n_read < 42)
    	{
            printf("error when recv msg\n");
            return -1;
    	}
        eth_head = buffer;
        p = eth_head;
        int n = 0xff;
        sprintf(des_mac,"%02x:%02x:%02x:%02x:%02x:%02x",p[0]&n,p[1]&n,p[2]&n,p[3]&n,p[4]&n,p[5]&n);
        printf("the destination mac(the next hop)is %s\n ",des_mac);
        printf("check the destination mac in device \n ");
        if(if_des_mac_in_device(des_mac)==1)
    	{	
            printf("check the des_mac,find that the des_mac is in device,so recv data...\n ");
            sprintf(type,"%02x%02x",p[12]&n,p[13]&n);
            printf("TYPE:  %s      ",type);
            if(strncmp(type,"0800",4)==0)
            {   printf("packet is IP protocol\n");
            	//get ip
                ip_head = eth_head+14;
                p = ip_head+12;
                sprintf(des_ip,"%d.%d.%d.%d",(256+p[4])%256,(256+p[5])%256,(256+p[6])%256,(256+p[7])%256);
                printf("the des_ip is: %s\n",des_ip);
                dec_type = decide_type(des_ip);
                if(dec_type == 1)
        		{
                    printf("vpn in\n");
                    unpack_packet(buffer,eth_head,des_mac,sock_fd,n_read);
        		}
                else
        		{
                    printf("vpn out\n");
                    repack_packet(buffer,eth_head,des_mac,sock_fd,n_read);	
        		}
    		}
            printf("***one packet process end ,get next packet...***\n\n");
    	}
    }   			
    return 0;
}


