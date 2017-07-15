#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <string.h>

void print_ether_header(const unsigned char *packet);
int print_ip_header(const unsigned char *packet);
int print_tcp_header(const unsigned char *packet);
void print_data(const unsigned char *packet);

int main(int argc, char *argv[])
{
        pcap_t *handle;                 
        char *dev;                      
        char errbuf[PCAP_ERRBUF_SIZE];  
        struct bpf_program fp;          
        char filter_exp[] = "port 80";  
        bpf_u_int32 mask;               
        bpf_u_int32 net;                
        struct pcap_pkthdr *header;     
        const u_char *packet;           
        int offset = 0;
        int len = 0;

        dev = pcap_lookupdev(errbuf);
        if (dev == NULL) {
                fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
                return(2);
        }

        if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
                fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
                net = 0;
                mask = 0;
        }

        handle = pcap_open_live(dev, BUFSIZ, 1, 0, errbuf);
        if (handle == NULL) {
                fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
                return(2);
        }

        if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
                fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
                return(2);
        }
        if (pcap_setfilter(handle, &fp) == -1) {
                fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
                return(2);
        }

        while(1)
        {
                if(pcap_next_ex(handle, &header, &packet))
                {
                        print_ether_header(packet);
                        packet = packet + 14; 
                        offset = print_ip_header(packet);
                        packet = packet + offset;
                        offset = print_tcp_header(packet);
                        packet = packet + offset;   
                        print_data(packet);
                 }
                continue;

        }
}

void print_ether_header(const unsigned char *packet)
{
        int i,j = 0;
        u_short ether_type; 
        memcpy(&ether_type, packet+12, 2);
        ether_type=ntohs(ether_type);

        if (ether_type!=0x0800)
        {
                printf("ether type wrong\n");
                return ;
        }

        printf("\n============ETHERNET HEADER============\n");
        printf("Dst MAC Addr : ");
        for(i=0;i<5;i++)
                printf("%02x:", packet[i]); 
        printf("%02x\n", packet[i+1]);

        printf("Src MAC Addr : ");
        for(j=6;j<11;j++)
                printf("%02x:", packet[j]);
        printf("%02x\n", packet[j+1]);
        printf("\n");
}

int print_ip_header(const unsigned char *packet)
{
        u_char version;
        u_char ip_protocol;
        struct in_addr ip_src;
        struct in_addr ip_dst;
        memcpy(&version, packet, 1);
        memcpy(&ip_protocol, packet+10, 1);
        memcpy(&ip_src, packet+12, 4);
        memcpy(&ip_dst, packet+16, 4);

        printf("\n============IP HEADER============\n");

        if(ip_protocol == 0x06)
                printf("Protocol : TCP\n");

        printf("Src IP Addr : %s\n", inet_ntoa(ip_src) );
        printf("Dst IP Addr : %s\n", inet_ntoa(ip_dst) );

        return (version & 0x0f)*4; // header_length return
}

int print_tcp_header(const unsigned char *packet)
{
        u_short s_port;
        u_short d_port;
        u_char offset;
        memcpy(&s_port, packet, 2);
        memcpy(&d_port, packet+2, 2);
        memcpy(&offset, packet+12 , 1);
        printf("\n============TCP HEADER============\n");
        printf("Src port number : %d\n", ntohs(s_port) );
        printf("Dst port number : %d\n", ntohs(d_port) );
        printf("\n");
 
        return ((offset >> 4) & 0x0f)*4;
}

void print_data(const unsigned char *data)
{
    printf("\n============DATA============\n");
    printf("%s\n\n", data);
}
