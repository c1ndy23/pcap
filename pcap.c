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

#define ETHER_ADDR_LEN  6

        struct sniff_ethernet {
                u_char ether_dhost[ETHER_ADDR_LEN]; 
                u_char ether_shost[ETHER_ADDR_LEN]; 
                u_short ether_type;
        };

        struct sniff_ip {
                u_char ip_vhl;        
                u_char ip_tos;        
                u_short ip_len;       
                u_short ip_id;        
                u_short ip_off;       
        #define IP_RF 0x8000          
        #define IP_DF 0x4000          
        #define IP_MF 0x2000          
        #define IP_OFFMASK 0x1fff     
                u_char ip_ttl;        
                u_char ip_p;          
                u_short ip_sum;        
                struct  in_addr ip_src, ip_dst;
        };
        #define IP_V(ip)                ((((ip)->ip_vhl) >> 4) & 0x0f)
        #define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)

        struct sniff_tcp {
                u_short th_sport;     
                u_short th_dport;     
                u_int th_seq;         
                u_int th_ack;          
                u_char th_off;        
        #define TH_OFF(th)      ((((th)->th_off) >> 4) & 0x0f)
                u_char th_flags;
        #define TH_FIN 0x01
        #define TH_SYN 0x02
        #define TH_RST 0x04
        #define TH_PUSH 0x08
        #define TH_ACK 0x10
        #define TH_URG 0x20
        #define TH_ECE 0x40
        #define TH_CWR 0x80
        #define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
                u_short th_win;         
                u_short th_sum;         
                u_short th_urp;         
};

void print_ether_header(const unsigned char *data);
int print_ip_header(const unsigned char *data);
int print_tcp_header(const unsigned char *data);
void print_data(const unsigned char *data);

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
	    unsigned char *user;
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

        pcap_close(handle);
        return 0;
}

int print_ip_header(const unsigned char *data)
{
        struct sniff_ip *ih;         
        ih = (struct sniff_ip *)data;  
 
        printf("\n============IP HEADER============\n");
        if(ih->ip_p == 0x06)
        {
                printf("Protocol : TCP\n");
        }
        printf("src IP : %s\n", inet_ntoa(ih->ip_src) );
        printf("dst IP : %s\n", inet_ntoa(ih->ip_dst) );
       
        return IP_HL(ih)*4;
}

void print_ether_header(const unsigned char *data)
{
        struct sniff_ethernet *eh;
        eh = (struct sniff_ethernet *)data;
        unsigned short ether_type;
        ether_type=ntohs(eh->ether_type); 

        if (ether_type!=0x0800)
        {
                printf("ether type wrong\n");

                return ;
        }
      
        printf("\n============ETHERNET HEADER==========\n");
        printf("Dst MAC Addr [%02x:%02x:%02x:%02x:%02x:%02x]\n", 
                    eh->ether_dhost[0],
                    eh->ether_dhost[1],
                    eh->ether_dhost[2],
                    eh->ether_dhost[3],
                    eh->ether_dhost[4],
                    eh->ether_dhost[5]);
        printf("Src MAC Addr [%02x:%02x:%02x:%02x:%02x:%02x]\n", 
                    eh->ether_shost[0],
                    eh->ether_shost[1],
                    eh->ether_shost[2],
                    eh->ether_shost[3],
                    eh->ether_shost[4],
                    eh->ether_shost[5]);
}

int print_tcp_header(const unsigned char *data)
{
        struct sniff_tcp *th;
        th = (struct sniff_tcp *)data;
 
        printf("\n============TCP HEADER============\n");
        printf("src port : %d\n", ntohs(th->th_sport) );
        printf("dst port : %d\n", ntohs(th->th_dport) );
        printf("\n");
 
        return TH_OFF(th)*4;
}

void print_data(const unsigned char *data)
{
    printf("\n============DATA============\n");
    printf("%s\n\n", data);
}
