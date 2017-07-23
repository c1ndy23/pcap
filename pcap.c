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
#include <stdint.h>
#include <ctype.h>
#define ETHER_ADDR_LEN  6

        struct sniff_ethernet {
                u_char ether_dhost[ETHER_ADDR_LEN]; 
                u_char ether_shost[ETHER_ADDR_LEN]; 
                u_int16_t ether_type;
        };

        struct sniff_ip {
                u_char ip_vhl;        
                u_char ip_tos;        
                u_int16_t ip_len;       
                u_int16_t ip_id;        
                u_int16_t ip_off;       
        #define IP 0x8000          
        #define IP_DF 0x4000          
        #define IP_MF 0x2000          
        #define IP_OFFMASK 0x1fff     
                u_char ip_ttl;        
                u_char ip_p;          
                u_int16_t ip_sum;        
                struct  in_addr ip_src, ip_dst;
        };
        #define IP_V(ip)                ((((ip)->ip_vhl) >> 4) & 0x0f)
        #define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)

        struct sniff_tcp {
                u_int16_t th_sport;     
                u_int16_t th_dport;     
                u_int32_t th_seq;         
                u_int32_t th_ack;          
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
                u_int16_t th_win;         
                u_int16_t th_sum;         
                u_int16_t th_urp;         
        };


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
        int i,j = 0;
        int offset = 0;
        int data_len = 0;
        struct sockaddr_in sa;
        char input[100];
        char output[100];
        unsigned short ether_type;

        struct sniff_ethernet *eh;
        struct sniff_ip *ih;         
        struct sniff_tcp *th;

        if(argc <2)
        {
            printf("%s", "argc error\n");
            return(2);
        }

        dev = argv[1];

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
                    eh = (struct sniff_ethernet *)packet;
                    ih = (struct sniff_ip *)(packet + 14);
                    th = (struct sniff_tcp *)(packet + 14 + ((((ih)->ip_vhl) & 0x0f)*4));
                    
                    ether_type=ntohs(eh->ether_type); 

                    if (ether_type!=ETHERTYPE_IP)
                    {
                            printf("ether type wrong\n");
                            return ;
                    }

                    printf("\n============ETHERNET HEADER============\n");
                    printf("dst MAC Addr : ");
                    for(i=0;i<5;i++)
                            printf("%02x:", eh->ether_shost[i]); 
                    printf("%02x\n", eh->ether_shost[i+1]);
            
                    printf("src MAC Addr : ");
                    for(j=0;j<5;j++)
                            printf("%02x:", eh->ether_dhost[j]);
                    printf("%02x\n", eh->ether_dhost[j+1]);


                    printf("\n============IP HEADER============\n");
                    if(ih->ip_p == IPPROTO_TCP)
                    {
                            printf("Protocol : TCP\n");
                    }
               
                    printf("src IP : %s\n", inet_ntop(AF_INET, &(ih->ip_src), output, 100));
                    printf("dst IP : %s\n", inet_ntop(AF_INET, &(ih->ip_dst), output, 100));

                    printf("\n============TCP HEADER============\n");
                    printf("src port : %d\n", ntohs(th->th_sport) );
                    printf("dst port : %d\n", ntohs(th->th_dport) );
                    printf("\n");
                    
                    printf("\n============DATA============\n");
                    offset = (((((ih)->ip_vhl) & 0x0f)*4) + (((((th)->th_off) >> 4) & 0x0f)*4));
                    packet = (packet + 14 + offset);
                    
                    data_len = ((ih)->ip_len);
                    
                    data_len = (data_len - offset);
                    
                    for(i=0;i<=data_len;i++)
                    {
                        if(isdigit(*(packet+i)))
                            printf("%c", *(packet+i));
                        else 
                            printf(".");
                            
                    }
                    
                }
                else
                {
                    printf("%s", "packet can't read\n");
                    return(2);
                }
                continue;
        }

        pcap_close(handle);
        return 0;
}
