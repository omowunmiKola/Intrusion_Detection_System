//
//  sniffer.c
//  IDS_Lightwork
//
//  Created by KOLAWOLE ESTHER on 6/24/26.
//

#include <stdlib.h>
#include <stdio.h>
#include <pcap/pcap.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define SNAP_LEN 1518 //max number of bytes per packet to capture
#define SIZE_ETHERNET 14 //14 bytes for ethernet headers
#define ETHER_ADDR_LEN 6 //ethernet address es 6



/*ETHERNET HEADER*/
struct ethernet_sniff{
    u_char  ether_dhost[ETHER_ADDR_LEN]; // destination host address
    u_char  ether_shost[ETHER_ADDR_LEN]; // source host address
    u_short ether_type; //IP? ARP? RARP? etc
};

/*IP HEADER*/
struct ip_sniff {
    u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
    u_char  ip_tos;                 /* type of service */
    u_short ip_len;                 /* total length */
    u_short ip_id;                  /* identification */
    u_short ip_off;                 /* fragment offset field */
    
    #define IP_RF 0x8000            /* reserved fragment flag */
    #define IP_DF 0x4000            /* don't fragment flag */
    #define IP_MF 0x2000            /* more fragments flag */
    #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
    
    u_char  ip_ttl;                 /* time to live */
    u_char  ip_p;                   /* protocol */
    u_short ip_sum;                 /* checksum */
    struct  in_addr ip_src,ip_dst;  /* source and dest address */
};

#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)  (((ip)->ip_vhl) >> 4)

/*TCP HEADER*/
typedef uint tcp_seq;
struct tcp_sniff {
    u_short th_sport;               /* source port */
    u_short th_dport;               /* destination port */
    tcp_seq th_seq;                 /* sequence number */
    tcp_seq th_ack;                 /* acknowledgement number */
    u_char  th_offx2;               /* data offset, rsvd */
    
    #define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
    
    u_char  th_flags;
    
    #define TH_FIN  0x01
    #define TH_SYN  0x02
    #define TH_RST  0x04
    #define TH_PUSH 0x08
    #define TH_ACK  0x10
    #define TH_URG  0x20
    #define TH_ECE  0x40
    #define TH_CWR  0x80
    #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    
    u_short th_win;                 /* window */
    u_short th_sum;                 /* checksum */
    u_short th_urp;                 /* urgent pointer */
};

struct attacker {
    struct in_addr ip_address;
    int  SYN_count;
};

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void print_payload(const u_char *payload, int len);
void print_hex_ascii_line(const u_char *payload, int len, int offset);

/*
 * print data in rows of 16 bytes: offset   hex   ascii
 *
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
void print_hex_ascii_line(const u_char *payload, int len, int offset){
    int i;
    int gap;
    const u_char *ch;

    /* offset */
    printf("%05d   ", offset);

    /* hex */
    ch = payload;
    for(i = 0; i < len; i++) {
        printf("%02x ", *ch);
        ch++;
        /* print extra space after 8th byte for visual aid */
        if (i == 7)
            printf(" ");
    }
    /* print space to handle line less than 8 bytes */
    if (len < 8)
        printf(" ");

    /* fill hex gap with spaces if not full line */
    if (len < 16) {
        gap = 16 - len;
        for (i = 0; i < gap; i++) {
            printf("   ");
        }
    }
    printf("   ");

    /* ascii (if printable) */
    ch = payload;
    for(i = 0; i < len; i++) {
        if (isprint(*ch))
            printf("%c", *ch);
        else
            printf(".");
        ch++;
    }

    printf("\n");

    return;
}

void print_payload(const u_char *payload, int len) {

    int len_rem = len;
    int line_width = 16;            /* number of bytes per line */
    int line_len;
    int offset = 0;                    /* zero-based offset counter */
    const u_char *ch = payload;

    if (len <= 0)
        return;

    /* data fits on one line */
    if (len <= line_width) {
        print_hex_ascii_line(ch, len, offset);
        return;
    }

    /* data spans multiple lines */
    for ( ;; ) {
        /* compute current line length */
        line_len = line_width % len_rem;
        /* print line */
        print_hex_ascii_line(ch, line_len, offset);
        /* compute total remaining */
        len_rem = len_rem - line_len;
        /* shift pointer to remaining bytes to print */
        ch = ch + line_len;
        /* add offset */
        offset = offset + line_width;
        /* check if we have line width chars or less */
        if (len_rem <= line_width) {
            /* print last line and get out */
            print_hex_ascii_line(ch, len_rem, offset);
            break;
        }
    }
   return;
}

void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
   #define MAX_ARRAY_SIZE 100
    static int count = 1;                   /* packet counter */

    /* declare pointers to packet headers */
    const struct ethernet_sniff *ethernet;  /* The ethernet header [1] */
    const struct ip_sniff *ip;              /* The IP header */
    const struct tcp_sniff *tcp;            /* The TCP header */
    const u_char *payload;                    /* Packet payload */
    int dynamic_header_size = *(int *)args;
    static struct attacker tracked_attackers[100]; //keeping track of connection attempts
    static int unique_attacker_count = 0;

    int size_ip;
    int size_tcp;
    int size_payload;

    printf("\nPacket number %d:\n", count);
    count++;

    /* define ethernet header */
    ethernet = (struct ethernet_sniff*)(packet);

    /* define/compute ip header offset */
    ip = (struct ip_sniff*)(packet + dynamic_header_size);
    size_ip = IP_HL(ip)*4;
    if (size_ip < 20) {
        printf("   * Invalid IP header length: %u bytes\n", size_ip);
        return;
    }

    /* print source and destination IP addresses */
    printf("       From: %s\n", inet_ntoa(ip->ip_src));
    printf("         To: %s\n", inet_ntoa(ip->ip_dst));

    /* determine protocol */
    switch(ip->ip_p) {
        case IPPROTO_TCP:
            printf("   Protocol: TCP\n");
            break;
        case IPPROTO_UDP:
            printf("   Protocol: UDP\n");
            return;
        case IPPROTO_ICMP:
            printf("   Protocol: ICMP\n");
            return;
        case IPPROTO_IP:
            printf("   Protocol: IP\n");
            return;
        default:
            printf("   Protocol: unknown\n");
            return;
    }

    /*
     *  OK, this packet is TCP.
     */

    /* define/compute tcp header offset */
    tcp = (struct tcp_sniff*)(packet + dynamic_header_size + size_ip);
    size_tcp = TH_OFF(tcp)*4;
    if (size_tcp < 20) {
        printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
        return;
    }

    printf("   Src port: %d\n", ntohs(tcp->th_sport));
    printf("   Dst port: %d\n", ntohs(tcp->th_dport));
    
    if(tcp->th_flags & TH_SYN){//tracking connection attempts and a local alert if IP hits certain threshholds
        int found = 0;
        for (int i=0; i<unique_attacker_count; i++) {
            if (ip->ip_src.s_addr == tracked_attackers[i].ip_address.s_addr) {
                tracked_attackers[i].SYN_count++;
                if (tracked_attackers[i].SYN_count == 20) {
                    printf("[!!!] PORT SCAN DETECTED [!!!]\n");
                    
                }
                found = 1;
                break;
            }
        }
        
        if (found == 0) {
            if ((unique_attacker_count < MAX_ARRAY_SIZE)) {
                tracked_attackers[unique_attacker_count].ip_address = ip->ip_src;
                tracked_attackers[unique_attacker_count].SYN_count = 1;
                unique_attacker_count++;
                printf("ONE UNIQUE ATTACKER ADDED. ATTACKER COUNT: %d", unique_attacker_count);
            }else {
                printf("ATTACKERS REACHED MAX OF 100!!\n");
            }
        }
    }

    /* define/compute tcp payload (segment) offset */
    payload = (const u_char *)(packet + dynamic_header_size + size_ip + size_tcp);//ntohs/ntohl work to keep data read right because of endianess
    //endianess is how the computer reads information

    /* compute tcp payload (segment) size */
    size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);

    /*
     * Print payload data; it might be binary, so don't just
     * treat it as a string.
     */
    if (size_payload > 0) {
        printf("   Payload (%d bytes):\n", size_payload);
        print_payload(payload, size_payload);
    }

return;
}

int main(int argc, char * argv[]) {
    char *dev, errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle; // session handler
    pcap_if_t *alldevs; // This is a struct that holds the list of devices
    bpf_u_int32 mask; //subnet mask
    bpf_u_int32 net; //IP
    int num_packets = 10; //number of packets to capture
    int dl_header_size;
    struct pcap_pkthdr header;
    const u_char *packet;
    
    if(pcap_findalldevs(&alldevs,errbuf)==-1){
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return(2);
    };
    dev = alldevs->name; //Grab the name of the very first device in the list
    //printf("Device found: %s\n", dev);
    
    if (pcap_lookupnet(dev, &net, &mask, errbuf)==-1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n",dev, errbuf);
        net = 0;
        mask = 0;
    }
    printf("Device: %s\n", dev);
    printf("Number of packets: %d\n", num_packets);

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle==NULL) {
        fprintf(stderr, "Could not open device %s: %s\n",dev, errbuf);
        return(2);
    }
    
    switch (pcap_datalink(handle)) { /*MAKING HEADER DYNAMIC*/
        case DLT_EN10MB:
            dl_header_size = 14;
            break;
        case DLT_NULL:
            dl_header_size = 4;
            break;
        case DLT_LINUX_SLL:
            dl_header_size = 16;
            break;
        default:
            printf("Unsupported Data Link Type\n");
            exit(0);
    }

     //printf("Jacked a packet with length of [%d]\n", header.len);
    pcap_loop(handle, num_packets, got_packet, (u_char *)&dl_header_size);
    pcap_close(handle);
    pcap_freealldevs(alldevs);
    printf("\nCapture complete.\n");
    return 0;
}
