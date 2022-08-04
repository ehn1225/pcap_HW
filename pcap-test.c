#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#define ETHER_ADDR_LEN	6
#define SIZE_ETHERNET 14


/* Ethernet header */
struct ethernet {
	u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
	u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
	u_short ether_type; /* IP? ARP? RARP? etc */
};

/* IP header */
struct ip {
	u_char ip_vhl;		/* version << 4 | header length >> 2 */
	u_char ip_tos;		/* type of service */
	u_short ip_len;		/* total length */
	u_short ip_id;		/* identification */
	u_short ip_off;		/* fragment offset field */
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* don't fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
	u_char ip_ttl;		/* time to live */
	u_char ip_p;		/* protocol */
	u_short ip_sum;		/* checksum */
	struct in_addr ip_src,ip_dst; /* source and dest address */
};
#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct tcp {
	u_short th_sport;	/* source port */
	u_short th_dport;	/* destination port */
	tcp_seq th_seq;		/* sequence number */
	tcp_seq th_ack;		/* acknowledgement number */
	u_char th_offx2;	/* data offset, rsvd */
#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
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
	u_short th_win;		/* window */
	u_short th_sum;		/* checksum */
	u_short th_urp;		/* urgent pointer */
};


void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param  = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}
	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		//modify sector
		struct ethernet *eth_hdr = (struct ethernet *)packet; //Ethernt Header Struct

		//if next layer is not ip, move next packet
		if(ntohs(eth_hdr->ether_type)!=0x0800){
			printf("This Packet is not IP ptotocol\n");
		       	continue; 
		}

		struct ip *ip_hdr = (struct ip *)(packet+SIZE_ETHERNET); //IP Header Struct
		//if next layer is not tcp, move next packet
		if(ip_hdr->ip_p != 0x06){
			printf("This Packet is not TCP  ptotocol\n");
		       	continue;
		}
		u_int size_ip;
		u_int size_tcp;
		size_ip = IP_HL(ip_hdr)*4;
		struct tcp *tcp_hdr = (struct tcp*)(packet + SIZE_ETHERNET + size_ip); //TCP Header Struct
		size_tcp = TH_OFF(tcp_hdr)*4; 
		
		printf("================ Ethernet ================\n");
		printf("Source MAC Address     : %02x:%02x:%02x:%02x:%02x:%02x\n", eth_hdr->ether_shost[0],eth_hdr->ether_shost[1],eth_hdr->ether_shost[2],eth_hdr->ether_shost[3],eth_hdr->ether_shost[4],eth_hdr->ether_shost[5]);
		printf("Dstination MAC Address : %02x:%02x:%02x:%02x:%02x:%02x\n", eth_hdr->ether_dhost[0],eth_hdr->ether_dhost[1],eth_hdr->ether_dhost[2],eth_hdr->ether_dhost[3],eth_hdr->ether_dhost[4],eth_hdr->ether_dhost[5]);

		printf("=================== IP ===================\n");
		printf("Source IP Address     : %s\n", inet_ntoa(ip_hdr->ip_src));
		printf("Destnation IP Address : %s\n", inet_ntoa(ip_hdr->ip_dst));

		printf("================== TCP ===================\n");
        	printf("Source Port     : %d\n", ntohs(tcp_hdr->th_sport));
        	printf("Destnation Port : %d\n", ntohs(tcp_hdr->th_dport));
		const char * payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
		u_int payload_size = ntohs(ip_hdr->ip_len) - size_ip - size_tcp;
		if(payload_size > 10){payload_size = 10;}
		if(payload_size == 0){
                        printf("No Data");
                }
                else{
                        for(int i =0; i < payload_size;i++){
                                printf("%02x ", payload[i]);
                        }


                }	
		printf("\n============= End Of Packet ==============\n\n\n");

			
	}

	pcap_close(pcap);
}
