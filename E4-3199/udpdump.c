/*
 * Copyright (c) 1999 - 2005 NetGroup, Politecnico di Torino (Italy)
 * Copyright (c) 2005 - 2006 CACE Technologies, Davis (California)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Politecnico di Torino, CACE Technologies 
 * nor the names of its contributors may be used to endorse or promote 
 * products derived from this software without specific prior written 
 * permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifdef _MSC_VER
/*
 * we do not want the warnings about the old deprecated and unsecure CRT functions
 * since these examples can be compiled under *nix as well
 */
#define _CRT_SECURE_NO_WARNINGS
#endif

#include "pcap.h"
#include <ntddndis.h>
#include "Packet32.h"

#pragma comment(lib, "Packet")
#pragma comment(lib, "wpcap")
#pragma comment(lib, "WS2_32")


/* 4 bytes IP address */
typedef struct ip_address
{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;

/*帧格式*/
typedef struct mac_header {
	u_char dest_addr[6];
	u_char src_addr[6];
	u_char type[2];
} mac_header;

/* IPv4 header */
typedef struct ip_header
{
	u_char	ver_ihl;		// Version (4 bits) + Internet header length (4 bits)
	u_char	tos;			// Type of service 
	u_short tlen;			// Total length 
	u_short identification; // Identification
	u_short flags_fo;		// Flags (3 bits) + Fragment offset (13 bits)
	u_char	ttl;			// Time to live
	u_char	proto;			// Protocol
	u_short crc;			// Header checksum
	ip_address	saddr;		// Source address
	ip_address	daddr;		// Destination address
	u_int	op_pad;			// Option + Padding
}ip_header;

/* UDP header*/
typedef struct udp_header
{
	u_short sport;			// Source port
	u_short dport;			// Destination port
	u_short len;			// Datagram length
	u_short crc;			// Checksum
}udp_header;

typedef struct macandip {
	u_char mac_addr[6];
	ip_address ip_addr;
	long len;
	struct macandip*next;
}macandip;
typedef struct ftp_header {
	u_short	src_port;
	u_short	des_port;
	u_short	seq_num[2];
	u_short	ack_num[2];
	u_char bit_len;			// Total bit length 
	u_char flags;			//标志位
	u_short win_size;		//window size value
	u_short checksum;		//Checksum
	u_short urg_pointer;	//urgent pointer
} ftp_header;


/* prototype of the packet handler */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
void print();

int main()
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i=0;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_int netmask;
	char packet_filter[] = "tcp port ftp";//捕获ftp数据包
	struct bpf_program fcode;
	
	/* Retrieve the device list */
	if(pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}
	
	/* Print the list */
	for(d=alldevs; d; d=d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if(i==0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}
	
	printf("Enter the interface number (1-%d):",i);
	scanf("%d", &inum);
	
	/* Check if the user specified a valid adapter */
	if(inum < 1 || inum > i)
	{
		printf("\nAdapter number out of range.\n");
		
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* Jump to the selected adapter */
	for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++);
	
	/* Open the adapter */
	if ((adhandle= pcap_open_live(d->name,	// name of the device
							 65536,			// portion of the packet to capture. 
											// 65536 grants that the whole packet will be captured on all the MACs.
							 1,				// promiscuous mode (nonzero means promiscuous)
							 1000,			// read timeout
							 errbuf			// error buffer
							 )) == NULL)
	{
		fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
	
	/* Check the link layer. We support only Ethernet for simplicity. */
	if(pcap_datalink(adhandle) != DLT_EN10MB)
	{
		fprintf(stderr,"\nThis program works only on Ethernet networks.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
	
	if(d->addresses != NULL)
		/* Retrieve the mask of the first address of the interface */
		netmask=((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/* If the interface is without addresses we suppose to be in a C class network */
		netmask=0xffffff; 


	//compile the filter
	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) <0 )
	{
		fprintf(stderr,"\nUnable to compile the packet filter. Check the syntax.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
	
	//set the filter
	if (pcap_setfilter(adhandle, &fcode)<0)
	{
		fprintf(stderr,"\nError setting the filter.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
	
	printf("\nlistening on %s...\n", d->description);
	
	/* At this point, we don't need any more the device list. Free it */
	pcap_freealldevs(alldevs);

	
	/* start the capture */
	pcap_loop(adhandle, 0, packet_handler, NULL);
	
	return 0;
}


/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	struct tm *ltime;
	char timestr[16];
	ip_header *ih;
	udp_header *uh;
	u_int ip_len;
	u_short sport,dport;
	time_t local_tv_sec;
	mac_header* mh;
	ftp_header *ftp;
	const int head = 54;
	FILE *fp = NULL;
	FILE *fpw = NULL;
	char *user = NULL;
	char *password = NULL;



	/*
	 * unused parameter
	 */
	(VOID)(param);

	/* convert the timestamp to readable format 初设时间*/
	local_tv_sec = header->ts.tv_sec;
	ltime=localtime(&local_tv_sec);
	strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);

	/* print timestamp and length of the packet 数据包大小 */
	printf("%s,", timestr);

	/* retireve the position of the ip header IP结构 */
	ih = (ip_header *) (pkt_data +
		14); //length of ethernet header

	mh = (mac_header*)pkt_data;
	/* retireve the position of the udp header */
	ip_len = (ih->ver_ihl & 0xf) * 4;
	uh = (udp_header *) ((u_char*)ih + ip_len);

	ftp = (ftp_header *)(pkt_data + sizeof(ip_header) + sizeof(mac_header));
	/* convert from network byte order to host byte order */
	sport = ntohs( uh->sport );
	dport = ntohs( uh->dport );

	for (int i = 0; i < 6; i++)
	{
		printf("%02X", mh->src_addr[i]);
		if (i < 5)
			printf("-");
	}
	printf(",");
	/* print ip addresses and udp ports */
	printf("%d.%d.%d.%d.%d",
		ih->saddr.byte1,
		ih->saddr.byte2,
		ih->saddr.byte3,
		ih->saddr.byte4, sport
	);
	printf(",");
	for (int i = 0; i < 6; i++)
	{
		printf("%02X", mh->dest_addr[i]);
		if (i < 5)
			printf("-");
	}
	printf(",");
	printf("%d.%d.%d.%d.%d",
		ih->daddr.byte1,
		ih->daddr.byte2,
		ih->daddr.byte3,
		ih->daddr.byte4, dport
	);
	printf("\n");
	fp = fopen("e4test.xls", "a");
	fpw = fopen("log.csv", "a+");
	if (pkt_data[head] == 'U'&&pkt_data[head + 1] == 'S')	//数据段是USER开头
	{
	
		fprintf(fp, "FTP:");
		fprintf(fp, "%d.%d.%d.%d",
			ih->saddr.byte1,
			ih->saddr.byte2,
			ih->saddr.byte3,
			ih->saddr.byte4);

		fprintf(fpw, "%s,", timestr);
		for (int i = 0; i < 6; i++)
		{
			fprintf(fpw,"%02X", mh->src_addr[i]);
			if (i < 5)
				printf("-");
		}
		fprintf(fpw,",");
		
		fprintf(fpw,"%d.%d.%d.%d.%d",
			ih->saddr.byte1,
			ih->saddr.byte2,
			ih->saddr.byte3,
			ih->saddr.byte4, sport
		);
		fprintf(fpw,",");
		for (int i = 0; i < 6; i++)
		{
			fprintf(fpw,"%02X", mh->dest_addr[i]);
			if (i < 5)
				fprintf(fpw,"-");
		}
		fprintf(fpw,",");
		fprintf(fpw,"%d.%d.%d.%d.%d",
			ih->daddr.byte1,
			ih->daddr.byte2,
			ih->daddr.byte3,
			ih->daddr.byte4, dport
		);
		fprintf(fpw, ",");

		fprintf(fp, "\t");
		for (int i = head ; i < header->caplen - 2; i++)
		{
			fprintf(fp, "%c", pkt_data[i]);
			if (i == head + 3)
				fprintf(fp, ":");
			if(i>head+4)
				fprintf(fpw, "%c", pkt_data[i]);
		}
		fprintf(fpw, ",");

	}
	else if (pkt_data[head] == 'P'&&pkt_data[head + 1] == 'A')	//数据段是PASS开头
	{
	
		
		fprintf(fp, "\t");
		for (int i = head ; (i < header->caplen - 2); i++)
		{
			fprintf(fp, "%c", pkt_data[i]);
			if (i == head + 3)
				fprintf(fp, ":");
			if (i > head + 4)
				fprintf(fpw, "%c", pkt_data[i]);
		}
		fprintf(fpw, ",");
	}
	else if (pkt_data[head] == '2'&&pkt_data[head + 1] == '3'&&pkt_data[head + 2] == '0')	//数据段是230开头
	{
		
		fprintf(fp, "\tSTA:OK\n");
		fprintf(fpw, "SUCCEED\n");
	}
	else if (pkt_data[head] == '5'&&pkt_data[head + 1] == '3'&&pkt_data[head + 2] == '0')	//数据段是530开头
	{

		fprintf(fp, "\tSTA:FAILD\n");
		fprintf(fpw, "FAILED\n");
	}
	fclose(fp);
	fclose(fpw);
	for (int i = head; (i < header->caplen-2); i++)
	{
		printf("%c", pkt_data[i]);
	}
	
	printf("\n");
		
		
}
