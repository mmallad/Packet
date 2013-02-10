//Dpak Malla
//mmallad
#include "/media/Backup/Projects/Packet/PacketCapture/libPacket.h"
int main()
{
	//printf("Hello");
	struct pcap_pkthdr header;
	const u_char *pkt, *pkt_data;
	pcap_t *handle;
	char *dev; //Holds the device.
	char e_buff[PCAP_ERRBUF_SIZE];
	//Let us scan device and assign it to dev pointer.
	dev = pcap_lookupdev(e_buff);
	if(dev == NULL)
	{
		printf("Could not scan devices. May be no device found.");
		return 0;
	}
	//Here you can show which device you are listening.
	printf("Device %s",dev);
	//Start the capture logic
	handle = pcap_open_live("wlan0",65535,1,0,e_buff);
	//Check handle if it is null
	if(handle == NULL)
	{
		printf("Could not start the pcap.");
		return 0;
	}
	//Start capturing the packet.
	pcap_loop(handle,-1,start_capture_packet,NULL);
	//Now close the pcap
	pcap_close(handle);
	return 0;
		
}
void start_capture_packet(u_char *args,const struct pcap_pkthdr *header, const u_char *pkt)
{
	//Make some space to hold some data :)
	int pkt_headerSize, pkt_data_len, tcp_header_len, packet_size;
	u_char *packet_data;
	
	//Start Calling Appropriate Handler.
	packet_size = header->len;
	capture_ethernet_packet(pkt);
	capture_ip_packet(pkt+ETHER_HDR_LEN);
	tcp_header_len = capture_tcp_packet(pkt+ETHER_HDR_LEN+sizeof(struct ip_hdr));
	pkt_headerSize = ETHER_HDR_LEN+sizeof(struct ip_hdr)+tcp_header_len;
	packet_data = (u_char *)pkt+pkt_headerSize;
	pkt_data_len = packet_size - pkt_headerSize;
	if(pkt_data_len > 0)
	{
		printf("Total bytes of packet data: %u \n",pkt_data_len);
		int i;
		unsigned char byte;
		for(i = 0 ; i < pkt_data_len; i++)
		{
			byte = packet_data[i];
			if((byte > 31) && (byte < 127)) 
				printf("%c",byte);
			else
				printf("#");
		}
		printf("\n");
	}
	else
	{
			printf("No data on this packet.\n");
	}
}
void capture_ethernet_packet(const u_char *pkt)
{
	const struct ether_hdr *ethernet_header;
	ethernet_header = (const struct ether_hdr *)pkt;
	printf("=======================================================\n");
	printf("Ethernet Layer 2 Header\n");
	printf("=======================================================\n");
	printf("Source MAC: %02x",ethernet_header->ether_src_addr[0]);
	int i;
	for(i = 0; i < ETHER_ADDR_LEN; i++)
		printf("%02x",ethernet_header->ether_src_addr[i]);
	
	printf("\t\tDestination MAC: %02x",ethernet_header->ether_dest_addr[0]);
	for(i=0; i < ETHER_ADDR_LEN; i++)
		printf("%02x",ethernet_header->ether_dest_addr[0]);
	printf("\t\t Type: %hu \n",ethernet_header->ether_type);
	
}
void capture_ip_packet(const u_char *pkt)
{
	const struct ip_hdr *ip_header;
	ip_header = (const struct ip_hdr *)pkt;
	printf("=======================================================\n");
	printf("Layer 3 IP Header\n");
	printf("=======================================================\n");
	printf("Source IP: %d",inet_ntoa(ip_header->ip_src_addr));
	printf("\tDestination IP: %d\n",inet_ntoa(ip_header->ip_dest_addr));
	printf("\t Type: %u\t",(u_int) ip_header->ip_type);
	printf("ID: %hu\tLength: %hu \n",ntohs(ip_header->ip_id),ntohs(ip_header->ip_len));
}
u_int capture_tcp_packet(const u_char *pkt)
{
	const struct tcp_hdr *tcp_header;
	tcp_header = (const struct tcp_hdr *)pkt;
	u_int header_size = tcp_header->tcp_offset * 4;
	printf("=======================================================\n");
	printf("Layer 4 TCP Header\n");
	printf("=======================================================\n");
	printf("Source Port: %hu\t",ntohs(tcp_header->tcp_src_port));
	printf("Destination Port: %hu\n",ntohs(tcp_header->tcp_dest_port));
	printf("Sequence Number: %u\t",ntohl(tcp_header->tcp_seq));
	printf("Ack Number: %u\n",ntohl(tcp_header->tcp_ack));
	printf("Header Size: %u\tFlags: ",header_size);
	if(tcp_header->tcp_flags & TCP_FIN)
		printf("FIN ");
	if(tcp_header->tcp_flags & TCP_SYN)
		printf("SYN ");
	if(tcp_header->tcp_flags & TCP_RST)
		printf("RST ");
	if(tcp_header->tcp_flags & TCP_PUSH)
		printf("PUSH ");
	if(tcp_header->tcp_flags & TCP_ACK)
		printf("ACK ");
	if(tcp_header->tcp_flags & TCP_URG)
		printf("URG ");
	
	printf("\n");
	return header_size;
	
}
