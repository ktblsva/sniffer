#include <unistd.h>
#include <iostream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>	
#include <string.h>
#define PACKAGE_SIZE 65536


int sock;
std::string message;

int tcp = 0, other = 0, all = 0, udp = 0;

void PrintData(unsigned char *data, unsigned long size) {

    for (int i = 0; i < size; i++) {
        if (i != 0 && i % 16 == 0)   //if one line of hex printing is complete...
        {
            std::cout << "         ";
            for (int j = i - 16; j < i; j++) {
                if (data[j] >= 32 && data[j] <= 128)
                    std::cout << (unsigned char) data[j]; //if its a number or alphabet

                else
                    std::cout << "."; //otherwise print a dot
            }
            std::cout << std::endl;
        }

        if (i % 16 == 0)
            std::cout << "   ";
        printf( " %02X", (unsigned int) data[i]);

        if (i == size - 1)  //print the last spaces
        {
            for (int j = 0; j < 15 - i % 16; j++)
                std::cout << "   "; //extra spaces

            std::cout << "         ";

            for (int j = i - i % 16; j <= i; j++) {
                if (data[j] >= 32 && data[j] <= 128)
                    std::cout << (unsigned char) data[j];
                else
                    std::cout << ".";
            }
            fprintf(stdout, "\n");
        }
    }
}

void printEthernetHeader(unsigned char* Buffer, int Size)
{
	using namespace std;
	struct ethhdr *eth = (struct ethhdr *)Buffer;
	cout << "Ethernet Header" << endl;
	fprintf(stdout , "	> Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
	fprintf(stdout , "	> Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
	fprintf(stdout , "	> Protocol            : %u \n\n\n",(unsigned int)eth->h_proto);
}

void printIPHeader(struct iphdr *iph) {
	using namespace std;
	unsigned int dL = (unsigned int) iph -> ihl;
	cout << "IP Header" << endl;
	cout << "	> IP Version			: " << (unsigned int) iph -> version << endl;
	cout << "	> IP Header Length		: " << dL * 4 << " bytes" << endl;
	cout << "	> Type of service		: " << (unsigned int) iph -> tos << endl;
	cout << "	> IP Total Length		: " << ntohs(iph -> tot_len) << " bytes" << endl;
	cout << "	> Identification		: " << ntohs(iph -> id) << endl;
	cout << "	> TTL 				: " << (unsigned int) iph->ttl << endl;
	cout << "	> Protocol 			: " << (unsigned int) iph -> protocol << endl;
	cout << "	> Checksum			: " << ntohs(iph -> check) << endl;
	cout << "	> Source IP			: " << inet_ntoa(*(in_addr *)&iph -> saddr) << endl;
	cout << "	> Destination IP		: " << inet_ntoa(*(in_addr *)&iph -> daddr) << endl;
	cout << endl << endl;
}

void printTCPHeader(struct tcphdr *tcph) {
	using namespace std;
    unsigned int dLength = (unsigned int) tcph -> doff;
    cout << endl;
    cout << "TCP Header" << endl;
    cout << "	> Source Port          : " << ntohs(tcph -> source) << endl;
    cout << "	> Destination Port     : " << ntohs(tcph -> dest) << endl;
    cout << "	> Sequence Number      : " << ntohl(tcph -> seq) << endl;
    cout << "	> Acknowledge Number   : " << ntohl(tcph -> ack_seq) << endl;
    cout << "	> Header Length        : " << dLength * 4 << " bytes" << endl;
    cout << "	> Urgent Flag          : " << (unsigned int) tcph -> urg << endl;
    cout << "	> Acknowledgement Flag : " << (unsigned int) tcph -> ack << endl;
    cout << "	> Push Flag            : " << (unsigned int) tcph -> psh << endl;
    cout << "	> Reset Flag           : " << (unsigned int) tcph -> rst << endl;
    cout << "	> Synchronise Flag     : " << (unsigned int) tcph -> syn << endl;
    cout << "	> Finish Flag          : " << (unsigned int) tcph -> fin << endl;
    cout << "	> Window               : " << ntohs(tcph -> window) << endl;
    cout << "	> Checksum             : " << ntohs(tcph -> check) << endl;
    cout << "	> Urgent Pointer       : " << tcph -> urg_ptr << endl;
    cout << endl << endl;
}

void printTCP(unsigned char* package, int packageSize) {
	
	struct iphdr *iph = (struct iphdr *)(package  + sizeof(struct ethhdr) );
	unsigned short iphdrlen = iph->ihl*4;
	struct tcphdr *tcph=(struct tcphdr*)(package + iphdrlen + sizeof(struct ethhdr));
			
	int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;

    std::cout << std::endl;
    std::cout << "************************** TCP Packet **************************" << std::endl;
    printEthernetHeader(package, packageSize);
    printIPHeader(iph);
    printTCPHeader(tcph);
    std::cout << std::endl;
    std::cout << "                   		     DATA Dump        	                 " << std::endl;
    std::cout << std::endl;
    std::cout << "IP Header" << std::endl;
    PrintData(package, iphdrlen);
    std::cout << "TCP Header" << std::endl;
    PrintData(package + iphdrlen, sizeof(tcph));
    std::cout << "Data Payload" << std::endl;
    PrintData(package + header_size, packageSize - header_size);
}

void printUDPHeader(struct udphdr *udph) {
	using namespace std;
    cout << endl;
    cout << "UDP Header" << endl;
    cout << "	> Source Port 			: " << ntohs(udph -> source) << endl;
    cout << "	> Destination Port 		: " << ntohs(udph -> dest) << endl;
    cout << "	> UDP Length 			: " << (unsigned int) udph -> len << endl;
    cout << "	> Checksum 			: " << ntohs(udph -> check) << endl;
}

void printUDP(unsigned char* package, int packageSize) {
	struct iphdr *iph = (struct iphdr *)(package +  sizeof(struct ethhdr));
	unsigned short iphdrlen = iph->ihl*4;
	
	struct udphdr *udph = (struct udphdr*)(package + iphdrlen  + sizeof(struct ethhdr));
	
	int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof udph;
	std::cout << std::endl;
	std::cout << "************************** UDP Packet **************************" << std::endl;
	printEthernetHeader(package, packageSize);
	printIPHeader(iph);
	printUDPHeader(udph);
	std::cout << std::endl << std::endl;
	std::cout << "                           DATA DUMP                            " << std::endl;
	std::cout << "IP Header" << std::endl;
	PrintData(package, iphdrlen);
	std::cout << "UDP Header" << std::endl;
	PrintData(package + iphdrlen, sizeof(udph));
	std::cout << "Data payload" << std::endl;
	PrintData(package + header_size, packageSize - header_size);
}

void processUDP(unsigned char* package, int packageSize) {
	struct iphdr *iph = (struct iphdr *)(package +  sizeof(struct ethhdr));
	unsigned short iphdrlen = iph->ihl*4;
	
	struct udphdr *udph = (struct udphdr*)(package + iphdrlen  + sizeof(struct ethhdr));
	
	int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof udph;
	auto *data = package + header_size;

	char *contain = strstr((char *) data, message.c_str());
    if (!contain)
        return;
	printUDP(package, packageSize);
}

void processTCP(unsigned char* package, int packageSize) {
	struct iphdr *iph = (struct iphdr *)(package  + sizeof(struct ethhdr) );
	unsigned short iphdrlen = iph->ihl*4;
	struct tcphdr *tcph=(struct tcphdr*)(package + iphdrlen + sizeof(struct ethhdr));
			
	int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;
    auto *data = package + header_size;

    char *contain = strstr((char *) data, message.c_str());
    std::cout << "Process TCP!" << std::endl;
    if (!contain)
        return;
    printTCP(package, packageSize);
}

void handlePackage(unsigned char *package, long packageSize) {
    auto *ipHeader = (struct iphdr *) package + sizeof(struct ethhdr);
    unsigned long ipLength = ipHeader->ihl * 4u;
    switch (ipHeader -> protocol) {
		case 6:
			++tcp;
			std::cout<<"TCP!"<<std::endl;
			processTCP(package, packageSize);
			break;
		case 17: 
			std::cout<<"UDP!"<<std::endl;
			processUDP(package, packageSize);
			++udp;
			break;
		default:
			++other; 
			break;
	}
}

void listenPackets() {
	while (true) {
        unsigned char buffer[PACKAGE_SIZE];
        long bytesReceived = recvfrom(sock, buffer, PACKAGE_SIZE, 0, nullptr, nullptr);
        if (bytesReceived < 0)
            throw std::runtime_error("error " + std::to_string(errno) + ": recvfrom failed to get packages.");
        handlePackage(buffer, bytesReceived);
    }
}

int main(int argc, char * argv[]) {
	if (getuid() != 0) {
		throw std::runtime_error("Error: you're not root!");
	}
	if (argc < 2) {
		message.append("");
	}
	else {
		message.append(argv[1]);
	}

	std::cout << "Looking for <" << message << "> in buffers..." << std::endl;
	std::cout << "Starting..." << std::endl;
	sock = socket(AF_PACKET , SOCK_RAW , htons(ETH_P_ALL)) ;
	setsockopt(sock, SOL_SOCKET , SO_BINDTODEVICE , "wlp3s0" , strlen("wlp3s0") + 1);
	//sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	//sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
	if (sock < 0) {
		throw std::runtime_error("Error " + std::to_string(errno) + ": can't create socket");
	}
	listenPackets();
}
