#include <unistd.h>
#include <iostream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
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

void printIPHeader(iphdr *ipHeader) {
    using namespace std;
    auto dLength = (unsigned int) ipHeader->ihl;
    cout << endl;
    cout << "IP Header" << endl;
    cout << "	> IP Version        : " << (unsigned int) ipHeader->version << endl;
    cout << "	> IP Header Length  : " << dLength * 4 << " Bytes" << endl;
    cout << "	> Type Of Service   : " << (unsigned int) ipHeader->tos << endl;
    cout << "	> IP Total Length   : " << ntohs(ipHeader->tot_len) << " Bytes" << endl;
    cout << "	> Identification    : " << ntohs(ipHeader->id) << endl;
    cout << "	> TTL               : " << (unsigned int) ipHeader->ttl << endl;
    cout << "	> Protocol          : " << (unsigned int) ipHeader->protocol << endl;
    cout << "	> Checksum          : " << ntohs(ipHeader->check) << endl;
    cout << "	> Source IP         : " << inet_ntoa(*(in_addr *) &ipHeader->saddr) << endl;
    cout << "	> Destination IP    : " << inet_ntoa(*(in_addr *) &ipHeader->daddr) << endl;
}

void printTCPHeader(tcphdr *tcpHeader) {
    using namespace std;
    auto dLength = (unsigned int) tcpHeader->doff;
    cout << endl;
    cout << "TCP Header" << endl;
    cout << "	> Source Port          : " << ntohs(tcpHeader->source) << endl;
    cout << "	> Destination Port     : " << ntohs(tcpHeader->dest) << endl;
    cout << "	> Sequence Number      : " << ntohl(tcpHeader->seq) << endl;
    cout << "	> Acknowledge Number   : " << ntohl(tcpHeader->ack_seq) << endl;
    cout << "	> Header Length        : " << dLength * 4 << " BYTES" << endl;
    cout << "	> Urgent Flag          : " << (unsigned int) tcpHeader->urg << endl;
    cout << "	> Acknowledgement Flag : " << (unsigned int) tcpHeader->ack << endl;
    cout << "	> Push Flag            : " << (unsigned int) tcpHeader->psh << endl;
    cout << "	> Reset Flag           : " << (unsigned int) tcpHeader->rst << endl;
    cout << "	> Synchronise Flag     : " << (unsigned int) tcpHeader->syn << endl;
    cout << "	> Finish Flag          : " << (unsigned int) tcpHeader->fin << endl;
    cout << "	> Window               : " << ntohs(tcpHeader->window) << endl;
    cout << "	> Checksum             : " << ntohs(tcpHeader->check) << endl;
    cout << "	> Urgent Pointer       : " << tcpHeader->urg_ptr << endl;
}

void printPackage(unsigned char *package, long packageSize) {
    auto *ipHeader = (struct iphdr *) package;
    unsigned long ipLength = ipHeader->ihl * 4u;
    auto *tcpHeader = (struct tcphdr *) (package + ipLength);
    unsigned long tcpLength = tcpHeader->doff * 4u;

    std::cout << std::endl;
    std::cout << "************************** TCP Packet **************************" << std::endl;
    printIPHeader(ipHeader);
    printTCPHeader(tcpHeader);
    std::cout << std::endl;
    std::cout << "                   		     DATA Dump        	                 " << std::endl;
    std::cout << std::endl;
    std::cout << "IP Header" << std::endl;
    PrintData(package, ipLength);
    std::cout << "TCP Header" << std::endl;
    PrintData(package + ipLength, tcpLength);
    std::cout << "Data Payload" << std::endl;
    PrintData(package + ipLength + tcpLength, packageSize - ipLength - tcpLength);
}

void handlePackage(unsigned char *package, long packageSize) {
    auto *ipHeader = (struct iphdr *) package;
    unsigned long ipLength = ipHeader->ihl * 4u;
    if (ipHeader->protocol != 6)
        return;
    auto *tcpHeader = (struct tcphdr *) (package + ipLength);
    unsigned long tcpLength = tcpHeader->doff * 4u;
    auto *data = package + ipLength + tcpLength;
    char *contain = strstr((char *) data, message.c_str());
    if (!contain)
        return;
    printPackage(package, packageSize);
}

void listenPackages() {
    while (true) {
        unsigned char buffer[PACKAGE_SIZE];
        long bytesReceived = recvfrom(sock, buffer, PACKAGE_SIZE, 0, nullptr, nullptr);
        if (bytesReceived < 0)
            throw std::runtime_error("error " + std::to_string(errno) + ": recvfrom failed to get packages.");
        handlePackage(buffer, bytesReceived);
    }
}


int main(int argc, char * argv[]) {
	auto userId = getuid();
    if (userId != 0)
        throw std::runtime_error("error: you are not root.");
    if (argc < 2) {
    	message.append("");
    } else {
    	message.append(argv[1]);
    }
    std::cout << "Looking for <" << message << "> in buffers..." << std::endl;
	std::cout << "Starting..." << std::endl;
    if ((sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0)
        throw std::runtime_error("error " + std::to_string(errno) + ": can't create socket.");
    listenPackages();
}