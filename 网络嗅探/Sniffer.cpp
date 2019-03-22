////////////////////////////////////////////
// Sniffer.cpp文件

#include "initsock.h"
#include "protoinfo.h" 
#include <stdio.h> 
#include <winsock2.h>
#include <WINSOCK.H>
#include <Ws2tcpip.h>
#include <iostream>
using namespace std;
#define SIO_RCVALL   _WSAIOW(IOC_VENDOR,1) //在mstcpip.h定义
//#include <mstcpip.h>

//#pragma comment(lib, "Advapi32.lib")

//CInitSock theSock;

void DecodeTCPPacket(char *pData)
{
	TCPHeader *pTCPHdr = (TCPHeader *)pData;
	cout << "源端口 ：" + ntohs(pTCPHdr->sourcePort) << "目的端口" + ntohs(pTCPHdr->destinationPort);
	printf("*TCP:\n");		 
	printf("*序列号:             %u\n",pTCPHdr->sequenceNumber);
	printf("*确认号:             %u\n",pTCPHdr->acknowledgeNumber);	
	printf("*数据偏移:           %d\n",(pTCPHdr->dataoffset&0xf0)>>4);
    printf("*标志: FIN:%d  SYN:%d  RST:%d  PSH:%d  ACK:%d  URG:%d  ACE:%d  CWR:%d \n",pTCPHdr->flags&0x01,(pTCPHdr->flags&0x02)>>1,(pTCPHdr->flags&0x04)>>2,(pTCPHdr->flags&0x08)>>3,(pTCPHdr->flags&0x10)>>4,(pTCPHdr->flags&0x20)>>5,(pTCPHdr->flags&0x40)>>6,(pTCPHdr->flags&0x80)>>7);
	printf("*窗口大小:           %d\n",pTCPHdr->windows);
	printf("*校验和:             %d\n",pTCPHdr->checksum);
	printf("*紧急数据偏移量:     %d\n",pTCPHdr->urgentPointer);

	// 下面还可以根据目的端口号进一步解析应用层协议
	switch(::ntohs(pTCPHdr->destinationPort))
	{
	case 21:
		break;
	case 80:
	case 8080:
		break;
	}
}
void DecodeUDPPacket(char *pData)
{
    UDPHeader *pUDPHdr = (UDPHeader *)pData;
	 	 
    printf("*UDP:\n");  
	printf("*源端口号:           %d\n",pUDPHdr->sourcePort);//
	printf("*目的端口号:         %d\n",pUDPHdr->destinationPort);		 
	printf("*封包长度:           %d\n",pUDPHdr->len);
	printf("*校验和:             %d",pUDPHdr->checksum);	
	 

	//
	/*
	IPHeader *pIPHdr =(IPHeader *) ((UDPHeader *)pData+1); 
    in_addr source, dest;
	char szSourceIp[32], szDestIp[32]; 
	// 从IP头中取出源IP地址和目的IP地址
	source.S_un.S_addr = pIPHdr->ipSource;
	dest.S_un.S_addr = pIPHdr->ipDestination;
	strcpy(szSourceIp, ::inet_ntoa(source));
	strcpy(szDestIp, ::inet_ntoa(dest));
	printf("	P1=%s -> P2=%s \n", szSourceIp, szDestIp);
	*/
}
void DecodeICMPPacket(char *pData)
{
   printf("ICMP\n");
}
void DecodeIPPacket(char *pData)
{
	IPHeader *pIPHdr = (IPHeader*)pData;	
	in_addr source, dest;
	char szSourceIp[32], szDestIp[32]; 

	// 

	// 从IP头中取出源IP地址和目的IP地址
	/*

	char FAR * inet_ntoa (struct in_addr in );
	The Windows Sockets inet_ntoa function converts 
	an (Ipv4) Internet network address into a string 
	in Internet standard dotted format.

	*/
	source.S_un.S_addr = pIPHdr->ipSource;
	dest.S_un.S_addr = pIPHdr->ipDestination;
	strcpy(szSourceIp, ::inet_ntoa(source));
	strcpy(szDestIp, ::inet_ntoa(dest));

	// printf("	%s -> %s \n", szSourceIp, szDestIp);
	// IP头长度
	("---------------------------------------------------\n");
    printf("源IP地址->目的IP地址： %s --> %s \n", szSourceIp, szDestIp);      //打印出源IP地址和目的IP地址
    printf("*IP:\n");
	printf("*版本号:             IPv%d\n",(pIPHdr->iphVerLen&0xf0)>>4);
	printf("*头长度:             %d\n",(pIPHdr->iphVerLen&0x0f));
	printf("*服务类型:           %d\n",pIPHdr->ipTOS);		 
	printf("*封包总长度:         %d\n",pIPHdr->ipLength);
	printf("*封包标识:           %d\n",pIPHdr->ipID);	
	printf("*标志:  0    DF:%d    MF:%d   \n",(pIPHdr->ipFlags>>14)&0x01,(pIPHdr->ipFlags>>13)&0x01);
    printf("*片偏移:             %d\n",pIPHdr->ipFlags&0x1fff);
    printf("*生存时间:           %d\n",pIPHdr->ipTTL);
	printf("*协议:               %d\n",pIPHdr->ipProtocol);
	printf("*校验和:             %d\n",pIPHdr->ipChecksum);
	printf("*源IP地址:           %s\n",szSourceIp);
	printf("*目的IP地址:         %s\n",szDestIp);
	/*cout << "***************************************************************************" << endl;
	cout << "***************************************************************************" << endl;
	cout << "source IP address --> destination IP address " << szSourceIp << " --> " << szDestIp << endl;
	cout << "IP protocol" <<endl;
	cout << "版本号 : IPv" << ((pIPHdr->iphVerLen&0xf0)>>4) <<endl;
	cout << "头长度"*/

	int nHeaderLen = (pIPHdr->iphVerLen & 0xf) * sizeof(ULONG);
    
	switch(pIPHdr->ipProtocol)
	{		 
	case IPPROTO_TCP: // TCP协议
		printf("---------------------------------------------------\n");
    printf("源IP地址->目的IP地址： %s --> %s \n", szSourceIp, szDestIp);
		DecodeTCPPacket(pData + nHeaderLen);
		break;
	case IPPROTO_UDP:
	
	printf("---------------------------------------------------\n");
    printf("源IP地址->目的IP地址： %s --> %s \n", szSourceIp, szDestIp);
		DecodeUDPPacket(pData + nHeaderLen);
		break;
	case IPPROTO_ICMP:
		DecodeICMPPacket(pData + nHeaderLen);
		break; 

	}

}


void main()
{
  	system("color 3f");
	WSADATA wsd; 
    if(WSAStartup(MAKEWORD(2,2),&wsd)!=0)    //WSA(Windows Sockets Asynchronous，Windows异步套接字)的启动命令
    {
     printf("装载Winsock失败！\n");
	 return ;
    } 
     

	// 创建原始套接字
	SOCKET sRaw = socket(AF_INET, SOCK_RAW, IPPROTO_IP);

	// 获取本地IP地址
	char szHostName[56];
	SOCKADDR_IN addr_in;
	struct  hostent *pHost;
	gethostname(szHostName, 56);
	if((pHost = gethostbyname((char*)szHostName)) == NULL)	
		return ;

	// 在调用ioctl之前，套接字必须绑定
	addr_in.sin_family  = AF_INET;
	addr_in.sin_port    = htons(0);
	memcpy(&addr_in.sin_addr.S_un.S_addr, pHost->h_addr_list[0], pHost->h_length);

	printf(" Binding to interface : %s \n", ::inet_ntoa(addr_in.sin_addr));
	if(bind(sRaw, (PSOCKADDR)&addr_in, sizeof(addr_in)) == SOCKET_ERROR)
		return;

	// 设置SIO_RCVALL控制代码，以便接收所有的IP包	
	DWORD dwValue = 1;
	if(ioctlsocket(sRaw, SIO_RCVALL, &dwValue) != 0)	
		return ;
	
	// 开始接收封包
	char buff[1024];
	int nRet;
	while(TRUE)
	{
		nRet = recv(sRaw, buff, 1024, 0);
		if(nRet > 0)
		{
			DecodeIPPacket(buff);
		}
	}
	closesocket(sRaw);
	WSACleanup();
}

