////////////////////////////////////////////
// Sniffer.cpp�ļ�

#include "initsock.h"
#include "protoinfo.h" 
#include <stdio.h> 
#include <winsock2.h>
#include <WINSOCK.H>
#include <Ws2tcpip.h>
#include <iostream>
using namespace std;
#define SIO_RCVALL   _WSAIOW(IOC_VENDOR,1) //��mstcpip.h����
//#include <mstcpip.h>

//#pragma comment(lib, "Advapi32.lib")

//CInitSock theSock;

void DecodeTCPPacket(char *pData)
{
	TCPHeader *pTCPHdr = (TCPHeader *)pData;
	cout << "Դ�˿� ��" + ntohs(pTCPHdr->sourcePort) << "Ŀ�Ķ˿�" + ntohs(pTCPHdr->destinationPort);
	printf("*TCP:\n");		 
	printf("*���к�:             %u\n",pTCPHdr->sequenceNumber);
	printf("*ȷ�Ϻ�:             %u\n",pTCPHdr->acknowledgeNumber);	
	printf("*����ƫ��:           %d\n",(pTCPHdr->dataoffset&0xf0)>>4);
    printf("*��־: FIN:%d  SYN:%d  RST:%d  PSH:%d  ACK:%d  URG:%d  ACE:%d  CWR:%d \n",pTCPHdr->flags&0x01,(pTCPHdr->flags&0x02)>>1,(pTCPHdr->flags&0x04)>>2,(pTCPHdr->flags&0x08)>>3,(pTCPHdr->flags&0x10)>>4,(pTCPHdr->flags&0x20)>>5,(pTCPHdr->flags&0x40)>>6,(pTCPHdr->flags&0x80)>>7);
	printf("*���ڴ�С:           %d\n",pTCPHdr->windows);
	printf("*У���:             %d\n",pTCPHdr->checksum);
	printf("*��������ƫ����:     %d\n",pTCPHdr->urgentPointer);

	// ���滹���Ը���Ŀ�Ķ˿ںŽ�һ������Ӧ�ò�Э��
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
	printf("*Դ�˿ں�:           %d\n",pUDPHdr->sourcePort);//
	printf("*Ŀ�Ķ˿ں�:         %d\n",pUDPHdr->destinationPort);		 
	printf("*�������:           %d\n",pUDPHdr->len);
	printf("*У���:             %d",pUDPHdr->checksum);	
	 

	//
	/*
	IPHeader *pIPHdr =(IPHeader *) ((UDPHeader *)pData+1); 
    in_addr source, dest;
	char szSourceIp[32], szDestIp[32]; 
	// ��IPͷ��ȡ��ԴIP��ַ��Ŀ��IP��ַ
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

	// ��IPͷ��ȡ��ԴIP��ַ��Ŀ��IP��ַ
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
	// IPͷ����
	("---------------------------------------------------\n");
    printf("ԴIP��ַ->Ŀ��IP��ַ�� %s --> %s \n", szSourceIp, szDestIp);      //��ӡ��ԴIP��ַ��Ŀ��IP��ַ
    printf("*IP:\n");
	printf("*�汾��:             IPv%d\n",(pIPHdr->iphVerLen&0xf0)>>4);
	printf("*ͷ����:             %d\n",(pIPHdr->iphVerLen&0x0f));
	printf("*��������:           %d\n",pIPHdr->ipTOS);		 
	printf("*����ܳ���:         %d\n",pIPHdr->ipLength);
	printf("*�����ʶ:           %d\n",pIPHdr->ipID);	
	printf("*��־:  0    DF:%d    MF:%d   \n",(pIPHdr->ipFlags>>14)&0x01,(pIPHdr->ipFlags>>13)&0x01);
    printf("*Ƭƫ��:             %d\n",pIPHdr->ipFlags&0x1fff);
    printf("*����ʱ��:           %d\n",pIPHdr->ipTTL);
	printf("*Э��:               %d\n",pIPHdr->ipProtocol);
	printf("*У���:             %d\n",pIPHdr->ipChecksum);
	printf("*ԴIP��ַ:           %s\n",szSourceIp);
	printf("*Ŀ��IP��ַ:         %s\n",szDestIp);
	/*cout << "***************************************************************************" << endl;
	cout << "***************************************************************************" << endl;
	cout << "source IP address --> destination IP address " << szSourceIp << " --> " << szDestIp << endl;
	cout << "IP protocol" <<endl;
	cout << "�汾�� : IPv" << ((pIPHdr->iphVerLen&0xf0)>>4) <<endl;
	cout << "ͷ����"*/

	int nHeaderLen = (pIPHdr->iphVerLen & 0xf) * sizeof(ULONG);
    
	switch(pIPHdr->ipProtocol)
	{		 
	case IPPROTO_TCP: // TCPЭ��
		printf("---------------------------------------------------\n");
    printf("ԴIP��ַ->Ŀ��IP��ַ�� %s --> %s \n", szSourceIp, szDestIp);
		DecodeTCPPacket(pData + nHeaderLen);
		break;
	case IPPROTO_UDP:
	
	printf("---------------------------------------------------\n");
    printf("ԴIP��ַ->Ŀ��IP��ַ�� %s --> %s \n", szSourceIp, szDestIp);
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
    if(WSAStartup(MAKEWORD(2,2),&wsd)!=0)    //WSA(Windows Sockets Asynchronous��Windows�첽�׽���)����������
    {
     printf("װ��Winsockʧ�ܣ�\n");
	 return ;
    } 
     

	// ����ԭʼ�׽���
	SOCKET sRaw = socket(AF_INET, SOCK_RAW, IPPROTO_IP);

	// ��ȡ����IP��ַ
	char szHostName[56];
	SOCKADDR_IN addr_in;
	struct  hostent *pHost;
	gethostname(szHostName, 56);
	if((pHost = gethostbyname((char*)szHostName)) == NULL)	
		return ;

	// �ڵ���ioctl֮ǰ���׽��ֱ����
	addr_in.sin_family  = AF_INET;
	addr_in.sin_port    = htons(0);
	memcpy(&addr_in.sin_addr.S_un.S_addr, pHost->h_addr_list[0], pHost->h_length);

	printf(" Binding to interface : %s \n", ::inet_ntoa(addr_in.sin_addr));
	if(bind(sRaw, (PSOCKADDR)&addr_in, sizeof(addr_in)) == SOCKET_ERROR)
		return;

	// ����SIO_RCVALL���ƴ��룬�Ա�������е�IP��	
	DWORD dwValue = 1;
	if(ioctlsocket(sRaw, SIO_RCVALL, &dwValue) != 0)	
		return ;
	
	// ��ʼ���շ��
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

