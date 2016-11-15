#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>   //网卡和 ip 相关的定义
#include <stdint.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include<string.h>
#include <sys/time.h>
#include <errno.h>
#define DEF_ICMP_TIMEOUT 1000
#define DATA_SIZE 32
 struct ICMPHEAD{
    u_int8_t type;
    u_int8_t code;
    u_int16_t checkSum;
    u_int16_t id;
    u_int16_t seq;
};
typedef struct tag_iphdr        //ip头
{
    u_int8_t   iphVerLen;
    u_int8_t   ipTOS;
    ushort  ipLength;
    ushort  ipID;
    ushort  ipFlags;
    u_int8_t   ipTTL;
    u_int8_t   ipProtacol;
    ushort  ipChecksum;
    int   ipSource;
    int   ipDestination;
} IPHDR;
ushort GenerationChecksum(ushort*pBuf,int iSize){
    unsigned long cksum = 0;
    while(iSize > 1){
        cksum+=*pBuf++;
        iSize-=sizeof(ushort);
    }
    if(iSize) cksum+=*pBuf++;
    cksum = (cksum>>16)+(cksum&0xffff);
    cksum += (cksum>>16);
    return (ushort)(~cksum);
}

int main(int argc, const char * argv[]) {
    
   // uint ulDestIP = inet_addr("106.187.102.92");
    in_addr_t ulDestIP = inet_addr(argv[1]);
    
    printf("%u\n",ulDestIP);
    if(ulDestIP == INADDR_NONE){
        struct hostent* pHostent = gethostbyname(argv[1]);
        if(pHostent){
            ulDestIP = (*(in_addr_t*)pHostent->h_addr);
            printf("%u\n",ulDestIP);
        }
    }
    int client = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (client == -1) {
        printf("获取套接字失败\n");
        perror("socket");
    }
    printf("client= %d\n",client);
    /*扩大套接字接收缓冲区到50K这样做主要为了减小接收缓冲区溢出的
     的可能性,若无意中ping一个广播地址或多播地址,将会引来大量应答*/
    int size = 50 *1024;
    setsockopt(client,SOL_SOCKET,SO_RCVBUF,&size,sizeof(size) );
    int iTimeout = DEF_ICMP_TIMEOUT;
    if(setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, (char*)&iTimeout, sizeof(iTimeout)) != -1){
        printf("设置等待SO_RCVTIMEO失败\n");
        return  0;
    }
    
    if(setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, (char*)&iTimeout, sizeof(iTimeout)) != -1){
        printf("设置等待SO_SNDTIMEO失败\n");
        return  0;
    }
    
    struct sockaddr_in destSocketAddr;
    destSocketAddr.sin_family = AF_INET;
    destSocketAddr.sin_addr.s_addr = ulDestIP;
    destSocketAddr.sin_port = htons(0);
    memset(destSocketAddr.sin_zero, 0, sizeof(destSocketAddr.sin_zero));
  //  destSocketAddr.sin_len = 0;
    
    
    char* icmp = (char*)malloc(sizeof(struct ICMPHEAD)+DATA_SIZE);
    printf("icmp=%lu %lu\n",sizeof(icmp),sizeof(IPHDR));
    memset(icmp, 0, sizeof(struct ICMPHEAD)+DATA_SIZE);
  //  memset(icmp+sizeof(struct ICMPHEAD),'E',DATA_SIZE);

    struct ICMPHEAD*icmphead = (struct ICMPHEAD*)icmp;
    icmphead->type = 8;
    icmphead->code = 0;
    icmphead->id = 1;
    
    
    for(int i = 0; i < 3; i++){
        struct timeval start, end;

         // 16位整数 主机字节序转网络字节序
        
        icmphead->seq = htons(i);
        icmphead->checkSum = 0;
        icmphead->checkSum = GenerationChecksum((ushort*)icmp,sizeof(struct ICMPHEAD)+DATA_SIZE);
        gettimeofday( &start, NULL );
        printf("size=%lu  %lu %d\n",sizeof(icmp),sizeof(struct ICMPHEAD),DATA_SIZE);
        long result = sendto(client, icmp, sizeof(struct ICMPHEAD)+DATA_SIZE, 0, (struct sockaddr*)&destSocketAddr, sizeof(destSocketAddr));
        if(result == -1){
            printf("传送出错\n");
        }
        printf("传送数据成功 %ld",result);
        struct sockaddr_in from;
        unsigned int iFromLen = sizeof(from);
        long iReadLen;
        char recvBuf[1024];
        memset(recvBuf, 0, sizeof(recvBuf));
        while(1){
            printf("接受数据\n");
            iReadLen = recvfrom(client, recvBuf, 1024, 0, (struct sockaddr*)&from, &iFromLen);
            gettimeofday( &end, NULL );
            if(iReadLen != -1){
                 IPHDR *pIP = (IPHDR*)recvBuf;
         //       printf("ip = %d %d %d %d %d \n",pIP->iphVerLen&0x0F,pIP->ipTOS,pIP->ipLength,pIP->ipID,pIP->ipSource);
                int ipTTL = (int)pIP->ipTTL;
          //      printf("%d %d %ld\n",pIP->ipLength,pIP->iphVerLen,iReadLen);
                struct ICMPHEAD *p = (struct ICMPHEAD*)(recvBuf+(pIP->iphVerLen&0x0F)*4);
            //    printf("from=%d %s\n",from.sin_len,from.sin_zero);
            //   printf("p= %d %d %d %d %d\n",p->checkSum,p->code,p->seq,p->type,p->id);
                if(p->type != 0){
                    printf("error type %d received\n",p->type);
                    break;
                }
                if(p->id != icmphead->id){
                    printf("some else's packet\n");
                    return -1;
                }
                if(iReadLen >= (sizeof(IPHDR)+sizeof(struct ICMPHEAD)+DATA_SIZE))
                printf("reply from %s size= %ld seq=%d  TTL= %d  time = %fs\n",inet_ntoa(from.sin_addr),iReadLen,p->seq/256,ipTTL,( end.tv_sec - start.tv_sec ) + (end.tv_usec - start.tv_usec)*0.0000001);
                sleep(1);
                break;
                
            }else{
                
                printf("接受数据出错");
                break;
            }
        }
    }
    return 0;
    
}
