//
//  main.cpp
//  MyPing
//
//  Created by Yuhui on 4/19/20.
//  Copyright © 2020 Yuhui. All rights reserved.
//

#include <stdio.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <unistd.h>
#include <signal.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/time.h>
#include <string.h>
#include <netdb.h>
#include <pthread.h>

#define PACKET_SEND_MAX_NUM 64

typedef struct ping_packet_status{
    struct timeval begin_time;
    struct timeval end_time;
    
    int flag;
    int seq;
}ping_packet_status;

ping_packet_status ping_packet[PACKET_SEND_MAX_NUM];
int alive;
int rawsock;
int send_count;
int recv_count;
pid_t pid;
struct sockaddr_in dest;
struct timeval start_time;
struct timeval end_time;
struct timeval time_interval;


unsigned short cal_chksum(unsigned short *addr,int len){
    int nleft=len;
    int sum=0;
    unsigned short *w=addr;
    unsigned short answer=0;

    //add header in icmp as binary operation
    while(nleft>1){
        sum+=*w++;
        nleft-=2;
    }
    if( nleft==1){
        *(unsigned char *)(&answer)=*(unsigned char *)w;
        sum+=answer;
    }
    sum=(sum>>16)+(sum&0xffff);
    sum+=(sum>>16);
    answer=~sum;
    return answer;
}

struct timeval cal_time_offset(struct timeval begin, struct timeval end){
    struct timeval ans;
    ans.tv_sec = end.tv_sec - begin.tv_sec;
    ans.tv_usec = end.tv_usec - begin.tv_usec;
    if(ans.tv_usec < 0){
        ans.tv_sec--;
        ans.tv_usec+=1000000;
    }
    return ans;
}
 
void icmp_pack(struct icmp* icmphdr, int seq, int length){
    int i = 0;
    
    icmphdr->icmp_type = ICMP_ECHO;
    icmphdr->icmp_code = 0;
    icmphdr->icmp_cksum = 0;
    icmphdr->icmp_seq = seq;
    icmphdr->icmp_id = pid & 0xffff;
    for(i=0;i<length;i++){
        icmphdr->icmp_data[i] = i;
    }

    icmphdr->icmp_cksum = cal_chksum((unsigned short*)icmphdr, length);
}
 
int icmp_unpack(char* buf, int len){
    int iphdr_len;
    struct timeval begin_time, recv_time, offset_time;
    int rtt;  //round trip time
    
    struct ip* ip_hdr = (struct ip *)buf;
    iphdr_len = ip_hdr->ip_hl*4;
    struct icmp* icmp = (struct icmp*)(buf+iphdr_len);
    //length of icmp package
    len-=iphdr_len;
    //check if it matches length of icmp package
    if(len < 8){
        fprintf(stderr, "Invalid icmp packet.Its length is less than 8\n");
        return -1;
    }

    if((icmp->icmp_type == ICMP_ECHOREPLY) && (icmp->icmp_id == (pid & 0xffff))){
        if((icmp->icmp_seq < 0) || (icmp->icmp_seq > PACKET_SEND_MAX_NUM)){
            fprintf(stderr, "icmp packet seq is out of range!\n");
            return -1;
        }
        
        ping_packet[icmp->icmp_seq].flag = 0;
        begin_time = ping_packet[icmp->icmp_seq].begin_time;
        gettimeofday(&recv_time, NULL);
        
        offset_time = cal_time_offset(begin_time, recv_time);
        rtt = offset_time.tv_sec*1000 + offset_time.tv_usec/1000;

        printf("%d byte from %s: icmp_seq=%u ttl=%d rtt=%d ms\n", len, inet_ntoa(ip_hdr->ip_src), icmp->icmp_seq, ip_hdr->ip_ttl, rtt);
     }
     else{
         fprintf(stderr, "Invalid ICMP packet! Its id is not matched!\n");
         return -1;
     }
     return 0;
}

static void ping_send(){
    char send_buf[128];
    memset(send_buf, 0, sizeof(send_buf));
    //record time for first sent ping package
    gettimeofday(&start_time, NULL);
    while(alive){
        int size = 0;
        gettimeofday(&(ping_packet[send_count].begin_time), NULL);
        //mark the package as sent
        ping_packet[send_count].flag = 1;

        icmp_pack((struct icmp*)send_buf, send_count, 64);
        size = sendto(rawsock, send_buf, 64, 0, (struct sockaddr*)&dest, sizeof(dest));
        //record the total number of sent ping package
        send_count++;
        if(size < 0){
            fprintf(stderr, "send icmp packet fail!\n");
            continue;
        }
        sleep(1);
     }
 }

static void ping_recv(){
    struct timeval tv;
    tv.tv_usec = 200;
    tv.tv_sec = 0;
    fd_set read_fd;
    char recv_buf[512];
    memset(recv_buf, 0 ,sizeof(recv_buf));
    while(alive){
        int ret = 0;
        FD_ZERO(&read_fd);
        FD_SET(rawsock, &read_fd);
        ret = select(rawsock+1, &read_fd, NULL, NULL, &tv);
        switch(ret){
            case -1:
                fprintf(stderr,"fail to select!\n");
                break;
            case 0:
                break;
            default:
                {
                    int size = recv(rawsock, recv_buf, sizeof(recv_buf), 0);
                    if(size < 0){
                        fprintf(stderr,"recv data fail!\n");
                        continue;
                    }
                    //unpack received package
                    ret = icmp_unpack(recv_buf, size);
                    
                    //discard wrong icmp package
                    if(ret == -1)
                        continue;
                    
                    //record the total received package
                    recv_count++;
                }
                break;
        }
    }
}

void icmp_sigint(int signo){
    alive = 0;
    gettimeofday(&end_time, NULL);
    time_interval = cal_time_offset(start_time, end_time);
}

void ping_stats_show()
{
    long time = time_interval.tv_sec*1000+time_interval.tv_usec/1000;
    printf("%d packets transmitted, %d recieved, %d%c packet loss, time %ldms\n", send_count, recv_count, (send_count-recv_count)*100/send_count, '%', time);
 }

int main(int argc, char* argv[]){
    int size = 128*1024;
    struct protoent* protocol = NULL;
    char dest_addr_str[80];
    memset(dest_addr_str, 0, 80);
    unsigned int inaddr = 1;
    struct hostent* host = NULL;
    
    if(argc < 2){
        printf("Invalid IP ADDRESS!\n");
        return -1;
    }

    protocol = getprotobyname("icmp");
    if(protocol == NULL){
        printf("Fail to getprotobyname!\n");
        return -1;
    }

    memcpy(dest_addr_str, argv[1], strlen(argv[1])+1);

    rawsock = socket(AF_INET, SOCK_STREAM, protocol->p_proto);
    if(rawsock < 0){
        printf("Fail to create socket!\n");
        return -1;
    }

    pid = getpid();

    setsockopt(rawsock, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));

    bzero(&dest,sizeof(dest));

    dest.sin_family = AF_INET;

    inaddr = inet_addr(argv[1]);
    
    //check the input content
    if(inaddr == INADDR_NONE){
        host = gethostbyname(argv[1]);
        if(host == NULL){
            printf("Fail to gethostbyname!\n");
            return -1;
        }
        memcpy((char*)&dest.sin_addr, host->h_addr, host->h_length);
    }else{
        memcpy((char*)&dest.sin_addr, &inaddr, sizeof(inaddr));
    }
    inaddr = dest.sin_addr.s_addr;
    printf("PING %s, (%d.%d.%d.%d) 56(84) bytes of data.\n",dest_addr_str, (inaddr&0x000000ff), (inaddr&0x0000ff00)>>8, (inaddr&0x00ff0000)>>16, (inaddr&0xff000000)>>24);

    signal(SIGINT, icmp_sigint);
     
    ping_send();
    ping_recv();

    ping_stats_show();

    close(rawsock);
    return 0;
}
