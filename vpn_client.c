#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h> 
#include <sys/select.h>
#include <sys/time.h>
#include <errno.h>
#include <stdarg.h>
#include <netinet/in.h>
#include <pthread.h>

#define IP_VERSION 4
#define IP_HEADER_LENGTH 20 // IPv4头部长度，单位为字节
#define DEST_IP "10.0.0.1"
#define SERVER_IP "192.168.239.129"  // 服务器 IP 地址
#define SERVER_PORT 18889           // 服务器端口号
#define SERVER_CHANLLENGE_PORT 18888 //服务器认证端口号

// 定义结构体来封装参数
typedef struct {
    int sockfd;
    int tun_fd;
} ThreadArgs;

struct iphdr {
    unsigned char  ihl_version;
    unsigned char  tos;
    unsigned short total_length;
    unsigned short id;
    unsigned short frag_off;
    unsigned char  ttl;
    unsigned char  protocol;
    unsigned short checksum;
    unsigned int   saddr;
    unsigned int   daddr;
};
//一下代码基于simpletun.c
int tun_alloc(char *dev, int flags) {
    struct ifreq ifr;
    int fd, err;
    char *clonedev = "/dev/net/tun";
 
    /* Arguments taken by the function:
     *
     * char *dev: the name of an interface (or '\0'). MUST have enough
     *   space to hold the interface name if '\0' is passed
     * int flags: interface flags (eg, IFF_TUN etc.)
     */
    
     /* open the clone device */
    if( (fd = open(clonedev, O_RDWR)) < 0 ) {
        return fd;
    }
    
    /* preparation of the struct ifr, of type "struct ifreq" */
    memset(&ifr, 0, sizeof(ifr));
    
    ifr.ifr_flags = flags;   /* IFF_TUN or IFF_TAP, plus maybe IFF_NO_PI */
    
    if (*dev) {
        /* if a device name was specified, put it in the structure; otherwise,
         * the kernel will try to allocate the "next" device of the
         * specified type */
        strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    }
    
    /* try to create the device */
    if( (err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0 ) {
        close(fd);
        return err;
    }
    
    /* if the operation was successful, write back the name of the
     * interface to the variable "dev", so the caller can know
     * it. Note that the caller MUST reserve space in *dev (see calling
     * code below) */
    strcpy(dev, ifr.ifr_name);
    
    /* this is the special file descriptor that the caller will use to talk
     * with the virtual interface */
    return fd;
}

void write_route() {
    system("sudo ifconfig tun0 10.0.0.1 up");//启动tun虚拟网卡
    system("sudo ip route add 39.156.66.14 via 10.0.0.1 dev tun0");//将所有发送到 10.0.0.2 的数据包，通过网络接口 "tun0" 进行传输，而且这个目标地址被视为一个单独的主机，而不是一个整个网络。
    // system("sudo route add -net 192.168.6.1 netmask 255.255.255.255 dev tun0");
}

int start_chanllenge() {
    int sockfd;
    struct sockaddr_in serverAddr;
    const unsigned char byte[] = {0x88, 0x88, 0x88, 0x88, 0x99, 0x99, 0x99, 0x99, 0x10, 0x10};

    // 创建套接字
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        perror("socket");
        return -1;
    }

    // 设置服务器地址信息
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = inet_addr(SERVER_IP);
    serverAddr.sin_port = htons(SERVER_CHANLLENGE_PORT);

    // 绑定设备 ens33
    if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, "ens33", strlen("ens33")) == -1) {
        perror("setsockopt");
        return -1;
    }

    // 连接服务器
    if (connect(sockfd, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == -1) {
        perror("connect");
        return -1;
    }

    if (send(sockfd, byte, 10, 0) == -1) {
        perror("send");
        exit(1);
    }

    //后面可以考虑这里添加一个回复认证报文

    return 0;
}

int create_socket() {
    int sockfd;
    struct sockaddr_in serverAddr;

    // 创建套接字
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        perror("socket");
        return -1;
    }

    // 设置服务器地址信息
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = inet_addr(SERVER_IP);
    serverAddr.sin_port = htons(SERVER_PORT);

    // 绑定设备 ens33
    if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, "ens33", strlen("ens33")) == -1) {
        perror("setsockopt");
        return -1;
    }

    // 连接服务器
    if (connect(sockfd, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == -1) {
        perror("connect");
        return -1;
    }

    return sockfd;
}

void* ListenTUN_SendServer(void* arg) {
    ThreadArgs* threadArgs = (ThreadArgs*)arg;
    int sockfd = threadArgs->sockfd;
    int tun_fd = threadArgs->tun_fd;
    int nread = 0;
    char buffer[2000];

    printf("Thread ListenTUN_SendServer start \n");
    
    while (1) {
        //发送数据包到TUN/TAP设备
        memset(buffer,0,sizeof(buffer));
        //读取协议栈发送来的信息
        nread = read(tun_fd, buffer, sizeof(buffer));
        if (nread < 0) {
            close(tun_fd);
            exit(1);
        }
        
        printf("Read %zd bytes from tun/tap device\n", nread);
            // 以十六进制格式输出IP数据包
        for (int i = 0; i < nread; i++) {
            printf("%02X ", buffer[i]);
            if ((i + 1) % 16 == 0) {
                printf("\n");
            }
        }
        printf("\n");
        buffer[nread] = '\0';

        printf("nread: %d\n", nread);
        //const char* sendData = "Hello, Server!";
        if (send(sockfd, buffer, nread, 0) == -1) {
            perror("send");
            exit(1);
        }
    }

    printf("Thread ListenTUN_SendServer end \n");
    pthread_exit(NULL);
}

void* ListenServer_SendTUN(void* arg) {
    ThreadArgs* threadArgs = (ThreadArgs*)arg;
    int sockfd = threadArgs->sockfd;
    int tun_fd = threadArgs->tun_fd;
    char buffer[2000];

    printf("Thread ListenServer_SendTUN start \n");
    
    while (1) {
        //接受服务器端的数据
        memset(buffer,0,sizeof(buffer));
        int numBytes = recv(sockfd, buffer, sizeof(buffer) - 1, 0);
        if (numBytes == -1) {
            perror("recv");
            exit(1);
        }
        buffer[numBytes] = '\0';

        printf("Read %zd bytes from server\n", numBytes);
            // 以十六进制格式输出IP数据包
        for (int i = 0; i < numBytes; i++) {
            printf("%02X ", buffer[i]);
            if ((i + 1) % 16 == 0) {
                printf("\n");
            }
        }
        printf("\n");
        
        //直接将接受的数据（已经是一个完整IP数据报文了）write tun
        //这里先不做处理。默认远方发送过来的数据是一个完整的IP数据报文
        int nwrite = write(tun_fd, buffer, numBytes);
        if (nwrite < 0) {
            perror("Writing to TUN device");
            exit(1);
        }
    }

    printf("Thread ListenServer_SendTUN end \n");
    pthread_exit(NULL);
}


int main()
{
    int sockfd;
    int tun_fd, nread;
    ThreadArgs threadArgs1, threadArgs2;
    pthread_t t1 = 0;
    pthread_t t2 = 1;
    
    
    char buffer1[IP_HEADER_LENGTH + 100]; // IP头部长度 + 应用层数据长度        
    char tun_name[IFNAMSIZ];


    strcpy(tun_name, "tun0");
    tun_fd = tun_alloc(tun_name, IFF_TUN | IFF_NO_PI);
    write_route();

    if (tun_fd < 0) {
        perror("Allocating interface");
        exit(1);
    }

    start_chanllenge();
    sockfd = create_socket();
    if (sockfd == -1) {
        return -1;
    }

    threadArgs1.tun_fd = tun_fd;
    threadArgs1.sockfd = sockfd;
    threadArgs2.tun_fd = tun_fd;
    threadArgs2.sockfd = sockfd;

    pthread_create(&t1, NULL, ListenTUN_SendServer, &threadArgs1);
    pthread_create(&t2, NULL, ListenServer_SendTUN, &threadArgs2);

    while (1) {
        
    }

    close(sockfd);
    close(tun_fd);

    return 0;
}
