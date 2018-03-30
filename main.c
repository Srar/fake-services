#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <libnet.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>

#define SNAP_LEN 65535

uint8_t openPorts[65536];

size_t lastIndexOf(char *str, char target)
{
    int i;
    for (i = strlen(str); i != 0; i--)
    {
        if (str[i] == target)
            return i;
    }
    return -1;
}

void *flushOpenPorts()
{
    while (1)
    {
        int i;
        for (i = 0; i < 65536; i++)
        {
            openPorts[i] = 0;
        }

        FILE *fp;
        char *line = malloc(1024);
        int lineSize = 1024 - 1;

        fp = popen("ss -ltn", "r");
        if (fp == NULL)
        {
            printf("Failed to run command\n");
            exit(1);
        }

        uint8_t firstLine = 1;
        while (fgets(line, lineSize, fp) != NULL)
        {
            if (firstLine == 1)
            {
                firstLine = 0;
                continue;
            }

            char listenInfo[64] = {0};
            sscanf(line, "%*s %*s %*s %[^ ]", listenInfo);
            size_t addressEnd = lastIndexOf(listenInfo, ':');
            int port = atoi(listenInfo + addressEnd + 1);
            openPorts[port] = 1;
        }

        pclose(fp);
        free(line);
        sleep(15);
    }
}

libnet_t *start_libnet(char *dev)
{
    char errbuf[LIBNET_ERRBUF_SIZE];
    libnet_t *libnet_handler = libnet_init(LIBNET_RAW4_ADV, dev, errbuf);

    if (NULL == libnet_handler)
    {
        printf("libnet_init: error %s\n", errbuf);
    }
    return libnet_handler;
}

void got_packet(void *args, const struct pcap_pkthdr *header, const void *packet)
{
    libnet_t *libnetHandler = (libnet_t *)args;
    struct libnet_ipv4_hdr *ipHeader = (struct libnet_ipv4_hdr *)(packet + 14);
    struct libnet_tcp_hdr *tcpHeader = (struct libnet_tcp_hdr *)(packet + 14 + 20);

    u_int16_t sourcePort = ntohs(tcpHeader->th_sport);
    u_int16_t destPort = ntohs(tcpHeader->th_dport);

    const uint32_t *ipSrcZ = &(ipHeader->ip_src.s_addr);
    const uint8_t *ipSrc = (const uint8_t *)ipSrcZ;
    const uint32_t *ipDstZ = &(ipHeader->ip_dst.s_addr);
    const uint8_t *ipDst = (const uint8_t *)ipDstZ;

    if (openPorts[destPort] == 1)
        return;
    if (!(tcpHeader->th_flags & TH_SYN))
        return;
    if(tcpHeader->th_ack != 0)
        return;

    libnet_build_tcp(
        destPort,                     /* source port */
        sourcePort,                   /* destination port */
        random(),                     /* sequence number */
        htonl(tcpHeader->th_seq) + 1, /* acknowledgement num */
        TH_SYN | TH_ACK,              /* control flags */
        tcpHeader->th_win,            /* window size */
        0,                            /* checksum */
        0,                            /* urgent pointer */
        20,                           /* TCP packet size */
        NULL,                         /* payload */
        0,                            /* payload size */
        libnetHandler,               /* libnet handle */
        0);

    libnet_build_ipv4(
        LIBNET_IPV4_H + LIBNET_TCP_H, /* length */
        0,                            /* TOS */
        random(),                     /* IP ID */
        0,                            /* IP Frag */
        64,                           /* TTL */
        IPPROTO_TCP,                  /* protocol */
        0,                            /* checksum */
        ipHeader->ip_dst.s_addr,      /* source IP */
        ipHeader->ip_src.s_addr,      /* destination IP */
        NULL,                         /* payload */
        0,                            /* payload size */
        libnetHandler,               /* libnet handle */
        0);

    libnet_write(libnetHandler);
    printf("[%d.%d.%d.%d:%d] was scan port [%d].\n", ipSrc[0], ipSrc[1], ipSrc[2], ipSrc[3], sourcePort, destPort);
}

int main(int argc, char **argv)
{
    pthread_t flushPortsThreadId;
    pthread_create(&flushPortsThreadId, NULL, &flushOpenPorts, NULL);

    char *interfaceName = argv[1];
    pcap_t *pcapHandle;
    struct bpf_program fp;
    bpf_u_int32 net, mask;
    char errbuf[PCAP_ERRBUF_SIZE];

    /* check if interface is exists */
    if (pcap_lookupnet(interfaceName, &net, &mask, errbuf) == -1)
    {
        printf("Couldn't get netmask for device %s: %s\n", interfaceName, errbuf);
        net = 0;
        mask = 0;
    }

    printf("init pcap\n");
    pcapHandle = pcap_open_live(interfaceName, SNAP_LEN, 1, 1000, errbuf);
    if (pcapHandle == NULL)
    {
        printf("pcap_open_live dev:[%s] err:[%s]\n", interfaceName, errbuf);
        printf("init pcap failed\n");
        return -1;
    }
    printf("init libnet\n");
    libnet_t *libnetHandler = start_libnet(interfaceName);
    if (libnetHandler == NULL)
    {
        printf("init libnet failed\n");
        return -1;
    }

    char rule[50] = "tcp and dst host ";
    strcat(rule, libnet_addr2name4(libnet_get_ipaddr4(libnetHandler), LIBNET_DONT_RESOLVE));
    if (pcap_compile(pcapHandle, &fp, rule, 0, net) == -1)
    {
        printf("filter rule err:[%s][%s]\n", rule, pcap_geterr(pcapHandle));
        return -1;
    }
    if (pcap_setfilter(pcapHandle, &fp) == -1)
    {
        printf("set filter failed:[%s][%s]\n", rule, pcap_geterr(pcapHandle));
        return -1;
    }

    while (1)
    {
        pcap_loop(pcapHandle, 1, got_packet, (void *)libnetHandler);
    }
}
