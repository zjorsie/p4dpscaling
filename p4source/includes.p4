/* Definitions */



#define VNF_PROXYLESS           0x00
#define VNF_PACKETFUL           0x0f
#define VNF_FWLESS              0xf0
#define VNF_FWFUL               0xff
#define FLOWID_HDR              0x1433
#define MIG_HDR                 0x3341
#define MIG_TO_CONTROL          0x3143

#define MIGST_INITSYNC          0x00
#define MIGST_INITACK           0x3c
#define MIGST_SENDUPDATE        0x0f
#define MIGST_INITFORWARD       0x3f
#define MIGST_FORWARD           0xff
#define MIGST_REC_TIME          0x55
#define MIGST_TRA_TIME          0xaa
#define HASH_SIZE               1024

#define CPU_PORT                255
#define DROP_PORT               511
#define PACKETCOUNTAPPSTATEFUL  0x1
#define PROXYAPPSTATELESS       0x2
#define FWAPPSTATEFUL           0x3
#define FWAPPSTATELESS          0x4
#define FWMIGRATION             0x5
#define S1_LABEL                0xC
#define S2_LABEL                0x3
#define S3_LABEL                0x9
#define ETHERTYPE_SEND_CPU     0xffff
#define ETHERTYPE_LABELROUTING 0xf0f0
#define ETHERTYPE_BF_FABRIC    0x9000
#define ETHERTYPE_VLAN         0x8100
#define ETHERTYPE_QINQ         0x9100
#define ETHERTYPE_MPLS         0x8847
#define ETHERTYPE_IPV4         0x0800
#define ETHERTYPE_IPV6         0x86dd
#define ETHERTYPE_ARP          0x0806
#define ETHERTYPE_RARP         0x8035
#define ETHERTYPE_NSH          0x894f
#define ETHERTYPE_ETHERNET     0x6558
#define ETHERTYPE_ROCE         0x8915
#define ETHERTYPE_FCOE         0x8906
#define ETHERTYPE_TRILL        0x22f3
#define ETHERTYPE_VNTAG        0x8926
#define ETHERTYPE_LLDP         0x88cc
#define ETHERTYPE_LACP         0x8809


#define IP_PROTOCOLS_ICMP              1
#define IP_PROTOCOLS_IGMP              2
#define IP_PROTOCOLS_IPV4              4
#define IP_PROTOCOLS_TCP               6
#define IP_PROTOCOLS_UDP               17
#define IP_PROTOCOLS_IPV6              41
#define IP_PROTOCOLS_GRE               47
#define IP_PROTOCOLS_IPSEC_ESP         50
#define IP_PROTOCOLS_IPSEC_AH          51
#define IP_PROTOCOLS_ICMPV6            58
#define IP_PROTOCOLS_EIGRP             88
#define IP_PROTOCOLS_OSPF              89
#define IP_PROTOCOLS_PIM               103
#define IP_PROTOCOLS_VRRP              112


#define IP_PROTOCOLS_IPHL_ICMP         0x501
#define IP_PROTOCOLS_IPHL_IPV4         0x504
#define IP_PROTOCOLS_IPHL_TCP          0x506
#define IP_PROTOCOLS_IPHL_UDP          0x511
#define IP_PROTOCOLS_IPHL_IPV6         0x529
#define IP_PROTOCOLS_IPHL_GRE 		   0x52f

#define UDP_PORT_BOOTPS                67
#define UDP_PORT_BOOTPC                68
#define UDP_PORT_RIP                   520
#define UDP_PORT_RIPNG                 521
#define UDP_PORT_DHCPV6_CLIENT         546
#define UDP_PORT_DHCPV6_SERVER         547
#define UDP_PORT_HSRP                  1985
#define UDP_PORT_BFD                   3785
#define UDP_PORT_LISP                  4341
#define UDP_PORT_VXLAN                 4789
#define UDP_PORT_VXLAN_GPE             4790
#define UDP_PORT_ROCE_V2               4791
#define UDP_PORT_GENV                  6081
#define UDP_PORT_SFLOW 				   6343

#define SEND_DIGEST_ENQ_QDEPTH_LIM      0
#define SEND_DIGEST_DEQ_QDEPTH_LIM      20
#define SEND_DIGEST_DEQ_TIMEDELTA_LIM   10000


#define PKT_INSTANCE_TYPE_NORMAL        0
#define PKT_INSTANCE_TYPE_INGRESS_CLONE 1
#define PKT_INSTANCE_TYPE_EGRESS_CLONE  2
#define PKT_INSTANCE_TYPE_COALESCED     3
#define PKT_INSTANCE_TYPE_REPLICATION   5
#define PKT_INSTANCE_TYPE_RESUBMIT      6
