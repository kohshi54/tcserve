#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
//#include "network.h"
//#include <ctype.h>

#define HTTP_GET "GET "
#define HTTP_GET_LEN 4
#define HTTP_RESPONSE "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 13\r\n\r\nHello, World!"
#define HTTP_RESPONSE_LEN 77

int tc_serve(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    int rcvdatalen = data_end - data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return TC_ACT_OK;

    struct iphdr *ip = (struct iphdr *)(data + sizeof(struct ethhdr));
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    if (ip->protocol != IPPROTO_TCP)
        return TC_ACT_OK;

/*
    int ip_header_len = ip->ihl * 4;
    if ((void *)ip + ip_header_len > data_end)
        return TC_ACT_OK;
*/

    //struct tcphdr *tcp = (struct tcphdr *)((char *)ip + ip_header_len);
    struct tcphdr *tcp = (struct tcphdr *)((char *)ip + sizeof(struct iphdr));
    if ((void *)tcp + sizeof(struct tcphdr) > data_end)
        return TC_ACT_OK;

bpf_trace_printk("before adjust, src %u, dst %u", ntohs(tcp->source), ntohs(tcp->dest));

    //bpf_trace_printk("here1");
    int tcp_data_offset = tcp->doff * 4;
    char *payload = (char *)tcp + tcp_data_offset;
    //char *payload = (char *)tcp + sizeof(struct tcphdr);
    //if ((void *)tcp + sizeof(struct tcphdr) > data_end)
    if ((void *)tcp + tcp_data_offset > data_end)
        return TC_ACT_OK;

    //bpf_trace_printk("here2");
    // Check for HTTP GET request
    if ((void *)(payload + HTTP_GET_LEN) > data_end)
        return TC_ACT_OK;

    int payload_size1 = (char *)data_end - payload;
    //int packet_size = data_end - data;
    __be16 packet_size = ip->tot_len;
    //int payload_size = packet_size - (ip->ihl * 4 + tcp->doff * 4);
    //bpf_trace_printk("xxxxxxxxxxxxxxx=%d", payload_size);
    
    int all_size = data_end - data;
    int phead = payload - (char *)data;
    bpf_trace_printk("payloadsize=%d, packaetsize=%d", payload_size1, all_size);
    bpf_trace_printk("phead=%d, ptail=%d", phead, phead+payload_size1);

    if (payload_size1 > 0) {
        if ((void *)(payload + payload_size1) > data_end)
            return TC_ACT_OK;

        //limit iteration num (limit sinaito verfier tooranai)
        if (payload_size1 > 100) {
            payload_size1 = 100;
        }

        #pragma clang loop unroll(full)
        for (int i = 0; i < payload_size1; i++) {
            // kokonazehituyounanokafumei, uedekakuninnsiterunoni...?
            if ((void *)(payload + i + 1) > data_end) {
                return TC_ACT_OK;
            }
            bpf_trace_printk("%c", payload[i] - 0);
            //if (isprint(payload[i]) {
            //if (32 <= payload[i] && payload[i] <= 126) {
            //    break;
            //}
        }
    }

    bpf_trace_printk("here3");
/*
    bpf_trace_printk("%u", payload[0]); //71 'G'
    bpf_trace_printk("%u", payload[1]); //69 'E'
    bpf_trace_printk("%u", payload[2]); //84 'T'
    bpf_trace_printk("%u", payload[3]); //32 ' '
    bpf_trace_printk("%s", payload);
*/

/*
    #pragma clang loop unroll(full)
    for (int i = 0; i < 4; i++) {
        bpf_trace_printk("%c", payload[i] - 0);
    }
*/

    if (__builtin_memcmp(payload, HTTP_GET, HTTP_GET_LEN) == 0) {
    bpf_trace_printk("in");
    // packet size fuyasu
    bpf_skb_change_tail(skb, HTTP_RESPONSE_LEN * 7, 0); // payload size ga daini2 hikisuuninaltuteru?
/* kottchi dato l3 no space ga fuerudake de l4 no space ha fuenai.
        if (bpf_skb_adjust_room(skb, HTTP_RESPONSE_LEN, BPF_ADJ_ROOM_NET, 0)) {
            return TC_ACT_SHOT;
        }
*/

        // Re-fetch pointers after adjusting the packet
        data = (void *)(long)skb->data;
        data_end = (void *)(long)skb->data_end;

        eth = data;
        if ((void *)(eth + 1) > data_end)
            return TC_ACT_OK;

        ip = data + sizeof(struct ethhdr);
        if ((void *)(ip + 1) > data_end)
            return TC_ACT_SHOT;

        //if (ip->protocol != IPPROTO_TCP)
        //    return TC_ACT_OK;

        tcp = (struct tcphdr *)((char *)ip + sizeof(struct iphdr));
        //tcp = (struct tcphdr *)((char *)ip + sizeof(struct iphdr) + HTTP_RESPONSE_LEN);
        if ((void *)tcp + sizeof(struct tcphdr) > data_end)
            return TC_ACT_OK;
bpf_trace_printk("xxxxxxxxxxxxxxxxxxxxxxxxxxxx");
    tcp_data_offset = tcp->doff * 4;
    payload = (char *)tcp + tcp_data_offset;
    payload_size1 = (char *)data_end - payload;
    packet_size = ip->tot_len;
    all_size = data_end - data;
    phead = payload - (char *)data;
 
bpf_trace_printk("after adjust, src %u, dst %u", ntohs(tcp->source), ntohs(tcp->dest));
    bpf_trace_printk("after adjust, payloadsize=%d, packaetsize=%d", payload_size1, all_size);
    bpf_trace_printk("after adjust, phead=%d, ptail=%d", phead, phead+payload_size1);

        tcp_data_offset = tcp->doff * 4;
        payload = (char *)tcp + tcp_data_offset;
        if ((void *)tcp + tcp_data_offset > data_end)
            return TC_ACT_OK;

    bpf_trace_printk("in2");
        if ((void *)(payload + HTTP_RESPONSE_LEN) > data_end)
            return TC_ACT_OK;
    bpf_trace_printk("in333333333333333333");

        int new_tot_len = bpf_ntohs(ip->tot_len) + HTTP_RESPONSE_LEN;
        ip->tot_len = bpf_htons(new_tot_len);

	    //__u32 src_ip = ntohl(ip->saddr);
	    //__u32 dst_ip = ntohl(ip->daddr);
	    __u32 src_ip = ip->saddr;
	    __u32 dst_ip = ip->daddr;
        ip->saddr = dst_ip;
        ip->daddr = src_ip;
        ip->ttl = 125;

        unsigned char src_mac[6];
        unsigned char dst_mac[6];
        memcpy(src_mac, eth->h_source, 6);
        memcpy(dst_mac, eth->h_dest, 6);
        memcpy(eth->h_source, dst_mac, 6);
        memcpy(eth->h_dest, src_mac, 6);

        __be16 src_port = tcp->source;
        __be16 dst_port = tcp->dest;
//        bpf_trace_printk("src %d, dst %d", htons(ntohs(tcp->source)), htons(ntohs(tcp->dest)));
        tcp->source = htons(ntohs(dst_port));
        tcp->dest = htons(ntohs(src_port));
        //tcp->source = htons(ntohs(dst_port));
        //tcp->dest = htons(ntohs(src_port));
        //bpf_trace_printk("src %d, dst %d", tcp->source, tcp->dest);

        
        //payload[0] = 'H';
        //payload[1] = 'T';
        //payload[2] = 'T';
        //payload[3] = 'P';

        bpf_trace_printk("%u", payload[0]);
        bpf_trace_printk("%u", payload[1]);
        bpf_trace_printk("%u", payload[2]);
        bpf_trace_printk("%u", payload[3]);
        bpf_trace_printk("%u", payload[4]);
        bpf_trace_printk("%u", payload[5]);
        bpf_trace_printk("%u", payload[6]);
        bpf_trace_printk("%s", payload); //'HTTP/1.1 200 OK
        bpf_trace_printk("%u", payload[17]); //'C'
        bpf_trace_printk("%u", payload[18]); //'o'
        bpf_trace_printk("%u", payload[19]); //'n'
        bpf_trace_printk("%u", payload[20]); //'t'
        bpf_trace_printk("%u", payload[21]); //'e'
        bpf_trace_printk("%u", payload[22]); //'n'


        tcp->doff = sizeof(struct tcphdr) / 4;
        tcp->ack_seq = htonl(ntohl(tcp->seq) + rcvdatalen); 
        //tcp->seq = htonl(ntohl(tcp->ack_seq));
        //tcp->ack_seq = htonl(ntohl(tcp->seq) + 1);

        tcp->fin = 0;
        tcp->syn = 1;
        tcp->rst = 0;
        tcp->psh = 1;
        tcp->ack = 1;

        memcpy(payload, HTTP_RESPONSE, HTTP_RESPONSE_LEN);

        #pragma clang loop unroll(full)
        for (int i = 0; i < HTTP_RESPONSE_LEN; i++) { // response hyouji
            if ((void *)(payload + i + 1) > data_end) {
                return TC_ACT_OK;
            }
            bpf_trace_printk("res=%c", payload[i] - 0);
        }


        //bpf_l3_csum_replace(skb, offsetof(struct iphdr, check), 0, 0, BPF_F_HDR_FIELD_MASK);
        //bpf_l4_csum_replace(skb, offsetof(struct tcphdr, check), 0, 0, BPF_F_PSEUDO_HDR | BPF_F_HDR_FIELD_MASK);


/*
        bpf_l3_csum_replace(skb, IP_CSUM_OFF, dst_ip, ip->saddr, 4);
        bpf_l3_csum_replace(skb, IP_CSUM_OFF, src_ip, ip->daddr, 4);
        bpf_l4_csum_replace(skb, TCP_CSUM_OFF, src_port, tcp->dest, 4);
        bpf_l4_csum_replace(skb, TCP_CSUM_OFF, dst_port, tcp->source, 4);
*/

	    bpf_clone_redirect(skb, skb->ifindex, 0);
	    //bpf_redirect(skb->ifindex, 0);
        return TC_ACT_SHOT;
    }

    return TC_ACT_OK;
}

