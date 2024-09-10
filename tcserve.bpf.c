#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include "network.h"
//#include <ctype.h>
//#include <asm/checksum.h>
#include <net/checksum.h> 

#define HTTP_GET "GET "
#define HTTP_GET_LEN 4
#define HTTP_RESPONSE "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 13\r\n\r\nHello, World!"
#define HTTP_RESPONSE_LEN 77

#define IP_CSUM_OFF (ETH_HLEN + offsetof(struct iphdr, check))
#define TCP_CSUM_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, check))
#define TCP_SRC_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, source))
#define TCP_DST_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, dest))
#define TCP_SEQ_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, seq))
#define TCP_ACKSEQ_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, ack_seq))
#define TCP_FLAGS_OFF (ETH_HLEN + sizeof(struct iphdr) + 13)

static __always_inline __u16 update_tcp_checksum(__u16 old_csum, __u32 old_val, __u32 new_val) {
    __u32 csum = bpf_csum_diff((__be32 *)&old_val, sizeof(old_val), (__be32 *)&new_val, sizeof(new_val), ~old_csum);
    return ~csum;
}


/*
struct pseudo_header {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint8_t reserved;
    uint8_t protocol;
    uint16_t tcp_length;
};
*/

int tc_serve(struct __sk_buff *skb) {
/* pass through l3=ip,l4=tcp,port80 */
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
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
    //struct tcphdr *tcp = (struct tcphdr *)((char *)ip + ip_header_len);
    struct tcphdr *tcp = (struct tcphdr *)((char *)ip + sizeof(struct iphdr));
    if ((void *)tcp + sizeof(struct tcphdr) > data_end)
        return TC_ACT_OK;
    if (ntohs(tcp->dest) != 80)
        return TC_ACT_OK;

    bpf_trace_printk("before adjust, src %u, dst %u", ntohs(tcp->source), ntohs(tcp->dest));

/* pkts check */
    int tcp_data_offset = tcp->doff * 4;
    bpf_trace_printk("****tcpdoffbefore: %d", tcp_data_offset);
    char *payload = (char *)tcp + tcp_data_offset;
    if ((void *)tcp + tcp_data_offset > data_end)
        return TC_ACT_OK;
    if ((void *)(payload + HTTP_GET_LEN) > data_end)    
        return TC_ACT_OK;
    int payload_size = (char *)data_end - payload;
    __be16 packet_size = ip->tot_len;
    __be16 old_tot_len = ip->tot_len;
    
    int pkt_size = data_end - data;
    int phead = payload - (char *)data;
    bpf_trace_printk("payloadsize=%d, packaetsize=%d", payload_size, pkt_size);
    bpf_trace_printk("phead=%d, ptail=%d", phead, phead+payload_size);

/* print received payload */
/*
    if (payload_size > 0) {
        if ((void *)(payload + payload_size) > data_end)
            return TC_ACT_OK;
        //limit iteration num (limit sinaito verfier tooranai)
        if (payload_size > 100) {
            payload_size = 100;
        }
        #pragma clang loop unroll(full)
        for (int i = 0; i < payload_size; i++) {
            // kokonazehituyounanokafumei, uedekakuninnsiterunoni...?
            if ((void *)(payload + i + 1) > data_end) {
                return TC_ACT_OK;
            }
            bpf_trace_printk("%c", payload[i] - 0);
        }
    }
*/

/*
    bpf_trace_printk("%u", payload[0]); //71 'G'
    bpf_trace_printk("%u", payload[1]); //69 'E'
    bpf_trace_printk("%u", payload[2]); //84 'T'
    bpf_trace_printk("%u", payload[3]); //32 ' '
    bpf_trace_printk("%s", payload);
*/

/* HTTP GET request nara... */
    if (__builtin_memcmp(payload, HTTP_GET, HTTP_GET_LEN) == 0) {
        bpf_trace_printk("in");
/* l3 swap */
	    __u32 src_ip = ip->saddr; //__u32 src_ip = ntohl(ip->saddr);
	    __u32 dst_ip = ip->daddr; //__u32 dst_ip = ntohl(ip->daddr);
        ip->saddr = dst_ip;
        ip->daddr = src_ip;

        unsigned char src_mac[6];
        unsigned char dst_mac[6];
        memcpy(src_mac, eth->h_source, 6);
        memcpy(dst_mac, eth->h_dest, 6);
        memcpy(eth->h_source, dst_mac, 6);
        memcpy(eth->h_dest, src_mac, 6);

/* l4 swap */
/* tcp port swap */
        __be16 src_port = tcp->source;
        __be16 dst_port = tcp->dest;
        //tcp->source = htons(ntohs(dst_port));
        //tcp->dest = htons(ntohs(src_port));
        bpf_skb_store_bytes(skb, TCP_SRC_OFF, &dst_port, 2, BPF_F_RECOMPUTE_CSUM);
        bpf_skb_store_bytes(skb, TCP_DST_OFF, &src_port, 2, BPF_F_RECOMPUTE_CSUM);

/* update seq/ack_seq */
        void *data = (void *)(long)skb->data;
        void *data_end = (void *)(long)skb->data_end;
        struct iphdr *ip = data + sizeof(struct ethhdr);
        if ((void *)ip + sizeof(struct iphdr) > data_end)
            return TC_ACT_OK;
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)tcp + sizeof(struct tcphdr) > data_end)
            return TC_ACT_OK;
        uint32_t prevseq = ntohl(tcp->seq);
        uint32_t prevackseq = tcp->ack_seq;
        //tcp->seq = tcp->ack_seq;
        //tcp->ack_seq = (__be32)htonl(prevseq + payload_size); // naze +1 sinakute yoi?
        uint32_t newackseq = (__be32)htonl(prevseq + payload_size); // naze +1 sinakute yoi?
        bpf_skb_store_bytes(skb, TCP_SEQ_OFF, &prevackseq, 4, BPF_F_RECOMPUTE_CSUM);
        bpf_skb_store_bytes(skb, TCP_ACKSEQ_OFF, &newackseq, 4, BPF_F_RECOMPUTE_CSUM);
        
/* update tcp flag */
        data = (void *)(long)skb->data;
        data_end = (void *)(long)skb->data_end;
        ip = data + sizeof(struct ethhdr);
        if ((void *)ip + sizeof(struct iphdr) > data_end)
            return TC_ACT_OK;
        tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)tcp + sizeof(struct tcphdr) > data_end)
            return TC_ACT_OK;

         /*
        tcp->fin = 0;
        tcp->syn = 0;
        tcp->rst = 0;
        tcp->psh = 1;
        tcp->ack = 1;
        */
        u8 tcp_flags = 0;
        tcp_flags |= (1 << 3);
        tcp_flags |= (1 << 4);
        bpf_skb_store_bytes(skb, TCP_FLAGS_OFF, &tcp_flags, sizeof(tcp_flags), BPF_F_RECOMPUTE_CSUM);

/* expand payload */
        bpf_skb_change_tail(skb, HTTP_RESPONSE_LEN * 7, 0);

/* recheck pointer is within packet */
        data = (void *)(long)skb->data;
        data_end = (void *)(long)skb->data_end;
        ip = data + sizeof(struct ethhdr);
        if ((void *)ip + sizeof(struct iphdr) > data_end)
            return TC_ACT_SHOT;

/* update ip->tot_len since tcp payload is expanded */
        int new_tot_len = bpf_ntohs(ip->tot_len) + HTTP_RESPONSE_LEN * 7;
        ip->tot_len = bpf_htons(new_tot_len);

        tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)tcp + sizeof(struct tcphdr) > data_end)
            return TC_ACT_OK;

        bpf_trace_printk("after adjust, src %u, dst %u", ntohs(tcp->source), ntohs(tcp->dest));
        bpf_trace_printk("after adjust, payloadsize=%d, packaetsize=%d", payload_size, pkt_size);
        bpf_trace_printk("after adjust, phead=%d, ptail=%d", phead, phead+payload_size);

        payload = (void *)tcp + (tcp->doff * 4);
        if ((void *)payload + HTTP_RESPONSE_LEN > data_end)
            return TC_ACT_OK;

/* rewrite payload */
        char http_response[HTTP_RESPONSE_LEN] = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 13\r\n\r\nHello, World!";
        bpf_skb_store_bytes(skb, (__u32)((void *)payload - (void *)data), http_response, HTTP_RESPONSE_LEN, BPF_F_RECOMPUTE_CSUM);
        //memcpy(payload, HTTP_RESPONSE, HTTP_RESPONSE_LEN);
        bpf_trace_printk("%s", payload); //'HTTP/1.1 200 OK
  

/* print payload after change
        #pragma clang loop unroll(full)
        for (int i = 0; i < HTTP_RESPONSE_LEN; i++) { // response hyouji
            if ((void *)(payload + i + 1) > data_end) {
                return TC_ACT_OK;
            }
            bpf_trace_printk("res=%c", payload[i] - 0);
        }
*/

/* update ip csum */
        data = (void *)(long)skb->data;
        data_end = (void *)(long)skb->data_end;
        ip = data + sizeof(struct ethhdr);
        if ((void *)ip + sizeof(struct iphdr) > data_end)
            return TC_ACT_SHOT;
        csum_replace2(&ip->check, src_ip, ip->saddr);
        csum_replace2(&ip->check, dst_ip, ip->daddr);
        csum_replace2(&ip->check, old_tot_len, ip->tot_len);

/* update tcp csum */
        tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)tcp + sizeof(struct tcphdr) > data_end)
            return TC_ACT_OK;

tcp->check = update_tcp_checksum(tcp->check, ip->saddr, src_ip);
tcp->check = update_tcp_checksum(tcp->check, ip->daddr, dst_ip);

__u16 tcp_length = bpf_ntohs(ip->tot_len) - (ip->ihl * 4);
tcp->check = update_tcp_checksum(tcp->check, 0, (__u32)tcp_length);

__u16 new_tcp_check = tcp->check;
bpf_skb_store_bytes(skb, TCP_CSUM_OFF, &new_tcp_check, sizeof(new_tcp_check), 0);


/*
        csum_replace2(&tcp->check, src_port, tcp->source);
        csum_replace2(&tcp->check, dst_port, tcp->dest);
        csum_replace2(&tcp->check, prevseq, tcp->seq);
        csum_replace2(&tcp->check, prev_ackseq, tcp->ack_seq);
        csum_replace2(&tcp->check, prev_fin, tcp->fin);
        csum_replace2(&tcp->check, prev_syn, tcp->syn);
        csum_replace2(&tcp->check, prev_rst, tcp->rst);
        csum_replace2(&tcp->check, prev_psh, tcp->psh);
        csum_replace2(&tcp->check, prev_ack, tcp->ack);
*/
/*
        data = (void *)(long)skb->data;
        data_end = (void *)(long)skb->data_end;
        eth = data;
        if ((void *)(eth + 1) > data_end) return TC_ACT_OK;
        ip = data + sizeof(struct ethhdr);
        if ((void *)(ip + 1) > data_end) return TC_ACT_SHOT;
        
        bpf_l3_csum_replace(skb, IP_CSUM_OFF, src_ip, ip->saddr, 4);
        
        data = (void *)(long)skb->data;
        data_end = (void *)(long)skb->data_end;
        eth = data;
        if ((void *)(eth + 1) > data_end) return TC_ACT_OK;
        ip = data + sizeof(struct ethhdr);
        if ((void *)(ip + 1) > data_end) return TC_ACT_SHOT;
        
        bpf_l3_csum_replace(skb, IP_CSUM_OFF, dst_ip, ip->daddr, 4);
        
        data = (void *)(long)skb->data;
        data_end = (void *)(long)skb->data_end;
        eth = data;
        if ((void *)(eth + 1) > data_end) return TC_ACT_OK;
        ip = data + sizeof(struct ethhdr);
        if ((void *)(ip + 1) > data_end) return TC_ACT_SHOT;
        tcp = (struct tcphdr *)((char *)ip + sizeof(struct iphdr));
        if ((void *)tcp + sizeof(struct tcphdr) > data_end) return TC_ACT_OK;
        
        bpf_l4_csum_replace(skb, TCP_CSUM_OFF, src_port, tcp->source, 2);
        
        data = (void *)(long)skb->data;
        data_end = (void *)(long)skb->data_end;
        eth = data;
        if ((void *)(eth + 1) > data_end) return TC_ACT_OK;
        ip = data + sizeof(struct ethhdr);
        if ((void *)(ip + 1) > data_end) return TC_ACT_SHOT;
        tcp = (struct tcphdr *)((char *)ip + sizeof(struct iphdr));
        if ((void *)tcp + sizeof(struct tcphdr) > data_end) return TC_ACT_OK;
        
        bpf_l4_csum_replace(skb, TCP_CSUM_OFF, dst_port, tcp->dest, 2);
*/

/* send back packet */
	    bpf_clone_redirect(skb, skb->ifindex, 0);

/* discard packet */
        return TC_ACT_SHOT;
    }

    return TC_ACT_OK;
}

