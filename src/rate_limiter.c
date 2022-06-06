#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <errno.h>
#include <string.h>
#include <syslog.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <libnetfilter_queue/libnetfilter_queue.h>
#include <unistd.h>
#include <sys/stat.h>


#include "../lib/rate_limiter.h"

#define IPTYPE 8
#define TCPTYPE 6

#define VERSION "0.0.1"


typedef u_int tcp_seq;


u_int32_t id;
u_int8_t flag;


static int go_background_service() {
    pid_t process_id = 0;
    pid_t sid = 0;
    process_id = fork();
    if (process_id < 0) {
        syslog(LOG_ERR, "fork failed!");
        exit(1);
    }
    if (process_id > 0) {
        syslog(LOG_NOTICE, "new child process pid -> {%d}", process_id);
        exit(0);
    }
    umask(0);
    sid = setsid();
    if (sid < 0) {
        exit(1);
    }
    chdir("/");
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
    syslog(LOG_NOTICE, "start rate_limiter %s daemon...", VERSION);
    return 0;
}


static u_int32_t request_process(struct nfq_data *tb) {
    struct nfqnl_msg_packet_hdr *ph;
    struct nfqnl_msg_packet_hw *hwph;
    u_int32_t mark, ifi;
    int ret;
    unsigned char *data;

    struct ip *ip_header;
    struct tcphdr *tcp_header;
    char *tcp_data_area;
    int ip_header_size;
    int tcp_header_size;
    int tcp_data_len;

    flag = DROP_REQUEST;

    ph = nfq_get_msg_packet_hdr(tb);
    if (ph) id = ntohl(ph->packet_id); // id

    hwph = nfq_get_packet_hw(tb);
    if (hwph) {
        int i, hlen = ntohs(hwph->hw_addrlen);
    }

    mark = nfq_get_nfmark(tb);
    ifi = nfq_get_indev(tb);
    ifi = nfq_get_outdev(tb);
    ifi = nfq_get_physindev(tb);
    ifi = nfq_get_physoutdev(tb);
    ret = nfq_get_payload(tb, &data);
    int i = 0;
    int size = ret;

    ip_header = (struct ip *) data;
    ip_header_size = ip_header->ip_hl * 4;


    tcp_header = (struct tcphdr *) (data + ip_header_size);
    tcp_header_size = (tcp_header->th_off * 4);
    tcp_data_area = data + ip_header_size + tcp_header_size;
    tcp_data_len = ret - ip_header_size - tcp_header_size;


    const int r_dst_port = htons(tcp_header->th_dport);
    const int r_src_port = htons(tcp_header->th_sport);

    char *src_ip_info;
    src_ip_info = malloc(sizeof(char) * 20);
    if (src_ip_info == NULL) {
        syslog(LOG_NOTICE, "error while memory allocation, exit.");
        exit(false);
    }

    memset(src_ip_info, '\0', strlen(src_ip_info));
    char *src = dump_ip(htonl(ip_header->ip_src.s_addr), src_ip_info);

    char *dst_ip_info;
    dst_ip_info = malloc(sizeof(char) * 20);
    if (dst_ip_info == NULL) {
        syslog(LOG_NOTICE, "error while memory allocation, exit.");
        exit(false);
    }
    memset(dst_ip_info, '\0', strlen(dst_ip_info));
    char *dst = dump_ip(htonl(ip_header->ip_dst.s_addr), dst_ip_info);

    remove_spaces(dst);
    remove_spaces(src);

    // here where we go to manage incoming traffic
    if (is_flooding_request(src_ip_info) == true) {
        flag = DROP_REQUEST;
    } else {
        flag = ALLOW_REQUEST;
    }
    iterate_req_src_queue();

    free(src_ip_info);
    free(dst_ip_info);
    src_ip_info = NULL; // avoid use after free attack
    dst_ip_info = NULL;// avoid use after free attack
    return id;

}


static int hooking_(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
                    struct nfq_data *nfa, void *data) {
    u_int32_t id = request_process(nfa);
    return nfq_set_verdict(qh, id, flag, 0, NULL);
}

int main(int argc, char *argv[]) {
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfnl_handle *nh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));


    // reset linux iptables,
    system("iptables -F");
    system("iptables -X");
    system("iptables -t nat -F");

    // check req form local machine (lo)
    system("sudo echo 1 > /proc/sys/net/ipv4/ip_forward");

    //enable tcp syn-cookie
    system("echo 1 > /proc/sys/net/ipv4/tcp_syncookies");


    system("sudo iptables -A INPUT -j NFQUEUE --queue-num 0");
    system("sudo iptables -A OUTPUT -j NFQUEUE --queue-num 0");

    syslog(LOG_NOTICE, "opening library handle");
    h = nfq_open();

    if (!h) {
        syslog(LOG_NOTICE, "error during nfq_open()");
        exit(1);
    }

    syslog(LOG_NOTICE, "unbinding existing nf_queue handler for AF_INET (if any)");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        syslog(LOG_NOTICE, "error during nfq_unbind_pf()");
        exit(1);
    }

    syslog(LOG_NOTICE, "binding nfnetlink_queue as nf_queue handler for AF_INET");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        syslog(LOG_NOTICE, "error during nfq_bind_pf()");
        exit(1);
    }

    syslog(LOG_NOTICE, "binding this socket to queue '0'");
    qh = nfq_create_queue(h, 0, &hooking_, NULL);
    if (!qh) {
        syslog(LOG_NOTICE, "error during nfq_create_queue()");
        exit(1);
    }

    syslog(LOG_NOTICE, "setting copy_packet mode");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        syslog(LOG_NOTICE, "can't set packet_copy mode");
        exit(1);
    }

    go_background_service();

    fd = nfq_fd(h);
    for (;;) {
        if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {

            nfq_handle_packet(h, buf, rv);
            continue;
        }
        if (rv < 0 && errno == ENOBUFS) {
            syslog(LOG_NOTICE, "losing packets!");
            continue;
        }
        break;
    }

    syslog(LOG_NOTICE, "unbinding from queue 0");
    nfq_destroy_queue(qh);

#ifdef INSANE
    /* normally, applications SHOULD NOT issue this command, since
     * it detaches other programs/sockets from AF_INET, too ! */
    syslog(LOG_NOTICE,"unbinding from AF_INET");
    nfq_unbind_pf(h, AF_INET);
#endif

    syslog(LOG_NOTICE, "closing library handle");
    nfq_close(h);
    exit(0);

}
