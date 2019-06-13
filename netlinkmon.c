#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <libmnl/libmnl.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <time.h>
#include <stdlib.h>
#include <net/if.h>


#define INET6_ADDRLEN (16)
#define GUA_MASK (0xe0)
#define GUA_VALUE (0x20)


typedef uint8_t inet6_addr[INET6_ADDRLEN];


struct addrinfo {
    inet6_addr address;
};


bool prefix_known;
inet6_addr known_prefix;
uint8_t known_prefix_len;
char **call_base;
int call_first_iparg;


bool is_global_unicast(const inet6_addr addr) {
    return (addr[0] & GUA_MASK) == GUA_VALUE;
}


void mask_address(const inet6_addr addr, const uint8_t prefix_len, inet6_addr out) {
    memcpy(&out[0], &addr[0], INET6_ADDRLEN);
    for (uint8_t curr_bit = prefix_len;
         curr_bit < 128;
         ++curr_bit)
    {
        const uint8_t curr_byte = curr_bit / 8;
        const uint8_t curr_mask = 1 << (7 - (curr_bit % 8));
        out[curr_byte] &= ~curr_mask;
    }
}


int handle_attr(const struct nlattr *attr, void *_data) {
    struct addrinfo *data = (struct addrinfo *)_data;
    const uint16_t type = mnl_attr_get_type(attr);
    if (type == IFA_ADDRESS) {
        memcpy(data->address, mnl_attr_get_payload(attr),
               sizeof(data->address));
        return MNL_CB_STOP;
    }
    return MNL_CB_OK;
}


const char *inet_ntop_nr(const inet6_addr addr) {
    static char buf[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, (char*)&addr[0], &buf[0], sizeof(buf));
    return &buf[0];
}


void handle_prefix_changed(const inet6_addr old_prefix,
                           const uint8_t old_prefixlen,
                           const inet6_addr new_prefix,
                           const uint8_t new_prefixlen)
{
    static time_t last_invoke = 0;
    /* char buf[INET6_ADDRSTRLEN]; */
    /* inet_ntop(AF_INET6, &old_prefix[0], &buf[0], INET6_ADDRSTRLEN); */
    /* printf("old_prefix = %s/%d, ", buf, old_prefixlen); */
    /* inet_ntop(AF_INET6, &new_prefix[0], &buf[0], INET6_ADDRSTRLEN); */
    /* printf("new_prefix = %s/%d\n", buf, new_prefixlen); */

    time_t curr_time = time(NULL);
    if (curr_time - last_invoke < 1800) {
        fprintf(stderr, "throttling prefix change invocation\n");
        return;
    }
    last_invoke = curr_time;

    int newpid = fork();
    if (newpid == 0) {
        sprintf(call_base[call_first_iparg],
                "%s/%d",
                inet_ntop_nr(old_prefix),
                old_prefixlen);
        sprintf(call_base[call_first_iparg+1],
                "%s/%d",
                inet_ntop_nr(new_prefix),
                new_prefixlen);
        execv(call_base[0], call_base);
        perror("execv");
    } else if (newpid < 0) {
        perror("fork");
    }
    fprintf(stderr, "prefix change detected\n");
}


int process_message(struct mnl_socket *sock, const unsigned ifindex) {
    uint8_t buf[MNL_SOCKET_BUFFER_SIZE];
    int remaining = mnl_socket_recvfrom(sock, &buf[0],
                                        MNL_SOCKET_BUFFER_SIZE);
    if (remaining < 0) {
        perror("mnl_socket_recvfrom");
        return 1;
    }

    /* printf("received message: %zd bytes\n", remaining); */

    const struct nlmsghdr *hdr = (const struct nlmsghdr*)&buf[0];
    while (mnl_nlmsg_ok(hdr, remaining)) {
        /* printf("type: %d\n", hdr->nlmsg_type); */
        if (hdr->nlmsg_type == RTM_NEWADDR || hdr->nlmsg_type == RTM_GETADDR) {
            const struct ifaddrmsg *msg = (const struct ifaddrmsg*)mnl_nlmsg_get_payload(hdr);
            if (msg->ifa_family != AF_INET6) {
                hdr = mnl_nlmsg_next(hdr, &remaining);
                continue;
            }

            if (msg->ifa_index != ifindex) {
                hdr = mnl_nlmsg_next(hdr, &remaining);
                continue;
            }

            struct addrinfo info;
            mnl_attr_parse(hdr, sizeof(*msg), handle_attr, &info);

            inet6_addr prefix;
            mask_address(info.address, msg->ifa_prefixlen, prefix);

            if (is_global_unicast(prefix) && msg->ifa_prefixlen != 128) {
                if (prefix_known) {
                    if (known_prefix_len != msg->ifa_prefixlen ||
                        memcmp(&known_prefix[0], &prefix[0], sizeof(prefix)) != 0)
                    {
                        if (hdr->nlmsg_type == RTM_GETADDR) {
                            fprintf(stderr, "error: multiple prefixes found\n");
                            return 1;
                        }

                        handle_prefix_changed(known_prefix, known_prefix_len,
                                              prefix, msg->ifa_prefixlen);
                    }
                } /* else {
                    handle_prefix_changed(known_prefix, known_prefix_len,
                                          prefix, msg->ifa_prefixlen);
                } */

                memcpy(&known_prefix[0], &prefix[0], sizeof(prefix));
                known_prefix_len = msg->ifa_prefixlen;
                fprintf(stderr,
                        "detected prefix: %s/%d\n",
                        inet_ntop_nr(prefix),
                        msg->ifa_prefixlen);
                prefix_known = true;
            }
        }

        hdr = mnl_nlmsg_next(hdr, &remaining);
    }


    return 0;
}


int main(int argc, char **argv) {
    (void)argc;
    (void)argv;
    int ret = 0;

    memset(&known_prefix[0], 0, sizeof(known_prefix));
    prefix_known = false;
    known_prefix_len = 0;

    if (argc < 4 || strcmp(argv[2], "--") != 0) {
        fprintf(stderr, "usage: %s INTERFACE -- COMMAND [ARGV] ...\n", argv[0]);
        return 1;
    }

    const char *ifname = argv[1];
    const unsigned ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        perror("if_nametoindex");
        return 1;
    }

    int nargs = argc - 3 + 2;
    call_base = malloc(sizeof(char*) * (nargs+1));
    for (int i = 3; i < argc; i++) {
        int len = strlen(argv[i]);
        char *dest = call_base[i - 3] = malloc(len+1);
        memcpy(&dest[0], &argv[i][0], len+1);
    }
    call_first_iparg = nargs-2;
    call_base[nargs-2] = malloc((INET6_ADDRSTRLEN + 4));
    call_base[nargs-1] = malloc((INET6_ADDRSTRLEN + 4));
    call_base[nargs] = NULL;

    struct mnl_socket *sock = mnl_socket_open(NETLINK_ROUTE);
    if (!sock) {
        perror("mnl_socket_open");
        ret = 1;
        goto cleanup;
    }

    if (mnl_socket_bind(sock, RTMGRP_IPV6_IFADDR, 0)) {
        perror("mnl_socket_bind");
        ret = 1;
        goto cleanup;
    }

    uint64_t seq;

    {
        char reqbuf[MNL_SOCKET_BUFFER_SIZE];
        memset(&reqbuf[0], 0, sizeof(reqbuf));
        struct nlmsghdr *hdr = mnl_nlmsg_put_header(reqbuf);
        hdr->nlmsg_type = RTM_GETADDR;
        hdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
        hdr->nlmsg_seq = seq = time(NULL);
        struct ifaddrmsg *rt = mnl_nlmsg_put_extra_header(
            hdr,
            sizeof(struct rtgenmsg));
        rt->ifa_family = AF_INET6;
        if (mnl_socket_sendto(sock, hdr, hdr->nlmsg_len) < 0) {
            perror("mnl_socket_sendto");
            ret = 1;
            goto cleanup;
        }
    }

    while (1) {
        if (process_message(sock, ifindex) != 0) {
            ret = 2;
            goto cleanup;
        }
    }

cleanup:
    mnl_socket_close(sock);
    return ret;
}
