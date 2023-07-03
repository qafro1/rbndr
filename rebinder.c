#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <time.h>
#include <arpa/inet.h>

#define __packed __attribute__((packed))

struct qname {
    uint8_t len;
    uint8_t label[8];
} __packed;

struct __packed root {
    struct __packed {
        uint8_t len;        // 5
        uint8_t data[5];    // 'r' 'b' 'n' 'd' 'r'
    } domain;
    struct __packed {
        uint8_t len;        // 2
        uint8_t data[2];    // 'u' 's'
    } tld;
    uint8_t root;           // 0
};

static const struct root expectedDomain = {
    .domain = { 5, { 'r', 'b', 'n', 'd', 'r' } },
    .tld = { 2, { 'u', 's' } },
    .root = 0,
};

struct __packed header {
    uint16_t id;
    struct __packed {
        unsigned  rd      : 1;
        unsigned  tc      : 1;
        unsigned  aa      : 1;
        unsigned  opcode  : 4;
        unsigned  qr      : 1;
        unsigned  rcode   : 4;
        unsigned  ra      : 1;
        unsigned  ad      : 1;
        unsigned  z       : 2;
    } flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
    struct __packed {
        struct qname primary;
        struct qname secondary;
        struct root  domain;
    } labels;
    uint16_t qtype;
    uint16_t qclass;
    struct __packed {
        uint8_t flag;
        uint8_t offset;
    } ptr;
    uint16_t type;
    uint16_t class;
    uint32_t ttl;
    uint16_t rdlength;
    struct in_addr rdata;
} __packed;

bool parse_ip4_label(struct in_addr *out, const uint8_t label[8])
{
    char ip4addr[] = {
        '0', 'x', label[0], label[1],
        label[2], label[3], label[4],
        label[5], label[6], label[7],
        0,
    };

    // Check for invalid characters, lowercase hexadecimal digits only.
    if (strspn(ip4addr + 2, "0123456789abcdef") != 8)
        return false;

    return inet_aton(ip4addr, out) != 0;
}

int main(int argc, char **argv)
{
    struct servent *domain;
    struct passwd *nobody;
    struct sockaddr_in server;
    struct sockaddr_in address;
    struct header reply;
    struct header query;
    socklen_t addrlen;
    time_t querytime;
    int sockfd;

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        err(EXIT_FAILURE, "failed to create socket");
    }

    if ((domain = getservbyname("domain", "udp")) == NULL) {
        errx(EXIT_FAILURE, "unable to lookup domain properties");
    }

    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = domain->s_port;
    addrlen = sizeof(address);
    nobody = getpwnam("nobody");

    if (nobody == NULL) {
        errx(EXIT_FAILURE, "unable to lookup unprivileged user");
    }

    if (bind(sockfd, (struct sockaddr *)&server, sizeof(server)) != 0) {
        errx(EXIT_FAILURE, "unable to bind server");
    }

    if (chdir("/var/empty") != 0 || chroot(".") != 0) {
        errx(EXIT_FAILURE, "unable to change root directory");
    }

    if (setgid(nobody->pw_gid) != 0 || setuid(nobody->pw_uid) != 0) {
        errx(EXIT_FAILURE, "unable to change to unprivileged user");
    }

    while (true) {
        char clientaddr[INET_ADDRSTRLEN];

        memset(&query, 0, sizeof query);
        memset(&reply, 0, sizeof reply);

        if (recvfrom(sockfd, &query, sizeof query, 0, (struct sockaddr *)&address, &addrlen) < 0) {
            warn("error receiving query packet from network");
            continue;
        }

        time(&querytime);

        fprintf(stdout, "%s\t%s", inet_ntop(AF_INET, &address.sin_addr, clientaddr, sizeof(clientaddr)), ctime(&querytime));

        memcpy(&reply.labels, &query.labels, sizeof reply.labels);

        reply.id = query.id;
        reply.flags.qr = true;
        reply.flags.aa = true;
        reply.ptr.flag = NS_CMPRSFLGS;
        reply.ptr.offset = offsetof(struct header, labels);
        reply.type = htons(ns_t_a);
        reply.class = htons(ns_c_in);
        reply.ttl = htonl(1);
        reply.rdlength = htons(sizeof reply.rdata);
        reply.qtype = query.qtype;
        reply.qclass = query.qclass;
        reply.qdcount = query.qdcount;
        reply.ancount = query.qdcount;

        if (query.qdcount != htons(1)) {
            warnx("more than one question per query is not supported (%u queries)", ntohs(query.qdcount));
            reply.flags.rcode = ns_r_notimpl;
            goto error;
        }

        if (query.labels.primary.len != 8) {
            warnx("query with %u byte primary label (must be 8)", query.labels.primary.len);
            reply.flags.rcode = ns_r_nxdomain;
            goto error;
        }

        if (query.labels.secondary.len != 8) {
            warnx("query with %u byte secondary label (must be 8)", query.labels.secondary.len);
            reply.flags.rcode = ns_r_nxdomain;
            goto error;
        }

        if (memcmp(query.labels.primary.label, query.labels.secondary.label, 8) == 0) {
            warnx("query with matching labels disallowed to discourage abuse");
            reply.flags.rcode = ns_r_refused;
            goto error;
        }

        if (memcmp(&query.labels.domain, &expectedDomain, sizeof expectedDomain) != 0) {
            warnx("query for unrecognized domain (must be .rbndr.us)");
            reply.flags.rcode = ns_r_nxdomain;
            goto error;
        }

        if (query.qtype != htons(ns_t_a)) {
            warnx("unsupported qtype in question, returning no answers (qtype %u)", ntohs(query.qtype));
            goto error;
        }

        if (!parse_ip4_label(&reply.rdata, (query.id & 1) ? query.labels.primary.label : query.labels.secondary.label)) {
            warnx("query with invalid IP4 address label");
            reply.flags.rcode = ns_r_nxdomain;
            goto error;
        }

        if (sendto(sockfd, &reply, sizeof reply, 0, (struct sockaddr *)&address, addrlen) < 0) {
            warn("error sending reply packet to network");
            continue;
        }

        continue;

    error:
        reply.ancount = 0;
        reply.nscount = 0;
        reply.arcount = 0;

        if (sendto(sockfd, &reply, sizeof reply, 0, (struct sockaddr *)&address, addrlen) < 0) {
            warn("error sending error reply packet to network");
            continue;
        }
    }

    return EXIT_SUCCESS;
}

