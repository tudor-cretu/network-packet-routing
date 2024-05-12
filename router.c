#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <arpa/inet.h>
#include <stdint.h> 
#include <stdlib.h>
#include <stdio.h>
#include <string.h>


/* Routing table */
struct route_table_entry *rtable;
int rtable_len;

/* Mac table */
struct arp_table_entry *arp_table;
int arp_table_len;


/* Compare 2 route entries, used for sorting the routing talbe with qsort */
int compare_route(const void *a, const void *b) {
    const struct route_table_entry *routeA = (const struct route_table_entry *)a;
    const struct route_table_entry *routeB = (const struct route_table_entry *)b;

	/* Comparing prefixes and masks to determine order */
    if (ntohl(routeA->prefix) > ntohl(routeB->prefix)) 
		return 1;
	if (ntohl(routeA->prefix) == ntohl(routeB->prefix) 
	&& ntohl(routeA->mask) > ntohl(routeB->mask)) 
		return 1;
    return -1;
}

/* Initialize the routing and ARP tables */
void setup(char *rtable_path, char *arp_table_path) {
    rtable = malloc(sizeof(struct route_table_entry) * 100000); 
    DIE(rtable == NULL, "rtable allocation failed");

    arp_table = malloc(sizeof(struct arp_table_entry) * 6);
    DIE(arp_table == NULL, "arp_table allocation failed");

    rtable_len = read_rtable(rtable_path, rtable);
    qsort(rtable, rtable_len, sizeof(struct route_table_entry), compare_route);

    arp_table_len = parse_arp_table(arp_table_path, arp_table);
}


/* Finds the best route for a given IP address */
struct route_table_entry *get_best_route(uint32_t ip_dest) {
    int low = 0, high = rtable_len - 1;
    struct route_table_entry *best_route = NULL;

	/* Binary search to find the best matching route */
    while (low <= high) {
        int mid = low + (high - low) / 2;
        if ((ip_dest & rtable[mid].mask) == rtable[mid].prefix 
		&& (best_route == NULL || rtable[mid].mask > best_route->mask)) {
            best_route = &rtable[mid];
        } 
		if (ntohl(ip_dest) > ntohl(rtable[mid].prefix)) {
            low = mid + 1;
        } else {
            high = mid - 1;
        }
    }

    return best_route;
}

/* Finds the ARP table entry for a given IP address */
struct arp_table_entry *get_arp_entry(uint32_t given_ip) {
	for (int i = 0; i < arp_table_len; ++i) {
		if (arp_table[i].ip == given_ip)
			return (arp_table + i);
	}
	return NULL;
}

/* Prepare ICMP payload */
static uint8_t *prepare_icmp_payload(struct iphdr *ip_hdr, size_t *icmp_payload_len) {
    *icmp_payload_len = sizeof(struct iphdr) + 8;
    uint8_t *icmp_payload = malloc(*icmp_payload_len);
    DIE(!icmp_payload, "Failed to allocate ICMP payload.\n");
    memcpy(icmp_payload, ip_hdr, *icmp_payload_len);
    return icmp_payload;
}

/* Adjust the IP header for the ICMP response */
static void adjust_ip_header_for_icmp(struct iphdr *ip_hdr, uint32_t interface, size_t icmp_payload_len) {
    uint32_t router_ip = inet_addr(get_interface_ip(interface));
    ip_hdr->daddr = ip_hdr->saddr;
    ip_hdr->saddr = router_ip;
    ip_hdr->ttl = MAX_TTL;
    ip_hdr->protocol = IPPROTO_ICMP;
    ip_hdr->tot_len = htons(sizeof(struct icmphdr) + icmp_payload_len);
    ip_hdr->check = 0;
    ip_hdr->check = checksum((uint16_t *)ip_hdr, sizeof(struct iphdr));
}

/* Adjust the Ethernet header for the ICMP response */
static void adjust_ethernet_header_for_icmp(struct ether_header *eth_hdr, uint32_t interface) {
    uint8_t mac[ETH_ALEN];
    get_interface_mac(interface, mac);
    memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, ETH_ALEN);
    memcpy(eth_hdr->ether_shost, mac, ETH_ALEN);
}

/* Construct and send ICMP packet */
static void construct_and_send_icmp(struct ether_header *eth_hdr, struct icmphdr *icmp_hdr, uint8_t *icmp_payload, size_t icmp_payload_len, uint32_t interface) {
    memcpy((uint8_t *)icmp_hdr + sizeof(struct icmphdr), icmp_payload, icmp_payload_len);
    icmp_hdr->checksum = checksum((uint16_t *)icmp_hdr, sizeof(struct icmphdr) + icmp_payload_len);
    size_t packet_size = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr) + icmp_payload_len;
    send_to_link(interface, (char *)eth_hdr, packet_size);
}

static void send_icmp_response(struct ether_header *eth_hdr, uint8_t icmp_type, uint32_t interface) {
    struct iphdr *ip_hdr = (struct iphdr *)((uint8_t *)eth_hdr + sizeof(struct ether_header));
    struct icmphdr *icmp_hdr = (struct icmphdr *)((uint8_t *)ip_hdr + sizeof(struct iphdr));

    // Prepare ICMP header
    icmp_hdr->type = icmp_type;
    icmp_hdr->code = 0;
    icmp_hdr->checksum = 0;

    size_t icmp_payload_len;
    uint8_t *icmp_payload = prepare_icmp_payload(ip_hdr, &icmp_payload_len);
    adjust_ip_header_for_icmp(ip_hdr, interface, icmp_payload_len);
    adjust_ethernet_header_for_icmp(eth_hdr, interface);
    construct_and_send_icmp(eth_hdr, icmp_hdr, icmp_payload, icmp_payload_len, interface);

    free(icmp_payload); // Free allocated ICMP payload memory
}

/* Clean up allocated memory for routing and ARP tables */
void cleanup() {
    free(rtable);
    free(arp_table);
}


int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	/* Initialization and setup */
	init(argc - 2, argv + 2);
	setup(argv[1], "arp_table.txt");


	while (1) {

		int interface;
		size_t len;

		/* Recieve packets from any interface */
		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) buf;
		struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));

		/* Determine the best route for the packet */
		struct route_table_entry *best_route = get_best_route(ip_hdr->daddr);

		uint32_t int_ip;

		inet_pton(AF_INET, get_interface_ip(interface), &int_ip);

		/* Handle packets intended for the router itself */
		if (ip_hdr->daddr == int_ip) {
			send_icmp_response(eth_hdr, 0, interface);
			continue;
		}

		/* Check if we got an IPv4 packets */
		if (eth_hdr->ether_type != ntohs(ETHERTYPE_IP)) {
			printf("Ignored non-IPv4 packet\n");
			continue;
		}

		/* Verify IP checksum */
		if (checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)) != 0) {
			printf("Checksum gone wrong\n");
			fflush(stdout);
			continue;
		}

		/* Decrement TTL and update checksum */
		int old_ttl = ip_hdr->ttl;
		int old_check = ip_hdr->check;
		ip_hdr->ttl--;
		ip_hdr->check = ~(~old_check +  ~((uint16_t)old_ttl) + (uint16_t)ip_hdr->ttl) - 1;

		/* ICMP Time Exceeded if TTL expired */
		if (ip_hdr->ttl < 1) {
			printf("Packet gone wrong beacuse of time\n");
			send_icmp_response(eth_hdr, ICMP_TIME_EXCEEDED, interface);
			continue;
		}

		if (best_route == NULL) {
			send_icmp_response(eth_hdr, ICMP_DEST_UNREACH, interface); 
			continue;
		}

		/* Find the corresponding ARP entry for the next-hop IP */
		struct arp_table_entry *arp_entry = get_arp_entry(best_route->next_hop);
		if (arp_entry == NULL) {
			printf("No mac entry found\n");
			fflush(stdout);
			continue;
		}

		/* Update Ethernet header with the destination and source MAC address */
		for (int i = 0; i < 6; ++i) {
			eth_hdr->ether_dhost[i] = arp_entry->mac[i];
		}
		uint8_t mac[6];
		get_interface_mac(best_route->interface, mac);

		for (int i = 0; i < 6; ++i) {
			eth_hdr->ether_shost[i] = mac[i];
		}

		/* Forward the packet to the best route's interface */
		send_to_link(best_route->interface, buf, len);
	}

	cleanup();
}
