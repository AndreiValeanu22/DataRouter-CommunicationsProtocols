#include <string.h>
#include <arpa/inet.h>
#include <net/if.h>

#include "queue.h"
#include "lib.h"
#include "protocols.h"

struct packet {
	int len;
	char buf[MAX_PACKET_LEN];
} __attribute__((packed));

int min(int x, int y) {
	return (x < y) ? x : y;
}

struct route_table_entry *binary_search(uint32_t ip, int left, int right, struct route_table_entry *route_table) {
	if (left > right) {
		return NULL;
	}
	
	int mid = (left + right) / 2;
	uint32_t masked_ip = ip & route_table[mid].mask;
	if (route_table[mid].prefix == masked_ip) {
		struct route_table_entry *best_match = &route_table[mid];
		return binary_search(ip, mid + 1, right, route_table) ?: best_match;
	} else {
		if (ntohl(route_table[mid].prefix) < ntohl(ip)) {
			return binary_search(ip, mid + 1, right, route_table);
		} else {
			return binary_search(ip, left, mid - 1, route_table);
		}
	}
}

int compare_fn(const void *a, const void *b) {
	const struct route_table_entry *entry_a = (const struct route_table_entry *) a;
	uint32_t prefix_a = ntohl(entry_a->prefix);
	uint32_t mask_a = ntohl(entry_a->mask);
	
	const struct route_table_entry *entry_b = (const struct route_table_entry *) b;
	uint32_t prefix_b = ntohl(entry_b->prefix);
	uint32_t mask_b = ntohl(entry_b->mask);
	
	int prefix_diff = prefix_a - prefix_b;
	if (prefix_diff != 0) {
		return prefix_diff;
	}
	
	return mask_a - mask_b;
}

void handle_packet(char *buf, size_t len, int interface, int code) {
	char buf2[MAX_PACKET_LEN] = {0};
	
	struct icmphdr *icmp_hdr = (struct icmphdr *) (buf + sizeof(struct ether_header) + sizeof(struct iphdr));
	struct icmphdr *icmp_hdr2 = (struct icmphdr *) (buf2 + sizeof(struct ether_header) +
	                                                sizeof(struct iphdr));
	
	if (code == 0 && icmp_hdr->type != 8) {
		return;
	}
	
	struct ether_header *eth_hdr = (struct ether_header *) buf;
	struct ether_header *eth_hdr2 = (struct ether_header *) buf2;
	eth_hdr2->ether_type = htons(0x0800);
	memcpy(eth_hdr2->ether_dhost, eth_hdr->ether_shost, 6);
	memcpy(eth_hdr2->ether_shost, eth_hdr->ether_dhost, 6);
	
	int len2 = code == 0 ? len - sizeof(struct ether_header) - sizeof(struct iphdr) - sizeof(struct icmphdr)
	                     : min(len - sizeof(struct ether_header), sizeof(struct iphdr) + 64);
	
	struct iphdr *ip_hdr = (struct iphdr *) (buf + sizeof(struct ether_header));
	struct iphdr *ip_hdr2 = (struct iphdr *) (buf2 + sizeof(struct ether_header));
	ip_hdr2->daddr = ip_hdr->saddr;
	ip_hdr2->saddr = htonl(inet_pton(AF_INET, get_interface_ip(interface), &ip_hdr2->saddr));
	ip_hdr2->version = 4;
	ip_hdr2->tos = 0;
	ip_hdr2->frag_off = 0;
	ip_hdr2->ttl = 64;
	ip_hdr2->id = htons(1);
	ip_hdr2->check = 0;
	ip_hdr2->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr) + len2);
	ip_hdr2->ihl = 5;
	ip_hdr2->protocol = 1;
	ip_hdr2->check = htons(checksum((uint16_t *) ip_hdr2, sizeof(struct iphdr)));
	
	icmp_hdr2->type = code;
	icmp_hdr2->code = 0;
	if (code == 0) {
		icmp_hdr2->un.echo.id = icmp_hdr->un.echo.id;
		icmp_hdr2->un.echo.sequence = icmp_hdr->un.echo.sequence;
	}
	icmp_hdr2->checksum = 0;
	icmp_hdr2->checksum = htons(checksum((uint16_t *) icmp_hdr2, sizeof(struct icmphdr) + len2));
	
	memcpy(buf2 + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr),
	       buf + sizeof(struct ether_header) + sizeof(struct iphdr) + (code == 0 ? sizeof(struct icmphdr) : 0),
	       len2);
	
	send_to_link(interface, buf2, sizeof(struct ether_header) + ntohs(ip_hdr2->tot_len));
}

int main(int argc, char *argv[]) {
	char buf[MAX_PACKET_LEN];
	
	// Do not modify this line
	init(argc - 2, argv + 2);
	
	struct route_table_entry *rtable = (struct route_table_entry *) calloc(100000,
	                                                                       sizeof(struct route_table_entry));
	int rtable_size = read_rtable(argv[1], rtable);
	
	struct arp_table_entry *arp_table = (struct arp_table_entry *) calloc(10, sizeof(struct arp_table_entry));
	int arp_table_size = 10;
	int current_arp_entry = 0;
	
	qsort(rtable, rtable_size, sizeof(struct route_table_entry), compare_fn);
	
	queue q = queue_create();
	
	while (1) {
		int interface;
		size_t len;
		
		interface = recv_from_any_link(buf, &len);
		
		struct ether_header *eth_hdr = (struct ether_header *) buf;
		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */
		
		if (ntohs(eth_hdr->ether_type) == 0x0800) {
			struct iphdr *ip_hdr = (struct iphdr *) (buf + sizeof(struct ether_header));
			
			if (ntohs(checksum((uint16_t *) ip_hdr, sizeof(struct iphdr)))) {
				continue;
			}
			
			if (ip_hdr->ttl <= 1) {
				handle_packet(buf, len, interface, 11);
				continue;
			} else {
				ip_hdr->ttl--;
			}
			
			if (ip_hdr->daddr == inet_addr(get_interface_ip(interface))) {
				handle_packet(buf, len, interface, 0);
				continue;
			}
			
			struct route_table_entry *best_rtable_entry = binary_search(ip_hdr->daddr, 0, rtable_size, rtable);
			if (best_rtable_entry == NULL) {
				handle_packet(buf, len, interface, 3);
				continue;
			}
			
			ip_hdr->check = ~(~ip_hdr->check + ~((uint16_t) (ip_hdr->ttl + 1)) + (uint16_t) (ip_hdr->ttl)) - 1;
			
			uint8_t *mac = NULL;
			for (int i = 0; i < arp_table_size; i++) {
				if (arp_table[i].ip == best_rtable_entry->next_hop) {
					mac = arp_table[i].mac;
					break;
				}
			}
			
			if (mac == NULL) {
				struct packet *packet = (struct packet *) malloc(sizeof(struct packet));
				memcpy(packet->buf, buf, len);
				packet->len = len;
				queue_enq(q, packet);
				
				struct arp_header arp_hdr;
				arp_hdr.ptype = htons(0x0800);
				arp_hdr.plen = 4;
				arp_hdr.hlen = 6;
				eth_hdr->ether_type = htons(0x0806);
				arp_hdr.htype = htons(1);
				arp_hdr.op = htons(1);
				
				get_interface_mac(best_rtable_entry->interface, eth_hdr->ether_shost);
				get_interface_mac(best_rtable_entry->interface, arp_hdr.sha);
				arp_hdr.spa = inet_addr(get_interface_ip(best_rtable_entry->interface));
				
				unsigned char broadcast_mac[6];
				for (int i = 0; i < 6; i++) {
					broadcast_mac[i] = 0xff;
				}
				memcpy(eth_hdr->ether_dhost, broadcast_mac, sizeof(eth_hdr->ether_dhost));
				memcpy(arp_hdr.tha, broadcast_mac, sizeof(broadcast_mac));
				arp_hdr.tpa = best_rtable_entry->next_hop;
				
				char buf2[MAX_PACKET_LEN];
				memset(buf2, 0, MAX_PACKET_LEN);
				memcpy(buf2, eth_hdr, sizeof(struct ether_header));
				memcpy(buf2 + sizeof(struct ether_header), &arp_hdr, sizeof(struct arp_header));
				
				send_to_link(best_rtable_entry->interface, buf2,
				             sizeof(struct ether_header) + sizeof(struct arp_header));
				continue;
			}
			
			memcpy(eth_hdr->ether_dhost, mac, sizeof(eth_hdr->ether_dhost));
			get_interface_mac(best_rtable_entry->interface, eth_hdr->ether_shost);
			send_to_link(best_rtable_entry->interface, buf, len);
		}
		
		if (ntohs(eth_hdr->ether_type) == 0x0806) {
			struct arp_header *arp_hdr = (struct arp_header *) (buf + sizeof(struct ether_header));
			
			if (ntohs(arp_hdr->op) == 1) {
				uint8_t router_mac[6];
				get_interface_mac(interface, router_mac);
				
				for (int i = 0; i < 6; i++) {
					arp_hdr->tha[i] = arp_hdr->sha[i];
					eth_hdr->ether_dhost[i] = arp_hdr->sha[i];
					arp_hdr->sha[i] = router_mac[i];
					eth_hdr->ether_shost[i] = router_mac[i];
				}
				
				unsigned int temp_spa = arp_hdr->spa;
				unsigned int temp_tpa = arp_hdr->tpa;
				arp_hdr->spa = temp_tpa;
				arp_hdr->tpa = temp_spa;
				arp_hdr->op = htons(2);
				
				send_to_link(interface, buf, len);
				continue;
			}
			
			if (ntohs(arp_hdr->op) == 2) {
				if (inet_addr(get_interface_ip(interface)) != arp_hdr->tpa) {
					struct route_table_entry *best_rtable_entry = binary_search(arp_hdr->tpa, 0, rtable_size, rtable);
					if (best_rtable_entry == NULL) {
						continue;
					}
					send_to_link(best_rtable_entry->interface, buf, len);
					continue;
				}
				
				uint8_t *mac = NULL;
				for (int i = 0; i < current_arp_entry + 1; i++) {
					if (arp_table[i].ip == arp_hdr->spa) {
						mac = arp_table[i].mac;
						break;
					}
				}
				
				if (mac == NULL) {
					memcpy(arp_table[current_arp_entry].mac, arp_hdr->sha, sizeof(arp_table[current_arp_entry].mac));
					arp_table[current_arp_entry].ip = arp_hdr->spa;
					current_arp_entry = current_arp_entry + 1;
				}
				
				if (current_arp_entry == arp_table_size) {
					arp_table = (struct arp_table_entry *) realloc(arp_table,
					                                               2 * arp_table_size * sizeof(struct arp_table_entry));
					arp_table_size = arp_table_size * 2;
				}
				
				while (!queue_empty(q)) {
					struct packet *packet = (struct packet *) queue_deq(q);
					struct route_table_entry *best_rtable_entry = binary_search(
							((struct iphdr *) (packet->buf + sizeof(struct ether_header)))->daddr, 0, rtable_size, rtable);
					
					mac = NULL;
					for (int i = 0; i < current_arp_entry + 1; i++) {
						if (arp_table[i].ip == best_rtable_entry->next_hop) {
							mac = arp_table[i].mac;
							break;
						}
					}
					
					if (mac == NULL) {
						queue_enq(q, packet);
						continue;
					}
					
					memcpy(((struct ether_header *) packet->buf)->ether_dhost, mac, sizeof(eth_hdr->ether_dhost));
					send_to_link(best_rtable_entry->interface, packet->buf, packet->len);
					free(packet);
				}
			}
		}
	}
}