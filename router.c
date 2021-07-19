#include <queue.h>

#include "skel.h"

struct route_table_entry * rtable;
long rtable_size;
struct arp_entry * arp_table;
int arp_table_len;
int arp_cur_ind = 0;

// comparator function used for qsort
// sort ascending by prefix, then by mask
int compare_function(const void * a,
    const void * b) {
    struct route_table_entry x = * (struct route_table_entry * ) a;
    struct route_table_entry y = * (struct route_table_entry * ) b;
    if (x.prefix > y.prefix) {
        return 1;
    } else if (x.prefix == y.prefix && x.mask > y.mask) {
        return -1;
    } else return -1;
}
// bonus ip_checksum
void change_checksum(struct iphdr * ip_hdr){
    uint16_t old, new;
    old = ip_hdr->protocol << 8 | ip_hdr->ttl;
    ip_hdr->ttl--;
    new = ip_hdr->protocol << 8 | ip_hdr->ttl;
    ip_hdr->check = ip_hdr->check - (~old) - new - 1;
}
// implemented during a lab
void parse_rtable(char * file) {
    FILE * input_file = fopen(file, "r");
    char line[128];

    if (input_file == NULL) {
        fprintf(stderr, "Cannot open file\n");
    }
    long ind = 0;
    while (fgets(line, 128, input_file)) {
        char my_prefix[20], my_next_hop[20], my_mask[20], my_interface[20];
        sscanf(line, "%s %s %s %s", my_prefix, my_next_hop, my_mask, my_interface);
        rtable[ind].prefix = inet_addr(my_prefix);
        rtable[ind].next_hop = inet_addr(my_next_hop);
        rtable[ind].mask = inet_addr(my_mask);
        rtable[ind].interface = atoi(my_interface);
        ++ind;
        if (ind == rtable_size) {
            rtable = realloc(rtable, sizeof(struct route_table_entry) * rtable_size * 2);
            rtable_size *= 2;
        }
    }
    rtable_size = ind;
    rtable = realloc(rtable, sizeof(struct route_table_entry) * rtable_size);
    fclose(input_file);
}

// binary search to get the wanted rtable entry in O(logN)
struct route_table_entry * get_best_route(__u32 dest_ip) {
    int left = 0;
    int right = rtable_size;
    int mid;
    while (left <= right) {
        mid = left + (right - left) / 2;
        if (rtable[mid].prefix == (dest_ip & rtable[mid].mask)) {
            //search for the max mask
            int i = mid;
            while (rtable[i + 1].prefix == rtable[i].prefix) {
                i++;
            }
            return &rtable[i];
        }
        // look for best route in a different place
        if (rtable[mid].prefix < (dest_ip & rtable[mid].mask)) {
            left = mid + 1;
        } else {
            right = mid - 1;
        }
    }
    return NULL;
}
// find arp entry
struct arp_entry * get_arp_entry(__u32 ip) {
    for (int i = 0; i < arp_cur_ind; i++) {
        if (arp_table[i].ip == ip) {
            return &arp_table[i];
        }
    }
    return NULL;
}

int main(int argc, char * argv[]) {
    setvbuf(stdout, NULL, _IONBF, 0);
    packet m;
    int rc;
    // initial sizes of the arp and route table 
    rtable_size = 1000;
    arp_table_len = 100;
    // initiliazing the two tables
    rtable = (struct route_table_entry * ) malloc(sizeof(struct route_table_entry) * rtable_size);
    arp_table = (struct arp_entry * ) malloc(sizeof(struct arp_entry) * arp_table_len);
    parse_rtable(argv[1]);
    queue q;
    // sorting the route entries
    qsort(rtable, rtable_size, sizeof(struct route_table_entry), compare_function);
    q = queue_create();
    init(argc - 2, argv + 2);
    while (1) {
        rc = get_packet( & m);
        DIE(rc < 0, "get_message");
        // extracting ethernet header
        struct ether_header * eth_hdr = (struct ether_header * ) m.payload;
        struct in_addr test;
        // getting the interface ip -> to be used later
        inet_aton(get_interface_ip(m.interface), & test);
        // if the protovol is of type ARP
        if (eth_hdr -> ether_type == htons(ETHERTYPE_ARP)) {
            struct arp_header * arp_hdr = parse_arp(m.payload);
            // if arp is received, arp reply is sent
            if (arp_hdr -> op == htons(ARPOP_REQUEST)) {
                memcpy(eth_hdr -> ether_dhost, eth_hdr -> ether_shost, 6);
                get_interface_mac(m.interface, eth_hdr -> ether_shost);
                send_arp(arp_hdr -> spa, arp_hdr -> tpa, eth_hdr, m.interface, htons(ARPOP_REPLY));
                continue;
            } // if arp reply is received, update arp_table and send remaining packages  
            if (arp_hdr -> op == htons(ARPOP_REPLY)) {
                // check if entry already existst, if it does, don t add it again
                if (get_arp_entry(arp_hdr -> spa) == NULL) {
                    memcpy(arp_table[arp_cur_ind].mac, arp_hdr -> sha, 6);
                    arp_table[arp_cur_ind].ip = arp_hdr -> spa;
                    arp_cur_ind++;
                    // increase size if more entries have to be introduced
                    if (arp_cur_ind == arp_table_len) {
                        arp_table = realloc(arp_table, sizeof(struct arp_entry) * arp_table_len * 2);
                        arp_table_len *= 2;
                    }
                }
                // send all packages in the queue 
                while (!queue_empty(q)) {
                    // update destination mac 
                    packet * old = (packet * ) queue_deq(q);
                    struct ether_header * eth_hdr2 = (struct ether_header * ) old -> payload;
                    struct iphdr * ip_hdr = (struct iphdr * )(old -> payload + sizeof(struct ether_header));
                    struct route_table_entry * best_entry = get_best_route(ip_hdr -> daddr);
                    struct arp_entry * new_entry = get_arp_entry(best_entry -> next_hop);
                    //send packet to the destination
                    memcpy(eth_hdr2 -> ether_dhost, new_entry -> mac, 6);
                    send_packet(best_entry -> interface, old);
                    free(old);
                    continue;

                }
            }
        }
        // if protocol is of type IP
        if (eth_hdr -> ether_type == htons(ETHERTYPE_IP)) {
            struct iphdr * ip_hdr = (struct iphdr * )(m.payload + sizeof(struct ether_header));
            // if the checksum of the packet is wrong, drop it
            if (ip_checksum(ip_hdr, sizeof(struct iphdr)) != 0) {
                continue;
            }
            // if the ttl of the packet reaches 0, send an icmp error (TIME LIMIT EXCEEDED) back and drop the packet
            if (ip_hdr -> ttl <= 1) {
                send_icmp_error(ip_hdr -> saddr, ip_hdr -> daddr, eth_hdr -> ether_dhost, eth_hdr -> ether_shost, ICMP_TIME_EXCEEDED, 0, m.interface);
                continue;
            }
            // if an icmp echo request is sent to the router, send reply back
            if (ip_hdr -> protocol == IPPROTO_ICMP) {
                struct icmphdr * icmp_hdr = parse_icmp(m.payload);
                if (icmp_hdr -> type == ICMP_ECHO) {
                    if (ip_hdr -> daddr == test.s_addr) {
                        send_icmp(ip_hdr -> saddr, ip_hdr -> daddr, eth_hdr -> ether_dhost, eth_hdr -> ether_shost, ICMP_ECHOREPLY, 0, m.interface, icmp_hdr -> un.echo.id, icmp_hdr -> un.echo.sequence);
                        continue;
                    }
                }
            }

            // update packet fields
            change_checksum(ip_hdr);

            // find next hop
            struct route_table_entry * best_entry = get_best_route(ip_hdr -> daddr);
            //if no route table entry is found, send icmp error (DESTINATION UNKNOWN)
            if (best_entry == NULL) {
                send_icmp_error(ip_hdr -> saddr, ip_hdr -> daddr, eth_hdr -> ether_dhost, eth_hdr -> ether_shost, ICMP_DEST_UNREACH, ICMP_NET_UNREACH, m.interface);
                continue;
            } else {
                struct arp_entry * new_entry = get_arp_entry(best_entry -> next_hop);
                if (new_entry == NULL) {
                    // if no arp entry is found, add packet to the queue and send arp request
                    packet * old = (packet * ) malloc(sizeof(packet));
                    memcpy(old, & m, sizeof(packet));
                    queue_enq(q, old);
                    get_interface_mac(best_entry -> interface, eth_hdr -> ether_shost);
                    //  destination mac is broadcast adress
                    memset(eth_hdr -> ether_dhost, 0xff, 6 * sizeof(u_char));

                    struct in_addr aux;
                    inet_aton(get_interface_ip(best_entry -> interface), & aux);
                    send_arp(best_entry -> next_hop, aux.s_addr, eth_hdr, best_entry -> interface, htons(ARPOP_REQUEST));
                    continue;
                } else {
                    // send packet normally (no errors needed to solve)
                    get_interface_mac(best_entry -> interface, eth_hdr -> ether_shost);
                    memcpy(eth_hdr -> ether_dhost, new_entry -> mac, sizeof(uint8_t) * 6);
                    send_packet(best_entry -> interface, & m);
                    continue;
                }
            }
        }
    }
}