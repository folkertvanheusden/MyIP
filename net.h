#include <optional>
#include <stdint.h>
#include <string>

#include "any_addr.h"


void swap_mac(uint8_t *a, uint8_t *b);
void swap_ipv4(uint8_t *a, uint8_t *b);

int create_datagram_socket(const int port);

std::optional<std::string> get_host_as_text(struct sockaddr *const a);

bool check_subnet(const any_addr & addr, const any_addr & network, const int cidr);
bool check_subnet(const any_addr & addr, const any_addr & network, const uint8_t netmask[4]);

any_addr gen_opponent_mac(const any_addr & my_mac);
