#include <optional>
#include <stdint.h>
#include <string>

void swap_mac(uint8_t *a, uint8_t *b);
void swap_ipv4(uint8_t *a, uint8_t *b);

int create_datagram_socket(const int port);

std::optional<std::string> get_host_as_text(struct sockaddr *const a);
