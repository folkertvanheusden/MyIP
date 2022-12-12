// (C) 2020-2022 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
#include <chrono>

#include "icmp.h"
#include "ipv4.h"
#include "log.h"
#include "time.h"
#include "utils.h"


icmp::icmp(stats *const s) : transport_layer(s, "icmp")
{
}

icmp::~icmp()
{
}
