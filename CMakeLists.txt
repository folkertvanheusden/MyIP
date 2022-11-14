# (C) 2020-2022 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
cmake_minimum_required(VERSION 3.9.4)

project(myip VERSION 6.5)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

add_definitions("-D_FILE_OFFSET_BITS=64")

set(CMAKE_BUILD_TYPE Debug)

add_compile_options(-Wall -pedantic)

add_executable(myip
	address_cache.cpp
	any_addr.cpp
	arp.cpp
	dns.cpp
	fifo-stats.cpp
	font.cpp
	hash.cpp
	http.cpp
	icmp.cpp
	icmp6.cpp
	ip_protocol.cpp
	ipv4.cpp
	ipv6.cpp
	lldp.cpp
	log.cpp
	main.cpp
	mdns.cpp
	mqtt.cpp
	ndp.cpp
	nrpe.cpp
	ntp.cpp
	packet.cpp
	phys.cpp
	phys_ethernet.cpp
	phys_ppp.cpp
	phys_slip.cpp
	protocol.cpp
	sip.cpp
	snmp.cpp
	snmp-data.cpp
	snmp-elem.cpp
	socks_proxy.cpp
	stats.cpp
	stats-utils.cpp
	str.cpp
	syslog.cpp
	tcp.cpp
	tcp_udp_fw.cpp
	time.cpp
	udp.cpp
	utils.cpp
	vnc.cpp
	)

add_executable(myiptop
	log.cpp
	myiptop.cpp
	stats-utils.cpp
	str.cpp
	time.cpp
	utils.cpp
	)

set(CMAKE_THREAD_PREFER_PTHREAD TRUE)
set(THREADS_PREFER_PTHREAD_FLAG TRUE)
find_package(Threads)
target_link_libraries(myip Threads::Threads)
target_link_libraries(myiptop Threads::Threads)

set(CMAKE_THREAD_PREFER_PTHREAD TRUE)
set(THREADS_PREFER_PTHREAD_FLAG TRUE)
find_package(Threads)
target_link_libraries(myip Threads::Threads)

target_link_libraries(myip -lrt)

include(FindPkgConfig)

pkg_check_modules(SNDFILE REQUIRED sndfile)
target_link_libraries(myip ${SNDFILE_LIBRARIES})
target_include_directories(myip PUBLIC ${SNDFILE_INCLUDE_DIRS})
target_compile_options(myip PUBLIC ${SNDFILE_CFLAGS_OTHER})

pkg_check_modules(SAMPLERATE REQUIRED samplerate)
target_link_libraries(myip ${SAMPLERATE_LIBRARIES})
target_include_directories(myip PUBLIC ${SAMPLERATE_INCLUDE_DIRS})
target_compile_options(myip PUBLIC ${SAMPLERATE_CFLAGS_OTHER})

pkg_check_modules(NCURSES REQUIRED ncurses)
target_link_libraries(myiptop ${NCURSES_LIBRARIES})
target_include_directories(myiptop PUBLIC ${NCURSES_INCLUDE_DIRS})
target_compile_options(myiptop PUBLIC ${NCURSES_CFLAGS_OTHER})

pkg_check_modules(SPEEX REQUIRED speex)
target_link_libraries(myip ${SPEEX_LIBRARIES})
target_include_directories(myip PUBLIC ${SPEEX_INCLUDE_DIRS})
target_compile_options(myip PUBLIC ${SPEEX_CFLAGS_OTHER})

pkg_check_modules(ZLIB REQUIRED zlib)
target_link_libraries(myip ${ZLIB_LIBRARIES})
target_include_directories(myip PUBLIC ${ZLIB_INCLUDE_DIRS})
target_compile_options(myip PUBLIC ${ZLIB_CFLAGS_OTHER})

find_package(OpenSSL REQUIRED)
target_include_directories(myip PUBLIC ${OPENSSL_INCLUDE_DIR})
target_link_libraries(myip OpenSSL::SSL OpenSSL::Crypto)
target_include_directories(myiptop PUBLIC ${OPENSSL_INCLUDE_DIR})
target_link_libraries(myiptop OpenSSL::SSL OpenSSL::Crypto)

pkg_check_modules(LIBCONFIG REQUIRED libconfig++)
target_link_libraries(myip ${LIBCONFIG_LIBRARIES})
target_include_directories(myip PUBLIC ${LIBCONFIG_INCLUDE_DIRS})
target_compile_options(myip PUBLIC ${LIBCONFIG_CFLAGS_OTHER})

target_link_libraries(myiptop -lrt -lz)
