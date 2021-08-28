# (C) 2020-2021 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0
cmake_minimum_required(VERSION 3.9.4)

project(myip VERSION 6.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

add_definitions("-D_FILE_OFFSET_BITS=64")

set(CMAKE_BUILD_TYPE Debug)

add_compile_options(-Wall -pedantic)

add_executable(myip
	any_addr.cpp
	arp.cpp
	font.cpp
	http.cpp
	icmp.cpp
	icmp6.cpp
	ip_protocol.cpp
	ipv4.cpp
	ipv6.cpp
	main.cpp
	ndp.cpp
	ntp.cpp
	packet.cpp
	phys.cpp
	protocol.cpp
	sip.cpp
	stats.cpp
	stats-utils.cpp
	tcp.cpp
	tcp_udp_fw.cpp
	udp.cpp
	utils.cpp
	vnc.cpp
	)

add_executable(myiptop
	myiptop.cpp
	stats-utils.cpp
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

target_link_libraries(myip -lrt -liniparser)

find_package(Curses REQUIRED)
include_directories(${CURSES_INCLUDE_DIR})
target_link_libraries(myiptop ${CURSES_LIBRARIES})

include(FindPkgConfig)

pkg_check_modules(SNDFILE REQUIRED sndfile)
target_link_libraries(myip ${SNDFILE_LIBRARIES})
target_include_directories(myip PUBLIC ${SNDFILE_INCLUDE_DIRS})
target_compile_options(myip PUBLIC ${SNDFILE_CFLAGS_OTHER})

pkg_check_modules(SAMPLERATE REQUIRED samplerate)
target_link_libraries(myip ${SAMPLERATE_LIBRARIES})
target_include_directories(myip PUBLIC ${SAMPLERATE_INCLUDE_DIRS})
target_compile_options(myip PUBLIC ${SAMPLERATE_CFLAGS_OTHER})

pkg_check_modules(SPEEX REQUIRED speex)
target_link_libraries(myip ${SPEEX_LIBRARIES})
target_include_directories(myip PUBLIC ${SPEEX_INCLUDE_DIRS})
target_compile_options(myip PUBLIC ${SPEEX_CFLAGS_OTHER})

target_link_libraries(myiptop -lrt)
