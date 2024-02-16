#ifndef MAIN_H
#define MAIN_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>

// zlib is a library that I wrote that includes data structures and algos in C.
// It is built on ZSTATUS statuses to track execution and offer better erroring.
// Just going to use the statusing in this project.
#include "ZStatus.h"

// we are allowed 64 byte domain names, including the null terminator.
// -RFC 1035
#define MAX_HOSTNAME_SIZE       0x40
#define SEND_BUF_SIZE       0x100
#define RECV_BUF_SIZE       0x1000
#define RR_OFFSET           0xc
#define DNS_ADDR            "8.8.8.8"

ZSTATUS
build_dns_header
(
    uint8_t* send_buf
);

ZSTATUS
get_hostname
(
    char* Hostname
);

ZSTATUS
process_hostname
(
    char*   Hostname,
    char*   Proc_hostname
);

ZSTATUS
print_name_at_offset
(
    uint8_t*    Buf,
    uint32_t    Offset
);

ZSTATUS
process_data_type1
(
    uint8_t*    Buf,
    uint32_t    DataOffset,
    uint16_t    DataLen

);

ZSTATUS
process_general_rr
(
    uint8_t*    Buf,
    uint32_t*   CurOffset,
    uint32_t*   NameOffset
);

ZSTATUS
process_response
(
    uint8_t*    Buf
);

#endif
