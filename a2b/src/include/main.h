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

#define MAX_HOSTNAME_SIZE   0x40
#define SEND_BUF_SIZE       0x100
#define RECV_BUF_SIZE       0x1000
#define RR_OFFSET           0xc
#define DNS_ADDR            "8.8.8.8"

// Just builds out the first few bytes of a DNS request.
ZSTATUS
build_dns_header
(
    uint8_t* send_buf
);

// Need a new strlen implementation that stops a string
// at a DNS compressed name pointer as well as the null
// character. Implemented here.
ZSTATUS
dns_strlen
(
    char*       Str,
    size_t*     Len
);

// Gets the hostname from the user, does
// some preprocessing.
ZSTATUS
get_hostname
(
    char* Hostname
);

// process from hostname string into an array of the form
// <len1><label1><len2><lable2>...0x00
ZSTATUS
process_hostname
(
    char*   Hostname,
    char*   Proc_hostname
);

// need to do this to add dots back in.
// according to RFC 1035, top 2 bits being 0
// indicates a size marker, so we turn these
// into dots. Otherwise just print the char.
//
// Also has to deal with compressed names,
// does so with recursive calls to itself.
ZSTATUS
print_name_at_offset
(
    uint8_t*    Buf,
    uint32_t    Offset
);

// processes and prints data field from a Type 1 response.
// DataOffset is the offset within the response buffer that
// points to the data section of the RR in question.
ZSTATUS
process_data_A
(
    uint8_t*    Buf,
    uint32_t    DataOffset,
    uint16_t    DataLen

);

// processes and prints data field from a Type 5 (CNAME) response.
// DataOffset is the offset within the response buffer that
// points to the data section of the RR in question.
// Does NOT increment the main CurOffset
ZSTATUS
process_data_CNAME
(
    uint8_t*    Buf,
    uint32_t    DataOffset
);

// proccesses and prints a general type 1 RR response.
// INCREMENTS CurOffset as needed, sets NameOffset if
// name in response not seen yet.
ZSTATUS
process_general_rr
(
    uint8_t*    Buf,
    uint32_t*   CurOffset
);

// processes the data received and prints it to
// the terminal window.
ZSTATUS
process_response
(
    uint8_t*    Buf
);

#endif
