#include "main.h"

ZSTATUS
build_dns_header
(
    uint8_t* Send_buf
)
{
    ZSTATUS     status      = ZSTATUS_OK;

    if ( Send_buf )
    {
        // Transaction ID. Just picked a random number 0x4242.
        Send_buf[0] = 0x42;
        Send_buf[1] = 0x42;
        // Flags. 0x0100 used to set query flag, recursion desired.
        Send_buf[2] = 0x01;
        Send_buf[3] = 0x00;
        // Num questions, set to 0x0001 (one question)
        Send_buf[4] = 0x00;
        Send_buf[5] = 0x01;
        // Answer, Authority, and Response RRs are all 0. No need to set.
        // Do it anyway to be explicit.
        Send_buf[6]  = 0x00;
        Send_buf[7]  = 0x00;
        Send_buf[8]  = 0x00;
        Send_buf[9]  = 0x00;
        Send_buf[10] = 0x00;
        Send_buf[11] = 0x00;
    }
    else
    {
        printf("build_dns_header: INVALID_ARGS\n");
        status = ZSTATUS_INVALID_ARGS;
    }

    return status;
}

// Need a new strlen implementation that stops a string
// at a DNS compressed name pointer as well as the null
// character. Implemented here.
ZSTATUS
dns_strlen
(
    char*       Str,
    size_t*     Len
)
{
    ZSTATUS     status          = ZSTATUS_FAILED;
    uint8_t     cur             = 0;

    if( Str && Len )
    {
        *Len = 0;

        while(1)
        {
            cur = (uint8_t)Str[*Len];
            // null
            if( cur == 0 )
            {
                status = ZSTATUS_OK;
                break;
            }
            // ptr
            else if( cur >= 0xc0 )
            {
                *Len += 1;
                status = ZSTATUS_OK;
                break;
            }
            // normal char
            else
            {
                *Len += 1;
            }
        }
    }
    else
    {
        status = ZSTATUS_INVALID_ARGS;
    }

    return status;
}

// process from hostname string into an array of the form
// <len1><label1><len2><lable2>...0x00
ZSTATUS
process_hostname
(
    char*   Hostname,
    char*   Proc_hostname
)
{
    ZSTATUS     status          = ZSTATUS_FAILED;
    int         lastlabelidx    = 0;
    char        curchar         = 0x00;
    uint8_t     count           = 0;

    if( Hostname && Proc_hostname )
    {
        for(int i = 0; i < (int)strlen(Hostname); i++)
        {
            curchar = Hostname[i];
            if( curchar == '.' )
            {
                Proc_hostname[lastlabelidx] = count;
                lastlabelidx = i + 1;
                count = 0;
            }
            else
            {
                Proc_hostname[i + 1] = curchar;
                count += 1;
            }
        }
        Proc_hostname[lastlabelidx] = count;
        status = ZSTATUS_OK;
    }
    else
    {
        status = ZSTATUS_INVALID_ARGS;
    }

    return status;
}

ZSTATUS
get_hostname
(
    char* Hostname
)
{
    ZSTATUS     status      = ZSTATUS_FAILED;

    if( Hostname )
    {
        // get hostname from user
        printf("Please enter a hostname\n");
        fgets( Hostname, MAX_HOSTNAME_SIZE, stdin );

        // fgets will always append a null terminator, and will append the newline
        // if there is space. Could get crafty with retries but that would involve
        // flushing the stdin buffer, just exit and retry.
        if( strlen(Hostname) == MAX_HOSTNAME_SIZE - 1)
        {
            printf("\nPlease enter a shorter hostname\n");
            status = ZSTATUS_INVALID_INPUT;
        }
        else
        {
            // get rid of newline from fgets
            Hostname[ strlen(Hostname) - 1 ] = 0x00;
            status = ZSTATUS_OK;
        }
    }
    else
    {
        printf("\nprocess_hostname: hostname addr invalid.\n");
        status = ZSTATUS_INVALID_ARGS;
    }

    return status;

}

// need to do this to add dots back in.
// according to RFC 1035, top 2 bits being 0
// indicates a size marker, so we turn these
// into dots. Otherwise just print the char.
ZSTATUS
print_name_at_offset
(
    uint8_t*    Buf,
    uint32_t    Offset
)
{
    ZSTATUS     status          = ZSTATUS_FAILED;
    size_t      name_len        = 0;
    uint16_t    name_offset     = 0;

    if( Buf )
    {
        if( Buf[Offset] < 64 )
        {
            status = dns_strlen((char*)(Buf+Offset), &name_len );
            if( ZSTATUS_OK == status )
            {

                for( size_t j = 1; j < name_len; j++ )
                {
                    // setting max here to 48 to allow numbers in a hostname.
                    // technically should be 64 if we strictly want to use the
                    // top two bits as a flag.
                    if( Buf[j + Offset] < 48 )
                    {
                        printf(".");
                    }
                    // compressed lable ptr starts at 0xc0 == 192
                    else if( Buf[j + Offset] < 192 )
                    {
                        printf("%c", Buf[j + Offset]);
                    }
                    else
                    {
                        // Found a pointer to an earlier name. Calculate offset
                        // and print starting at that spot.
                        // RFC 1035 section 4.1.4

                        name_offset = ntohs(*(uint16_t*)(Buf + Offset + j)) - 0xc000;
                        printf(".");
                        status = print_name_at_offset( Buf, name_offset );
                        // skip over next byte, it was used above.
                        j += 1;
                    }
                }
            }
        }
        else
        {
            // called this func directly on a compressed name
            name_offset = ntohs(*(uint16_t*)(Buf + Offset)) - 0xc000;
            status = print_name_at_offset( Buf, name_offset );
        }
    }
    else
    {
        status = ZSTATUS_INVALID_ARGS;
    }


    status = ZSTATUS_OK;
    return status;
}

// processes and prints data field from a Type 1 response.
// DataOffset is the offset within the response buffer that
// points to the data section of the RR in question.
ZSTATUS
process_data_A
(
    uint8_t*    Buf,
    uint32_t    DataOffset,
    uint16_t    DataLen

)
{
    ZSTATUS         status          = ZSTATUS_FAILED;
    struct in_addr  response_addr   = { 0 };

    if( Buf )
    {
        if( DataLen != 4 )
        {
            printf("Expected an IP but got something else...?\n");
        }
        else
        {
            response_addr.s_addr = *(uint32_t*)(Buf + DataOffset);
            printf("IP address:\t%s\n", inet_ntoa(response_addr));
            status = ZSTATUS_OK;
        }
    }
    else
    {
        status = ZSTATUS_INVALID_ARGS;
    }

    return status;
}

// processes and prints data field from a Type 5 (CNAME) response.
// DataOffset is the offset within the response buffer that
// points to the data section of the RR in question.
// Does NOT increment the main CurOffset
ZSTATUS
process_data_CNAME
(
    uint8_t*    Buf,
    uint32_t    DataOffset
)
{
    ZSTATUS         status          = ZSTATUS_FAILED;
    size_t          name_len        = 0;

    if( Buf )
    {
        // Deals with CNAME field
        printf("CNAME:\t\t");
        status = print_name_at_offset( Buf, DataOffset );
        printf("\n");

        if( ZSTATUS_OK == status )
        {
            status = dns_strlen((char*)(Buf + DataOffset), &name_len );
            if( ZSTATUS_OK == status )
            {
                DataOffset += name_len + 1;
            }
        }
    }
    else
    {
        status = ZSTATUS_INVALID_ARGS;
    }

    return status;
}

// proccesses and prints a general type 1 RR response.
// INCREMENTS CurOffset as needed, sets NameOffset if
// name in response not seen yet.
ZSTATUS
process_general_rr
(
    uint8_t*    Buf,
    uint32_t*   CurOffset
)
{
    ZSTATUS         status          = ZSTATUS_FAILED;
    size_t          name_len        = 0;
    uint16_t        type            = 0;
    uint16_t        rd_len          = 0;

    if( Buf && CurOffset )
    {
        printf("Name:\t\t");
        status = print_name_at_offset( Buf, *CurOffset );
        printf("\n");

        if( ZSTATUS_OK == status )
        {
            status = dns_strlen((char*)(Buf + *CurOffset), &name_len );
            if( ZSTATUS_OK == status )
            {
                *CurOffset += name_len + 1;
            }
        }

        if( ZSTATUS_OK == status )
        {
            type = ntohs(*(uint16_t*)(Buf + *CurOffset));
            printf("Type:\t\t");
            printf("%hu\n", type);
            *CurOffset += 2;

            printf("Class:\t\t");
            printf("%hu\n", ntohs(*(uint16_t*)(Buf + *CurOffset)));
            *CurOffset += 2;

            printf("TTL:\t\t");
            printf("%d seconds\n", ntohl(*(uint32_t*)(Buf + *CurOffset)));
            *CurOffset += 4;

            rd_len = ntohs(*(uint16_t*)(Buf + *CurOffset));
            printf("RD_len:\t\t");
            printf("%hu\n", rd_len);
            *CurOffset += 2;

            if( type == 1 )
            {
                status = process_data_A( Buf, *CurOffset, rd_len );
            }
            else if( type == 5 )
            {
                status = process_data_CNAME( Buf, *CurOffset );
            }
            else
            {
                printf("Type of RR not implemented :(\n");
            }

            *CurOffset += rd_len;
            printf("---------------------------\n");
        }
        else
        {
            printf("Failed to print name\n");
        }
    }
    else
    {
        status = ZSTATUS_INVALID_ARGS;
    }

    return status;
}
// processes the data received and prints it to
// the terminal window.
ZSTATUS
process_response
(
    uint8_t*    Buf
)
{
    ZSTATUS         status          = ZSTATUS_FAILED;
    uint16_t        num_questions   = 0;
    uint16_t        num_answers     = 0;
    uint16_t        num_authority   = 0;
    uint16_t        num_additional  = 0;
    uint32_t        cur_offset      = 0;
    size_t          name_len        = 0;

    if( Buf )
    {
        printf("\n");
        // pull number of each response
        // need to flip endianess with ntohs,
        // constants are the offsets for each value.
        num_questions   = ntohs(*(uint16_t*)(Buf + 4));
        num_answers     = ntohs(*(uint16_t*)(Buf + 6));
        num_authority   = ntohs(*(uint16_t*)(Buf + 8));
        num_additional  = ntohs(*(uint16_t*)(Buf + 10));

        printf("Number of question responses: %d\n", num_questions);
        printf("Number of answer responses: %d\n", num_answers);
        printf("Number of authority responses: %d\n", num_authority);
        printf("Number of additional responses: %d\n", num_additional);

        // first rr starts at byte 12
        cur_offset = 12;
        // print each individually
        if( num_questions > 0 )
        {
            printf("\nQuestion Responses:\n");
            for(uint16_t i = 0; i < num_questions; i++)
            {
                status = print_name_at_offset( Buf, cur_offset );
                printf("\n");

                if( ZSTATUS_OK == status )
                {
                    status = dns_strlen((char*)(Buf + cur_offset), &name_len );
                    if( ZSTATUS_OK == status )
                    {
                        cur_offset += name_len + 1;
                    }
                }

                if( ZSTATUS_OK == status )
                {
                    printf("Type:\t\t");
                    printf("%hu\n", ntohs(*(uint16_t*)(Buf + cur_offset)));
                    cur_offset += 2;

                    printf("Class:\t\t");
                    printf("%hu\n", ntohs(*(uint16_t*)(Buf + cur_offset)));
                    cur_offset += 2;

                    printf("---------------------------\n");
                }
                else
                {
                    printf("Failed to print name\n");
                }
            }
        }

        if( ZSTATUS_OK == status && num_answers > 0 )
        {
            printf("\nAnswer Responses:\n");
            for(uint16_t i = 0; i < num_answers; i++)
            {
                status = process_general_rr( Buf, &cur_offset );
                if( ZSTATUS_OK != status ) break;
            }
        }

        if( ZSTATUS_OK == status && num_authority > 0 )
        {
            printf("\nAuthority Responses:\n");
            for(uint16_t i = 0; i < num_authority; i++)
            {
                status = process_general_rr( Buf, &cur_offset );
                if( ZSTATUS_OK != status ) break;
            }
        }

        if( ZSTATUS_OK == status && num_additional > 0 )
        {
            printf("\nAdditional Responses:\n");
            for(uint16_t i = 0; i < num_authority; i++)
            {
                status = process_general_rr( Buf, &cur_offset );
                if( ZSTATUS_OK != status ) break;
            }
        }
    }
    else
    {
        status = ZSTATUS_INVALID_ARGS;
    }

    return status;
}

int main()
{
    ZSTATUS             status                      = ZSTATUS_FAILED;
    char*               hostname                    = NULL;
    char*               proc_hostname               = NULL;
    size_t              proc_hostname_len           = 0;
    uint8_t             send_buf[SEND_BUF_SIZE]     = { 0 };
    uint8_t             recv_buf[RECV_BUF_SIZE]     = { 0 };
    int                 sock                        = 0;
    struct sockaddr_in  dest                        = { 0 };
    struct sockaddr     src                         = { 0 };
    struct in_addr      inaddr                      = { 0 };
    socklen_t           src_len                     = 0;

    hostname = malloc( MAX_HOSTNAME_SIZE );
    if( hostname )
    {
        status = get_hostname( hostname );
        if( ZSTATUS_OK == status )
        {
            // 2 extra spots for null terminator and inital len field
            proc_hostname = malloc( strlen( hostname ) + 2 );
            // convert hostname from domainname.xxx.something to RR-firendly form,
            // breaking dots into labels.
            status = process_hostname( hostname, proc_hostname );
            if( ZSTATUS_OK == status )
            {
                proc_hostname_len = strlen( proc_hostname );
                // create a socket to send request
                sock = socket( AF_INET, SOCK_DGRAM, 0 );
                if( sock != -1 )
                {
                    // need to wrap ulong in in_addr struct to pass into sockaddr_in struct
                    inaddr.s_addr   = inet_addr(DNS_ADDR);
                    // fill sockaddr_in fields
                    dest.sin_family = AF_INET;
                    dest.sin_addr   = inaddr;
                    dest.sin_port   = htons( 53 );

                    // build send_buf (the request)
                    build_dns_header( send_buf );
                    // Now we build the RR
                    // name field, processed above. +1 for null label.
                    memcpy(send_buf + RR_OFFSET, proc_hostname, proc_hostname_len + 1);
                    // Type A RR, value of 1
                    send_buf[RR_OFFSET + proc_hostname_len + 1] = 0x00;
                    send_buf[RR_OFFSET + proc_hostname_len + 2] = 0x01;
                    // class field. We use 1 for internet
                    send_buf[RR_OFFSET + proc_hostname_len + 3] = 0x00;
                    send_buf[RR_OFFSET + proc_hostname_len + 4] = 0x01;

                    // send request
                    sendto( sock, (void*)send_buf, sizeof( send_buf ), 0, (struct sockaddr*)&dest, sizeof( dest ) );

                    // Need to initialize before recvfrom call, although call will set this
                    src_len = sizeof( src );

                    // get response from server
                    recvfrom( sock, recv_buf, sizeof( recv_buf ), 0, &src, &src_len );

                    // display results
                    status = process_response( recv_buf );

                }
                else
                {
                    printf("Failed to create socket.\n");
                    status = ZSTATUS_ERR_INTERNAL;
                }
                free( proc_hostname );
            }
        }
        free( hostname );
    }
    else
    {
        printf("Failed to malloc hostname.\n");
        status = ZSTATUS_OUT_OF_MEMORY;
    }

    return status;
}
