// Copyright (c) 2019  Diamond Key Security, NFP
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
// - Redistributions of source code must retain the above copyright notice,
//   this list of conditions and the following disclaimer.
//
// - Redistributions in binary form must reproduce the above copyright
//   notice, this list of conditions and the following disclaimer in the
//   documentation and/or other materials provided with the distribution.
//
// - Neither the name of the NORDUnet nor the names of its contributors may
//   be used to endorse or promote products derived from this software
//   without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
// TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
// PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
// TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dks_transfer.h"

void dks_send_file(struct tls *tls, char *file_to_send)
{
    FILE *fp = fopen(file_to_send, "rb");

    if(fp != NULL)
    {
        printf("\r\nSending file %s to HSM\r\n", file_to_send);

        dks_send_file_fp(tls, fp);

        fclose(fp);
    }
    else
    {
        printf("\r\nUnable to open (%s).\r\n", file_to_send);

        // send 0 which means the file wasn't found
        dks_send_file_none(tls);  
    }
    
}

void dks_send_file_fp(struct tls *tls, FILE *fp)
{
    char buffer[1024];

    // get the size of the file
    fseek(fp, 0, SEEK_END);
    long file_len = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    // send the file size
    sprintf(buffer, "%ld\r", file_len);

    tls_write(tls, buffer, strlen(buffer));

    int remaining = file_len;

    // send the file
    int read_count;
    do
    {
        read_count = 1024;
        if(read_count > remaining) read_count = remaining;

        int n = fread(buffer, read_count, 1, fp);

        if(n > 0)
        {
            // send to the HSM
            tls_write(tls, buffer, read_count);
        }

        remaining -= read_count;

    } while (remaining > 0);
}

void dks_send_file_none(struct tls *tls)
{
    char buffer[16];

    sprintf(buffer, "0\r0000000");

    tls_write(tls, buffer, strlen(buffer));  
}

void dks_send_file_mem(struct tls *tls, char *file_data, long length)
{
    char buffer[1024];

    // send the file size
    sprintf(buffer, "%ld\r", length);

    tls_write(tls, buffer, strlen(buffer));

    int remaining = length;

    char *fp = file_data;

    // send the file
    int read_count;
    do
    {
        read_count = 1024;
        if(read_count > remaining) read_count = remaining;

        memcpy(buffer, fp, read_count);
        fp += read_count;

        // send to the HSM
        tls_write(tls, buffer, read_count);

        remaining -= read_count;

    } while (remaining > 0);
}

char *dks_recv_from_hsm(struct tls *tls, unsigned int num_bytes_to_receive)
{
    // first, make sure we can actually allocate memory
    char *result_buffer = malloc(num_bytes_to_receive+1);
    char *error_message = NULL;

    if (result_buffer == NULL)
    {
        error_message = "FAILED: Not enough memory on host.";
        goto failed;
    }

    char msg_buffer[256];

    // Send OK
    int n = snprintf(msg_buffer, 255, "OK:{%i}", num_bytes_to_receive);
    if (n < 0 || n > 255)
    {
        error_message = "FAILED: Format error (OK)";
        goto failed;
    }
    else
    {
        tls_write(tls, msg_buffer, strlen(msg_buffer));
    }
    
    // Receive the data
    int received_bytes = 0;
    while(received_bytes < num_bytes_to_receive)
    {
        int count = tls_read(tls, &result_buffer[received_bytes], (num_bytes_to_receive - received_bytes));
        received_bytes += count;
    }
    result_buffer[received_bytes] = 0;


    // Send Received
    n = snprintf(msg_buffer, 255, "RECEIVED:{%i}", received_bytes);
    if (n < 0 || n > 255)
    {
        error_message = "FAILED: Format error (RECEIVED)";
        goto failed;
    }
    else
    {
        tls_write(tls, msg_buffer, strlen(msg_buffer));
    }

    // we didn't get the number of bytes that we wanted
    if(received_bytes != num_bytes_to_receive)
    {
        goto failed;
    }

    // return data
    return result_buffer;

failed:
    free(result_buffer);
    if(error_message != NULL)
    {
        tls_write(tls, error_message, strlen(error_message));
    }

    return NULL;
}