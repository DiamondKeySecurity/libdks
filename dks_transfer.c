// Copyright (c) 2019  Diamond Key Security, NFP
// 
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; version 2
// of the License only.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License
// along with this program; if not, If not, see <https://www.gnu.org/licenses/>.
//
// Script to import CrypTech code into DKS HSM folders.
//
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dks_transfer.h"

void dks_send_file(struct tls *tls, char *file_to_send)
{
    char buffer[1024];

    FILE *fp = fopen(file_to_send, "rb");

    if(fp != NULL)
    {
        printf("\r\nSending file %s to HSM\r\n", file_to_send);

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

        fclose(fp);
    }
    else
    {
        printf("\r\nUnable to open (%s).\r\n", file_to_send);

        // send 0 which means the file wasn't found
        dks_send_file_none(tls);
    }
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
