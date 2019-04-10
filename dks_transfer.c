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
        sprintf(buffer, "0\r0000000");

        tls_write(tls, buffer, strlen(buffer));            
    }
}
