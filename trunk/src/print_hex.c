/*
 *  print_hex.c
 *  YiXun
 *
 *  Created by Summer Town on 9/16/10.
 *  Copyright 2010 __MyCompanyName__. All rights reserved.
 *
 */

#include <stdint.h>     // uint8_t
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

int hex_to_ascii(char out_buff[], size_t out_len, const void *in_buff, size_t in_len);
 
void print_hex(const void *data, size_t len)
{
    const char *head = "******DEBUG******\n";
    size_t bufflen = sizeof(char) * (len * 3 + len / 16 + strlen(head) + 1); // '\0'
    char *buff = (char *)malloc(bufflen);
    if (buff == NULL) {
        perror("Error:[print_hex] malloc");
        return;
    }
    
    char *end = buff + bufflen;
    char *p = buff;
    
    p += snprintf(p, end - p, head);
    p += hex_to_ascii(p, end - p, data, len);

    fprintf(stderr, "%s\n", buff);
    free(buff);
}


/*
 * Notice: hex_to_ascii convert hex to ascii from in_buff to out_buff no more than in_len bytes
 * then append out_buff with '\0'
 * So better out_len is in_len * (3 + 1 / 16) + 1
 */
int hex_to_ascii(char out_buff[], size_t out_len, const void *in_buff, size_t in_len)
{
    char *p = out_buff;
    size_t i;
    for (i = 0; i < (out_len << 4) / 49 && i < in_len; i++) {// (out_len - 1) * 16 / 49
        if (i != 0) {
            size_t t = i % 16;
            if (t == 8)
                p += sprintf(p, "  ");
            else if (t == 0)
                p += sprintf(p, "\n");
            else
                p += sprintf(p, " ");
        }
        p += sprintf(p, "%02x", (uint32_t)*((uint8_t *)in_buff++));
    }
    return p - out_buff;
}
