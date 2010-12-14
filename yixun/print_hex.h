#ifndef _PRINT_HEX_H
#define _PRINT_HEX_H

extern void print_hex(const void *data, size_t len);
extern int hex_to_ascii(char out_buff[], size_t out_len, const void *in_buff, size_t in_len);

#ifdef DEBUG
#define debug_print_hex(s, t) print_hex(s, t)
#else
#define debug_print_hex(s, t) (void)0
#endif

#endif
