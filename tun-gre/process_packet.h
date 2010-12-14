#ifndef _PROCESS_PACKET_H
#define _PROCESS_PACKET_H

#define PACKET_BUFF_LEN 8192 // Maximum length of packet can be processed
#define GRE_CP		0x8000  /* Checksum Present */

struct gre_h {
	uint16_t flags;	/* GRE flags */
	uint16_t ptype;	/* protocol type of payload typically Ether protocol type*/
	uint16_t sum;	/* The Checksum field contains the IP (one's complement) checksum sum of
                     * the all the 16 bit words in the GRE header and the payload packet.
                     * For purposes of computing the checksum, the value of the checksum
                     * field is zero. This field is present only if the Checksum Present bit
                     * is set to one.
                     */
    uint16_t rsv;   /* The Reserved1 field is reserved for future use, and if present, MUST
                     * be transmitted as zero. The Reserved1 field is present only when the
                     * Checksum field is present (that is, Checksum Present bit is set to
                     * one).
                     */
};

struct greip {
	struct ip gi_i;
	struct gre_h  gi_g;
};

extern void * add_gre_header(void *buff, int chksum_flag);
extern void * process_gre_packet(void *buff, size_t *len);
//extern void process_outbound_packet(void *buff, size_t len);
extern uint16_t chksum(uint16_t *, size_t);
/*
extern int process_gre_packet(struct ip *ip_p, u_char buff[], size_t *len);
extern int process_outbound_packet(struct ip *ip_p, u_char buff[], size_t *len);

*/
#endif