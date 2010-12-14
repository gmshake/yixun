#include <stdio.h>
#include <string.h> //bcopy()
#include <netinet/ip.h> // struct ip
#include <net/ethernet.h> //ETHERTYPE_IP

#include "tun-dev.h"
#include "process_packet.h"


/*
 * The following are deprecated in RFC2784
 */

//#define GRE_RP		0x4000  /* Routing Present */
//#define GRE_KP		0x2000  /* Key Present */
//#define GRE_SP		0x1000  /* Sequence Present */
//#define GRE_SS		0x0800	/* Strict Source Route */

/*
 * Processes a packet received over the GRE tunnel
 * len(in/out)
 * Caution: return full GRE payload
 */ 
inline void * process_gre_packet(void *buff, size_t *len)
{
    struct gre_h *hp     = (struct gre_h *)(buff + sizeof(struct ip));
    
    if (hp->ptype != htons(ETHERTYPE_IP)) // not IP packet...
        return NULL;
    
    //int newlen = *len - sizeof(struct ip);
    //void *rval;
    if (hp->flags & GRE_CP) // Checksum present
    {
        uint16_t sum = hp->sum;
        hp->sum = 0xffff; // Filled with one's
        if (chksum((uint16_t *)hp, *len) != sum) // checksum error, drop it
            return NULL;
        //rval = (void *)hp + sizeof(struct gre_h);
        *len -= sizeof(struct ip) + sizeof(struct gre_h);
        return (void *)hp + sizeof(struct gre_h);
    }
    else // not check sum
    {
        //rval = (void *)hp + 4;
        *len -= sizeof(struct ip) + 4;
        return (void *)hp + 4;
    }
    //return rval;
}


inline void process_outbound_packet(void *buff, size_t len)
{    
//    struct gre_h *hp     = (struct gre_h *)buff;
    if (((struct gre_h *)buff)->flags & GRE_CP) // Checksum present
    {
        ((struct gre_h *)buff)->sum = 0xffff; // Filled with one's
        ((struct gre_h *)buff)->sum = (chksum((uint16_t *)buff, len));
    }
}

void * add_gre_header(void *buff, int chksum_flag)
{
    struct gre_h *hp = (struct gre_h *)buff;
    void *rval;
    if (chksum_flag)
    {
        bzero(hp, sizeof(struct gre_h));
        hp->flags = htons(GRE_CP);
        hp->rsv = 0x0;   // Always be 0's
        // checksum is to be done by process_outbound_packet
        rval = buff + sizeof(struct gre_h);
    }
    else
    {   
        hp->flags = 0x0;
        rval = buff + 4;
    }
    hp->ptype = htons(ETHERTYPE_IP);
    
    return rval;
}
 
/*
int process_gre_packet(struct ip *p, u_char buff[], size_t *len)
{
    bcopy((char *)p + sizeof(struct greip), buff, *len);
    return 0;
}
*/

/*
 * Processes a packet heading outbound.
 * len(in/out)
 */
/*

int process_outbound_packet(struct ip *p, u_char buff[], size_t *len)
{
    struct gre_h *hp    = (struct gre_h *)buff;
    hp->flags           = 0x0;
    hp->ptype           = htons(ETHERTYPE_IP);
    
    if (*len + sizeof(struct gre_h) > PACKET_BUFF_LEN) // overflow
        return -1;
        
    bcopy(p, buff + sizeof(struct gre_h), *len);
    
    *len += sizeof(struct gre_h);
    return 0;
}

*/
/*
 * do a checksum of a buffer - much like in_cksum, which operates on
 * mbufs.
 */
uint16_t chksum(uint16_t *p, size_t len)
{
	uint32_t sum = 0;
	size_t nwords = len >> 1;

	while (nwords-- != 0)
		sum += *p++;

	if (len & 1) {
		union {
			u_short w;
			u_char c[2];
		} u;
		u.c[0] = *(u_char *)p;
		u.c[1] = 0;
		sum += u.w;
	}

	/* end-around-carry */
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	return (~sum);
}