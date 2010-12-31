/*
 * route_op.h
 * by SummerTown
 * 2011.01.01 12:07 am
 */

/* 
 * dst, in/out parameter 
 * mask, in/out
 * gateway, out parameter
 * iface, out
 */
extern int route_get(in_addr_t *dst, in_addr_t *mask, in_addr_t *gateway, char iface[]);
extern int route_add(in_addr_t dst, in_addr_t mask, in_addr_t gateway, const char *iface);
extern int route_change(in_addr_t dst, in_addr_t mask, in_addr_t gateway, const char *iface);
extern int route_delete(in_addr_t dst, in_addr_t mask);
