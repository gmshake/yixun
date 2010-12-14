#ifndef _CHANGE_ROUTES_H
#define _CHANGE_ROUTES_H

extern int route_add(in_addr_t sip, size_t bits, in_addr_t gateway, const char *iface, const char *flag);
extern int route_change(in_addr_t sip, size_t bits, in_addr_t gateway, const char *iface);
extern int route_delete(in_addr_t sip, size_t bits);
extern in_addr_t route_get(in_addr_t sip, size_t bits);
extern int route_exist(in_addr_t sip, size_t bits);

#endif //_CHANGE_ROUTES_H