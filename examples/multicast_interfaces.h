#ifndef _MULTICAST_INTERFACES_H_
#define _MULTICAST_INTERFACES_H_

typedef struct mcast_ifc_list_st {
    struct mcast_ifc_list_st* ifc_next;
    char*                     ifc_name;
    unsigned int              ifc_idx;
    struct sockaddr*          ifc_addr;
    socklen_t                 ifc_addrlen;
} mcast_ifc_list;

extern mcast_ifc_list* get_multicast_interfaces();
extern void free_multicast_interfaces(mcast_ifc_list*);

#endif /* _MULTICAST_INTERFACES_H_ */

// vim:ts=8:sts=4:sw=4:expandtab:
