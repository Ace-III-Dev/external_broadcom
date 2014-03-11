#include "dnsmasq.h"

#ifdef HAVE_DHCP6

#define DEBUG 1
#define BLOCK_PACKET 1

struct old_prefix_list {
    char interface[IF_NAMESIZE+1];
    struct in6_addr old_prefix;
    struct old_prefix_list *next;
};

static struct old_prefix_list *g_old_prefix = NULL;

extern int run_ip_cmd(char*);

static int set_forward_rule(struct in6_addr prefix, char *interface, int add)
{
    char *cmd;
    char block_prefix[256] = {'\0',};
    inet_ntop(AF_INET6, &prefix, block_prefix, ADDRSTRLEN); 

    asprintf(&cmd, "%s -%s natctrl_FORWARD -i %s  -m iprange --src-range %s-%sffff:ffff:ffff:ffff -j DROP", 
            "system/bin/ip6tables", (add ? "A" : "D" ), interface, block_prefix, block_prefix);

#if DEBUG
    my_syslog(MS_DHCP | LOG_INFO, "%s", cmd);
#endif

    
    if (run_ip_cmd(cmd) < 0) {
        my_syslog(MS_DHCP | LOG_INFO, "failed to run_ip_cmd");
        return -1;
    }

    return 1;
}

int deprecate_old_prefix(struct in6_addr old_prefix, char *interface)
{

#if BLOCK_PACKET
    struct old_prefix_list *cur = NULL;
    struct old_prefix_list *new = NULL;

    for (cur = g_old_prefix; cur; cur = cur->next) {
        if ((memcmp(&old_prefix, &cur->old_prefix, sizeof(struct in6_addr)) == 0) &&
            (strcmp(interface, cur->interface) == 0)) {
            return -1;
        }
    }

    new = safe_malloc(sizeof(struct old_prefix_list));   
    memset(new, 0, sizeof(struct old_prefix_list));
    memcpy(&new->old_prefix, &old_prefix, sizeof(struct in6_addr));
    strncpy(new->interface, interface, strlen(interface)+1);

#if DEBUG
    my_syslog(MS_DHCP | LOG_INFO, "%s", __FUNCTION__);
    print_ipv6_address("deprecate prefix", &new->old_prefix);
#endif

    cur = new;
    cur->next = g_old_prefix;
    g_old_prefix = cur;

#endif
    return 1;
}

void block_old_prefix_list(char* interface)
{
#if BLOCK_PACKET
    struct old_prefix_list *cur = NULL;
    for (cur = g_old_prefix; cur; cur = cur->next) {
        if (strcmp(interface, cur->interface) == 0) {
            set_forward_rule(cur->old_prefix, cur->interface, 1);
        }
    }
#endif
}

void print_old_prefix_list(char* interface)
{
#if BLOCK_PACKET
    struct old_prefix_list *cur = NULL;
#if DEBUG
    for (cur = g_old_prefix; cur; cur = cur->next) {
        my_syslog(MS_DHCP | LOG_INFO, "%s inf:%s", __FUNCTION__, cur->interface);
        print_ipv6_address("cur deprecate prefix", &cur->old_prefix);
    }
#endif
#endif
}

int active_old_prefix(struct in6_addr new_prefix, char *interface)
{
#if BLOCK_PACKET
    struct old_prefix_list *cur = NULL;
    struct old_prefix_list *pre_cur = NULL;
    struct old_prefix_list *del = NULL;

    for (cur = g_old_prefix; cur; cur = cur->next) {
        if ((memcmp(&new_prefix, &cur->old_prefix, sizeof(struct in6_addr)) == 0) && 
            (strcmp(interface, cur->interface) == 0 )) {

            if (pre_cur == NULL) { 
                g_old_prefix = cur->next; 
            } else {
                pre_cur->next = cur->next;
            }
            free(cur);
            return 1;
        }
        pre_cur = cur;
    }

#endif
    return -1;
}

#endif
