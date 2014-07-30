/*

   mod_hostprotect module for Apache
   Donatas Abraitis <donatas@hostinger.com>

*/

#include <httpd.h>
#include <http_config.h>
#include <http_core.h>
#include <http_log.h>
#include <http_main.h>
#include <http_protocol.h>
#include <http_request.h>
#include <http_connection.h>
#include <apr.h>
#include <apr_skiplist.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/socket.h>
#include <sys/un.h>
#include "mod_hostprotect.h"

struct hostprotect hp;
apr_skiplist *sl;
apr_skiplistnode *node;

module AP_MODULE_DECLARE_DATA hostprotect_module;

static int compare(void *a, void *b)
{
  void *ac = (void *) (((apr_skiplist *) a)->compare);
  void *bc = (void *) (((apr_skiplist *) b)->compare);
  return ((ac < bc) ? -1 : ((ac > bc) ? 1 : 0));
}

void inline __attribute__((always_inline)) swap_bytes(unsigned char *orig, unsigned char *changed)
{
  int i = 3;
  int j;
  char *tmp[4];
  char *t = strtok(strdup(orig), ".");
  while(t != NULL) {
    tmp[i--] = t;
    t = strtok(NULL, ".");
  }
  for(j = 0; j < 4; j++) {
    strcat(changed, tmp[j]);
    strcat(changed, ".");
  }
  strcat(changed, "in-addr.arpa");
}

char inline __attribute__((always_inline)) *change_to_dns_format(unsigned char *orig)
{
  int init[] = {47,-84,1,0,0,1,0,0,0,0,0,0};
  int end[] = {0,0,12,0,1,0};
  char *t = strtok(strdup(orig), ".");
  char ip[48];
  int i, n;
  int j = sizeof(init) / sizeof(init[0]);
  int m = sizeof(end) / sizeof(end[0]);
  int k = sizeof(ip) / sizeof(ip[0]);

  for(i = 0; i < j; i++) {
    ip[i] = init[i];
  }

  while(t != NULL) {
    int l = strlen(t);
    int x = 0;
    ip[i++] = l; //12
    ip[i++] = *t; //13
    if(l > 1) {
      --i;
      for(x; x < l; x++) {
        ip[++i] = *(++t);
      }
    }
    t = strtok(NULL, ".");
  }

  for(n = 0; n < m; n++) {
    ip[i++] = end[n];
  }

  return ip;
}

static void check_rbl(char *ip, char *resolver, int *status)
{
  int s;
  int r;
  int j = 0;
  int p = 13;
  struct sockaddr_in addr;
  struct timeval tv;
  char buf[65536];
  char host[40];
  unsigned char *qname;
  struct dns_answer *ans;
  struct dns_header *dns;
  unsigned char *reader = NULL;
  char *packet;
  fd_set readfds;

  tv.tv_sec = 10;
  tv.tv_usec = 500000;
  FD_ZERO(&readfds);

  s = socket(PF_INET, SOCK_DGRAM|SOCK_NONBLOCK, IPPROTO_IP);
  FD_SET(s, &readfds);

  memset(buf, 0, sizeof(buf));
  memset(&addr, 0, sizeof(addr));
  memset(host, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(53);
  addr.sin_addr.s_addr = inet_addr(resolver);

  swap_bytes(ip, host);
  packet = change_to_dns_format(host);
  connect(s, (struct sockaddr *)&addr, sizeof(addr));
  send(s, (void *)packet, 48, MSG_NOSIGNAL);

  r = select(s+1, &readfds, NULL, NULL, &tv);
  if(r) {
    if(FD_ISSET(s, &readfds)) {
      recv(s, buf, sizeof(buf), 0);
      qname = (unsigned char*)&buf[sizeof(struct dns_header)];
      reader = &buf[sizeof(struct dns_header) + (strlen(qname)+1) + sizeof(struct dns_question)];
    }
  }

  ans = (struct dns_answer *)reader;
  ans->data = (unsigned char *) malloc(ntohs(ans->rdlength));
  for(j; j < ntohs(ans->rdlength); j++)
    ans->data[j] = reader[j];

  if(ans->data[p++] == '1' && ans->data[++p] == 'b')
    *status = 1;

}

static int hostprotect_handler(request_rec *r)
{
  char *client_ip;
  int is_ip = 0;
  int rbl_status = 0;
  ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "HostProtect enabled: %d, Resolver IP: %s", hp.enabled, hp.resolver);
  if(hp.enabled == 1) {
    client_ip = ap_get_remote_host(r->connection, r->per_dir_config, REMOTE_NAME, &is_ip);
    if(is_ip) {
      apr_skiplistnode *found;
      apr_skiplist_set_compare(sl, compare, compare);
      apr_skiplist_find(sl, (void *)client_ip, &found);
      if(found != NULL) {
        rbl_status = 1;
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "HostProtect Found match with client_ip %s", (char *)found->data);
        goto rbl_err;
      } else {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "HostProtect Not found match with client_ip");
      }
      ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "HostProtect enabled, checking RBL for IP %s", client_ip);
      check_rbl(client_ip, hp.resolver, &rbl_status);

      if(rbl_status) {
        node = apr_skiplist_insert_compare(sl, (void *)client_ip, compare);
        if(node != NULL)
          ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "HostProtect Added IP (%s) to cache!", client_ip);
        rbl_err:
          ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "HostProtect IP (%s) is blacklisted!", client_ip);
          ap_set_content_type(r, "text/html");
          ap_rprintf(r, "<html><head><title>Your IP is blacklisted in bl.hostprotect.net - redirecting..</title><META http-equiv='refresh' content='3;URL=http://www.hostprotect.net/'></head><body bgcolor='#ffffff'><center>Your IP is blacklisted in bl.hostprotect.net. You will be redirected automatically in 3 seconds.</center></body></html>");
        return OK;
      }
    }
  }
  return DECLINED;
}

static void hostprotect_module_register_hooks(apr_pool_t *p)
{
  ap_hook_handler(hostprotect_handler, NULL, NULL, APR_HOOK_FIRST);
  apr_skiplist_init(&sl, NULL);
}

static const char *enable_hostprotect(cmd_parms *cmd, void *cfg, const char arg[])
{
  hp.enabled = 0;
  if(arg != NULL && !strncmp(arg, "On", 2)) {
    hp.enabled = 1;
    strncpy(hp.resolver, DEFAULT_RESOLVER, strlen(DEFAULT_RESOLVER));
  }
  return NULL;
}

static const char *resolver_hostprotect(cmd_parms *cmd, void *cfg, const char arg[])
{
  if(arg != NULL && strlen(arg) < 16) {
    memset(hp.resolver, 0, sizeof(hp.resolver));
    strncpy(hp.resolver, arg, strlen(arg));
  }
  return NULL;
}

static const command_rec hostprotect_module_directives[] =
{
  AP_INIT_TAKE1("HostProtect", enable_hostprotect, NULL, RSRC_CONF, "Enable/Disable HostProtect module."),
  AP_INIT_TAKE1("HostProtectResolver", resolver_hostprotect, NULL, RSRC_CONF, "Set resolver IP for HostProtect module."),
  {NULL}
};

module AP_MODULE_DECLARE_DATA hostprotect_module = {
   STANDARD20_MODULE_STUFF,
   NULL,                  /* create per-dir    config structures */
   NULL,                  /* merge  per-dir    config structures */
   NULL,                  /* create per-server config structures */
   NULL,                  /* merge  per-server config structures */
   hostprotect_module_directives,                  /* table of config file commands       */
   hostprotect_module_register_hooks  /* register hooks                      */
};
