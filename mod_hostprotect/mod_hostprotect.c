/*

  mod_hostprotect module for Apache
  Donatas Abraitis <donatas@hostinger.com>

  LoadModule hostprotect_module modules/mod_hostprotect.so
  HostProtect "On"
  HostProtectResolver "10.2.1.251"
  HostProtectPurger "31.220.23.11"
  HostProtectDebug "On"

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

module AP_MODULE_DECLARE_DATA hostprotect_module;

void inline __attribute__((always_inline)) swap_bytes(unsigned char *orig, char *changed)
{
  int i = 3;
  int j;
  char *tmp[4] = {0};
  char *t = strtok(strndup(orig, 15), ".");

  while(t != NULL) {
    tmp[i--] = t;
    t = strtok(NULL, ".");
  }

  for(j = 0; j < 4; j++) {
    if(tmp[j] != NULL) {
      strcat(changed, tmp[j]);
      strcat(changed, ".");
    }
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

static void check_rbl(char *ip, char *resolver, int *status, request_rec *req)
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

  tv.tv_sec = 5;
  tv.tv_usec = 0;
  FD_ZERO(&readfds);

  s = socket(PF_INET, SOCK_DGRAM|SOCK_NONBLOCK, IPPROTO_IP);
  if(!s)
    return DECLINED;

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
      int bytes_recv = recv(s, buf, sizeof(buf), 0);
      if(bytes_recv) {

        if(bytes_recv > 80)
          goto err_go;

        qname = (unsigned char*)&buf[sizeof(struct dns_header)];
        reader = &buf[sizeof(struct dns_header) + (strlen(qname)+1) + sizeof(struct dns_question)];
      }
    }
  }

  ans = (struct dns_answer *)reader;
  if(ans != NULL) {
    int size_a = ntohs(ans->rdlength);
    ans->data = (unsigned char *) malloc(size_a);
    for(j; j < size_a; j++)
      ans->data[j] = reader[j];

    if(ans->data[p++] == '1' && ans->data[++p] == 'b')
      *status = 1;
  }

  err_go:
    /* don't forget to close the socket, because you will reach socket limit by pid */
    close(s);
    return;

}
static int hostprotect_handler(request_rec *r)
{
  char *client_ip;
  int is_ip = 0;
  int rbl_status = 0;
  if(hp.enabled == 1) {
    client_ip = ap_get_remote_host(r->connection, r->per_dir_config, REMOTE_NAME, &is_ip);
    if(is_ip) {

      /* purging */
      if(!strcmp(client_ip, hp.purger) && !strcmp(r->method, "DELETE")) {

        char *ip_to_purge = apr_table_get(r->headers_in, "X-Purge-From-BL");
        if(ip_to_purge == NULL)
          return DECLINED;

        int purge_status = purge_shm(ip_to_purge);
        if(purge_status == PURGE_OK) {
          if(hp.debug)
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "%s: PURGED FROM CACHE %s", MODULE_NAME, ip_to_purge);
        }
        return DECLINED;

      }

      /* cache search */
      int cache_hit = search_shm(client_ip);

      /* cache hit */
      if(cache_hit > 1) {
        if(hp.debug)
          ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "%s: CACHE HIT FOR %s (counter %d)", MODULE_NAME, client_ip, cache_hit);
        update_shm(client_ip);
        rbl_status = 1;
        goto err_redirect;
      } else {

        /* cache miss */
        check_rbl(client_ip, hp.resolver, &rbl_status, r);
        if(hp.debug)
          ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "%s: Checking for blacklist %s | status %d", MODULE_NAME, client_ip, rbl_status);

err_redirect:
        /* blacklisted */
        if(rbl_status) {
          update_shm(client_ip);
          ap_set_content_type(r, "text/html");
          ap_rprintf(r, "<html><head><title>Your IP is blacklisted in bl.hostprotect.net - redirecting..</title><META http-equiv='refresh' content='1;URL=http://www.hostprotect.net/'></head><body bgcolor='#ffffff'><center>Your IP is blacklisted in bl.hostprotect.net. You will be redirected automatically in 3 seconds.</center></body></html>");
          return OK;
        }

      }

    }
  }
  return DECLINED;
}

static void hostprotect_module_register_hooks(apr_pool_t *p)
{
  ap_hook_handler(hostprotect_handler, NULL, NULL, APR_HOOK_FIRST);
  hp.enabled = 0;
  hp.debug = 0;
}

static const char *enable_hostprotect(cmd_parms *cmd, void *cfg, const char arg[])
{
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

static const char *purger_hostprotect(cmd_parms *cmd, void *cfg, const char arg[])
{
  if(arg != NULL && strlen(arg) < 16) {
    memset(hp.purger, 0, sizeof(hp.purger));
    strncpy(hp.purger, arg, strlen(arg));
  }
  return NULL;
}

static const char *debug_hostprotect(cmd_parms *cmd, void *cfg, const char arg[])
{
  if(arg != NULL && !strncmp(arg, "On", 2)) {
    hp.debug = 1;
  }
  return NULL;
}

static const command_rec hostprotect_module_directives[] =
{
  AP_INIT_TAKE1("HostProtect", enable_hostprotect, NULL, RSRC_CONF, "Enable/Disable HostProtect module."),
  AP_INIT_TAKE1("HostProtectResolver", resolver_hostprotect, NULL, RSRC_CONF, "Set resolver IP for HostProtect module."),
  AP_INIT_TAKE1("HostProtectPurger", purger_hostprotect, NULL, RSRC_CONF, "Set IP which can purge data from cache."),
  AP_INIT_TAKE1("HostProtectDebug", debug_hostprotect, NULL, RSRC_CONF, "Enable/Disable debug level."),
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
