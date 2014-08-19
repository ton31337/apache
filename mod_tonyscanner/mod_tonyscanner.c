/*
     $ /opt/httpd/bin/apxs -c -i mod_tonyscanner.c
     TonyScannerSocket "/var/run/tonyscanner/tonyscanner.sock"
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
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

module AP_MODULE_DECLARE_DATA tonyscanner_module;

#define MAX_READ_SIZE 1024
#define DEFAULT_SOCKET "/var/run/tonyscanner/tonyscanner.sock"
#define DEFAULT_EXTENSIONS ".php .html .htm .js .phtml .php5 .php4 .php3"

char *msocket = DEFAULT_SOCKET;
char *extensions = DEFAULT_EXTENSIONS;

static int check_extension(const char *ext)
{
  int extlen = strlen(extensions);
  char tmp_extensions[extlen];
  strcpy(tmp_extensions, extensions);
  char *tok = strtok(tmp_extensions, " ");
  while(tok) {
    if(strcmp(tok, ext) == 0)
      return 1;
    tok = strtok(NULL, " ");
  }
  return 0;
}

static int tonyscanner_handler(request_rec *r)
{
  int sd = -1;
  int rc = 0;
  struct sockaddr_un addr;
  apr_finfo_t file_info;
  char buf[MAX_READ_SIZE];

  for(; r->prev != NULL; r = r->prev) {}
  char *extension = ap_strrchr(r->filename, '.');

  if(extension == NULL)
    return DECLINED;

  if(apr_stat(&file_info, r->filename, APR_FINFO_NORM, r->pool) != APR_SUCCESS) {
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "[mod_tonyscanner]: Can't access to file: %s", r->filename);
    return DECLINED;
  }

  if(check_extension(extension) == 0) {
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "[mod_tonyscanner]: Not matched extension in file: %s extension: %s", r->filename, extension);
    return DECLINED;
  }

 if((sd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "[mod_tonyscanner]: Can't construct socket information for socket: %s", msocket);
    return DECLINED;
  } else {
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, msocket, sizeof(addr.sun_path) - 1);
  }

  if(connect(sd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "[mod_tonyscanner]: Can't connect to socket: %s (%s).", addr.sun_path, strerror(errno));
    return DECLINED;
  } else {
    if(send(sd, r->filename, strlen(r->filename), 0) < 0)
      ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "[mod_tonyscanner]: Can't send data to socket (%s).", strerror(errno));
    else {
      memset(&buf, 0, sizeof(buf));
      if(recv(sd, buf, sizeof(buf), 0) > 0) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "[mod_tonyscanner]: Data from socket: (%s).", buf);
      }
      close(sd);
    }
  }

  if(*buf != '\0' && *buf != '0' && strcmp(file_info.fname, r->filename) == 0) {
        ap_log_rerror(APLOG_MARK, APLOG_ALERT, 0, r, "[mod_tonyscanner]: Malicious file: %s blocked. Detected as: %s", r->filename, buf);
        r->status = 403;
        r->content_type = "text/html";
        apr_bucket_brigade *bb = apr_brigade_create (r->pool, r->connection->bucket_alloc);
        ap_basic_http_header (r, bb);

        if (r->header_only)
          return DONE;

        ap_rvputs (r, "\n"
             DOCTYPE_HTML_2_0
             "<HTML><HEAD>\n<TITLE>403 Forbidden</TITLE>\n"
             "</HEAD><BODY>\n" "<H1>Forbidden: a malicious file has been detected.</H1>\n", NULL);
        ap_rprintf(r, "Detected as: %s\n", buf);
        ap_rputs ("</BODY></HTML>\n", r);
        ap_finalize_request_protocol (r);
        ap_rflush (r);
        return DONE;
  } else

  return DECLINED;

}

static void tonyscanner_module_register_hooks(apr_pool_t *p)
{
  ap_hook_handler(tonyscanner_handler, NULL, NULL, APR_HOOK_FIRST);
}

static const char *set_socket(cmd_parms *cmd, void *cfg, const char *arg)
{
  if( arg != NULL && strcmp(arg, "") != 0)
    msocket = arg;
  return NULL;
}

static const char *set_extensions(cmd_parms *cmd, void *cfg, const char arg[])
{
  if( arg != NULL && strcmp(arg, "") != 0) {
    extensions = arg;
  }
  return NULL;
}

static const command_rec tonyscanner_module_directives[] =
{
  AP_INIT_TAKE1("TonyScannerSocket", set_socket, NULL, RSRC_CONF, "Set socket for mod_tonyscanner."),
  AP_INIT_TAKE1("TonyScannerExtensions", set_extensions, NULL, RSRC_CONF, "Set extensions to parse."),
  {NULL}
};

module AP_MODULE_DECLARE_DATA tonyscanner_module = {
   STANDARD20_MODULE_STUFF,
   NULL,                  /* create per-dir    config structures */
   NULL,                  /* merge  per-dir    config structures */
   NULL,                  /* create per-server config structures */
   NULL,                  /* merge  per-server config structures */
   tonyscanner_module_directives,                  /* table of config file commands       */
   tonyscanner_module_register_hooks  /* register hooks                      */
};
