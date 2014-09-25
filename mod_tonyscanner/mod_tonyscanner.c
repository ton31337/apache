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

static void inline get_info(char *sock_data, char *mod_ver, long *db_ver, char *malicious)
{
  if(sock_data != NULL && *sock_data != '\0') {
    char *token = strtok(sock_data, "|");
    strncpy(mod_ver, token, strlen(token));
    token = strtok(NULL, "|");
    *db_ver = atoi(token);
    token = strtok(NULL, "|");
    strncpy(malicious, token, strlen(token));
  }
}

static int check_extension(const char *ext)
{
  int extlen = strlen(extensions);
  char tmp_extensions[extlen];
  strcpy(tmp_extensions, extensions);
  char *tok = strtok(tmp_extensions, " ");
  while( tok ) {
    if (strcmp(tok, ext) == 0)
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
  char malicious[60];
  char mod_ver[4];
  long db_ver;
  char full_path[256];

  for( ; r->prev != NULL; r = r->prev) {  }

  /* fix internal redirect stuff */
  memset(full_path, 0, sizeof(full_path));
  if(!strncmp(r->filename, "redirect:", 9)) {
    /* get the document_root of request */
    char *doc_root = ap_document_root(r);

    /* trim the "redirect:" from r->filename */
    char *file = r->filename+9;

    /* merge document_root with r->filename */
    sprintf(full_path, "%s%s", doc_root, file);
  } else {
    strcpy(full_path, r->filename);
  }

  char *extension = ap_strrchr(full_path, '.');

  if(apr_stat(&file_info, full_path, APR_FINFO_NORM, r->pool)!=APR_SUCCESS) {
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "[mod_tonyscanner]: Can't access to file: %s", full_path);
    return DECLINED;
  }

  if(extension == NULL)
    return DECLINED;

  ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "[mod_tonyscanner]: file: %s extensions: %s extension: %s Socket: %s", full_path, extensions, extension, msocket);

  if(!check_extension(extension)) {
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "[mod_tonyscanner]: Not matched extension in file: %s extension: %s", full_path, extension);
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

    if(send(sd, full_path, strlen(full_path), 0) < 0)
      ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "[mod_tonyscanner]: Can't send data to socket (%s).", strerror(errno));
    else {

      memset(&buf, 0, sizeof(buf));
      if( recv(sd, buf, sizeof(buf), 0) > 0) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "[mod_tonyscanner]: Data from socket: (%s).", buf);
      }
      memset(&malicious, 0, sizeof(malicious));
      get_info(&buf, &mod_ver, &db_ver, &malicious);
      close(sd);
    }

  }

  if(
      strcmp(malicious, "OK") != 0 &&
      strcmp(file_info.fname, full_path) == 0
    ) {
        ap_log_rerror(APLOG_MARK, APLOG_ALERT, 0, r, "[mod_tonyscanner]: Malicious file: %s blocked. Detected as: %s", full_path, malicious);
        r->status = 403;
        r->content_type = "text/html";
        apr_bucket_brigade *bb = apr_brigade_create (r->pool,
                       r->connection->bucket_alloc);
        ap_basic_http_header (r, bb);

        // Send header information only (HEAD request) ?
        if (r->header_only)
          return DONE;

        ap_rvputs (r, "\n"
             DOCTYPE_HTML_2_0
             "<HTML><HEAD>\n<TITLE>403 Forbidden</TITLE>\n"
             "</HEAD><BODY>\n" "<H1>Forbidden: a malicious file has been detected.</H1>\n", NULL);
        ap_rprintf(r, "Detected as: %s\n", malicious);
        //ap_rprintf(r, "<HR><CENTER>TonyScanner %s (%d)</CENTER>", mod_ver, db_ver);
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
