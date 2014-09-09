#define MODULE_NAME "hostprotect"
#define DEFAULT_RESOLVER "31.220.23.12"
#define DEFAULT_PURGER "31.220.23.11"

/* DNS */
struct dns_header
{
  unsigned short id; // 16 bits
  unsigned char rd :1; // 1 bit
  unsigned char tc :1; // 1 bit
  unsigned char aa :1; // 1 bit
  unsigned char opcode :4; // 4 bits
  unsigned char qr :1; // 1 bit
  unsigned char rcode :4; // 4 bits
  unsigned char cd :1; // 1 bit
  unsigned char ad :1; // 1 bit
  unsigned char z :1; // 1 bit
  unsigned char ra :1; // 1 bit
  unsigned short qcount; // 16 bits
  unsigned short ancount; // 16 bits
  unsigned short nscount; // 16 bits
  unsigned short arcount; // 16 bits
};

struct dns_question
{
  unsigned short qtype; // 16 bits
  unsigned short qclass; // 16 bits
};

struct dns_answer
{;
  unsigned char *name; // 32 bits
  struct dns_question *q_params; // 32 bits
  unsigned int ttl; // 32 bits
  unsigned short rdlength; // 16 bits
  unsigned char *data; // 32 bits
};

/* Skip list */
struct apr_skiplist {
  apr_skiplist_compare compare;
  apr_skiplist_compare comparek;
  int height;
  int preheight;
  int size;
  apr_skiplistnode *top;
  apr_skiplistnode *bottom;
  apr_skiplistnode *topend;
  apr_skiplistnode *bottomend;
  apr_skiplist *index;
  apr_array_header_t *memlist;
  apr_pool_t *pool;
};

struct apr_skiplistnode {
  void *data;
  apr_skiplistnode *next;
  apr_skiplistnode *prev;
  apr_skiplistnode *down;
  apr_skiplistnode *up;
  apr_skiplistnode *previndex;
  apr_skiplistnode *nextindex;
  apr_skiplist *sl;
};

/* Hosprotect */
struct hostprotect {
    unsigned char enabled:1;
    unsigned char debug:1;
    char resolver[16];
    char purger[16];
};

void inline __attribute__((always_inline)) swap_bytes(unsigned char *, char *);
char inline __attribute__((always_inline)) *change_to_dns_format(unsigned char *);
static void check_rbl(char *, char *, int *, request_rec *);
static int compare(void *, void *);
