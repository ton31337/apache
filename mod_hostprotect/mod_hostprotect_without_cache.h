#define MODULE_NAME "hostprotect"
#define DEFAULT_RESOLVER "31.220.19.20"

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

/* Hosprotect */
struct hostprotect {
    unsigned char enabled:1;
    unsigned char debug:1;
    char resolver[15];
};

void inline __attribute__((always_inline)) swap_bytes(unsigned char *, unsigned char *);
char inline __attribute__((always_inline)) *change_to_dns_format(unsigned char *);
static void check_rbl(char *, char *, int *, request_rec *);
