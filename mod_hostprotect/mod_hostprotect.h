#define MODULE_NAME "hostprotect"
#define DEFAULT_RESOLVER "31.220.23.12"
#define DEFAULT_PURGER "31.220.23.11"
#define SHM_SIZE (sizeof(struct hdata))

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
  char purger[16];
  char resolver[16];
} hp;

struct hdata {
  int counter;
  char ip[16];
};

enum {
  FOUND,
  NOT_FOUND,
  SHM_OK,
  SHM_ERR,
  PURGE_OK,
  PURGE_ERR
};

void inline __attribute__((always_inline)) swap_bytes(unsigned char *, char *);
char inline __attribute__((always_inline)) *change_to_dns_format(unsigned char *);
static void check_rbl(char *, char *, int *, request_rec *);
static int search_shm(char *);
static int update_shm(char *);
static int purge_shm(char *);

static int search_shm(char *ip)
{
  struct shm_info shm_info;
  struct shmid_ds shmds;
  int shmid, maxkey;
  int i = 0;
  struct hdata *shm;
  int counter = 0;

  /* find the shm segment */
  maxkey = shmctl(0, SHM_INFO, (void *) &shm_info);
  for(i = 0; i <= maxkey; ++i) {

    if((shmid = shmctl(i, SHM_STAT, &shmds)) < 0) {
      continue;
    }

    /* shm segment found */
    if(shmds.shm_segsz == SHM_SIZE) {
      shm = (struct hdata *) shmat(shmid, 0, 0);
      if(!strcmp(shm->ip, ip)) {
        counter = shm->counter;
      }
      shmdt(shm);
    }

  }

  if(counter)
    return counter;

  return NOT_FOUND;
}

static int update_shm(char *ip)
{
  struct shm_info shm_info;
  struct shmid_ds shmds;
  int shmid, maxkey;
  int i = 0;
  struct hdata *shm;
  int update = 0;

  /* find the shm segment */
  maxkey = shmctl(0, SHM_INFO, (void *) &shm_info);
  for(i = 0; i <= maxkey; ++i) {

    if((shmid = shmctl(i, SHM_STAT, &shmds)) < 0) {
      continue;
    }

    /* shm segment found, increment counter */
    if(shmds.shm_segsz == SHM_SIZE) {
      shm = (struct hdata *) shmat(shmid, 0, 0);
      if(!strcmp(shm->ip, ip)) {
        shm->counter++;
        update = 1;
      }
      shmdt(shm);
    }

  }

  if(update)
    return SHM_OK;

  /* if IP is not in cache */
  if((shmid = shmget(IPC_PRIVATE, SHM_SIZE, IPC_CREAT | 0600)) != -1) {
    struct hdata *shm = (struct hdata *) shmat(shmid, 0, 0);
    shm->counter = 1;
    strncpy(shm->ip, ip, 15);
    shmdt(shm);
    return SHM_OK;
  }

  return SHM_ERR;
}

static int purge_shm(char *ip)
{
  struct shm_info shm_info;
  struct shmid_ds shmds;
  int shmid, maxkey;
  int i = 0;
  struct hdata *shm;
  int purge = 0;

  /* find the shm segment */
  maxkey = shmctl(0, SHM_INFO, (void *) &shm_info);
  for(i = 0; i <= maxkey; ++i) {

    if((shmid = shmctl(i, SHM_STAT, &shmds)) < 0) {
      continue;
    }

    /* shm segment found, increment counter */
    if(shmds.shm_segsz == SHM_SIZE) {
      shm = (struct hdata *) shmat(shmid, 0, 0);
      if(!strcmp(shm->ip, ip)) {
        shmctl(shmid, IPC_RMID, NULL);
        purge = 1;
      }
      shmdt(shm);
    }

  }

  if(purge)
    return PURGE_OK;

  return PURGE_ERR;
}
