#ifndef __UTILS_H__
#define __UTILS_H__

#define _min(a,b) \
   ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
     _a > _b ? _b : _a; })

#define _max(a,b) \
   ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
     _a > _b ? _a : _b; })

typedef enum {
    S2ISUCCESS = 0,
    S2IOVERFLOW,
    S2IUNDERFLOW,
    S2IINCONVERTIBLE
} STR2INT_ERROR;

STR2INT_ERROR str2int(int *i, char *s, int base);
uint32_t name_resolve(char *host_name);
int setnonblock(int fd);
char * strrstr(const char *str, const char *strSearch);
char *str_replace(char *orig, char *rep, char *with);
int get_curr_time(void);
int conn_check(int fd);
char *rand_string(char *str, size_t size);
int url_parse(char* url, char** proto, char** host, int* port);
void daemonize(char * path);

#endif

