#ifndef __BALLOC_H_
#define __BALLOC_H_

//#define B_STATS

typedef char char_t;
//#define char_t char;

//uemf.h
#ifdef	B_STATS
#ifndef B_L
#define B_L				T(__FILE__), __LINE__
#define B_ARGS_DEC		char_t *file, int line
#define B_ARGS			__FILE__, __LINE__
#define FNAMESIZE   128
#define BUF_MAX     512
#endif /* B_L */
#else
#define B_ARGS_DEC		int line
#define B_ARGS			__LINE__
#endif /* B_STATS */

/*
 *	Block classes are: 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192,
 *					   16384, 32768, 65536
 */
typedef struct {
	union {
		void	*next;							/* Pointer to next in q */
		int		size;							/* Actual requested size */
	} u;
	int			flags;							/* Per block allocation flags */
} bType;

#define B_SHIFT			4					/* Convert size to class */
#define B_ROUND			((1 << (B_SHIFT)) - 1)
#define B_MAX_CLASS		13					/* Maximum class number + 1 */
#define B_MALLOCED		0x80000000			/* Block was malloced */
#define B_DEFAULT_MEM	(1024 * 1024)		/* Default memory allocation */
#define B_MAX_FILES		(512)				/* Maximum number of files */
#define B_FILL_CHAR		(0x77)				/* Fill byte for buffers */
#define B_FILL_WORD		(0x77777777)		/* Fill word for buffers */
#define B_MAX_BLOCKS	(8 * 1024)			/* Maximum allocated blocks */

/*
 *	Flags. The integrity value is used as an arbitrary value to fill the flags.
 */
#define B_INTEGRITY			0x8124000		/* Integrity value */
#define B_INTEGRITY_MASK	0xFFFF000		/* Integrity mask */
#define B_USE_MALLOC		0x1				/* Okay to use malloc if required */
#define B_USER_BUF			0x2				/* User supplied buffer for mem */

#define gstrcpy		strcpy
#define gstrncpy	strncpy
#define gstrncat	strncat
#define gstrlen		strlen
#define gstrcat		strcat
#define gstrcmp		strcmp
#define gstrncmp	strncmp
#define gstricmp	strcmpci
#define gstrchr		strchr
#define gstrrchr	strrchr
#define gstrtok		strtok
#define gstrnset	strnset
#define gstrrchr	strrchr
#define gstrspn	strspn
#define gstrcspn	strcspn
#define gstrstr		strstr
#define gstrtol		strtol

#define gfopen		fopen
#define gcreat		creat
#define gfgets		fgets
#define gfputs		fputs
#define gfscanf		fscanf
#define ggets		gets
#define gsprintf sprintf
#define gisalnum isalnum

#define a_assert(C)		if (1) ; else
#define T(a)    a

int bopen(void *buf, int bufsize, int flags);
void bclose(void);
void* balloc(B_ARGS_DEC, int size);
void bfree(B_ARGS_DEC, void *mp);
void bfreeSafe(B_ARGS_DEC, void *mp);
void* bcalloc(B_ARGS_DEC, int n, int size);

char_t *bstrdup(B_ARGS_DEC, char_t *s);
char_t *bmemdup(B_ARGS_DEC, char_t *s, int size);
void *brealloc(B_ARGS_DEC, void *mp, int newsize);
void bstats(int handle, void (*writefn)(int handle, char_t *fmt, ...));

#endif

