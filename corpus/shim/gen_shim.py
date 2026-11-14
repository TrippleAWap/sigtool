"""Write the declarations-only libc shim used to cross-build real libraries.

    python corpus/shim/gen_shim.py

There is no Linux sysroot on a typical cross host, and the corpus never links
against libc anyway: libraries are built as shared objects, so libc calls stay
undefined imports exactly as in a distro build. The shim declares only the
surface the pinned corpus libraries use. Types follow each target ABI through
clang's predefined macros, so the same headers serve LP64 and ILP32.
"""

from __future__ import annotations

from pathlib import Path

INCLUDE = Path(__file__).resolve().parent / "include"

HEADERS: dict[str, str] = {
    "_shim.h": """
#ifndef SHIM_H
#define SHIM_H
#include <stddef.h>
#include <stdarg.h>
typedef __INTPTR_TYPE__ ssize_t;
typedef long long off_t;
typedef long time_t;
typedef long clock_t;
typedef int pid_t;
typedef unsigned int mode_t;
typedef unsigned int uid_t;
typedef unsigned int gid_t;
#endif
""",
    "stdint.h": """
#ifndef SHIM_STDINT_H
#define SHIM_STDINT_H
typedef __INT8_TYPE__ int8_t; typedef __UINT8_TYPE__ uint8_t;
typedef __INT16_TYPE__ int16_t; typedef __UINT16_TYPE__ uint16_t;
typedef __INT32_TYPE__ int32_t; typedef __UINT32_TYPE__ uint32_t;
typedef __INT64_TYPE__ int64_t; typedef __UINT64_TYPE__ uint64_t;
typedef __INTPTR_TYPE__ intptr_t; typedef __UINTPTR_TYPE__ uintptr_t;
typedef __INTMAX_TYPE__ intmax_t; typedef __UINTMAX_TYPE__ uintmax_t;
typedef int8_t int_least8_t; typedef uint8_t uint_least8_t;
typedef int16_t int_least16_t; typedef uint16_t uint_least16_t;
typedef int32_t int_least32_t; typedef uint32_t uint_least32_t;
typedef int64_t int_least64_t; typedef uint64_t uint_least64_t;
typedef int8_t int_fast8_t; typedef uint8_t uint_fast8_t;
typedef intptr_t int_fast16_t; typedef uintptr_t uint_fast16_t;
typedef intptr_t int_fast32_t; typedef uintptr_t uint_fast32_t;
typedef int64_t int_fast64_t; typedef uint64_t uint_fast64_t;
#define INT8_MAX __INT8_MAX__
#define INT16_MAX __INT16_MAX__
#define INT32_MAX __INT32_MAX__
#define INT64_MAX __INT64_MAX__
#define INT8_MIN (-INT8_MAX-1)
#define INT16_MIN (-INT16_MAX-1)
#define INT32_MIN (-INT32_MAX-1)
#define INT64_MIN (-INT64_MAX-1)
#define UINT8_MAX __UINT8_MAX__
#define UINT16_MAX __UINT16_MAX__
#define UINT32_MAX __UINT32_MAX__
#define UINT64_MAX __UINT64_MAX__
#define INTPTR_MAX __INTPTR_MAX__
#define INTPTR_MIN (-INTPTR_MAX-1)
#define UINTPTR_MAX __UINTPTR_MAX__
#define SIZE_MAX __SIZE_MAX__
#define INTMAX_MAX __INTMAX_MAX__
#define UINTMAX_MAX __UINTMAX_MAX__
#define PTRDIFF_MAX __PTRDIFF_MAX__
#define INT64_C(c) c ## LL
#define UINT64_C(c) c ## ULL
#define INT32_C(c) c
#define UINT32_C(c) c ## U
#endif
""",
    "inttypes.h": """
#include <stdint.h>
#define PRId64 "lld"
#define PRIu64 "llu"
#define PRIx64 "llx"
#define PRIi64 "lli"
""",
    "stdlib.h": """
#include "_shim.h"
#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1
#define RAND_MAX 2147483647
void *malloc(size_t); void *calloc(size_t, size_t); void *realloc(void *, size_t); void free(void *);
void abort(void) __attribute__((noreturn)); void exit(int) __attribute__((noreturn));
int atexit(void (*)(void)); char *getenv(const char *); int system(const char *);
int atoi(const char *); long atol(const char *); double atof(const char *);
long strtol(const char *, char **, int); unsigned long strtoul(const char *, char **, int);
long long strtoll(const char *, char **, int); unsigned long long strtoull(const char *, char **, int);
double strtod(const char *, char **); float strtof(const char *, char **);
void qsort(void *, size_t, size_t, int (*)(const void *, const void *));
void *bsearch(const void *, const void *, size_t, size_t, int (*)(const void *, const void *));
int abs(int); long labs(long); int rand(void); void srand(unsigned); int mkstemp(char *);
""",
    "string.h": """
#include "_shim.h"
void *memcpy(void *, const void *, size_t); void *memmove(void *, const void *, size_t);
void *memset(void *, int, size_t); int memcmp(const void *, const void *, size_t);
void *memchr(const void *, int, size_t); size_t strlen(const char *); size_t strnlen(const char *, size_t);
char *strcpy(char *, const char *); char *strncpy(char *, const char *, size_t);
char *strcat(char *, const char *); char *strncat(char *, const char *, size_t);
int strcmp(const char *, const char *); int strncmp(const char *, const char *, size_t);
int strcoll(const char *, const char *); char *strchr(const char *, int); char *strrchr(const char *, int);
char *strstr(const char *, const char *); char *strpbrk(const char *, const char *);
size_t strspn(const char *, const char *); size_t strcspn(const char *, const char *);
char *strerror(int); char *strdup(const char *); char *strtok(char *, const char *);
""",
    "stdio.h": """
#include "_shim.h"
typedef struct _shim_FILE FILE;
typedef long long fpos_t;
extern FILE *stdin, *stdout, *stderr;
#define EOF (-1)
#define BUFSIZ 8192
#define FILENAME_MAX 4096
#define L_tmpnam 20
#define SEEK_SET 0
#define SEEK_CUR 1
#define SEEK_END 2
#define _IOFBF 0
#define _IOLBF 1
#define _IONBF 2
FILE *fopen(const char *, const char *); FILE *freopen(const char *, const char *, FILE *);
FILE *fdopen(int, const char *); int fclose(FILE *); int fflush(FILE *);
size_t fread(void *, size_t, size_t, FILE *); size_t fwrite(const void *, size_t, size_t, FILE *);
int fgetc(FILE *); int getc(FILE *); int ungetc(int, FILE *); int fputc(int, FILE *); int putc(int, FILE *);
int putchar(int); int getchar(void); char *fgets(char *, int, FILE *); int fputs(const char *, FILE *);
int puts(const char *);
int printf(const char *, ...); int fprintf(FILE *, const char *, ...); int sprintf(char *, const char *, ...);
int snprintf(char *, size_t, const char *, ...); int vsnprintf(char *, size_t, const char *, va_list);
int vfprintf(FILE *, const char *, va_list); int vsprintf(char *, const char *, va_list);
int sscanf(const char *, const char *, ...); int fscanf(FILE *, const char *, ...);
int fseek(FILE *, long, int); long ftell(FILE *); int fseeko(FILE *, off_t, int); off_t ftello(FILE *);
void rewind(FILE *); int feof(FILE *); int ferror(FILE *); void clearerr(FILE *);
int setvbuf(FILE *, char *, int, size_t); void perror(const char *);
int remove(const char *); int rename(const char *, const char *); FILE *tmpfile(void); char *tmpnam(char *);
FILE *popen(const char *, const char *); int pclose(FILE *);
void flockfile(FILE *); void funlockfile(FILE *); int getc_unlocked(FILE *); int fileno(FILE *);
""",
    "ctype.h": """
int isalnum(int); int isalpha(int); int iscntrl(int); int isdigit(int); int isgraph(int);
int islower(int); int isprint(int); int ispunct(int); int isspace(int); int isupper(int);
int isxdigit(int); int tolower(int); int toupper(int);
""",
    "math.h": """
#define HUGE_VAL (__builtin_huge_val())
#define INFINITY (__builtin_inff())
#define NAN (__builtin_nanf(""))
#define isnan(x) __builtin_isnan(x)
#define isinf(x) __builtin_isinf(x)
#define isfinite(x) __builtin_isfinite(x)
#define signbit(x) __builtin_signbit(x)
double fabs(double); double floor(double); double ceil(double); double fmod(double, double);
double sqrt(double); double pow(double, double); double exp(double); double log(double);
double log2(double); double log10(double); double sin(double); double cos(double); double tan(double);
double asin(double); double acos(double); double atan(double); double atan2(double, double);
double frexp(double, int *); double ldexp(double, int); double modf(double, double *);
double round(double); double trunc(double); double rint(double);
long lround(double); long long llround(double); float floorf(float); float fabsf(float);
double copysign(double, double);
""",
    "errno.h": """
extern int *__errno_location(void);
#define errno (*__errno_location())
#define ENOENT 2
#define EINTR 4
#define EIO 5
#define ENOMEM 12
#define EACCES 13
#define EINVAL 22
#define ERANGE 34
""",
    "time.h": """
#include "_shim.h"
struct tm { int tm_sec, tm_min, tm_hour, tm_mday, tm_mon, tm_year, tm_wday, tm_yday, tm_isdst; };
#define CLOCKS_PER_SEC 1000000L
time_t time(time_t *); clock_t clock(void); double difftime(time_t, time_t); time_t mktime(struct tm *);
struct tm *localtime(const time_t *); struct tm *gmtime(const time_t *);
struct tm *localtime_r(const time_t *, struct tm *); struct tm *gmtime_r(const time_t *, struct tm *);
size_t strftime(char *, size_t, const char *, const struct tm *);
""",
    "setjmp.h": """
typedef long jmp_buf[64];
int setjmp(jmp_buf) __attribute__((returns_twice));
void longjmp(jmp_buf, int) __attribute__((noreturn));
int _setjmp(jmp_buf) __attribute__((returns_twice));
void _longjmp(jmp_buf, int) __attribute__((noreturn));
""",
    "locale.h": """
struct lconv { char *decimal_point; char *thousands_sep; };
struct lconv *localeconv(void); char *setlocale(int, const char *);
#define LC_CTYPE 0
#define LC_NUMERIC 1
#define LC_TIME 2
#define LC_COLLATE 3
#define LC_MONETARY 4
#define LC_ALL 6
""",
    "signal.h": """
typedef int sig_atomic_t;
typedef void (*__sighandler_t)(int);
#define SIG_DFL ((__sighandler_t)0)
#define SIG_IGN ((__sighandler_t)1)
#define SIGINT 2
__sighandler_t signal(int, __sighandler_t);
""",
    "assert.h": """
#ifdef NDEBUG
#define assert(x) ((void)0)
#else
void __assert_fail(const char *, const char *, unsigned, const char *) __attribute__((noreturn));
#define assert(x) ((x) ? (void)0 : __assert_fail(#x, __FILE__, __LINE__, __func__))
#endif
""",
    "fcntl.h": """
#include "_shim.h"
#define O_RDONLY 0
#define O_WRONLY 1
#define O_RDWR 2
#define O_CREAT 0100
#define O_EXCL 0200
#define O_TRUNC 01000
#define O_APPEND 02000
int open(const char *, int, ...);
""",
    "unistd.h": """
#include "_shim.h"
ssize_t read(int, void *, size_t); ssize_t write(int, const void *, size_t); int close(int);
off_t lseek(int, off_t, int); int unlink(const char *); int access(const char *, int);
""",
    "sys/types.h": '#include "../_shim.h"\n',
    "sys/stat.h": '#include "../_shim.h"\n',
}


def main() -> None:
    for name, body in sorted(HEADERS.items()):
        path = INCLUDE / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            "/* Generated by corpus/shim/gen_shim.py; declarations only. */\n" + body.lstrip("\n"),
            encoding="utf-8",
            newline="\n",
        )


if __name__ == "__main__":
    main()
