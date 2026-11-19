# ruff: noqa: E501  (the header bodies are C declarations, kept one per line as in libc)
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
INCLUDE_WINDOWS = Path(__file__).resolve().parent / "include-win"

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
int setvbuf(FILE *, char *, int, size_t); void setbuf(FILE *, char *); void perror(const char *);
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
struct timespec { time_t tv_sec; long tv_nsec; };
typedef int clockid_t;
#define CLOCK_REALTIME 0
#define CLOCK_MONOTONIC 1
#define CLOCK_BOOTTIME 7
int clock_gettime(clockid_t, struct timespec *);
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
/* glibc's value; mbedtls picks its clock_gettime and gmtime_r paths from it. */
#define _POSIX_VERSION 200809L
""",
    "sys/types.h": '#include "../_shim.h"\n',
    "sys/stat.h": """
#include "../_shim.h"
struct stat { unsigned long st_dev, st_ino; mode_t st_mode; unsigned long st_nlink; uid_t st_uid; gid_t st_gid; off_t st_size; time_t st_mtime; };
#define S_IFMT 0170000
#define S_IFDIR 0040000
#define S_IFREG 0100000
#define S_ISDIR(m) (((m) & S_IFMT) == S_IFDIR)
#define S_ISREG(m) (((m) & S_IFMT) == S_IFREG)
int stat(const char *, struct stat *); int fstat(int, struct stat *);
""",
    "sys/time.h": """
#include "../_shim.h"
struct timeval { time_t tv_sec; long tv_usec; };
int gettimeofday(struct timeval *, void *);
""",
    "sys/auxv.h": """
/* mbedtls probes AArch64 crypto extensions at run time on Linux. */
unsigned long getauxval(unsigned long);
#define AT_HWCAP 16
#define AT_HWCAP2 26
""",
    "dirent.h": """
typedef struct _shim_DIR DIR;
struct dirent { unsigned long d_ino; long d_off; unsigned short d_reclen; unsigned char d_type; char d_name[256]; };
DIR *opendir(const char *); struct dirent *readdir(DIR *); int closedir(DIR *);
""",
}


# Searched before include/ by the PE builds (corpus/real.py --pe), which
# compile for *-pc-windows-msvc with no Windows SDK. The libraries take their
# _WIN32 paths there, as a real Windows build does, so these declare what
# those paths use, UCRT-style: errno and the standard streams are function
# calls, and the Win32 API is __declspec(dllimport) as in the SDK, so its
# calls load the IAT directly while CRT calls go through linker thunks.
WINDOWS_HEADERS: dict[str, str] = {
    "errno.h": """
#include_next <errno.h>
#undef errno
int *_errno(void);
#define errno (*_errno())
""",
    "stdio.h": """
#include_next <stdio.h>
FILE *__acrt_iob_func(unsigned);
#define stdin (__acrt_iob_func(0))
#define stdout (__acrt_iob_func(1))
#define stderr (__acrt_iob_func(2))
FILE *_popen(const char *, const char *); int _pclose(FILE *);
int _fseeki64(FILE *, long long, int); long long _ftelli64(FILE *);
""",
    "stdlib.h": """
#include_next <stdlib.h>
size_t wcstombs(char *, const wchar_t *, size_t);
/* MSVC declares its byte-swap intrinsics here; lz4's xxhash calls them. */
unsigned short _byteswap_ushort(unsigned short); unsigned long _byteswap_ulong(unsigned long);
unsigned long long _byteswap_uint64(unsigned long long);
""",
    "io.h": """
#include "_shim.h"
int _open(const char *, int, ...); int _wopen(const wchar_t *, int, ...);
int _read(int, void *, unsigned); int _write(int, const void *, unsigned); int _close(int);
long long _lseeki64(int, long long, int);
/* The POSIX names UCRT still exports, with its signatures. */
int read(int, void *, unsigned); int write(int, const void *, unsigned); int close(int);
""",
    "malloc.h": """
#include "_shim.h"
size_t _msize(void *);
void *_aligned_malloc(size_t, size_t); void _aligned_free(void *);
""",
    "windows.h": """
#include "_shim.h"
typedef unsigned long DWORD;
typedef int BOOL;
typedef void *HANDLE;
typedef struct HINSTANCE__ *HMODULE;
typedef const char *LPCSTR;
typedef char *LPSTR;
typedef long long (*FARPROC)(void);
#define WINAPI __stdcall
#define MAX_PATH 260
#define FORMAT_MESSAGE_IGNORE_INSERTS 0x00000200
#define FORMAT_MESSAGE_FROM_SYSTEM 0x00001000
__declspec(dllimport) HMODULE WINAPI LoadLibraryExA(LPCSTR, HANDLE, DWORD);
__declspec(dllimport) FARPROC WINAPI GetProcAddress(HMODULE, LPCSTR);
__declspec(dllimport) BOOL WINAPI FreeLibrary(HMODULE);
__declspec(dllimport) DWORD WINAPI GetModuleFileNameA(HMODULE, LPSTR, DWORD);
__declspec(dllimport) DWORD WINAPI FormatMessageA(DWORD, const void *, DWORD, DWORD, LPSTR, DWORD, va_list *);
__declspec(dllimport) DWORD WINAPI GetLastError(void);
/* Structured exception handling, which SQLite uses on MSVC (SQLITE_USE_SEH). */
typedef unsigned long long ULONG_PTR;
typedef struct _EXCEPTION_RECORD {
  DWORD ExceptionCode, ExceptionFlags; struct _EXCEPTION_RECORD *ExceptionRecord;
  void *ExceptionAddress; DWORD NumberParameters; ULONG_PTR ExceptionInformation[15];
} EXCEPTION_RECORD;
typedef struct _EXCEPTION_POINTERS { EXCEPTION_RECORD *ExceptionRecord; void *ContextRecord; } EXCEPTION_POINTERS;
#define EXCEPTION_IN_PAGE_ERROR 0xC0000006L
#define EXCEPTION_EXECUTE_HANDLER 1
#define EXCEPTION_CONTINUE_SEARCH 0
unsigned long _exception_code(void); void *_exception_info(void);
#define GetExceptionCode _exception_code
#define GetExceptionInformation() ((EXCEPTION_POINTERS *)_exception_info())
__declspec(dllimport) void WINAPI RaiseException(DWORD, DWORD, DWORD, const ULONG_PTR *);
""",
}


def main() -> None:
    for directory, headers in ((INCLUDE, HEADERS), (INCLUDE_WINDOWS, WINDOWS_HEADERS)):
        for name, body in sorted(headers.items()):
            path = directory / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                # mbedtls includes <time.h> more than once per translation unit;
                # struct definitions must not be repeated.
                "/* Generated by corpus/shim/gen_shim.py; declarations only. */\n#pragma once\n"
                + body.lstrip("\n"),
                encoding="utf-8",
                newline="\n",
            )


if __name__ == "__main__":
    main()
