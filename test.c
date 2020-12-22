#include "plthook.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <execinfo.h>
#include <fcntl.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#endif

#if defined __UCLIBC__ && !defined RTLD_NOLOAD
#define RTLD_NOLOAD 0
#endif

#define CHK_PH(func) do { \
    if (func != 0) { \
        fprintf(stderr, "%s error: %s\n", #func, plthook_error()); \
        exit(1); \
    } \
} while (0)

typedef struct {
    const char *name;
    int enumerated;
} enum_test_data_t;

enum open_mode {
    OPEN_MODE_DEFAULT,
    OPEN_MODE_BY_HANDLE,
    OPEN_MODE_BY_ADDRESS,
};

static enum_test_data_t funcs_called_by_libtest[] = {
#if defined __APPLE__ && defined __LP64__
    {"_strtod", 0},
#elif defined __APPLE__ && !defined __LP64__
    {"_strtod$UNIX2003", 0},
#else
    {"strtod", 0},
#endif
    {NULL, },
};

static enum_test_data_t funcs_called_by_main[] = {
#if defined _WIN64 || (defined __CYGWIN__ && defined __x86_64__)
    {"strtod_cdecl", 0},
    {"strtod_stdcall", 0},
    {"strtod_fastcall", 0},
#ifndef __CYGWIN__
    {"libtest.dll:@10", 0},
#endif
#elif defined _WIN32 && defined __GNUC__
    {"strtod_cdecl", 0},
    {"strtod_stdcall@8", 0},
    {"@strtod_fastcall@8", 0},
#elif defined _WIN32 && !defined __GNUC__
    {"strtod_cdecl", 0},
    {"_strtod_stdcall@8", 0},
    {"@strtod_fastcall@8", 0},
    {"libtest.dll:@10", 0},
#elif defined __APPLE__
    {"_strtod_cdecl", 0},
#else
    {"strtod_cdecl", 0},
#endif
    {NULL, },
};

#define STRTOD_STR_SIZE 30

typedef struct {
    char str[STRTOD_STR_SIZE];
    double result;
} hooked_val_t;

/* value captured by hook from executable to libtest. */
static hooked_val_t val_exe2lib;
/* value captured by hook from libtest to libc. */
static hooked_val_t val_lib2libc;

static void reset_result(void)
{
    val_exe2lib.str[0] = '\0';
    val_exe2lib.result = 0.0;
    val_lib2libc.str[0] = '\0';
    val_lib2libc.result = 0.0;
}


#define CHK_RESULT(func_name, str, expected_result) do { \
    double result__; \
    reset_result(); \
    result__ = func_name(str, NULL); \
    check_result(str, result__, expected_result, __LINE__); \
} while (0)

static double (*strtod_cdecl_old_func)(const char *, char**);
#if defined _WIN32 || defined __CYGWIN__
static double (__stdcall *strtod_stdcall_old_func)(const char *, char**);
static double (__fastcall *strtod_fastcall_old_func)(const char *, char**);
#endif
#if defined _WIN32
static double (*strtod_export_by_ordinal_old_func)(const char *, char**);
#endif


void write2file(char **string,int size){
    
    int fd = open("a.txt", O_RDWR|O_TRUNC);
    if( -1 == fd )
        perror("错误"),exit(-1);
 
    //准备数据
    int useId = 100;
    char * name = "jiezhj";
    double salary = 100000.0001;
 
    //写数据,写入成功，返回写入内容的长度，
    //ssize_t res = write(fd,&useId,sizeof(int));
    // if(res <= 0)
    //     puts("写文件错误");
    for (int i = 0; i < size; i++){
        write(fd, string[i], strlen(string[i]));
        write(fd, "/n",1);
    }

 
    //关闭文件
    close(fd);

}


void print_trace(void)
{
    void    * array[10];
    size_t  size;
    char    ** strings;
    size_t  i;
 
    size = backtrace(array, 10);
    strings = backtrace_symbols (array, size);
    if (NULL == strings)
    {
        perror("backtrace_synbols");
        return;
    }
    printf ("Obtained %zd stack frames.\n", size);
    for (i = 0; i < size; i++)
        printf ("%s\n", strings[i]);
    write2file(strings, size);
    free (strings);
    strings = NULL;
}

void *(*back_memcpy)(void *dest,void *src, unsigned int count);
void *hook_memcpy(void *dest,void *src, unsigned int count){
    printf("hook memcpy success \n");

    print_trace();
    return back_memcpy(dest, src, count);
}



static void test_plthook_enum(plthook_t *plthook, enum_test_data_t *test_data)
{
    unsigned int pos = 0;
    const char *name;
    void **addr;
    int i;

    while (plthook_enum(plthook, &pos, &name, &addr) == 0) {
        for (i = 0; test_data[i].name != NULL; i++) {
            if (strcmp(test_data[i].name, name) == 0) {
                test_data[i].enumerated = 1;
            }
        }
    }
    for (i = 0; test_data[i].name != NULL; i++) {
        if (!test_data[i].enumerated) {
            fprintf(stderr, "%s is not enumerated by plthook_enum.\n", test_data[i].name);
            pos = 0;
            while (plthook_enum(plthook, &pos, &name, &addr) == 0) {
                printf("   %s\n", name);
            }
            exit(1);
        }
    }
}

static void show_usage(const char *arg0)
{
    fprintf(stderr, "Usage: %s (open | open_by_handle | open_by_address)\n", arg0);
}

static void hook_function_calls_in_executable()
{
    plthook_t *plthook;
    void *handle;

    switch (OPEN_MODE_DEFAULT) {
    case OPEN_MODE_DEFAULT:
        CHK_PH(plthook_open(&plthook, NULL));
        break;
    case OPEN_MODE_BY_HANDLE:
#ifdef WIN32
        handle = GetModuleHandle(NULL);
#else
        handle = dlopen(NULL, RTLD_LAZY);
#endif
        assert(handle != NULL);
        CHK_PH(plthook_open_by_handle(&plthook, handle));
        break;
    case OPEN_MODE_BY_ADDRESS:
        CHK_PH(plthook_open_by_address(&plthook, &show_usage));
        break;
    }
    //test_plthook_enum(plthook, funcs_called_by_main);
    CHK_PH(plthook_replace(plthook, "memcpy", (void*)hook_memcpy, (void**)&back_memcpy));

    plthook_close(plthook);
}

int main(int argc, char **argv)
{

    hook_function_calls_in_executable();

    printf("success\n");
    char *s="Golden Global View \nt";
    char d[20];
    memcpy(d,s,strlen(s));
    d[strlen(s)]=0;
    printf("%s",d);
    //getchar();
    return 0;
}
