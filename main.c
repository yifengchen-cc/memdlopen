#include <stdio.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <stdbool.h>
#include <arpa/inet.h>

typedef struct {
    void * data;
    int size;
    int current;
} lib_t;

lib_t libdata;

#define LIBC "/lib/aarch64-linux-gnu/libc.so.6"

#define log(M, ...) fprintf(stdout, "[%s:%d] " M "\n", strrchr(__FILE__, '/') > 0 \
            ? strrchr(__FILE__, '/') + 1 : __FILE__ , __LINE__, ##__VA_ARGS__); 
#define error(M, ...) fprintf(stderr, "[%s:%d] " M " %s\n", strrchr(__FILE__, '/') > 0 \
            ? strrchr(__FILE__, '/') + 1 : __FILE__ , __LINE__, ##__VA_ARGS__, strerror(errno)); 

int     my_open(const char *pathname, int flags); 
//ssize_t my_pread64(int fd, void *buf, size_t count,off_t offset);
ssize_t my_read(int fd, void *buf, size_t count);
void *  my_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
int     my_fstat(int stat_ver, int fd, struct stat *buf);
int     my_close(int fd);

//0xfffff7fd2dd4                  sub    x2,  x24,  x1
//0xfffff7fd2dd8                  mov    w0,  w28
//0xfffff7fd2ddc                  add    x1,  x26,  x1
//0xfffff7fd2de0                  bl     0xfffff7fe3d20
//
//0xfffff7fd2dd4:	0x02	0x03	0x01	0xcb	0xe0	0x03	0x1c	0x2a
//0xfffff7fd2ddc:	0x41	0x03	0x01	0x8b	0xd0	0x43	0x00	0x94
const char read_pattern[] = {0x02,0x03,0x01,0xcb,0xe0,0x03,0x1c,0x2a,0x41,0x03,0x01,0x8b,0xd0,0x43,0x00,0x94};
#define read_pattern_length 16

//0xfffff7fd1d64                  str    w7,  [x29,  #144]
//0xfffff7fd1d68                  str    x11,  [x29,  #152]
//0xfffff7fd1d6c                  str    w12,  [x29,  #160]
//0xfffff7fd1d70                  bl     0xfffff7fe3e80
//
//0xfffff7fd1d64:	0xa7	0x93	0x00	0xb9	0xab	0x4f	0x00	0xf9
//0xfffff7fd1d6c:	0xac	0xa3	0x00	0xb9	0x44	0x48	0x00	0x94
const char mmap_pattern[] = {0xa7,0x93,0x00,0xb9,0xab,0x4f,0x00,0xf9,0xac,0xa3,0x00,0xb9,0x44,0x48,0x00,0x94};
#define mmap_pattern_length 16

/*
// 0x00007ffff7de26c2 <+2466>:sub    rsp,rax
// 0x00007ffff7de26c5 <+2469>:mov    edi,r15d
// 0x00007ffff7de26c8 <+2472>:lea    r12,[rsp+0x4c7]
// 0x00007ffff7de26cd <+2477>:call   0x7ffff7df3380 <lseek64>
//              
// 0x7ffff7de26c2 <_dl_map_object_from_fd+2466>:0x48 0x29 0xc4 0x44 0x89 0xff 0x4c 0x8d
// 0x7ffff7de26ca <_dl_map_object_from_fd+2474>:0x64 0x24 0x47 0xe8 0xae 0x0c 0x01 0x00
const char pread_pattern[] = {0x48,0x29,0xc4,0x44,0x89,0xff,0x4c,0x8d,0x64,0x24,0x47,0xe8};
#define pread_pattern_length 12
*/

//0xfffff7fd1f60                  add    x2,  x29,  #0xf0
//0xfffff7fd1f64                  mov    w1,  w21
//0xfffff7fd1f68                  mov    w0,  #0x0                  
//0xfffff7fd1f6c                  bl     0xfffff7fe3a20
//
//0xfffff7fd1f60:	0xa2	0xc3	0x03	0x91	0xe1	0x03	0x15	0x2a
//0xfffff7fd1f68:	0x00	0x00	0x80	0x52	0xad	0x46	0x00	0x94
//
const char fxstat_pattern[] = {0xa2,0xc3,0x03,0x91,0xe1,0x03,0x15,0x2a,0x00,0x00,0x80,0x52,0xad,0x46,0x00,0x94};
#define fxstat_pattern_length 16

//0xfffff7fd24c4                  add    x0,  x0,  x1
//0xfffff7fd24c8                  str    x0,  [x27,  #1104]
//0xfffff7fd24cc                  mov    w0,  w21
//0xfffff7fd24d0                  bl     0xfffff7fe3b20
//
//0xfffff7fd24c4:	0x00	0x00	0x01	0x8b	0x60	0x2b	0x02	0xf9
//0xfffff7fd24cc:	0xe0	0x03	0x15	0x2a	0x94	0x45	0x00	0x94  
const char close_pattern[] = {0x00,0x00,0x01,0x8b,0x60,0x2b,0x02,0xf9,0xe0,0x03,0x15,0x2a,0x94,0x45,0x00,0x94};
#define close_pattern_length 16

//0xfffff7fd2da4                  mov    x0,  x19
//0xfffff7fd2da8                  mov    w1,  #0x80000           
//0xfffff7fd2dac                  bl     0xfffff7fe3c00
//
//0xfffff7fd2da4:	0xe0	0x03	0x13	0xaa	0x01	0x01	0xa0	0x52
//0xfffff7fd2dac:	0x95	0x43	0x00	0x94
const char open_pattern[] = {0xe0,0x03,0x13,0xaa,0x01,0x01,0xa0,0x52,0x95,0x43,0x00,0x94};
#define open_pattern_length 12


const char* patterns[] = {read_pattern, mmap_pattern, fxstat_pattern, close_pattern,
                          open_pattern, NULL};
const size_t pattern_lengths[] = {read_pattern_length, mmap_pattern_length, 
                                  fxstat_pattern_length, close_pattern_length, open_pattern_length, 0};
const char* symbols[] = {"read", "mmap","fxstat", "close", "open", NULL};
uint64_t functions[] = {(uint64_t)&my_read, (uint64_t)&my_mmap, (uint64_t)&my_fstat, 
                        (uint64_t)&my_close, (uint64_t)&my_open, 0}; 

size_t page_size;


bool load_library_from_file(char * path, lib_t *libdata) {
    struct stat st;
    FILE * file;
    size_t read;

    if ( stat(path, &st) < 0 ) {
        error("failed to stat");
        return false;
    }
    
    log("lib size is %zu", st.st_size); 

    libdata->size = st.st_size;
    libdata->data = malloc( st.st_size );
    libdata->current = 0;

    file = fopen(path, "r");
    
    read = fread(libdata->data, 1, st.st_size, file); 
    log("read %zu bytes", read);

    fclose(file);

    return true;
}

bool load_library_from_network(int port, lib_t *libdata) {
    int serverfd = 0;
    int clientfd = 0;
    int value = 0;
    struct sockaddr_in addr = {0}; 
    size_t got = 0;
    char buffer[4096] = {0};
    uint32_t allocated = 0;

    serverfd = socket(AF_INET, SOCK_STREAM, 0);

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port); 

    setsockopt(serverfd, SOL_SOCKET, SO_REUSEADDR, &value, sizeof(int));

    if ( bind(serverfd, (struct sockaddr*)&addr, sizeof(addr)) != 0 ) { 
        log("failed to bind");
        return false;
    }

    if ( listen(serverfd, 1) != 0 ) {
        log("failed to listen");
        return false;
    }

    clientfd = accept(serverfd, NULL, NULL);
    if ( clientfd == -1 ) {
        log("accept failed");
        return false;
    }

    memset(libdata, 0, sizeof(lib_t));
    while ( (got = read(clientfd, buffer, 4096 )) > 0 ){
        log("got %zu", got); 
        if ( libdata->size + got > allocated ) {
            allocated += 4096;
            libdata->data = realloc(libdata->data, allocated);  
            if ( libdata->data == NULL ) {
                return false;
            }
        } 
        memcpy(libdata->data + libdata->size, buffer, got);
        libdata->size += got;
    }

    close(clientfd);
    close(serverfd);

    return true;
}


int my_open(const char *pathname, int flags) {
    void *handle;
    int (*mylegacyopen)(const char *pathnam, int flags);

    handle = dlopen (LIBC, RTLD_NOW);
    mylegacyopen = dlsym(handle, "open");

    log("in my_open");
    if ( strstr(pathname, "magic.so") != 0 ){
        log("magic open requested, fd is 0x66");
        return 0x66;
    }
    return mylegacyopen(pathname, flags);
}

/*
off_t my_lseek64(int fd, off_t offset, int whence) {
    void *handle;
    int (*mylegacylseek)(int fd, off_t offset, int whence);

    log("in my_lseek, fd is 0x%x", fd);
    handle = dlopen (LIBC, RTLD_NOW);
    mylegacylseek = dlsym(handle, "lseek");

    if ( fd == 0x66 ) {
        if ( whence == SEEK_SET ) {
            libdata.current = offset;
        }
        if ( whence == SEEK_CUR ) {
            libdata.current += offset;
        }
        if ( whence == SEEK_END ) {
            libdata.current = libdata.size + offset;
        } 
        log("current offset = %d", libdata.current)
        return libdata.current;
    }
    return mylegacylseek(fd, offset, whence); 
}
*/

ssize_t my_read(int fd, void *buf, size_t count){
    void *handle;
    int (*mylegacyread)(int fd, void *buf, size_t count);

    log("in my_read, fd is 0x%x", fd);
    handle = dlopen (LIBC, RTLD_NOW);
    mylegacyread = dlsym(handle, "read");

    if ( fd == 0x66 ) {
        size_t size = 0;    
        if ( libdata.size - libdata.current >= count ) {
            size = count;
        } else {
            size = libdata.size - libdata.current;
        }
        log("magic read, requested size : %d, i will read %d",(int)count, (int)size);
        memcpy(buf, libdata.data+libdata.current, size);
        libdata.current += size;
        return size;
    }
    return mylegacyread(fd, buf, count);
}

void * my_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset){
    int mflags = 0;
    void * ret = NULL;
    uint64_t start = 0;

    log("in my mmap, fd is 0x%x", fd);
    if ( fd == 0x66 ) {
        
        log("length is %d / flags = %d", (int)length, flags);
        //  0x802 : MAP_PRIVATE,MAP_DENYWRITE
        //  0x812 : MAP_PRIVATE,MAP_FIXED,MAP_DENYWRITE
        mflags = MAP_PRIVATE|MAP_ANON;
        if ( (flags & MAP_FIXED) != 0 ) {
            mflags |= MAP_FIXED;
        }
        ret = mmap(addr, length, PROT_READ|PROT_WRITE|PROT_EXEC, mflags, -1, 0);
        memcpy(ret, libdata.data, length > libdata.size ? libdata.size : length);

        start = (uint64_t)ret & (((size_t)-1) ^ (page_size - 1));
        while ( start < (uint64_t)ret) {
            mprotect((void *)start, page_size, prot); 
            start += page_size;
        }
        log("mmap : [0x%lx,0x%lx]", (uint64_t)ret, (uint64_t)ret+length);
        return ret;
    }

    return mmap(addr, length, prot, flags, fd, offset);
}


int my_fstat(int stat_ver, int fd, struct stat *buf){
    void *handle;
    int (*mylegacyfstat)(int fd, struct stat *buf);

    log("in my fstat, fd is 0x%x", fd);
    handle = dlopen (LIBC, RTLD_NOW);
    mylegacyfstat = dlsym(handle, "__fxstat64");

    if ( fd == 0x66 ) {
        log("magic fstat requested")
        memset(buf, 0, sizeof(struct stat));
        buf->st_size = libdata.size;
        buf->st_ino = 0x666;
        return 0;
    }
    return mylegacyfstat(fd, buf); 
}

int my_close(int fd) {

    log("in my close, fd is 0x%x", fd);
    if (fd == 0x66 ) {
        log("magic close requested");
        return 0;
    } 

    return close(fd);
}


bool search_and_patch(uint64_t start_addr, uint64_t end_addr, const char* pattern, const size_t length, const char* symbol, const uint64_t replacement_addr ) {

    bool     found = false;
    int32_t  offset = 0;
    uint64_t tmp_addr = 0;
    uint64_t symbol_addr = 0;
    char * code = NULL;
    void * page_addr = NULL;

    /*
    // stp     x29, x30, [sp, #-16]!
    // mov x29,sp
    // ldr x16,=0x1234567890abcdef
    // br    x16
    // ldp     x29, x30, [sp], #16 
    // ret
    // asm("stp x29,x30,[sp,#-16]!;mov x29,sp;ldr x16,=0x1234567890abcdef;br x16;ldp x29,x30,[sp],#16;ret;", arch = 'arm64', os = 'linux').hex()
    char stub[] = {0xfd,0x7b,0xbf,0xa9,0xfd,0x03,0x00,0x91,0x90,0x00,0x00,0x58,0x00,0x02,0x1f,0xd6,0xfd,0x7b,0xc1,0xa8,0xc0,0x03,0x5f,0xd6,0,0,0,0,0,0,0,0};
    size_t stub_length = 32;
    */

    char stub[] = {0x50,0x00,0x00,0x58,0x00,0x02,0x1f,0xd6,0,0,0,0,0,0,0,0};
    size_t stub_length = 16;
    size_t off = 8;

    tmp_addr = start_addr;
    while ( ! found && tmp_addr+length < end_addr) {
        if ( memcmp((void*)tmp_addr, (void*)pattern, length) == 0 ) {
            log("found %s candidate @ 0x%lx", symbol, tmp_addr);
            found = true;
            continue;
        }
        tmp_addr+=4;
    }

    if ( ! found ) {
        return false;
    }

    offset = *((uint64_t*)(tmp_addr-4 + length));
    symbol_addr = tmp_addr -4  + length + (((offset<<6)&0xffffffff)>>6)*4;

    log("offset is %d, %s addr is 0x%lx", offset, symbol, symbol_addr);

    log("my_%s is @ 0x%lx", symbol, replacement_addr);

    code = malloc(stub_length * sizeof(char));
    memcpy(code, stub, stub_length);
    memcpy(code+off, &replacement_addr, sizeof(uint64_t));


    // changing page protection before writting
    page_addr = (void*) (((size_t)symbol_addr) & (((size_t)-1) ^ (page_size - 1)));
    mprotect(page_addr, page_size, PROT_READ | PROT_WRITE); 
    memcpy((void*)symbol_addr, code, stub_length);
    mprotect(page_addr, page_size, PROT_READ | PROT_EXEC); 
    return true;
}



bool find_ld_in_memory(uint64_t *addr1, uint64_t *addr2) {
    FILE* f = NULL;
    char  buffer[1024] = {0};
    char* tmp = NULL;
    char* start = NULL;
    char* end = NULL;
    bool  found = false;

	if ((f = fopen("/proc/self/maps", "r")) == NULL){
		error("fopen");
        return found;
    }

	while ( fgets(buffer, sizeof(buffer), f) ){

		if ( strstr(buffer, "r-xp") == 0 ) {
			continue;
        }
        if ( strstr(buffer, "ld-2.31.so") == 0 ) {
            continue;        
        }

        buffer[strlen(buffer)-1] = 0;
        tmp = strrchr(buffer, ' ');
        if ( tmp == NULL || tmp[0] != ' ')
            continue;
        ++tmp;
		start = strtok(buffer, "-");
		*addr1 = strtoul(start, NULL, 16);
		end = strtok(NULL, " ");
		*addr2 = strtoul(end, NULL, 16);

        log("found ld : [%lx,%lx]", *addr1, *addr2);
        found = true;
    }
    fclose(f);
    return found;
}

void print_help( void ) {
    fprintf(stdout, "memdlopen :\n\
            -f path : load a library from a file\n\
            -l port : listen on a given port to get library\n");
}

int main(int argc, char **argv) {
    uint64_t start = 0;
    uint64_t end = 0;
    size_t i = 0;
    char * path = NULL;
    int port = 0;
    char c;

    page_size = sysconf(_SC_PAGESIZE);

    c = getopt (argc, argv, "f:l:h");
        switch (c) {
            case 'f':
                path = optarg;
                log("path is %s", path);
                break;
            case 'l':
                port = atoi(optarg);
                log("port is %d", port);
                break;
            case 'h':
                print_help();
                return 0;
            case '?':
                if (optopt == 'f' || optopt == 'l'){
                    error("Option -%c requires an argument.", optopt);
                } else {
                    error("Unknown option character `\\x%x'.", optopt);
                }
                return 1;
            default:
                abort();
        }
        
    
    if ( path == NULL && port == 0 ) {
        print_help();
        return 1;
    }

    log("starting (pid=%d)",getpid());

    if ( path != NULL && ! load_library_from_file(path, &libdata) ) {
        error("failed to load library from file %s", path);
        return 1;
    }

    if ( port != 0 && ! load_library_from_network(port, &libdata) ) {
        error("failed to load library from network");
        return 1;
        
    }

    if ( ! find_ld_in_memory(&start, &end) ) {
        error("failed to find ld in memory"); 
        return 2;
    }

    while ( patterns[i] != NULL ) {
        if ( ! search_and_patch(start, end, patterns[i], pattern_lengths[i], symbols[i], functions[i]) ) {
            error("failed to patch %s", symbols[i]);       
            return 3;
        } 
        ++i;
    }

    log("dlopen adress is @ 0x%lx", (uint64_t)dlopen);
    if ( dlopen("./magic.so", RTLD_LAZY) == NULL ) {
        error("[-] failed to dlopen : %s", dlerror());    
        return 4;
    }

    log("sleeping...");
    while(1) {
        sleep(1);
    }

    return 0;
}
