#include <unistd.h> 
#include <stdio.h> 
#include <stdlib.h> 
#include <string.h> 
#include <fcntl.h> 
#include <linux/fb.h> 
#include <sys/mman.h> 
#include <sys/ioctl.h> 
 
#define PAGE_SIZE 4096 
 
#define IOCTL_NUM 0xFE

#define DRIVER_TEST _IO (IOCTL_NUM, 0) 

static unsigned char array[10]={9,9,9,9,9,9,9,9,9,9};
int main(int argc , char *argv[]) 
{ 
int fd; 
int i; 
unsigned char *p_map; 
 
//打开设备 
fd = open("/dev/mymap",O_RDWR); 
if(fd < 0) 
{ 
printf("open fail\n"); 
exit(1); 
} 
 
//内存映射 
p_map = (unsigned char *)mmap(0, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED,fd, 0); 
if(p_map == MAP_FAILED) 
{
	printf("mmap fail\n");
	goto here;
}
 
//打印映射后的内存中的前10个字节内容 
for(i=0;i<10;i++){
	printf("address 0x%llx value%d\n",&p_map[i],p_map[i]); 

}


ioctl(fd,DRIVER_TEST,NULL);
for(i=0;i<10;i++) 
p_map[i] = array[i]; 
ioctl(fd,DRIVER_TEST,NULL);
here: 
munmap(p_map, PAGE_SIZE); 
return 0; 
} 