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
 
 
#define DEVICE_NAME "mymap" 
 
 
static unsigned char array[10]={0,1,2,3,4,5,6,7,8,9}; 
static unsigned char *buffer; 
 
 
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
 
//得到物理地址 
page = virt_to_phys(buffer); 
//将用户空间的一个vma虚拟内存区映射到以page开始的一段连续物理页面上 
if(remap_pfn_range(vma,start,page>>PAGE_SHIFT,size,PAGE_SHARED))//第三个参数是页帧号，由物理地址右移PAGE_SHIFT得到 
return -1; 
 
//往该内存写10字节数据 
for(i=0;i<10;i++) 
buffer[i] = array[i]; 
 
return 0; 
} 

static void showdate(void* addr,int len){
		 if(1){
		 	printk(KERN_WARNING "[x]showdate start\n");
		 	unsigned long int* paddr=(unsigned long int*)addr;
		 	int i=0;
		 	//void **p=&&addr;
		 	for(;i<len;){
				//mdelay(1);
		 		printk(KERN_WARNING "[x]addr 0x%llx value 0x%llx  +8:0x%llx -8:0x%llx i:%d\n",(paddr+i),*(paddr+i),*(paddr+i+1),*(paddr+i-1),i);
				i=i+1;		 	
			}
		 	printk(KERN_WARNING "[x]showdate end\n");
		 }

	}

static void showdate1(unsigned char* addr,int len){
		 if(1){
		 	printk(KERN_WARNING "[x]showdate1 start\n");
		 	//unsigned long int* paddr=(unsigned long int*)addr;
		 	int i=0;
		 	//void **p=&&addr;
		 	for(;i<len;){
				//mdelay(1);
				if(i>=1){
			 		printk(KERN_WARNING "[x]addr 0x%llx value 0x%d  +8:0x%d -8:0x%d i:%d\n",&addr[i],addr[i],addr[i+1],addr[i-1],i);

				}else{
			 		printk(KERN_WARNING "[x]addr 0x%llx value 0x%d  +8:0x%d i:%d\n",&addr[i],addr[i],addr[i+1],i);
				}
	 			i=i+1;	
			}
		 	printk(KERN_WARNING "[x]showdate1 end\n");
		 }

	}
#define IOCTL_NUM 0xFE

#define DRIVER_TEST _IO (IOCTL_NUM, 0) 
#define DRIVER_MAP _IO (IOCTL_NUM, 1) 

static long do_ioctl(struct file *filp, unsigned int cmd, unsigned long args)
{
	int ret;
	unsigned long *userva = (unsigned long *)args;
 	ret = 0;

	switch(cmd) {
	case DRIVER_TEST:
	{
		showdate(buffer,8);
		showdate1(buffer,8);
		break;
	}
	 //case DRIVER_MAP:
	 // {
	//	strcuct *page userpg = virt_to_page(userva)；
	//	kernelva = vmap(userpg,...);
	//	break;
	//   }
	}
}
 
static struct file_operations dev_fops = { 
.owner = THIS_MODULE, 
.open = my_open, 
.mmap = my_map, 
.unlocked_ioctl = do_ioctl,
}; 
 
static struct miscdevice misc = { 
.minor = MISC_DYNAMIC_MINOR, 
.name = DEVICE_NAME, 
.fops = &dev_fops, 
}; 
 
 
static int __init dev_init(void) 
{ 
int ret; 
 
//注册混杂设备 
ret = misc_register(&misc); 
//内存分配 
buffer = (unsigned char *)kmalloc(PAGE_SIZE,GFP_KERNEL); 
//将该段内存设置为保留 
SetPageReserved(virt_to_page(buffer)); 
 
return ret; 
} 
 
 
static void __exit dev_exit(void) 
{ 
//注销设备 
misc_deregister(&misc); 
//清除保留 
ClearPageReserved(virt_to_page(buffer)); 
//释放内存 
kfree(buffer); 
} 
 
 
module_init(dev_init); 
module_exit(dev_exit); 
MODULE_LICENSE("GPL"); 
MODULE_AUTHOR("LKN@SCUT"); 
