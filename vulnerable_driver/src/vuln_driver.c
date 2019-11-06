#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/miscdevice.h>
#include <linux/slab.h>
#include <linux/ioctl.h>
#include <linux/uaccess.h>

#include "vuln_driver.h"
#include "buffer_overflow.h"
#include "null_pointer_deref.h"
#include "use_after_free.h"
#include "arbitrary_rw.h"
#include "uninitialised_stack_var.h"
#include "mymap.h"
//#include "klog.h"


static long do_ioctl(struct file *filp, unsigned int cmd, unsigned long args)
{
	int ret;
	unsigned long *p_arg = (unsigned long *)args;
 	ret = 0;

	switch(cmd) {
		case DRIVER_TEST:
		{
			printk(KERN_WARNING "[x] Talking to device [x]\n");
			int i=klog_sprintf(KERN_WARNING"[x] Talking to device [x]   klog_sprintf\n");
			printk(KERN_WARNING "klog_buffer->data :%s i len %d  pos :%d \n",klog_buffer->data,i,klog_buffer->pos);
			break;
		}
		case BUFFER_OVERFLOW:
			buffer_overflow((char *) args);
			break;
		case NULL_POINTER_DEREF:
			null_pointer_deref(args);
			break;
		case ALLOC_UAF_OBJ:
			alloc_uaf_obj(args);
			break;
		case USE_UAF_OBJ:
			use_uaf_obj();
			break;
		case TEST_USE_UAF_OBJ:
			test_use_uaf_obj();
			break;
		case ALLOC_K_OBJ:
			alloc_k_obj((k_object *) args);
			break;
		case FREE_UAF_OBJ:
			free_uaf_obj();
			break;
		case ARBITRARY_RW_INIT:
		{
			init_args i_args;
			int ret;

			if(copy_from_user(&i_args, p_arg, sizeof(init_args)))
				return -EINVAL;

			ret = arbitrary_rw_init(&i_args);
			break;
		}
		case ARBITRARY_RW_REALLOC:
		{
			realloc_args r_args;

			if(copy_from_user(&r_args, p_arg, sizeof(realloc_args)))
				return -EINVAL;

			ret = realloc_mem_buffer(&r_args);
			break;
		}
		case ARBITRARY_RW_READ:
		{
			read_args r_args;

			if(copy_from_user(&r_args, p_arg, sizeof(read_args)))
				return -EINVAL;

			ret = read_mem_buffer(r_args.buff, r_args.count);
			break;
		}
		case INIT_KLOG:
		{
			klog_buffer = kmalloc(sizeof(log_mem_buffer), GFP_KERNEL);

			if(klog_buffer == NULL)
				goto error_no_mem;

			klog_buffer->data = kmalloc(0x1000, GFP_KERNEL);

			if(klog_buffer->data == NULL)
				goto error_no_mem_free;

			klog_buffer->data_size = 0x1000;
			klog_buffer->pos = 0;
			break;
		}
		case GET_KLOG:
		{
			log_read_args r_args;

			if(copy_from_user(&r_args, p_arg, sizeof(log_read_args)))
			 	return -EINVAL;

			if(klog_buffer == NULL)
				return -EINVAL;

			loff_t pos;
			int ret;
			int ret2;
			pos = klog_buffer->pos;

			if((pos) > klog_buffer->data_size)
				return -EINVAL;
			//r_args.count=pos;
			printk("GET_KLOG data:%p pos: %d",klog_buffer->data,klog_buffer->pos);
			ret = copy_to_user(r_args.buff, klog_buffer->data,pos);
			ret2 = copy_to_user(r_args.count,&pos,1);
			//klog_buffer->pos=0;
			break;
		}
		case ARBITRARY_RW_SEEK:
		{
			seek_args s_args;

			if(copy_from_user(&s_args, p_arg, sizeof(seek_args)))
				return -EINVAL;

			ret = seek_mem_buffer(&s_args);
			break;
		}
		case ARBITRARY_RW_WRITE:
		{
			write_args w_args;

			if(copy_from_user(&w_args, p_arg, sizeof(write_args)))
				return -EINVAL;

			ret = write_mem_buffer(&w_args);
			showdatebyterw(g_mem_buffer->data + g_mem_buffer->pos,100);
			break;
		}
		case UNINITIALISED_STACK_ALLOC:
		{
			ret = copy_to_stack((char *)p_arg);
			break;
		}
		case UNINITIALISED_STACK_USE:
		{
			use_obj_args use_obj_arg;
			
			if(copy_from_user(&use_obj_arg, p_arg, sizeof(use_obj_args)))
				return -EINVAL;
			
			
			use_stack_obj(&use_obj_arg);
	
			break;
		}
		case DRIVER_MAP:
		{
			showdatebyterw(buffer,100);
			//showdatebyte(ptr,30);
			break;
		}
		case DRIVER_MAP_SHOW:
		{
			//klog_sprintf("drivermap  %p",buffer);
			void (*test_get_root)(void)=buffer;
			(*test_get_root)();
			//get_root();
			//commit_creds(prepare_kernel_cred(0));
			break;
		}
	}

	return ret;

	error_no_mem:
			return -ENOMEM;

	error_no_mem_free:
		kfree(g_mem_buffer);
		return -ENOMEM;
}

static int vuln_release(struct inode *inode, struct file *filp)
{
	if(g_mem_buffer != NULL)
	{
		if(g_mem_buffer->data != NULL)
			kfree(g_mem_buffer->data);
		kfree(g_mem_buffer);
		g_mem_buffer = NULL;
	}

	return 0;
}

/**
* The operations allowed by userspace applications.
* We only really allow access through the ioctl interface.
*/
static struct file_operations vuln_ops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = do_ioctl,
	.release = vuln_release,
	.mmap = my_map, 
	.open = my_open, 
};

/**
* The miscdevice api is much simpler than creating a class
* and attaching it to a node using class_create etc.
*/
static struct miscdevice vuln_device = {
	MISC_DYNAMIC_MINOR, DEVICE_NAME, &vuln_ops
};

/**
* Register the device.
*/
static int vuln_module_init(void)
{
	int ret;

	ret = misc_register(&vuln_device);

	if(ret < 0) {
		printk(KERN_WARNING "[-] Error registering device [-]\n");
	}

	printk(KERN_WARNING "[!!!] use_stack_obj @%p [!!!]\n", use_stack_obj);
 	//myprintf("sum(16进制输出)dsfddfdsdfsdfsdfdsfsdf:\n");
  	//myprintf("sum(16进制输出):%p\n",use_stack_obj);  
	//内存分配 
	buffer = (unsigned long *)kmalloc(PAGE_SIZE,GFP_KERNEL); 
	//将该段内存设置为保留 
	SetPageReserved(virt_to_page(buffer)); 

	return ret;
}

/**
* Deregister the device.
*/
static void vuln_module_exit(void)
{
	misc_deregister(&vuln_device);

	//清除保留 
	ClearPageReserved(virt_to_page(buffer)); 
	//释放内存 
	kfree(buffer); 
}

module_init(vuln_module_init);
module_exit(vuln_module_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Invictus");
MODULE_DESCRIPTION("");
