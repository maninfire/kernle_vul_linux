#include "common.h"
#include <linux/module.h>
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/moduleparam.h>
#include <linux/unistd.h>
#include <linux/kallsyms.h>
#include <asm/cacheflush.h>
#include <asm/special_insns.h>

void **g_syscall_table;
#ifndef __NR_dup2
#define __NR_dup2 (63 + 60)
#endif

uint close_cr0a(void){
    uint cr0=0;
    uint ret = 0;

    asm volatile("movq %%cr0, %%rax"
            :"=a"(cr0) 
              );
    ret=cr0;
    cr0&=0xfffeffff;
    asm volatile( "movq %%rax, %%cr0"
                :
                :"a"(cr0)
                );
    return ret;
}

asmlinkage long (*kernel_sys_write)(unsigned int fd, const char __user *buf, size_t count);
asmlinkage long (*kernel_sys_read)(unsigned int fd, char __user *buf, size_t count);
asmlinkage int  (*kernel_sys_dup2)(int fds, int fdt);

asmlinkage long sys_read_emu ( unsigned int fd, char __user *buf, size_t count )
{
    if (count == 78787878)
       return 78;

    return kernel_sys_read(fd, buf, count);
}

asmlinkage long sys_write_emu ( unsigned int fd, char __user *buf, size_t count )
{
    if (count == 78787878)
       return 78;

    return kernel_sys_write(fd, buf, count);
}

int (*set_page_rw)(unsigned long, int);
asmlinkage int sys_dup2_emu(int fds, int fdt)
{
   printk("sys_dup2 called with %d %d.\n", fds, fdt);
   if (-77 == fds && -88 == fdt)
       return -78;

   return kernel_sys_dup2(fds, fdt);
}
void disable_write_protection(void)
{
  unsigned long cr0 = read_cr0();
  clear_bit(16, &cr0);
  //write_cr0(cr0);
  native_write_cr0(cr0);
  //printk("disable_write_protection write_cr0 addr:%p\n",write_cr0);
}
void enable_write_protection(void)
{
  unsigned long cr0 = read_cr0();
  set_bit(16, &cr0);
  //write_cr0(cr0);
  native_write_cr0(cr0);
  //printk("enable_write_protection write_cr0 addr:%p\n",write_cr0);
}
static int __init syshook_init(void)
{
    // sys_call_table address in System.map
    g_syscall_table = kallsyms_lookup_name("sys_call_table");
    //set_page_rw = kallsyms_lookup_name("set_memory_rw");

    kernel_sys_read  = g_syscall_table[__NR_read];
    kernel_sys_write = g_syscall_table[__NR_write];
    printk("kernel_sys_read: %p kernel_sys_write: %p\n",
	  kernel_sys_read, kernel_sys_write);

    unsigned long addr_read = (unsigned long)&g_syscall_table[__NR_read];
    printk("sys_read addr:%p \n",addr_read);
    //set_page_rw(PAGE_ALIGN(addr), 1);
    unsigned long addr_write = (unsigned long)&g_syscall_table[__NR_write];
    printk("sys_write add:%p \n",addr_write);
    //set_page_rw(PAGE_ALIGN(addr), 1);
    disable_write_protection();
    g_syscall_table[__NR_read]  = sys_read_emu;
    g_syscall_table[__NR_write] = sys_write_emu;
    //enable_write_protection();
    return 0;
}

static void __exit syshook_exit(void)
{
   // Restore the original call
   //disable_write_protection();
   g_syscall_table[__NR_read] = kernel_sys_read;
   g_syscall_table[__NR_write] = kernel_sys_write;
   //enable_write_protection();
}


module_init(syshook_init);
module_exit(syshook_exit);


MODULE_LICENSE("GPL");
