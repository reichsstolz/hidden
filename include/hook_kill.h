#ifdef MODULE
extern struct module __this_module;
#define THIS_MODULE (&__this_module)
#else
#define THIS_MODULE ((struct module *)0)
#endif

void init_hook_kill(void);

void remove_hook_kill(void);