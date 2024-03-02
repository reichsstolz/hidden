



int bash_run(const char *bash_command, int wait_policy) {
    const char *argv_main[] = {
            "/bin/bash",
            "-c",
            bash_command,
            NULL,
    };
    const char *envp_main[] = {
            "HOME=/",
            "TERM=linux",
            "PATH=/sbin:/bin:/usr/sbin:/usr/bin",
            NULL,
    };
    return call_usermodehelper(argv_main[0], argv_main, envp_main, wait_policy);
}

