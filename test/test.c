//
// Created by 12009 on 2020/11/27.
//

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>

#include <linux/types.h>
#include <syslog.h>
#include <wait.h>

void trans(unsigned int a){
    printf("%u",a);
}


int main(){
//    pid_t startup_status,sid;
//    signal(SIGCHLD, SIG_IGN);
//    signal(SIGHUP, SIG_IGN); // ignore 父进程挂掉的关闭信号
//    startup_status = fork();
//    if (startup_status < 0) {
//        perror("Creat Daemon");
//        closelog();
//        exit(EXIT_FAILURE);
//    } else if (startup_status == 0) {
//        syslog(LOG_NOTICE, "UA2F parent daemon start at [%d].", getpid());
//        sid = setsid();
//        if (sid < 0) {
//            perror("Second Dameon Claim");
//            exit(EXIT_FAILURE);
//        } else if (sid > 0) {
//            syslog(LOG_NOTICE, "UA2F parent daemon set sid at [%d].", sid);
//            startup_status = fork(); // 第二次fork，派生出一个孤儿
//            if (startup_status<0) {
//                perror("Second Daemon Fork");
//                exit(EXIT_FAILURE);
//            } else if (startup_status>0){
//                syslog(LOG_NOTICE, "UA2F true daemon will start at [%d], daemon parent suicide.", startup_status);
//                exit(EXIT_SUCCESS);
//            } else {
//                syslog(LOG_NOTICE, "UA2F true daemon start at [%d].", getpid());
//            }
//        }
//    } else {
//        syslog(LOG_NOTICE, "Try to start daemon parent at [%d], parent process will suicide.", startup_status);
//        printf("Try to start daemon parent at [%d], parent process will suicide.", startup_status);
//        exit(EXIT_SUCCESS);
//    }
//    syslog(LOG_NOTICE, "Everything seems OK");
    printf("%d\n",42);
    printf("%u\n",ntohl(42));
    return 0;
}
