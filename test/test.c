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
/*    char a = 'A';
    unsigned int b = 1;
    int c = 1;
    trans(b);
    trans(c);*/
    unsigned int a=20;
    unsigned int b=20;
    int childstatus;
    int status;
    status = fork();
    if (status<0){
        syslog(LOG_DEBUG,"Failed to creat child.");
    } else if (status==0){
        sleep(5);
        syslog(LOG_DEBUG,"set sid");
        setsid();
        syslog(LOG_DEBUG,"this is child");
        sleep(5);
        syslog(LOG_DEBUG,"child is still alive");
    } else {
        syslog(LOG_DEBUG,"Child start at %d.",status);
        wait(&childstatus);
        syslog(LOG_DEBUG,"Parent die.");
        exit(0);
    }
    return 0;
}
