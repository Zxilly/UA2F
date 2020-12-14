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
    char *a = "23333333";
    char b[] = "233";

    printf("%d",memcmp(a,&b,3));
    return 0;
}
