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

void trans(unsigned int a){
    printf("%u",a);
}


int main(){
    char a = 'A';
    unsigned int b = 1;
    int c = 1;
    trans(b);
    trans(c);
}
