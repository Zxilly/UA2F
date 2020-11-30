//
// Created by 12009 on 2020/12/1.
//

#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <stdlib.h>

int main(){
    int j=20;
    printf("%ld\n",clock());
    for(int i=0;i<=1000000000;i++){
        j++;
    }
    printf("%ld\n",clock());
    printf("%ld",CLOCKS_PER_SEC);
}