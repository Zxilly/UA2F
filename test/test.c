#include <libipset/ipset.h>

#include <stdio.h>

int main(){
    char cmd[50] = "add nohttp 192.168.1.1,223";
    ipset_load_types();
    struct ipset *Pipset = ipset_init();

    ipset_parse_line(Pipset,cmd);
}