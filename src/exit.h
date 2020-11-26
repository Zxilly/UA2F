//
// Created by 12009 on 2020/11/25.
//

#ifndef UA2F_EXIT_H
#define UA2F_EXIT_H

#endif //UA2F_EXIT_H

void exitnfq(struct nfq_handle *h){
    printf("close nft queue handle.\n");
    if (nfq_close(h) < 0) {
        fprintf(stderr, "error during nfq_close()\n");
        exit(1);
    }
}