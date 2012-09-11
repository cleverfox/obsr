#ifndef OBSRD_H
#define OBSRD_H


enum sockid
{
    SOCK_NG=0,
    SOCK_AUTH,
    SOCK_ACCT,
    SOCK_COA,
};

enum sesact
{
    SES_UPDATE=1,
    SES_DELETE,
    SES_CREATE,
};

#endif // OBSRD_H
