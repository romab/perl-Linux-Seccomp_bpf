#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "ppport.h"


MODULE = Linux::Seccomp_bpf		PACKAGE = Linux::Seccomp_bpf

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/prctl.h>
#include <linux/seccomp.h>
#include <seccomp.h>
#include "seccomp-bpf.h"

int
scmp_bpf_is_available()
CODE:
    int r;
    r = prctl(PR_GET_SECCOMP, 0, 0, 0, 0);
    if (r < 0) {
        RETVAL=0;
        switch (errno) {
            case ENOSYS:
                fprintf(stderr, "seccomp not available: Needs at least kernel 2.6.23\n");
                break;
            case EINVAL:
                fprintf(stderr, "SECCOMP_FILTER is not available.\nYour kernel needs\n\
                    CONFIG_HAVE_ARCH_SECCOMP_FILTER=y\nCONFIG_SECCOMP_FILTER=y\nCONFIG_SECCOMP=y\n");
                break;
            default:
                fprintf(stderr, "unknown PR_GET_SECCOMP error: %s\n",
                        strerror(errno));
        }
    }
    else {
        RETVAL=1;
    }
OUTPUT:
    RETVAL

void
inl_scmp_bpf_install_filter(SV* syscalls)
INIT:
     I32 numcalls = 0;

     SvGETMAGIC(syscalls);
     if ((!SvROK(syscalls)) || (SvTYPE(SvRV(syscalls)) != SVt_PVAV)
       || ((numcalls = av_len((AV *)SvRV(syscalls))) < 0))
     {
        XSRETURN_UNDEF;
     }
CODE:
    scmp_filter_ctx ctx;
    int i;
    int r;

    r = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    if (r < 0) {
        perror("failed to set PR_ST_NO_NEW_PRIVS:");
        exit(errno);
    }
    // libseccomp initialization
    ctx = seccomp_init(SCMP_ACT_TRAP);
    if (ctx == NULL) {
        fprintf(stderr, "seccomp_init failed\n");
        exit(-1);
    }

    for (i = 0; i < numcalls ; i++) {
        STRLEN l;
        char * h = SvPV(*av_fetch((AV *)SvRV(syscalls), i, 0), l);
        int num = atoi(h);
        r = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, num, 0);
        if (r < 0)  {
            fprintf(stderr, "Failed to add syscall %d\n", r);
        }
    }

    r = seccomp_load(ctx);
    if (r != 0) {
        fprintf(stderr, "seccomp_load failed with exit code %d\n", r);
        exit(r);
    }

    seccomp_release(ctx);
