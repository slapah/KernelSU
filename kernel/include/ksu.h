#ifndef __KSU_H_KSU
#define __KSU_H_KSU

#include <linux/types.h>
#include <linux/cred.h>
#include <linux/workqueue.h>

#define KERNEL_SU_VERSION KSU_VERSION

extern struct cred *ksu_cred;
extern bool ksu_late_loaded;
extern bool allow_shell;
extern struct selinux_policy *backup_sepolicy;
extern bool ksu_no_custom_rc;

/*
 * Late-load init race gate. On a late load the whole system is already running,
 * so a KSU hook goes live the instant its slot is patched and can fire on
 * another CPU while kernelsu_init() is still building state (policy swap,
 * cache_sid, cred escape, allowlist, throne/observer). That async hook into a
 * half-initialized module is the kostep-region crash. This flag is false until
 * kernelsu_init() has finished every step; live hooks pass straight through to
 * the original until it is set with release ordering at the end of init.
 */
extern bool ksu_hooks_live;

static inline int startswith(char *s, char *prefix)
{
    return strncmp(s, prefix, strlen(prefix));
}

static inline int endswith(const char *s, const char *t)
{
    size_t slen = strlen(s);
    size_t tlen = strlen(t);
    if (tlen > slen)
        return 1;
    return strcmp(s + slen - tlen, t);
}

#endif
