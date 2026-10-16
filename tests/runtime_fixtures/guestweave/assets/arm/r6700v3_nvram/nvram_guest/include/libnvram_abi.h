#ifndef LIBNVRAM_ABI_H
#define LIBNVRAM_ABI_H

int nvram_init(void);
char *nvram_get(const char *name);
int nvram_set(const char *name, const char *value);
int nvram_commit(void);

#endif