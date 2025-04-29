#ifndef C_SNIPPETS_H
#define C_SNIPPETS_H

#define NR_DUMMY_SECRETS 16
#define DUMMY_SECRET_P &dummy_secrets[0]
#define DUMMY_SECRET_ALT_P &dummy_secrets[1]

extern uint8_t dummy_secrets[NR_DUMMY_SECRETS];

void populate_bhb_bcond(int);
void t_leak(register char *frbuf, register uint8_t *secret_ptr);
void t_alt(register char *frbuf);
void t_empty();

#endif