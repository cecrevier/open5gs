/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef MME_OPERATOR_H
#define MME_OPERATOR_H
#include "mme-context.h"
int mme_operator_open(void);
void mme_operator_close(void);
void mme_operator_process(ogs_pkbuf_t *request);
/* Executes on the MME event-loop thread; never from the metrics HTTP thread. */
const char *mme_operator_rebalance(mme_ue_t *ue);
#endif
