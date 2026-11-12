/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "mme/mme-context.h"
#include "mme/s1ap-path.h"
#include "mme/s1ap-build.h"
#include "mme/sbc-handler.h"
#include "core/abts.h"

static mme_context_t routing_context;
static mme_enb_t routing_enbs[3];
static int routing_sent[3];
static mme_context_t *routing_self(void) { return &routing_context; }
static ogs_pkbuf_t *routing_packet(sbc_pws_data_t *p)
{ (void)p; return (ogs_pkbuf_t *)1; }
static int routing_send(mme_enb_t *enb,ogs_pkbuf_t *packet,uint16_t stream)
{ (void)packet;(void)stream;routing_sent[enb-routing_enbs]++;return OGS_OK; }

int routing_write(sbc_pws_data_t *p);
int routing_stop(sbc_pws_data_t *p);
#define mme_self routing_self
#define s1ap_build_write_replace_warning_request routing_packet
#define s1ap_build_kill_request routing_packet
#define s1ap_send_to_enb routing_send
#define sbc_handle_write_replace_warning_request routing_write
#define sbc_handle_stop_warning_request routing_stop
#include "mme/sbc-handler.c"
#undef mme_self
#undef s1ap_build_write_replace_warning_request
#undef s1ap_build_kill_request
#undef s1ap_send_to_enb
#undef sbc_handle_write_replace_warning_request
#undef sbc_handle_stop_warning_request

static void explicit_tai_routing(abts_case *tc,void *data)
{
    sbc_pws_data_t p;
    int i;
    memset(&routing_context,0,sizeof(routing_context));
    memset(routing_enbs,0,sizeof(routing_enbs));
    memset(routing_sent,0,sizeof(routing_sent));
    ogs_list_init(&routing_context.enb_list);
    for(i=0;i<3;i++) {
        routing_enbs[i].state.s1_setup_success=true;
        routing_enbs[i].num_of_supported_ta_list=1;
        ogs_plmn_id_build(&routing_enbs[i].supported_ta_list[0].plmn_id,1,1,i==1?3:2);
        routing_enbs[i].supported_ta_list[0].tac=i==2?2:1;
        ogs_list_add(&routing_context.enb_list,&routing_enbs[i]);
    }
    memset(&p,0,sizeof(p));p.explicit_tais=true;p.no_of_tai=1;
    p.tai[0]=routing_enbs[0].supported_ta_list[0];
    ABTS_INT_EQUAL(tc,1,routing_write(&p));
    ABTS_INT_EQUAL(tc,1,routing_sent[0]);
    ABTS_INT_EQUAL(tc,0,routing_sent[1]); /* Same TAC, different MNC length. */
    ABTS_INT_EQUAL(tc,0,routing_sent[2]); /* Same PLMN, different TAC. */
    p.no_of_tai=2;p.tai[1]=routing_enbs[2].supported_ta_list[0];
    ABTS_INT_EQUAL(tc,2,routing_stop(&p));
    ABTS_INT_EQUAL(tc,0,routing_sent[1]);
    p.no_of_tai=0;
    ABTS_INT_EQUAL(tc,0,routing_write(&p)); /* An empty explicit scope is never global. */
    p.no_of_tai=1;routing_enbs[0].state.s1_setup_success=false;
    ABTS_INT_EQUAL(tc,0,routing_write(&p));
}

abts_suite *test_sbc_routing(abts_suite *suite)
{
    suite=ADD_SUITE(suite)
    abts_run_test(suite,explicit_tai_routing,NULL);
    return suite;
}
