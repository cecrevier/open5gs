/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "mme/mme-operator.h"
#include "mme/mme-sm.h"
#include "mme/mme-s10.h"
#include "mme/mme-gtp-path.h"
#include "mme/s1ap-path.h"
#include "mme/mme-event.h"
#include "core/abts.h"

#ifdef __linux__
static mme_ue_t operator_ue;
static enb_ue_t operator_radio_ue;
static mme_enb_t operator_radio;
static sgw_ue_t operator_sgw;
static mme_sess_t operator_session;
static mme_bearer_t operator_bearer;
static bool operator_peer = true, operator_busy;
static int operator_sends, operator_action, operator_result;
static long operator_cause;
static bool fixture_peers(void) { return operator_peer; }
static bool fixture_busy(const mme_ue_t *ue) { (void)ue; return operator_busy; }
static bool fixture_clear(const mme_ue_t *ue) { (void)ue; return false; }
static int fixture_xacts(mme_ue_t *ue, uint8_t org) { (void)ue; (void)org; return 0; }
static enb_ue_t *fixture_radio_ue(ogs_pool_id_t id) { return id == 2 ? &operator_radio_ue : NULL; }
static mme_enb_t *fixture_radio(ogs_pool_id_t id) { return id == 3 ? &operator_radio : NULL; }
static sgw_ue_t *fixture_sgw(ogs_pool_id_t id) { return id == 4 ? &operator_sgw : NULL; }
static mme_ue_t *fixture_imsi(const char *imsi) { return !strcmp(imsi,"001010000000101") ? &operator_ue : NULL; }
static int fixture_release(enb_ue_t *enb_ue, mme_ue_t *ue, int action)
{
    (void)ue; operator_sends++; operator_action=action;
    operator_cause=enb_ue->relcause.cause; return operator_result;
}
static ogs_poll_t *fixture_add_poll(ogs_pollset_t *set, short when,
        ogs_socket_t fd, ogs_poll_handler_f handler, void *data)
{
    (void)set; (void)when; (void)fd; (void)handler; (void)data;
    return (ogs_poll_t *)1;
}
static void fixture_remove_poll(ogs_poll_t *poll) { (void)poll; }
void fixture_operator_process(ogs_pkbuf_t *buffer);
static int fixture_enqueue(ogs_queue_t *queue, void *data)
{
    mme_event_t *event=data;
    (void)queue;
    fixture_operator_process(event->pkbuf); mme_event_free(event);
    return OGS_OK;
}
/* Exercise production request parsing and eligibility; only the final network
 * dispatch/context lookups are replaced with deterministic local fixtures. */
#define mme_s10_has_peers fixture_peers
#define mme_s10_handover_busy fixture_busy
#define mme_s10_source_committed fixture_clear
#define mme_ue_have_session_release_pending fixture_clear
#define mme_ue_xact_count fixture_xacts
#define enb_ue_find_by_id fixture_radio_ue
#define mme_enb_find_by_id fixture_radio
#define sgw_ue_find_by_id fixture_sgw
#define mme_ue_find_by_imsi_bcd fixture_imsi
#define mme_gtp_send_release_access_bearers_request fixture_release
#define mme_operator_rebalance fixture_operator_rebalance
#define mme_operator_open fixture_operator_open
#define mme_operator_close fixture_operator_close
#define mme_operator_process fixture_operator_process
#define ogs_pollset_add(set,when,fd,handler,data) fixture_add_poll(NULL,when,fd,handler,data)
#define ogs_pollset_remove fixture_remove_poll
#define ogs_queue_trypush(queue,event) fixture_enqueue(NULL,event)
int fixture_operator_open(void);
void fixture_operator_close(void);
const char *fixture_operator_rebalance(mme_ue_t *ue);
#include "../../src/mme/mme-operator.c"

static void setup_operator(void)
{
    memset(&operator_ue,0,sizeof(operator_ue));
    memset(&operator_radio_ue,0,sizeof(operator_radio_ue));
    memset(&operator_radio,0,sizeof(operator_radio));
    memset(&operator_session,0,sizeof(operator_session));
    memset(&operator_bearer,0,sizeof(operator_bearer));
    memset(requests,0,sizeof(requests)); request_next=0;
    operator_peer=true;operator_busy=false;operator_sends=0;operator_result=OGS_OK;
    operator_ue.enb_ue_id=2;operator_ue.sgw_ue_id=4;
    operator_ue.security_context_available=1;
    OGS_FSM_TRAN(&operator_ue.sm,emm_state_registered);
    OGS_FSM_TRAN(&operator_bearer.sm,esm_state_active);
    operator_radio_ue.enb_id=3;operator_radio.state.s1_setup_success=true;
    operator_bearer.qos.index=9;operator_bearer.qos.arp.priority_level=8;
    ogs_list_init(&operator_ue.sess_list);ogs_list_init(&operator_session.bearer_list);
    ogs_list_add(&operator_ue.sess_list,&operator_session);
    ogs_list_add(&operator_session.bearer_list,&operator_bearer);
}
static void rebalance_policy(abts_case *tc, void *data)
{
    (void)data;setup_operator();
    ABTS_TRUE(tc,fixture_operator_rebalance(&operator_ue)==NULL);
    ABTS_INT_EQUAL(tc,1,operator_sends);
    ABTS_INT_EQUAL(tc,OGS_GTP_RELEASE_OPERATOR_REBALANCE,operator_action);
    ABTS_INT_EQUAL(tc,S1AP_CauseRadioNetwork_load_balancing_tau_required,operator_cause);
    setup_operator();operator_peer=false;
    ABTS_PTR_NOTNULL(tc,fixture_operator_rebalance(&operator_ue));ABTS_INT_EQUAL(tc,0,operator_sends);
    setup_operator();operator_ue.enb_ue_id=0;
    ABTS_PTR_NOTNULL(tc,fixture_operator_rebalance(&operator_ue));ABTS_INT_EQUAL(tc,0,operator_sends);
    setup_operator();operator_busy=true;
    ABTS_PTR_NOTNULL(tc,fixture_operator_rebalance(&operator_ue));ABTS_INT_EQUAL(tc,0,operator_sends);
    setup_operator();operator_bearer.qos.index=1;
    ABTS_PTR_NOTNULL(tc,fixture_operator_rebalance(&operator_ue));ABTS_INT_EQUAL(tc,0,operator_sends);
    setup_operator();operator_bearer.qos.arp.priority_level=1;
    ABTS_PTR_NOTNULL(tc,fixture_operator_rebalance(&operator_ue));ABTS_INT_EQUAL(tc,0,operator_sends);
    setup_operator();operator_ue.nas_eps.attach.value=OGS_NAS_ATTACH_TYPE_EPS_EMERGENCY_ATTACH;
    ABTS_PTR_NOTNULL(tc,fixture_operator_rebalance(&operator_ue));ABTS_INT_EQUAL(tc,0,operator_sends);
    setup_operator();operator_result=OGS_ERROR;
    ABTS_PTR_NOTNULL(tc,fixture_operator_rebalance(&operator_ue));
    ABTS_INT_EQUAL(tc,0,operator_radio_ue.relcause.group);
}
static void request_contract(abts_case *tc, void *data)
{
    char output[512],duplicate[512];
    const char *input="{\"operation\":\"rebalance\",\"request_id\":\"12345678-1234-1234-1234-123456789012\",\"imsi\":\"001010000000101\"}";
    (void)data;setup_operator();
    process_request("{\"operation\":\"capabilities\"}",output);
    ABTS_TRUE(tc,strstr(output,"\"protocol\":1")!=NULL);
    process_request(input,output);process_request(input,duplicate);
    ABTS_TRUE(tc,strstr(output,"\"status\":\"requested\"")!=NULL);
    ABTS_STR_EQUAL(tc,output,duplicate);ABTS_INT_EQUAL(tc,1,operator_sends);
    process_request("{\"operation\":\"rebalance\",\"request_id\":\"12345678-1234-1234-1234-123456789012\",\"imsi\":\"001010000000102\"}",output);
    ABTS_TRUE(tc,strstr(output,"\"status\":\"rejected\"")!=NULL);ABTS_INT_EQUAL(tc,1,operator_sends);
    process_request("{\"operation\":\"capabilities\",\"target\":\"fake\"}",output);
    ABTS_TRUE(tc,strstr(output,"\"status\":\"rejected\"")!=NULL);
}
static void unix_transport(abts_case *tc, void *data)
{
    char directory[]="/tmp/ogs-mme-operator-XXXXXX",server[108],client_path[108],reply[512];
    struct sockaddr_un target={0},client_address={0};
    struct stat st;
    int client;
    ssize_t n;
    const char *request="{\"operation\":\"capabilities\"}";
    (void)data;
    ABTS_PTR_NOTNULL(tc,mkdtemp(directory));
    ogs_snprintf(server,sizeof(server),"%s/control.sock",directory);
    ogs_snprintf(client_path,sizeof(client_path),"%s/client.sock",directory);
    setenv("OPEN5GS_MME_OPERATOR_SOCKET",server,1);
    ABTS_INT_EQUAL(tc,OGS_OK,fixture_operator_open());
    ABTS_INT_EQUAL(tc,0,lstat(server,&st));ABTS_INT_EQUAL(tc,0600,st.st_mode&0777);
    ABTS_INT_EQUAL(tc,OGS_ERROR,fixture_operator_open());
    client=socket(AF_UNIX,SOCK_DGRAM|SOCK_NONBLOCK,0);
    ABTS_TRUE(tc,client>=0);
    client_address.sun_family=AF_UNIX;
    ogs_cpystrn(client_address.sun_path,client_path,sizeof(client_address.sun_path));
    ABTS_INT_EQUAL(tc,0,bind(client,(struct sockaddr *)&client_address,sizeof(client_address)));
    target.sun_family=AF_UNIX;ogs_cpystrn(target.sun_path,server,sizeof(target.sun_path));
    ABTS_INT_EQUAL(tc,(int)strlen(request),(int)sendto(client,request,strlen(request),0,(struct sockaddr *)&target,sizeof(target)));
    receive_request(OGS_POLLIN,control_fd,NULL);
    n=recv(client,reply,sizeof(reply)-1,0);ABTS_TRUE(tc,n>0);
    if(n>0){reply[n]='\0';ABTS_TRUE(tc,strstr(reply,"\"protocol\":1")!=NULL);}
    close(client);unlink(client_path);fixture_operator_close();
    ABTS_TRUE(tc,lstat(server,&st)<0);
    chmod(directory,0755);ABTS_INT_EQUAL(tc,OGS_ERROR,fixture_operator_open());
    unsetenv("OPEN5GS_MME_OPERATOR_SOCKET");ABTS_INT_EQUAL(tc,0,rmdir(directory));
}
#endif

abts_suite *test_mme_operator(abts_suite *suite);
abts_suite *test_mme_operator(abts_suite *suite)
{
    suite=ADD_SUITE(suite);
#ifdef __linux__
    abts_run_test(suite,rebalance_policy,NULL);
    abts_run_test(suite,request_contract,NULL);
    abts_run_test(suite,unix_transport,NULL);
#endif
    return suite;
}
