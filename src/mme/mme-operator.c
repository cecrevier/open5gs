/* Copyright (C) 2026 Open5GS contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "mme-operator.h"
#include "mme-sm.h"
#include "mme-s10.h"
#include "mme-gtp-path.h"
#include "mme-event.h"
#include "s1ap-path.h"
#include "third-party/cjson/cJSON.h"
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <math.h>

#ifdef __linux__

/* Private local O+M interface, disabled unless explicitly configured in the
 * service environment. It never exposes mutations through Prometheus HTTP. */
static int control_fd = -1;
static ogs_poll_t *control_poll;
static char control_path[sizeof(((struct sockaddr_un *)0)->sun_path)];
static struct { char id[65], imsi[16], response[512]; } requests[64];
static unsigned request_next;
typedef struct {
    struct sockaddr_un peer;
    socklen_t peer_size;
    char input[2049];
} operator_request_t;

const char *mme_operator_rebalance(mme_ue_t *ue)
{
    enb_ue_t *enb_ue;
    mme_enb_t *enb;
    mme_sess_t *sess;
    mme_bearer_t *bearer;
    int rv;
    if (!ue) return "UE context not found";
    if (!mme_s10_has_peers()) return "No S10 context-transfer peer is configured";
    if (ue->nas_eps.attach.value == OGS_NAS_ATTACH_TYPE_EPS_EMERGENCY_ATTACH)
        return "Emergency UE cannot be offloaded by this maintenance operation";
    if (!OGS_FSM_CHECK(&ue->sm, emm_state_registered) ||
            !SECURITY_CONTEXT_IS_VALID(ue)) return "UE is not registered with a usable security context";
    if (!ECM_CONNECTED(ue)) return "UE is idle; wait for a connected session";
    if (mme_s10_handover_busy(ue) || mme_s10_source_committed(ue) ||
            MME_SESSION_RELEASE_PENDING(ue) ||
            mme_ue_xact_count(ue, OGS_GTP_LOCAL_ORIGINATOR) ||
            mme_ue_xact_count(ue, OGS_GTP_REMOTE_ORIGINATOR))
        return "UE has an in-progress mobility or gateway procedure";
    enb_ue = enb_ue_find_by_id(ue->enb_ue_id);
    if (!enb_ue || enb_ue->ue_ctx_rel_action != S1AP_UE_CTX_REL_INVALID_ACTION)
        return "Radio context is unavailable or already releasing";
    enb = mme_enb_find_by_id(enb_ue->enb_id);
    if (!enb || !enb->state.s1_setup_success || !sgw_ue_find_by_id(ue->sgw_ue_id))
        return "Radio or serving gateway context is unavailable";
    if (ogs_list_empty(&ue->sess_list)) return "UE has no PDN session";
    /* Reject active real-time and priority bearers in this maintenance API.
     * A radio-triggered connected handover is the route for active voice. */
    ogs_list_for_each(&ue->sess_list, sess) {
        if (sess->ue_request_type.value == OGS_NAS_EPS_REQUEST_TYPE_EMERGENCY)
            return "Emergency PDN cannot be offloaded by this maintenance operation";
        ogs_list_for_each(&sess->bearer_list, bearer) {
            if (!OGS_FSM_CHECK(&bearer->sm, esm_state_active))
                return "Bearer has an in-progress ESM procedure";
            if (bearer->qos.index == 1 || bearer->qos.index == 2 ||
                    bearer->qos.arp.priority_level <= 5)
                return "Voice, emergency or priority bearer requires radio-coordinated mobility";
        }
    }
    enb_ue->relcause.group = S1AP_Cause_PR_radioNetwork;
    enb_ue->relcause.cause = S1AP_CauseRadioNetwork_load_balancing_tau_required;
    rv = mme_gtp_send_release_access_bearers_request(enb_ue, ue,
            OGS_GTP_RELEASE_OPERATOR_REBALANCE);
    if (rv != OGS_OK) {
        enb_ue->relcause.group = 0;
        enb_ue->relcause.cause = 0;
        return "Unable to start Release Access Bearers";
    }
    /* This requests the standard release/TAU path, NOT Delete Session or NAS
     * Detach. The eNB selects the new MME; completion must be observed there. */
    return NULL;
}

static int digits(const char *value, size_t minimum, size_t maximum)
{
    size_t i, size = value ? strlen(value) : 0;
    if (size < minimum || size > maximum) return 0;
    for (i = 0; i < size; i++) if (!isdigit((unsigned char)value[i])) return 0;
    return 1;
}
static int integer_value(cJSON *item, unsigned maximum, unsigned *value)
{
    double whole, fraction;
    if (!cJSON_IsNumber(item) || item->valuedouble < 0 || item->valuedouble > maximum)
        return OGS_ERROR;
    fraction = modf(item->valuedouble, &whole);
    if (fraction < 0 || fraction > 0) return OGS_ERROR;
    *value = (unsigned)whole; return OGS_OK;
}

static void process_request(const char *input, char output[512])
{
    cJSON *json = cJSON_ParseWithOpts(input, NULL, 1), *item;
    const char *op, *id, *imsi, *error = NULL;
    unsigned i, count = 0;
    if (!json || !cJSON_IsObject(json)) goto invalid;
    cJSON_ArrayForEach(item, json) {
        if (strcmp(item->string, "operation") && strcmp(item->string, "request_id") &&
                strcmp(item->string, "imsi") && strcmp(item->string, "plmn") &&
                strcmp(item->string, "mme_gid") && strcmp(item->string, "mme_code")) goto invalid;
        count++;
    }
    item = cJSON_GetObjectItemCaseSensitive(json, "operation");
    op = cJSON_IsString(item) ? item->valuestring : NULL;
    if (op && !strcmp(op, "capabilities") && count == 1) {
        char identity[160] = "null", plmn[OGS_PLMNIDSTRLEN];
        mme_context_t *context = mme_self();
        if (context->num_of_served_gummei == 1) {
            served_gummei_t *served = &context->served_gummei[0];
            if (served->num_of_plmn_id == 1 && served->num_of_mme_gid == 1 && served->num_of_mme_code == 1) {
                ogs_plmn_id_to_string(&served->plmn_id[0], plmn);
                ogs_snprintf(identity, sizeof(identity), "{\"plmn\":\"%s\",\"mme_gid\":%u,\"mme_code\":%u}",
                        plmn, served->mme_gid[0], served->mme_code[0]);
            }
        }
        ogs_snprintf(output, 512, "{\"ok\":true,\"protocol\":1,"
                "\"rebalance\":true,\"pdn_bindings\":true,\"target_selection\":\"enodeb\","
                "\"identity\":%s,\"relative_capacity\":%u}", identity, context->relative_capacity);
        cJSON_Delete(json); return;
    }
    if (op && !strcmp(op, "peer-check") && count == 4) {
        unsigned gid, code;
        char mcc[4] = {0};
        ogs_plmn_id_t plmn;
        ogs_nas_eps_guti_t guti = {0};
        item = cJSON_GetObjectItemCaseSensitive(json, "plmn");
        if (!cJSON_IsString(item) || !digits(item->valuestring, 5, 6) ||
                integer_value(cJSON_GetObjectItemCaseSensitive(json,"mme_gid"),65535,&gid) != OGS_OK ||
                integer_value(cJSON_GetObjectItemCaseSensitive(json,"mme_code"),255,&code) != OGS_OK) goto invalid;
        memcpy(mcc,item->valuestring,3);
        ogs_plmn_id_build(&plmn,atoi(mcc),atoi(item->valuestring+3),strlen(item->valuestring)-3);
        ogs_nas_from_plmn_id(&guti.nas_plmn_id,&plmn);guti.mme_gid=gid;guti.mme_code=code;
        ogs_cpystrn(output,mme_s10_find_by_guti(&guti) ?
                "{\"ok\":true,\"route\":true}" :
                "{\"ok\":false,\"reason\":\"No reciprocal S10 route for this GUMMEI\"}",512);
        cJSON_Delete(json); return;
    }
    if (!op || strcmp(op, "rebalance") || count != 3) goto invalid;
    item = cJSON_GetObjectItemCaseSensitive(json, "request_id");
    id = cJSON_IsString(item) ? item->valuestring : NULL;
    item = cJSON_GetObjectItemCaseSensitive(json, "imsi");
    imsi = cJSON_IsString(item) ? item->valuestring : NULL;
    if (!id || strlen(id) != 36 || !digits(imsi, 5, 15)) goto invalid;
    for (i = 0; i < 36; i++)
        if (!isxdigit((unsigned char)id[i]) && id[i] != '-') goto invalid;
    for (i = 0; i < 64; i++) {
        if (!strcmp(requests[i].id, id)) {
            if (strcmp(requests[i].imsi, imsi)) goto invalid;
            ogs_cpystrn(output, requests[i].response, 512);
            cJSON_Delete(json); return;
        }
    }
    error = mme_operator_rebalance(mme_ue_find_by_imsi_bcd(imsi));
    ogs_snprintf(output, 512, "{\"ok\":%s,\"request_id\":\"%s\","
            "\"status\":\"%s\",\"reason\":\"%s\"}",
            error ? "false" : "true", id,
            error ? "rejected" : "requested", error ? error :
            "S1 release and load-balancing TAU requested; target MME is selected by the eNodeB");
    i = request_next++ % 64;
    ogs_cpystrn(requests[i].id, id, sizeof(requests[i].id));
    ogs_cpystrn(requests[i].imsi, imsi, sizeof(requests[i].imsi));
    ogs_cpystrn(requests[i].response, output, sizeof(requests[i].response));
    cJSON_Delete(json); return;
invalid:
    cJSON_Delete(json);
    ogs_cpystrn(output, "{\"ok\":false,\"status\":\"rejected\",\"reason\":\"Invalid operator request\"}", 512);
}

static void receive_request(short when, ogs_socket_t fd, void *data)
{
    char input[2049];
    union { struct cmsghdr alignment; char bytes[CMSG_SPACE(sizeof(struct ucred))]; } credentials;
    struct sockaddr_un peer;
    struct iovec vector = {input, sizeof(input) - 1};
    struct msghdr message = {0};
    struct cmsghdr *header;
    struct ucred *cred = NULL;
    ssize_t size;
    mme_event_t *event;
    ogs_pkbuf_t *buffer;
    operator_request_t *request;
    (void)when; (void)data;
    message.msg_name = &peer; message.msg_namelen = sizeof(peer);
    message.msg_iov = &vector; message.msg_iovlen = 1;
    message.msg_control = credentials.bytes; message.msg_controllen = sizeof(credentials.bytes);
    size = recvmsg(fd, &message, MSG_DONTWAIT);
    if (size <= 0 || message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) return;
    for (header = CMSG_FIRSTHDR(&message); header;
            header = CMSG_NXTHDR(&message, header))
        if (header->cmsg_level == SOL_SOCKET && header->cmsg_type == SCM_CREDENTIALS &&
                header->cmsg_len >= CMSG_LEN(sizeof(struct ucred)))
            cred = (struct ucred *)CMSG_DATA(header);
    if (!cred || (cred->uid != 0 && cred->uid != geteuid()) ||
            peer.sun_family != AF_UNIX || message.msg_namelen > sizeof(peer) ||
            message.msg_namelen <= sizeof(sa_family_t)) return;
    input[size] = '\0';
    if (memchr(input, '\0', (size_t)size)) return;
    buffer = ogs_pkbuf_alloc(NULL, sizeof(operator_request_t));
    if (!buffer) return;
    request = (operator_request_t *)ogs_pkbuf_put(buffer, sizeof(*request));
    memset(request, 0, sizeof(*request));
    memcpy(&request->peer, &peer, sizeof(peer)); request->peer_size = message.msg_namelen;
    memcpy(request->input, input, (size_t)size + 1);
    event = mme_event_new(MME_EVENT_OPERATOR_REQUEST); event->pkbuf = buffer;
    if (ogs_queue_trypush(ogs_app()->queue, event) != OGS_OK) {
        ogs_pkbuf_free(buffer); mme_event_free(event);
    }
}

void mme_operator_process(ogs_pkbuf_t *buffer)
{
    char output[512];
    operator_request_t *request;
    if (!buffer) return;
    if (buffer->len != sizeof(operator_request_t) || control_fd < 0) {
        ogs_pkbuf_free(buffer); return;
    }
    request = (operator_request_t *)buffer->data;
    process_request(request->input, output);
    if (sendto(control_fd, output, strlen(output), MSG_DONTWAIT | MSG_NOSIGNAL,
                (struct sockaddr *)&request->peer, request->peer_size) < 0)
        ogs_warn("MME operator response could not be delivered");
    ogs_pkbuf_free(buffer);
}

int mme_operator_open(void)
{
    const char *path = getenv("OPEN5GS_MME_OPERATOR_SOCKET");
    struct sockaddr_un address = {0};
    struct stat st;
    char parent[sizeof(control_path)], *slash;
    int one = 1;
    if (!path || !*path) return OGS_OK;
    if (strlen(path) >= sizeof(control_path) || path[0] != '/') return OGS_ERROR;
    ogs_cpystrn(parent, path, sizeof(parent)); slash = strrchr(parent, '/');
    if (!slash || slash == parent) return OGS_ERROR;
    *slash = '\0';
    if (lstat(parent, &st) || !S_ISDIR(st.st_mode) ||
            st.st_uid != geteuid() || (st.st_mode & 0077) ||
            lstat(path, &st) == 0 || errno != ENOENT) return OGS_ERROR;
    control_fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (control_fd < 0) return OGS_ERROR;
    address.sun_family = AF_UNIX;
    ogs_cpystrn(address.sun_path, path, sizeof(address.sun_path));
    if (setsockopt(control_fd, SOL_SOCKET, SO_PASSCRED, &one, sizeof(one)) ||
            bind(control_fd, (struct sockaddr *)&address, sizeof(address))) {
        close(control_fd); control_fd = -1; return OGS_ERROR;
    }
    ogs_cpystrn(control_path, path, sizeof(control_path));
    if (chmod(path, 0600)) { mme_operator_close(); return OGS_ERROR; }
    control_poll = ogs_pollset_add(ogs_app()->pollset, OGS_POLLIN,
            control_fd, receive_request, NULL);
    if (!control_poll) { mme_operator_close(); return OGS_ERROR; }
    return OGS_OK;
}

void mme_operator_close(void)
{
    if (control_poll) { ogs_pollset_remove(control_poll); control_poll = NULL; }
    if (control_fd >= 0) { close(control_fd); control_fd = -1; }
    if (*control_path) { unlink(control_path); *control_path = '\0'; }
}
#else
int mme_operator_open(void) { return getenv("OPEN5GS_MME_OPERATOR_SOCKET") ? OGS_ERROR : OGS_OK; }
void mme_operator_close(void) {}
void mme_operator_process(ogs_pkbuf_t *buffer) { if (buffer) ogs_pkbuf_free(buffer); }
const char *mme_operator_rebalance(mme_ue_t *ue)
{
    (void)ue;
    return "MME operator control requires Linux";
}
#endif
