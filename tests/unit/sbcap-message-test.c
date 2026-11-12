/*
 * Copyright (C) 2019-2023 by Sukchan Lee <acetcom@gmail.com>
 * Copyright (C) 2024 by Arnaud DJOUM <arnaudchewa65@gmail.com>
 *
 * This file is part of Open5GS.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "ogs-sbcap.h"
#include "mme/s1ap-build.h"
#include "core/abts.h"

/*
 * SBc-AP Message Tests for CMAS/PWS support
 * Reference: 3GPP TS 29.168 (SBc-AP specification)
 */

static void sbcap_message_test1(abts_case *tc, void *data)
{
    /*
     * Test 1: Verify procedure code constants
     */
    ABTS_INT_EQUAL(tc, 0, SBCAP_id_Write_Replace_Warning);
    ABTS_INT_EQUAL(tc, 1, SBCAP_id_Stop_Warning);
    ABTS_INT_EQUAL(tc, 2, SBCAP_id_Error_Indication);
}

static void sbcap_message_test2(abts_case *tc, void *data)
{
    /*
     * Test 2: Verify IE ID constants
     */
    ABTS_INT_EQUAL(tc, 5, SBCAP_ProtocolIE_ID_id_Message_Identifier);
    ABTS_INT_EQUAL(tc, 11, SBCAP_ProtocolIE_ID_id_Serial_Number);
}

static void sbcap_message_test3(abts_case *tc, void *data)
{
    /*
     * Test 3: Test PDU structure allocation
     */
    SBCAP_SBC_AP_PDU_t pdu;
    
    memset(&pdu, 0, sizeof(pdu));
    
    /* Set to initiating message */
    pdu.present = SBCAP_SBC_AP_PDU_PR_initiatingMessage;
    
    /* Verify */
    ABTS_INT_EQUAL(tc, SBCAP_SBC_AP_PDU_PR_initiatingMessage, pdu.present);
}

static void sbcap_tai_preservation(abts_case *tc, void *data)
{
    sbc_pws_data_t request;
    int kind, i;
    memset(&request,0,sizeof(request));
    request.explicit_tais=true;request.no_of_tai=2;
    ogs_plmn_id_build(&request.tai[0].plmn_id,1,1,2);request.tai[0].tac=1;
    ogs_plmn_id_build(&request.tai[1].plmn_id,1,1,3);request.tai[1].tac=257;
    request.message_id=4380;request.serial_number=0x4001;
    request.repetition_period=30;request.number_of_broadcast=3;
    request.data_coding_scheme=0x48;request.message_length=4;
    memcpy(request.message_contents,"test",4);
    for(kind=0;kind<2;kind++) {
        ogs_s1ap_message_t pdu;
        S1AP_WarningAreaList_t *area=NULL;
        ogs_pkbuf_t *packet=kind?s1ap_build_kill_request(&request):s1ap_build_write_replace_warning_request(&request);
        ABTS_PTR_NOTNULL(tc,packet);if(!packet)return;
        memset(&pdu,0,sizeof(pdu));
        ABTS_INT_EQUAL(tc,OGS_OK,ogs_s1ap_decode(&pdu,packet));
        if(kind) {
            S1AP_KillRequest_t *r=pdu.choice.initiatingMessage->value.choice.KillRequest;
            for(i=0;i<OGS_ASN_LIST_COUNT(r->protocolIEs);i++) {
                S1AP_KillRequestIEs_t *ie=OGS_ASN_LIST_GET(r->protocolIEs,i);
                if(ie->id==S1AP_ProtocolIE_ID_id_WarningAreaList)area=ie->value.choice.WarningAreaList;
            }
        }else {
            S1AP_WriteReplaceWarningRequest_t *r=pdu.choice.initiatingMessage->value.choice.WriteReplaceWarningRequest;
            for(i=0;i<OGS_ASN_LIST_COUNT(r->protocolIEs);i++) {
                S1AP_WriteReplaceWarningRequestIEs_t *ie=OGS_ASN_LIST_GET(r->protocolIEs,i);
                if(ie->id==S1AP_ProtocolIE_ID_id_WarningAreaList)area=ie->value.choice.WarningAreaList;
            }
        }
        ABTS_PTR_NOTNULL(tc,area);
        if(area) {
            ABTS_INT_EQUAL(tc,S1AP_WarningAreaList_PR_trackingAreaListforWarning,area->present);
            ABTS_INT_EQUAL(tc,2,area->choice.trackingAreaListforWarning->list.count);
            for(i=0;i<2;i++) {
                S1AP_TAI_t *t=area->choice.trackingAreaListforWarning->list.array[i];
                ABTS_INT_EQUAL(tc,0,memcmp(t->pLMNidentity.buf,&request.tai[i].plmn_id,3));
                ABTS_INT_EQUAL(tc,request.tai[i].tac,(t->tAC.buf[0]<<8)|t->tAC.buf[1]);
            }
        }
        ogs_s1ap_free(&pdu);ogs_pkbuf_free(packet);
    }
}

abts_suite *test_sbcap_message(abts_suite *suite)
{
    suite = ADD_SUITE(suite)

    abts_run_test(suite, sbcap_message_test1, NULL);
    abts_run_test(suite, sbcap_message_test2, NULL);
    abts_run_test(suite, sbcap_message_test3, NULL);
    abts_run_test(suite, sbcap_tai_preservation, NULL);

    return suite;
}
