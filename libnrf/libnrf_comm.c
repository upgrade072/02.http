#include "nrf_comm.h"

void nf_get_specific_info_str(nf_comm_type nfType, nf_type_info *nfTypeInfo, char *resBuf)
{
	if (nfType == NF_TYPE_UDM) {
		nf_udm_info *udmInfo = &nfTypeInfo->udmInfo;
        if (strlen(udmInfo->groupId))
		sprintf(resBuf + strlen(resBuf), "group %s\n", udmInfo->groupId);
        if (udmInfo->supiRangesNum)
            sprintf(resBuf + strlen(resBuf), "supiRanges\n");
		for (int i = 0; i < udmInfo->supiRangesNum; i++) {
			sprintf(resBuf + strlen(resBuf), " %s\n  %s\n", 
					udmInfo->supiRanges[i].start,
					udmInfo->supiRanges[i].end);
		}
        if (udmInfo->routingIndicatorsNum)
            sprintf(resBuf + strlen(resBuf), "routingInds\n");
		for (int i = 0; i < udmInfo->routingIndicatorsNum; i++) {
			sprintf(resBuf + strlen(resBuf), " %s\n",
				   udmInfo->routingIndicators[i]);
		}
	} else if (nfType == NF_TYPE_AMF) {
        nf_amf_info *amfInfo = &nfTypeInfo->amfInfo;
        if (strlen(amfInfo->amfRegionId))
            sprintf(resBuf + strlen(resBuf), "region %s\n", amfInfo->amfRegionId);
        if (strlen(amfInfo->amfSetId))
            sprintf(resBuf + strlen(resBuf), "setId  %s\n", amfInfo->amfSetId);
        if (amfInfo->guamiListNum)
            sprintf(resBuf + strlen(resBuf), "guamiList\n");
        for (int i = 0; i < amfInfo->guamiListNum; i++) {
            sprintf(resBuf + strlen(resBuf), " plmn  %s\n amfId %s\n", 
                    amfInfo->nf_guami[i].plmnId, amfInfo->nf_guami[i].amfId);
        }
    } else {
        sprintf(resBuf + strlen(resBuf), "unknown type\n");
    }
    // remove last newline
    if (strlen(resBuf) > 0) {
        resBuf[strlen(resBuf) - 1] = '\0';
    }
}

void nf_get_allowd_plmns_str(int allowdPlmnsNum, nf_comm_plmn *allowdPlmns, char *resBuf)
{
    if (allowdPlmnsNum > 0)
		sprintf(resBuf + strlen(resBuf), "allowdPlmns\n");

	for (int k = 0; k < allowdPlmnsNum; k++) {
		nf_comm_plmn *plmns = &allowdPlmns[k];
		sprintf(resBuf + strlen(resBuf), " %s-%s\n", plmns->mcc, plmns->mnc);
	}
    // remove last newline
    if (strlen(resBuf) > 0) {
        resBuf[strlen(resBuf) - 1] = '\0';
    }
}
