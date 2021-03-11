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
	// 2020.01.21 for ePCF
	} else if (nfType == NF_TYPE_UDR) {
		nf_udr_info *udrInfo = &nfTypeInfo->udrInfo;
        if (strlen(udrInfo->groupId))
		sprintf(resBuf + strlen(resBuf), "group %s\n", udrInfo->groupId);

        if (udrInfo->supiRangesNum)
            sprintf(resBuf + strlen(resBuf), "supiRanges\n");
		for (int i = 0; i < udrInfo->supiRangesNum; i++) {
			sprintf(resBuf + strlen(resBuf), " %s\n  %s\n", 
					udrInfo->supiRanges[i].start,
					udrInfo->supiRanges[i].end);
		}

        if (udrInfo->gpsiRangesNum)
            sprintf(resBuf + strlen(resBuf), "gpsiRanges\n");
		for (int i = 0; i < udrInfo->gpsiRangesNum; i++) {
			sprintf(resBuf + strlen(resBuf), " %s\n  %s\n", 
					udrInfo->gpsiRanges[i].start,
					udrInfo->gpsiRanges[i].end);
		}

        if (udrInfo->externalGroupIdentifierRangesNum)
            sprintf(resBuf + strlen(resBuf), "externalGrpIdRanges\n");
		for (int i = 0; i < udrInfo->externalGroupIdentifierRangesNum; i++) {
			sprintf(resBuf + strlen(resBuf), " %s\n  %s\n", 
					udrInfo->externalGrpIdRanges[i].start,
					udrInfo->externalGrpIdRanges[i].end);
		}

        if (udrInfo->supportedDataSets) {
			sprintf(resBuf + strlen(resBuf), " %s\n", udrInfo->supportedDataSets);
		}
	// 2020.01.21 for ePCF
	} else if (nfType == NF_TYPE_BSF) {
		nf_bsf_info *bsfInfo = &nfTypeInfo->bsfInfo;

        if (bsfInfo->ipv4AddressRangesNum)
            sprintf(resBuf + strlen(resBuf), "ipv4AddrRanges\n");
		for (int i = 0; i < bsfInfo->ipv4AddressRangesNum; i++) {
			sprintf(resBuf + strlen(resBuf), " %s\n  %s\n", 
					bsfInfo->ipv4AddrRanges[i].start,
					bsfInfo->ipv4AddrRanges[i].end);
		}

        if (bsfInfo->ipv6PrefixRangesNum)
            sprintf(resBuf + strlen(resBuf), "ipv6PrefixRanges\n");
		for (int i = 0; i < bsfInfo->ipv6PrefixRangesNum; i++) {
			sprintf(resBuf + strlen(resBuf), " %s\n  %s\n", 
					bsfInfo->ipv6PrefixRanges[i].start,
					bsfInfo->ipv6PrefixRanges[i].end);
		}

        if (bsfInfo->dnnListNum)
            sprintf(resBuf + strlen(resBuf), "dnnListNum\n");
		for (int i = 0; i < bsfInfo->dnnListNum; i++) {
			sprintf(resBuf + strlen(resBuf), " %s\n", bsfInfo->dnnList[i]);
		}

        if (bsfInfo->ipDomainListNum)
            sprintf(resBuf + strlen(resBuf), "ipDomainListNum\n");
		for (int i = 0; i < bsfInfo->ipDomainListNum; i++) {
			sprintf(resBuf + strlen(resBuf), " %s\n", bsfInfo->ipDomainList[i]);
		}
	// 2020.01.21 for ePCF
	} else if (nfType == NF_TYPE_CHF) {
		nf_chf_info *chfInfo = &nfTypeInfo->chfInfo;

        if (chfInfo->supiRangesNum)
            sprintf(resBuf + strlen(resBuf), "supiRanges\n");
		for (int i = 0; i < chfInfo->supiRangesNum; i++) {
			sprintf(resBuf + strlen(resBuf), " %s\n  %s\n", 
					chfInfo->supiRanges[i].start,
					chfInfo->supiRanges[i].end);
		}

        if (chfInfo->gpsiRangesNum)
            sprintf(resBuf + strlen(resBuf), "gpsiRanges\n");
		for (int i = 0; i < chfInfo->gpsiRangesNum; i++) {
			sprintf(resBuf + strlen(resBuf), " %s\n  %s\n", 
					chfInfo->gpsiRanges[i].start,
					chfInfo->gpsiRanges[i].end);
		}

        if (chfInfo->plmnRangesNum)
            sprintf(resBuf + strlen(resBuf), "plmnRanges\n");
		for (int i = 0; i < chfInfo->plmnRangesNum; i++) {
			sprintf(resBuf + strlen(resBuf), " %s\n  %s\n", 
					chfInfo->plmnRanges[i].start,
					chfInfo->plmnRanges[i].end);
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

