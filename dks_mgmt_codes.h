// Copyright (c) 2018, 2019 Diamond Key Security, NFP  All rights reserved.
//
#ifndef DKS_MGMT_CODES_HEADER
#define DKS_MGMT_CODES_HEADER

// Special codes that can be returned by the HSM mgmt port
typedef enum __hsm_mgmt_codes
{
    // the HSM wants to receive a tar.gz.signed file with the latest HSM update
    MGMTCODE_RECEIVEHSM_UPDATE = 0x11121314,

    // the HSM wants to receive a KEKEK that it will use for a remote backup
    MGMTCODE_RECIEVE_RMT_KEKEK = 0x11121315,

    // the HSM wants to send a local KEKEK for a remote restore
    MGMTCODE_SEND_LCL_KEKEK    = 0x11121316
} hsm_mgmt_codes_t;

#endif