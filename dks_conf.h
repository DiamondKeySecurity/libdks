// Copyright (c) 2018, 2019 Diamond Key Security, NFP  All rights reserved.
//
#ifndef DKS_CONF_H
#define DKS_CONF_H

// structure to hold information on the HSM that we should connect to
typedef struct __hsm_info
{
    char *ip_addr;
    int  port;
    char *servername;
    char *serial;
} hsm_info_t;

// results of operation to load conf file
typedef enum __hsm_conf_result
{
    HSMCONF_OK,
    HSMCONF_FAILED_FORMAT,
    HSMCONF_FAILED_FILENOTFOUND,
    HSMCONF_FAILED_PORTTYPENOTFOUND
} hsm_conf_result_t;

// type of ethernet connections on the HSM
typedef enum __hsm_port_type
{
    HSM_PORT_CTY,
    HSM_PORT_RPC
} hsm_port_type_t;

// load a conf file and create the necessary structures
hsm_conf_result_t LoadHSMInfo(hsm_info_t **hsm_info, hsm_port_type_t port_type);

// free the data created using LoadHSMInfo
void FreeHSMInfo(hsm_info_t **hsm_info);

#endif