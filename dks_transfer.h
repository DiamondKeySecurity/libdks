// Copyright (c) 2018, 2019 Diamond Key Security, NFP  All rights reserved.
//
#ifndef DKS_TRANSFER_H
#define DKS_TRANSFER_H

#include <tls.h>

// Code for using TLS to transfer files to the HSM
void dks_send_file(struct tls *tls, char *file_to_send);

#endif
