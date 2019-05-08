// Copyright (c) 2019  Diamond Key Security, NFP
// 
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; version 2
// of the License only.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License
// along with this program; if not, If not, see <https://www.gnu.org/licenses/>.
//
// Script to import CrypTech code into DKS HSM folders.
//
#ifndef DKS_TRANSFER_H
#define DKS_TRANSFER_H

#include <tls.h>

// Code for using TLS to transfer files to the HSM
void dks_send_file(struct tls *tls, char *file_to_send);
void dks_send_file_mem(struct tls *tls, char *file_data, long length);
void dks_send_file_fp(struct tls *tls, FILE *fp);
void dks_send_file_none(struct tls *tls);
char *dks_recv_from_hsm(struct tls *tls, unsigned int num_bytes_to_receive);

#endif
