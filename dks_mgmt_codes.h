// Copyright (c) 2019  Diamond Key Security, NFP
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
// - Redistributions of source code must retain the above copyright notice,
//   this list of conditions and the following disclaimer.
//
// - Redistributions in binary form must reproduce the above copyright
//   notice, this list of conditions and the following disclaimer in the
//   documentation and/or other materials provided with the distribution.
//
// - Neither the name of the NORDUnet nor the names of its contributors may
//   be used to endorse or promote products derived from this software
//   without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
// TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
// PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
// TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
#ifndef DKS_MGMT_CODES_HEADER
#define DKS_MGMT_CODES_HEADER

// Special codes that can be returned by the HSM mgmt port
typedef enum __hsm_mgmt_codes
{
    // the HSM wants to receive a tar.gz.signed file with the latest HSM update
    MGMTCODE_RECEIVEHSM_UPDATE   = 0x11121314,

    // the HSM wants to receive a KEKEK that it will use for a remote backup
    MGMTCODE_RECEIVE_RMT_KEKEK   = 0x11121315,

    // the HSM wants to send a local KEKEK for a remote restore
    MGMTCODE_SEND_LCL_KEKEK      = 0x11121316,

    // the HSM wants to send a local KEKEK for a remote restore
    MGMTCODE_SEND_EXPORT_DATA    = 0x11121317,

    // the HSM wants to receive import data from the HSM
    MGMTCODE_RECEIVE_IMPORT_DATA = 0x11121318
} hsm_mgmt_codes_t;

#endif