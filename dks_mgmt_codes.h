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
#ifndef DKS_MGMT_CODES_HEADER
#define DKS_MGMT_CODES_HEADER

// Special codes that can be returned by the HSM mgmt port
typedef enum __hsm_mgmt_codes
{
    MGMTCODE_RECEIVEHSM_UPDATE = 0x11121314,
} hsm_mgmt_codes_t;

#endif