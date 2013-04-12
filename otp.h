/** BEGIN COPYRIGHT BLOCK
 * This Program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation; version 2 of the License.
 *
 * This Program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this Program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place, Suite 330, Boston, MA 02111-1307 USA.
 *
 * In addition, as a special exception, Red Hat, Inc. gives You the additional
 * right to link the code of this Program with code not covered under the GNU
 * General Public License ("Non-GPL Code") and to distribute linked combinations
 * including the two, subject to the limitations in this paragraph. Non-GPL Code
 * permitted under this exception must only link to the code of this Program
 * through those well defined interfaces identified in the file named EXCEPTION
 * found in the source code files (the "Approved Interfaces"). The files of
 * Non-GPL Code may instantiate templates or use macros or inline functions from
 * the Approved Interfaces without causing the resulting work to be covered by
 * the GNU General Public License. Only Red Hat, Inc. may make changes or
 * additions to the list of Approved Interfaces. You must obey the GNU General
 * Public License in all respects for all of the Program code and other code used
 * in conjunction with the Program except the Non-GPL Code covered by this
 * exception. If you modify this file, you may extend this exception to your
 * version of the file, but you are not obligated to do so. If you do not wish to
 * provide this exception without modification, you must delete this exception
 * statement from your version and license this file solely under the GPL without
 * exception.
 *
 *
 * Copyright (C) 2013 Red Hat, Inc.
 * All rights reserved.
 * END COPYRIGHT BLOCK **/

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

/*
 * IPA OTP plug-in header file
 */
#include <stdio.h>
#include <ctype.h>
#include <strings.h>
#include <errno.h>
#include <dirsrv/slapi-plugin.h>

/*
 * Plug-in defines
 */
#define IPA_OTP_PLUGIN_SUBSYSTEM  "ipa-otp-plugin"
#define IPA_OTP_FEATURE_DESC      "IPA OTP"
#define IPA_OTP_PLUGIN_DESC       "IPA OTP plugin"
#define IPA_OTP_POSTOP_DESC       "IPA OTP postop plugin"
#define IPA_OTP_INT_POSTOP_DESC   "IPA OTP internal postop plugin"

/*
 * Attribute type defines
 */
#define IPA_OTP_ALLOWED_AUTH_TYPE    "ipaAllowedAuthType"
#define IPA_OTP_TOKEN_OWNER_TYPE     "ipaTokenOwner"
#define IPA_OTP_TOKEN_LENGTH_TYPE    "ipaTokenOTPDigits"
#define IPA_OTP_TOKEN_KEY_TYPE       "ipaTokenOTPKey"
#define IPA_OTP_TOKEN_ALGORITHM_TYPE "ipaTokenOTPAlgorithm"
#define IPA_OTP_TOKEN_OFFSET_TYPE    "ipaTokenTOTPClockOffset"
#define IPA_OTP_TOKEN_STEP_TYPE      "ipaTokenTOTPTimeStep"

/*
 * Objectclass defines
 */
#define IPA_OTP_TOKEN_TOTP_OC "ipaTokenTOTP"

/*
 * Return code defines
 */
#define IPA_OTP_OP_NOT_HANDLED 0
#define IPA_OTP_OP_HANDLED     1

/*
 * Authentication type defines
 */
#define IPA_OTP_AUTH_TYPE_NONE     0
#define IPA_OTP_AUTH_TYPE_DISABLED 1
#define IPA_OTP_AUTH_TYPE_PASSWORD 2
#define IPA_OTP_AUTH_TYPE_OTP      4
#define IPA_OTP_AUTH_TYPE_PKINIT   8
#define IPA_OTP_AUTH_TYPE_VALUE_DISABLED "DISABLED"
#define IPA_OTP_AUTH_TYPE_VALUE_PASSWORD "PASSWORD"
#define IPA_OTP_AUTH_TYPE_VALUE_OTP      "OTP"
#define IPA_OTP_AUTH_TYPE_VALUE_PKINIT   "PKINIT"

/*
 * Config struct
 */
struct ipaOtpConfigEntry {
    Slapi_DN *sdn;
};
