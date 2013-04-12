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

/*
 * OTP Plug-in
 */
#include "otp.h"

/*
 * Plug-in globals
 */
static void *_PluginID = NULL;
static Slapi_DN *_PluginDN = NULL;
static Slapi_DN *_ConfigAreaDN = NULL;
static int g_plugin_started = 0;
static PRInt32 g_allowed_auth_types = 0;
static Slapi_PluginDesc ipa_otp_plugin_desc = { IPA_OTP_FEATURE_DESC,
                                  "FreeIPA project",
                                  "FreeIPA/1.0",
                                  IPA_OTP_PLUGIN_DESC };

/*
 * Plug-in management functions
 */
int ipa_otp_init(Slapi_PBlock * pb);
static int ipa_otp_postop_init(Slapi_PBlock *pb);
static int ipa_otp_internal_postop_init(Slapi_PBlock *pb);
static int ipa_otp_start(Slapi_PBlock * pb);
static int ipa_otp_close(Slapi_PBlock * pb);


/*
 * Plug-in identity functions
 */
static void ipa_otp_set_plugin_id(void *pluginID);
static void *ipa_otp_get_plugin_id();
static void ipa_otp_set_plugin_sdn(Slapi_DN *pluginDN);
static Slapi_DN *ipa_otp_get_plugin_sdn();


/*
 * Operation callbacks
 */
static int ipa_otp_preop_bind(Slapi_PBlock *pb);
static int ipa_otp_postop_add(Slapi_PBlock *pb);
static int ipa_otp_postop_del(Slapi_PBlock *pb);
static int ipa_otp_postop_mod(Slapi_PBlock *pb);
static int ipa_otp_postop_modrdn(Slapi_PBlock *pb);
static int ipa_otp_postop(Slapi_PBlock *pb, int optype);
/* NGK - is a SLAPI_PLUGIN_PRE_RESULT_FN neededto return a control
 * if the server was responsible for processing the bind? */


/*
 * Config cache management functions
 */
static int ipa_otp_load_config();
static int ipa_otp_parse_config_entry(Slapi_Entry * e, int apply);


/*
 * Helper functions
 */
static Slapi_DN *ipa_otp_get_config_area();
static void ipa_otp_set_config_area(Slapi_DN *sdn);
static int ipa_otp_dn_is_config(Slapi_DN *sdn);
static int ipa_otp_oktodo(Slapi_PBlock *pb);
static int ipa_otp_is_disabled();
static int ipa_otp_is_auth_type_allowed(char **auth_type_list, int auth_type);
static int ipa_otp_do_otp_auth(Slapi_Entry *bind_entry, struct berval *creds);
static int ipa_otp_authenticate_totp_token(const char *token_code,
    int token_length, const char *token_key, const char *token_algorithm,
    const char *token_offset, const char *token_step);


/*
 * Plugin identity functions
 */
static void
ipa_otp_set_plugin_id(void *pluginID)
{
    _PluginID = pluginID;
}

static void *
ipa_otp_get_plugin_id()
{
    return _PluginID;
}

static void
ipa_otp_set_plugin_sdn(Slapi_DN *pluginDN)
{
    _PluginDN = pluginDN;
}

static Slapi_DN *
ipa_otp_get_plugin_sdn()
{
    return _PluginDN;
}


/*
 * Plug-in initialization functions
 */
int
ipa_otp_init(Slapi_PBlock *pb)
{
    int status = 0;
    char *plugin_identity = NULL;

    slapi_log_error(SLAPI_LOG_TRACE, IPA_OTP_PLUGIN_SUBSYSTEM,
                    "--> ipa_otp_init\n");

    /* Store the plugin identity for later use.
     * Used for internal operations. */
    slapi_pblock_get(pb, SLAPI_PLUGIN_IDENTITY, &plugin_identity);
    PR_ASSERT(plugin_identity);
    ipa_otp_set_plugin_id(plugin_identity);

    /* Register preop callbacks */
    if (slapi_pblock_set(pb, SLAPI_PLUGIN_VERSION,
                         SLAPI_PLUGIN_VERSION_03) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_START_FN,
                         (void *) ipa_otp_start) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_CLOSE_FN,
                         (void *) ipa_otp_close) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_DESCRIPTION,
                         (void *) &ipa_otp_plugin_desc) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_PRE_BIND_FN,
                         (void *) ipa_otp_preop_bind) != 0) {
        slapi_log_error(SLAPI_LOG_FATAL, IPA_OTP_PLUGIN_SUBSYSTEM,
                        "ipa_otp_init: failed to register preop plugin\n");
        status = -1;
    }

    /* Register our postop plug-in. */
    if (!status) {
        if (slapi_register_plugin("postoperation",
                                  1,
                                  "ipa_otp_init",
                                  ipa_otp_postop_init,
                                  IPA_OTP_POSTOP_DESC,
                                  NULL,
                                  plugin_identity)) {
            slapi_log_error(SLAPI_LOG_FATAL, IPA_OTP_PLUGIN_SUBSYSTEM,
                        "ipa_otp_init: failed to register postop plugin.\n");
            status = -1;
        }
    }

    /* Register our internal postop plug-in. */
    if (!status) {
        if (slapi_register_plugin("internalpostoperation",
                                  1,
                                  "ipa_otp_init",
                                  ipa_otp_internal_postop_init,
                                  IPA_OTP_INT_POSTOP_DESC,
                                  NULL,
                                  plugin_identity)) {
            slapi_log_error(SLAPI_LOG_FATAL, IPA_OTP_PLUGIN_SUBSYSTEM,
                        "ipa_otp_init: failed to register internal "
                        "postop plugin.\n");
            status = -1;
        }
    }

    slapi_log_error(SLAPI_LOG_TRACE, IPA_OTP_PLUGIN_SUBSYSTEM,
                    "<-- ipa_otp_init\n");
    return status;
}

static int
ipa_otp_postop_init(Slapi_PBlock *pb)
{
    int status = 0;

    if (slapi_pblock_set(pb, SLAPI_PLUGIN_VERSION,
                         SLAPI_PLUGIN_VERSION_03) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_DESCRIPTION,
                         (void *) &ipa_otp_plugin_desc) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_POST_ADD_FN,
                         (void *) ipa_otp_postop_add) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_POST_DELETE_FN,
                         (void *) ipa_otp_postop_del) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_POST_MODIFY_FN,
                         (void *) ipa_otp_postop_mod) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_POST_MODRDN_FN,
                         (void *) ipa_otp_postop_modrdn) != 0) { 
        status = -1;
    }

    return status;
}

static int
ipa_otp_internal_postop_init(Slapi_PBlock *pb)
{
    int status = 0;

    if (slapi_pblock_set(pb, SLAPI_PLUGIN_VERSION,
                         SLAPI_PLUGIN_VERSION_03) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_DESCRIPTION,
                         (void *) &ipa_otp_plugin_desc) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_INTERNAL_POST_ADD_FN,
                         (void *) ipa_otp_postop_add) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_INTERNAL_POST_DELETE_FN,
                         (void *) ipa_otp_postop_del) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_INTERNAL_POST_MODIFY_FN,
                         (void *) ipa_otp_postop_mod) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_INTERNAL_POST_MODRDN_FN,
                         (void *) ipa_otp_postop_mod) != 0) {
        status = -1;
    }

    return status;
}

/*
 * ipa_otp_start()
 *
 * Allocates our config lock and loads initial config.
 */
static int
ipa_otp_start(Slapi_PBlock * pb)
{
    Slapi_DN *plugindn = NULL;
    char *config_area = NULL;

    slapi_log_error(SLAPI_LOG_TRACE, IPA_OTP_PLUGIN_SUBSYSTEM,
                    "--> ipa_otp_start\n");

    /* Check if we're already started */
    if (g_plugin_started) {
        goto done;
    }

    /*
     * Get the plug-in target dn from the system
     * and store it for future use. */
    slapi_pblock_get(pb, SLAPI_TARGET_SDN, &plugindn);
    if (NULL == plugindn || 0 == slapi_sdn_get_ndn_len(plugindn)) {
        slapi_log_error(SLAPI_LOG_PLUGIN, IPA_OTP_PLUGIN_SUBSYSTEM,
                        "ipa_otp_start: unable to retrieve plugin dn\n");
        return -1;
    }

    ipa_otp_set_plugin_sdn(slapi_sdn_dup(plugindn));

    /* Set the alternate config area if one is defined. */
    slapi_pblock_get(pb, SLAPI_PLUGIN_CONFIG_AREA, &config_area);
    if (config_area) {
        ipa_otp_set_config_area(slapi_sdn_new_normdn_byval(config_area));
    }

    /*
     * Load the config.
     */
    if (ipa_otp_load_config() != 0) {
        slapi_log_error(SLAPI_LOG_FATAL, IPA_OTP_PLUGIN_SUBSYSTEM,
                        "ipa_otp_start: unable to load plug-in config\n");
        return -1;
    }

    g_plugin_started = 1;
    slapi_log_error(SLAPI_LOG_PLUGIN, IPA_OTP_PLUGIN_SUBSYSTEM,
                    "IPA OTP plug-in: ready for service\n");
    slapi_log_error(SLAPI_LOG_TRACE, IPA_OTP_PLUGIN_SUBSYSTEM,
                    "<-- ipa_otp_start\n");

done:
    return 0;
}

/*
 * ipa_otp_close()
 *
 * Clean up any resources allocated at startup.
 */
static int
ipa_otp_close(Slapi_PBlock * pb)
{
    slapi_log_error(SLAPI_LOG_TRACE, IPA_OTP_PLUGIN_SUBSYSTEM,
                    "--> ipa_otp_close\n");

    if (!g_plugin_started) {
        goto done;
    }

    g_plugin_started = 0;

    /* We are not guaranteed that other threads are finished accessing
     * PluginDN or ConfigAreaDN, so we don't want to free them.  This is
     * only a one-time leak at shutdown, so it should be fine.

    slapi_sdn_free(&_PluginDN);
    slapi_sdn_free(&_ConfigAreaDN);
    */

done:
    slapi_log_error(SLAPI_LOG_TRACE, IPA_OTP_PLUGIN_SUBSYSTEM,
                    "<-- ipa_otp_close\n");

    return 0;
}


/* 
 * Config cache management functions
 */
/*
 * ipa_otp_load_config()
 *
 * Loads the config entry, parses it, and applies it.
 *
 * Returns 0 upon success.
 */
static int
ipa_otp_load_config() {
    int ret = 0;
    Slapi_DN *config_sdn = NULL;
    Slapi_Entry *config_entry = NULL;
    char *config_attrs[] = { IPA_OTP_ALLOWED_AUTH_TYPE, NULL };

    slapi_log_error(SLAPI_LOG_TRACE, IPA_OTP_PLUGIN_SUBSYSTEM,
                    "--> ipa_otp_load_config\n");

    /* If we are using an alternate config area, check it for our
     * configuration, otherwise we just use our main plug-in config
     * entry. */
    if ((config_sdn = ipa_otp_get_config_area()) == NULL) {
        config_sdn = ipa_otp_get_plugin_sdn();
    }

    slapi_log_error(SLAPI_LOG_PLUGIN, IPA_OTP_PLUGIN_SUBSYSTEM,
                    "Looking for config settings in \"%s\".\n",
                    config_sdn ? slapi_sdn_get_ndn(config_sdn) : "null");

    /* Fetch the config entry. */
    slapi_search_internal_get_entry(config_sdn, config_attrs, &config_entry,
        ipa_otp_get_plugin_id());

    /* Parse and apply the config. */
    ipa_otp_parse_config_entry(config_entry, 1 /* apply */);

    slapi_entry_free(config_entry);

    slapi_log_error(SLAPI_LOG_TRACE, IPA_OTP_PLUGIN_SUBSYSTEM,
                    "<-- ipa_otp_load_config\n");

    return ret;
}


/*
 * ipa_otp_parse_config_entry()
 *
 * Parses and validates a config entry.  If apply is non-zero, then
 * we will load and start using the new config.  You can simply
 * validate config without making any changes by setting apply to 0.
 *
 * Returns 0 if the entry is valid and -1 if it is invalid.
 */
static int
ipa_otp_parse_config_entry(Slapi_Entry * e, int apply) {
    int ret = 0;
    PRInt32 default_auth_types = 0;
    PRInt32 allowed_auth_types = 0;

    slapi_log_error(SLAPI_LOG_TRACE, IPA_OTP_PLUGIN_SUBSYSTEM,
                    "--> ipa_otp_parse_config\n");

    /* If no auth types are set, we default to only allowing password
     * authentication.  Other authentication types can be allowed at the
     * user level. */
    default_auth_types |= IPA_OTP_AUTH_TYPE_PASSWORD;

    /* Parse and validate the config entry.  We currently tolerate invalid
     * config settings, so there is no real validation performed.  We will
     * likely want to reject invalid config as we expand the plug-in
     * functionality, so the validation logic is here for us to use later. */
    if (e) {
        char **auth_types = NULL;

        /* Fetch the auth type values from the config entry. */
        auth_types = slapi_entry_attr_get_charray(e, IPA_OTP_ALLOWED_AUTH_TYPE);

        /* Check each type to see if it is set. */
        if (auth_types) {
            if (ipa_otp_is_auth_type_allowed(auth_types,
                IPA_OTP_AUTH_TYPE_DISABLED)) {
                allowed_auth_types |= IPA_OTP_AUTH_TYPE_DISABLED;
            }

            if (ipa_otp_is_auth_type_allowed(auth_types,
                IPA_OTP_AUTH_TYPE_PASSWORD)) {
                allowed_auth_types |= IPA_OTP_AUTH_TYPE_PASSWORD;
            }

            if (ipa_otp_is_auth_type_allowed(auth_types,
                IPA_OTP_AUTH_TYPE_OTP)) { 
                allowed_auth_types |= IPA_OTP_AUTH_TYPE_OTP;
            }

            if (ipa_otp_is_auth_type_allowed(auth_types,
                IPA_OTP_AUTH_TYPE_PKINIT)) {
                allowed_auth_types |= IPA_OTP_AUTH_TYPE_PKINIT;
            }
        } else {
            /* No allowed auth types are specified, so set the defaults. */
            allowed_auth_types = default_auth_types;
        }

        slapi_ch_array_free(auth_types);
    } else {
        /* There is no config entry, so just set the defaults. */
        allowed_auth_types = default_auth_types;
    }

    if (apply) {
        /* Atomically set the global allowed types. */
        PR_ATOMIC_SET(&g_allowed_auth_types, allowed_auth_types);
    }

    slapi_log_error(SLAPI_LOG_TRACE, IPA_OTP_PLUGIN_SUBSYSTEM,
                    "<-- ipa_otp_parse_config\n");

    return ret;
}


/*
 * Helper functions
 */
static Slapi_DN *
ipa_otp_get_config_area() {
    return _ConfigAreaDN;
}

static void
ipa_otp_set_config_area(Slapi_DN *sdn) {
    _ConfigAreaDN = sdn;
}

static int
ipa_otp_dn_is_config(Slapi_DN *sdn) {
    int ret = 0;

    slapi_log_error(SLAPI_LOG_TRACE, IPA_OTP_PLUGIN_SUBSYSTEM,
                    "--> ipa_otp_dn_is_config\n");

    if (sdn == NULL) {
        goto bail;
    }

    /* If an alternate config area is configured, it is considered to be
     * the config entry, otherwise the main plug-in config entry is used. */
    if (ipa_otp_get_config_area()) {
        if (slapi_sdn_compare(sdn, ipa_otp_get_config_area()) == 0) {
            ret = 1;
        }
    } else {
        if (slapi_sdn_compare(sdn, ipa_otp_get_plugin_sdn()) == 0) {
            ret = 1;
        }
    }

bail:
    slapi_log_error(SLAPI_LOG_TRACE, IPA_OTP_PLUGIN_SUBSYSTEM,
                    "<-- ipa_otp_dn_is_config\n");

    return ret;
}

/*
 * ipa_otp_oktodo()
 *
 * Check if we want to process this operation.  We need to be
 * sure that the operation succeeded.
 */
static int
ipa_otp_oktodo(Slapi_PBlock *pb)
{
    int ret = 1;
    int oprc = 0;

    slapi_log_error(SLAPI_LOG_TRACE, IPA_OTP_PLUGIN_SUBSYSTEM,
                    "--> ipa_otp_oktodo\n");

    if(slapi_pblock_get(pb, SLAPI_PLUGIN_OPRETURN, &oprc) != 0) {
        slapi_log_error(SLAPI_LOG_FATAL, IPA_OTP_PLUGIN_SUBSYSTEM,
                        "ipa_otp_oktodo: could not get parameters\n");
        ret = -1;
    }

    /* This plugin should only execute if the operation succeeded. */
    if(oprc != 0) {
        ret = 0;
    }

    slapi_log_error( SLAPI_LOG_TRACE, IPA_OTP_PLUGIN_SUBSYSTEM,
                 "<-- ipa_otp_oktodo\n" );

    return ret;
}

/*
 * ipa_otp_is_disabled()
 *
 * Returns 1 if OTP authentication is globally enabled, 0 otherwise.
 */
static int
ipa_otp_is_disabled()
{
    int ret = 0;
    PRInt32 auth_type_flags;

    /* Do an atomic read of the allowed auth types bit field. */
    auth_type_flags = PR_ATOMIC_ADD(&g_allowed_auth_types, 0);

    /* Check if the disabled bit is set. */
    if (auth_type_flags & IPA_OTP_AUTH_TYPE_DISABLED) {
        ret = 1;
    }

    return ret;
}

/*
 * ipa_otp_is_auth_type_allowed()
 *
 * Checks if an authentication type is allowed.  A NULL terminated
 * list of allowed auth type values is passed in along with the flag
 * for the auth type you are inquiring about.  If auth_type_list is
 * NULL, the global config will be consulted.
 *
 * Returns 1 if the auth type is allowed, 0 otherwise.
 */
static int
ipa_otp_is_auth_type_allowed(char **auth_type_list, int auth_type)
{
    int ret = 0;
    int i = 0;
    char *auth_type_value = NULL;

    /* Get the string value for the authentication type we are checking for. */
    switch (auth_type) {
        case IPA_OTP_AUTH_TYPE_OTP:
            auth_type_value = IPA_OTP_AUTH_TYPE_VALUE_OTP;
            break;
        case IPA_OTP_AUTH_TYPE_PASSWORD:
            auth_type_value = IPA_OTP_AUTH_TYPE_VALUE_PASSWORD;
            break;
        case IPA_OTP_AUTH_TYPE_PKINIT:
            auth_type_value = IPA_OTP_AUTH_TYPE_VALUE_PKINIT;
            break;
        default:
            /*Unknown type.  Bail. */
            goto bail;
    }

    if (auth_type_list) {
        /* Check if the requested authentication type is in the user list. */
        for (i = 0; auth_type_list[i]; i++) {
            if (strcasecmp(auth_type_list[i], auth_type_value) == 0) {
                ret = 1;
            }
        }
    } else {
        /* Check if the requested authentication type is in the global list. */
        PRInt32 auth_type_flags;

        /* Do an atomic read of the allowed auth types bit field. */
        auth_type_flags = PR_ATOMIC_ADD(&g_allowed_auth_types, 0);

        /* Check if the flag for the desired auth type is set. */
        if (auth_type_flags & auth_type) {
            ret = 1;
        }
    }

bail:
    return ret;
}

/*
 * ipa_otp_do_otp_auth()
 *
 * Attempts to perform OTP authentication for the passed in bind entry using
 * the passed in credentials.
 *
 * Returns 1 if authentication was successful, 0 if unsuccessful.
 */
static int
ipa_otp_do_otp_auth(Slapi_Entry *bind_entry, struct berval *creds)
{
    int ret = 0;
    int result = 0;
    int pwd_numvals = 0;
    int i = 0;
    int hint = 0;
    Slapi_PBlock *search_pb = NULL;
    Slapi_Backend *be = NULL;
    Slapi_DN *base_sdn = NULL;
    Slapi_Entry **tokens = NULL;
    Slapi_Attr *pwd_attr = NULL;
    Slapi_Value **pwd_vals = NULL;
    char *filter = NULL;
    char *user_dn = NULL;

    search_pb = slapi_pblock_new();

    /* Fetch the user DN. */
    user_dn = slapi_entry_get_ndn(bind_entry);
    if (user_dn == NULL) {
        slapi_log_error(SLAPI_LOG_FATAL, IPA_OTP_PLUGIN_SUBSYSTEM,
                        "ipa_otp_do_otp_auth: error retrieving bind DN.\n");
        goto bail;
    }

    /* Search for TOTP tokens associated with this user.  We search for
     * tokens who list this user as the owner in the same backend where
     * the user entry is located. */
    filter = slapi_ch_smprintf("(&(%s=%s)(%s=%s))", SLAPI_ATTR_OBJECTCLASS,
        IPA_OTP_TOKEN_TOTP_OC, IPA_OTP_TOKEN_OWNER_TYPE, user_dn);

    be = slapi_be_select(slapi_entry_get_sdn(bind_entry));
    if (!be || (base_sdn = (Slapi_DN *)slapi_be_getsuffix(be,0)) == NULL) {
        slapi_log_error(SLAPI_LOG_FATAL, IPA_OTP_PLUGIN_SUBSYSTEM,
                        "ipa_otp_do_otp_auth: error determining the search "
                        "base for user \"%s\".\n", user_dn);
    }

    slapi_search_internal_set_pb(search_pb, slapi_sdn_get_ndn(base_sdn),
                                 LDAP_SCOPE_SUBTREE, filter, NULL, 0, NULL,
                                 NULL, ipa_otp_get_plugin_id(), 0);

    slapi_search_internal_pb(search_pb);
    slapi_pblock_get(search_pb, SLAPI_PLUGIN_INTOP_RESULT, &result);

    if (LDAP_SUCCESS != result) {
        slapi_log_error(SLAPI_LOG_FATAL, IPA_OTP_PLUGIN_SUBSYSTEM,
                        "ipa_otp_do_otp_auth: error searching for tokens "
                        "associated with user \"%s\" (err=%d).\n",
                        user_dn, result);
        goto bail;
    }

    slapi_pblock_get(search_pb, SLAPI_PLUGIN_INTOP_SEARCH_ENTRIES, &tokens);

    if (tokens == NULL) {
        /* This user has no associated tokens, so just bail out. */
        goto bail;
    }

    /* Fetch the userPassword values so we can perform the password checks
     * when processing tokens below. */
    if (slapi_entry_attr_find(bind_entry, SLAPI_USERPWD_ATTR, &pwd_attr) != 0 ||
        slapi_attr_get_numvalues(pwd_attr, &pwd_numvals) != 0 ) {
        slapi_log_error(SLAPI_LOG_PLUGIN, IPA_OTP_PLUGIN_SUBSYSTEM,
                        "ipa_otp_do_otp_auth: no passwords are set for user "
                        "\"%s\".\n", user_dn);
        goto bail;
    }

    /* We need to create a Slapi_Value  array of the present password values
     * for the compare function.  There's no nicer way of doing this. */
    pwd_vals = (Slapi_Value **)slapi_ch_calloc(pwd_numvals,
        sizeof(Slapi_Value *));

    for (hint = slapi_attr_first_value(pwd_attr, &pwd_vals[i]); hint != -1;
        hint = slapi_attr_next_value(pwd_attr, hint, &pwd_vals[i])) {
        ++i;
    }


    /* Loop through each token and attempt to authenticate. */
    for (i = 0; tokens && tokens[i]; i++) {
         int token_length = 0;
         char *password = NULL;
         Slapi_Value *password_val = NULL;

        /* Find out how long the token code is so we can split it from
         * the password.  */
        token_length = slapi_entry_attr_get_int(tokens[i],
            IPA_OTP_TOKEN_LENGTH_TYPE);

        /* If tokenLength is 0 or not defined, skip to next token. */
        if (token_length == 0) {
            slapi_log_error(SLAPI_LOG_PLUGIN, IPA_OTP_PLUGIN_SUBSYSTEM,
                        "ipa_otp_do_otp_auth: %s is not defined or set to 0 "
                        "for token \"%s\".\n", IPA_OTP_TOKEN_LENGTH_TYPE,
                        slapi_entry_get_ndn(tokens[i]));
            continue;
        }

        /* Is the credential too short?  If so, skip to the next token. */
        if (token_length >= creds->bv_len) {
            slapi_log_error(SLAPI_LOG_PLUGIN, IPA_OTP_PLUGIN_SUBSYSTEM,
                        "ipa_otp_do_otp_auth: supplied credential is less than "
                        "or equal to %s for token \"%s\".\n",
                        IPA_OTP_TOKEN_LENGTH_TYPE,
                        slapi_entry_get_ndn(tokens[i]));
            continue;
        }

        /* Extract the password from the supplied credential.  We hand the
         * memory off to a Slapi_Value, so we don't want to directly free the
         * string. */
        password = slapi_ch_malloc(creds->bv_len - token_length + 1);
        strncpy(password, creds->bv_val, creds->bv_len - token_length + 1);
        password_val = slapi_value_new_string_passin(password);

        /* Check if the password portion of the credential is correct. */
        if (slapi_pw_find_sv(pwd_vals, password_val) == 0) {
            char *token_code = NULL;
            char *token_key = NULL;
            char *token_algorithm = NULL;
            char *token_offset = NULL;
            char *token_step = NULL;

            /* Extract the token code from the supplied credential. */
            token_code = slapi_ch_malloc(token_length + 1);
            strncpy(token_code, creds->bv_val - token_length + 1,
                token_length + 1);

            /* Extract the rest of the token info that we need for
             * authentication from the token entry. */
            token_key = slapi_entry_attr_get_charptr(tokens[i],
                IPA_OTP_TOKEN_KEY_TYPE);
            token_algorithm = slapi_entry_attr_get_charptr(tokens[i],
                IPA_OTP_TOKEN_ALGORITHM_TYPE);
            token_offset = slapi_entry_attr_get_charptr(tokens[i],
                IPA_OTP_TOKEN_OFFSET_TYPE);
            token_step = slapi_entry_attr_get_charptr(tokens[i],
                IPA_OTP_TOKEN_STEP_TYPE);

            /* If any of our required values are NULL, don't attempt
             * to auth with this token. */
            if (!token_key || !token_algorithm || !token_offset ||
                !token_step) {
                slapi_log_error(SLAPI_LOG_PLUGIN, IPA_OTP_PLUGIN_SUBSYSTEM,
                                "ipa_otp_do_otp_auth: all required token "
                                "values not specified for token \"%s\".\n",
                                slapi_entry_get_ndn(tokens[i]));
            } else {
                /* Attempt to perform TOTP authentication for this token. */
                if (ipa_otp_authenticate_totp_token(token_code, token_length,
                    token_key, token_algorithm, token_offset, token_step)) {
                    /* Auth successful. */
                    slapi_log_error(SLAPI_LOG_PLUGIN, IPA_OTP_PLUGIN_SUBSYSTEM,
                                    "ipa_otp_do_otp_auth: successfully "
                                    "authenticated user \"%s\" using token "
                                    "\"%s\".\n", user_dn,
                                    slapi_entry_get_ndn(tokens[i]));
                    ret = 1;
                } else {
                    /* Auth failed. */
                    slapi_log_error(SLAPI_LOG_PLUGIN, IPA_OTP_PLUGIN_SUBSYSTEM,
                                    "ipa_otp_do_otp_auth: OTP auth failed when "
                                    "processing token \"%s\" for user \"%s\""
                                    ".\n", slapi_entry_get_ndn(tokens[i]),
                                    user_dn);
                }
            }

            /* Cleanup allocated token values. */
            slapi_ch_free_string(&token_code);
            slapi_ch_free_string(&token_key);
            slapi_ch_free_string(&token_algorithm);
            slapi_ch_free_string(&token_offset);
            slapi_ch_free_string(&token_step);

            /* Stop processing tokens if we successfully authenticated. */
            if (ret == 1) {
                break;
            }
        } else {
            slapi_log_error(SLAPI_LOG_PLUGIN, IPA_OTP_PLUGIN_SUBSYSTEM,
                            "ipa_otp_do_otp_auth: password check failed when "
                            "processing token \"%s\" for user \"%s\".\n",
                            slapi_entry_get_ndn(tokens[i]), user_dn);
        }

        /* Cleanup */
        slapi_value_free(&password_val);
    }

bail:
    slapi_ch_free_string(&filter);
    slapi_free_search_results_internal(search_pb);
    slapi_pblock_destroy(search_pb);

    return ret;
}

/*
 * ipa_otp_authenticate_totp_token()
 *
 * Performs a TOTP authentication using the passed in token parameters.
 *
 * Returns 1 for a successful auth, 0 for failure.
 */
static int
ipa_otp_authenticate_totp_token(const char *token_code, int token_length,
    const char *token_key, const char *token_algorithm,
    const char *token_offset, const char *token_step)
{
    int ret = 0;

    /* NGK - fill in TOTP authentication logic here. */

    return ret;
}


/*
 * Operation callback functions
 */
static int
ipa_otp_postop_add(Slapi_PBlock *pb)
{
    return ipa_otp_postop(pb, LDAP_CHANGETYPE_ADD);
}

static int
ipa_otp_postop_del(Slapi_PBlock *pb)
{
    return ipa_otp_postop(pb, LDAP_CHANGETYPE_DELETE);
}

static int
ipa_otp_postop_mod(Slapi_PBlock *pb)
{
    return ipa_otp_postop(pb, LDAP_CHANGETYPE_MODIFY);
}

static int
ipa_otp_postop_modrdn(Slapi_PBlock *pb)
{
    return ipa_otp_postop(pb, LDAP_CHANGETYPE_MODDN);
}

static int
ipa_otp_postop(Slapi_PBlock *pb, int optype)
{
    int ret = 0;
    Slapi_DN *sdn = NULL;
    Slapi_DN *new_sdn = NULL;
    Slapi_Entry *config_entry = NULL;

    slapi_log_error(SLAPI_LOG_PLUGIN, IPA_OTP_PLUGIN_SUBSYSTEM,
                    "--> ipa_otp_postop\n");

    /* Just bail if we are not started yet, or if the operation failed. */
    if (!g_plugin_started || !ipa_otp_oktodo(pb)) {
        goto bail;
    }

    /* Check if a change affected our config entry and reload the
     * in-memory config settings if needed. */
    slapi_pblock_get(pb, SLAPI_TARGET_SDN, &sdn);
    switch (optype) {
    case LDAP_CHANGETYPE_ADD:
    case LDAP_CHANGETYPE_MODIFY:
        if (ipa_otp_dn_is_config(sdn)) {
            /* The config entry was added or modified, so reload it from
             * the post-op entry. */
            slapi_pblock_get(pb, SLAPI_ENTRY_POST_OP, &config_entry);

            if (config_entry) {
                ipa_otp_parse_config_entry(config_entry, 1 /* apply */);
            } else {
                slapi_log_error(SLAPI_LOG_FATAL, IPA_OTP_PLUGIN_SUBSYSTEM,
                                "ipa_otp_postop: unable to retrieve config "
                                "entry.\n");
            }
        }

        break;
    case LDAP_CHANGETYPE_DELETE:
        if (ipa_otp_dn_is_config(sdn)) {
            /* The config entry was deleted, so this just sets the defaults. */
            ipa_otp_parse_config_entry(NULL, 1 /* apply */);
            break;
        }
    case LDAP_CHANGETYPE_MODDN:
        if (ipa_otp_dn_is_config(sdn)) {
            /* Our config entry was renamed.  We treat this like the entry
             * was deleted, so just set the defaults. */
            ipa_otp_parse_config_entry(NULL, 1 /* apply */);
        } else {
            /* Check if an entry was renamed such that it has become our
             * config entry.  If so, reload the config from this new entry. */
            slapi_pblock_get(pb, SLAPI_ENTRY_POST_OP, &config_entry);

            if (config_entry) {
                if (new_sdn = slapi_entry_get_sdn(config_entry)) {
                    if (ipa_otp_dn_is_config(new_sdn)) {
                        ipa_otp_parse_config_entry(config_entry, 1 /* apply */);
                    }
                } else {
                    slapi_log_error(SLAPI_LOG_FATAL, IPA_OTP_PLUGIN_SUBSYSTEM,
                                    "ipa_otp_postop: unable to retrieve DN of "
                                    "renamed entry.\n");
                }
            } else {
                slapi_log_error(SLAPI_LOG_FATAL, IPA_OTP_PLUGIN_SUBSYSTEM,
                                "ipa_otp_postop: unable to retrieve renamed "
                                "entry.\n");
            }
        }

        break;
    }

bail:
    slapi_log_error(SLAPI_LOG_TRACE, IPA_OTP_PLUGIN_SUBSYSTEM,
                    "<-- ipa_otp_postop\n");

    return ret;
}

static int
ipa_otp_preop_bind(Slapi_PBlock * pb)
{
    int ret = IPA_OTP_OP_NOT_HANDLED;
    int result = LDAP_SUCCESS;
    int method;
    const char *bind_dn = NULL;
    Slapi_DN *bind_sdn = NULL;
    Slapi_Entry *bind_entry = NULL;
    struct berval *creds = NULL;
    char *user_attrs[] = { IPA_OTP_ALLOWED_AUTH_TYPE, NULL };
    char **auth_types = NULL;
    int auth_type_used = IPA_OTP_AUTH_TYPE_NONE;

    slapi_log_error(SLAPI_LOG_TRACE, IPA_OTP_PLUGIN_SUBSYSTEM,
                    "--> ipa_otp_preop_bind\n");

    /* If we didn't start successfully, bail. */
    if (!g_plugin_started) {
        goto bail;
    }

    /* If global disabled flag is set, just punt. */
    if (ipa_otp_is_disabled()) {
        goto bail;
    }

    /* Retrieve parameters for bind operation. */
    if (slapi_pblock_get(pb, SLAPI_BIND_METHOD, &method) != 0 ||
            slapi_pblock_get(pb, SLAPI_BIND_TARGET_SDN, &bind_sdn) != 0 ||
            slapi_pblock_get(pb, SLAPI_BIND_CREDENTIALS, &creds) != 0 ) {
        slapi_log_error(SLAPI_LOG_FATAL, IPA_OTP_PLUGIN_SUBSYSTEM,
                "<= not handled (unable to retrieve bind parameters)\n" );
        goto bail;
    }
    bind_dn = slapi_sdn_get_dn(bind_sdn);

    /* We only handle non-anonymous simple binds.  We just pass everything
     * else through to the server. */
    if (method != LDAP_AUTH_SIMPLE || *bind_dn == '\0' ||
            creds->bv_len == 0) {
        slapi_log_error( SLAPI_LOG_PLUGIN, IPA_OTP_PLUGIN_SUBSYSTEM,
                 "<= not handled (not simple bind or NULL dn/credentials)\n" );
        goto bail;
    }

    /* Check if any allowed authentication types are set in the user entry.
     * If not, we just use the global settings from the config entry. */
    result = slapi_search_internal_get_entry(bind_sdn, user_attrs, &bind_entry,
            ipa_otp_get_plugin_id());

    if (result != LDAP_SUCCESS) {
        slapi_log_error(SLAPI_LOG_FATAL, IPA_OTP_PLUGIN_SUBSYSTEM,
                "<= not handled (could not search for BIND dn %s - "
                "error %d : %s)\n", bind_dn, result, ldap_err2string(result));
        goto bail;
    } else if (NULL == bind_entry) {
        slapi_log_error(SLAPI_LOG_PLUGIN, IPA_OTP_PLUGIN_SUBSYSTEM,
                "<= not handled (could not find entry for BIND dn %s)\n",
                bind_dn);
        goto bail;
    } else if (slapi_check_account_lock( pb, bind_entry, 0, 0, 0 ) == 1) {
        slapi_log_error(SLAPI_LOG_PLUGIN, IPA_OTP_PLUGIN_SUBSYSTEM,
                "<= not handled (account %s inactivated.)\n", bind_dn);
        goto bail;
    } else {
        auth_types = slapi_entry_attr_get_charray(bind_entry,
                IPA_OTP_ALLOWED_AUTH_TYPE);
    }                       


    /* If OTP is allowed, attempt to do OTP authentication. */
    if (ipa_otp_is_auth_type_allowed(auth_types, IPA_OTP_AUTH_TYPE_OTP)) {
        slapi_log_error(SLAPI_LOG_PLUGIN, IPA_OTP_PLUGIN_SUBSYSTEM,
                        "Attempting OTP authentication for \"%s\".\n", bind_dn);
        if (ipa_otp_do_otp_auth(bind_entry, creds)) {
            auth_type_used = IPA_OTP_AUTH_TYPE_OTP;
        }
    }

    /* If we haven't successfully authenticated with OTP already,
     * see if password authentication is allowed. */
    if (auth_type_used == IPA_OTP_AUTH_TYPE_NONE) {
        if (ipa_otp_is_auth_type_allowed(auth_types,
            IPA_OTP_AUTH_TYPE_PASSWORD)) {
            slapi_log_error(SLAPI_LOG_PLUGIN, IPA_OTP_PLUGIN_SUBSYSTEM,
                            "Attempting PASSWORD authentication for \"%s\".\n",
                            bind_dn);
            /* NGK - We just pass through to the server to do normal password
             * auth.  The problem is that we need to figure out how to build
             * the reponse control in that case.  Maybe we can use a
             * SLAPI_PLUGIN_PRE_RESULT_FN callback to handle that? */
        } else {
            /* OTP failed (or wasn't allowed), and password auth is not
             * allowed.  Return failure to the client. */
            slapi_send_ldap_result(pb, LDAP_INVALID_CREDENTIALS, NULL,
                NULL, 0, NULL);

            /* Let the server know we have already sent the result. */
            ret = IPA_OTP_OP_HANDLED;

            goto bail;
        }
    }

    /* If we authenticated successfully via OTP, send the response. */
    if (auth_type_used == IPA_OTP_AUTH_TYPE_OTP) {
        /* NGK - If the auth type request control was sent, construct the
         * response control to indicate what auth type was used.  We might be
         * able to do this in the SLAPI_PLUGIN_PRE_RESULT_FN callback instead
         * of here. */

        /* NGK - What about other controls, like the pwpolicy control?
         * If any other critical controls are set, we need to either
         * process them properly or reject the operation with an
         * unsupported critical control error. */

        slapi_send_ldap_result(pb, LDAP_SUCCESS, NULL, NULL, 0, NULL);
        ret = IPA_OTP_OP_HANDLED;
    }

bail:
    slapi_ch_array_free(auth_types);
    slapi_entry_free(bind_entry);

    slapi_log_error(SLAPI_LOG_TRACE, IPA_OTP_PLUGIN_SUBSYSTEM,
                    "<-- ipa_otp_preop_bind\n");
    return ret;
}
