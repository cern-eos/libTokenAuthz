# libTokenAuthz 
author: Andreas-Joachim Peters: CERN/IT-DSS
mail-to: Andreas.Joachim.Peters@cern.ch

TokenAuthz Module Configuration Behaviour:
==========================================

The TokenAuthz Authorization Object looks per default in the following locations for configuration files:
1	Environment Variable: export TTOKENAUTHZ_AUTHORIZATIONFILE="<authzfile>"
2	/etc/grid-security/<module-name>/TkAuthz.Authorization
3	$HOME/.globus/<module-name>/TkAuthz.Authorization
4	$HOME/.authz/<module-name>/TkAuthz.Authorization

If no one of these is found, the default behaviour is to disable the authorization for the complete namespace and to 
export the complete namespace.





TokenAuthz Configuration File Structure:
========================================

The structure can be best understood by inspecting the example files in the 'conf' directory.
The module works with the principle, the the first matching rule is applied. So, order
your rules in an appropriate way.  

Configuration File: "TkAuthz.Authorization"

```
#####################################################################
# Description:
# -------------------------------------------------------------------
# This file describes, which namespace paths are exported and can
# enforce token authorization for specific VO's and paths.
#
# Structure:
# -------------------------------------------------------------------
# The file contiains three section:
# KEYS:
# =======
# this section assigns to each VO the private and public key pairs
# to be used, to decode and verify authorization tokens
#
# EXPORT:
# =======
# this section defines, which namespace path's are exported.
# The rules can allow or deny part of the namespace for individual
# VO's and certificates
#
# RULES:
# =======
# this section contains specific ruls for each namespace path, if
# token authorization has to be applied, to which operations and
# for which VO and certificates it has to be applied.

# ------------------------------ Warning ----------------------------
# the key words
#       KEY, EXPORT, RULE
#       VO, PRIVKEY, PUBKEY
#       PATH, AUTHZ, NOAUTHZ, CERT
# have to be all uppercase! Values are assigned after a ':'
# -------------------------------------------------------------------


#####################################################################
# Key section
#####################################################################
#
# Syntax:KEY  VO:<voname>     PRIVKEY:<keyfile>      PUBKEY:<keyfile>
#
#  ------------------------------------------------------------------
# VO:* defines the default keys for unspecified vo

#KEY VO:ALICE  PRIVKEY:key.pem PUBKEY:pkey.pem
#KEY VO:CMS    PRIVKEY:<pkey>  PUBKEY:<pubkey>
#KEY VO:*      PRIVKEY:<pkey>  PUBKEY:<pubkey>

######################################################################
# Export Section
#####################################################################
#
# Syntax: EXPORT PATH:<path> 	VO:<vo>	ACCESS:<ALLOW|DENY>	CERT:<*|cert>
#		
#  ------------------------------------------------------------------
# - PATH needs to be terminated with /
# - ACCESS can be ALLOW or DENY
# - VO can be wildcarded with VO:*
# - CERT can be wildcarded with CERT:*
# - the first matching rule is applied 

#EXPORT PATH:/tmp/alice/ VO:ALICE ACCESS:ALLOW CERT:*
#EXPORT PATH:/tmp/cms/   VO:CMS   ACCESS:DENY CERT:*
#EXPORT PATH:/castor/    VO:*     ACCESS:ALLOW CERT:*

######################################################################
# RULES Section
######################################################################
#
#  Syntax: RULE PATH:<path> AUTHZ:<tag1|tag2|...|> NOAUTHZ:<tag1|tag2|...|> VO:<vo1|vo2|....|> CERT:<IGNORE|*|cert>
#   
#  ------------------------------------------------------------------
# - PATH  defines the namespace path
# - AUTHZ defines the actions which have to be authorized
# - NOAUTHZ defines the actions which don't have to be authorized
# - VO is a list of VO's, where this rule applies
# - CERT can be IGNORE,* or a specific certificate subject
#   IGNORE means, that the envelope certificate must not match the
#   USER certificate subject. * means, that the rule applies for any
#   certificate and the certificate subjects have to match.


#RULE PATH:/tmp/ AUTHZ:write|delete|write-once| NOAUTHZ:read| VO:ALICE|CMS| CERT:IGNORE
#RULE PATH:/tmp/ AUTHZ:read| NOAUTHZ:| VO:ALICE|CMS| CERT:*
```

