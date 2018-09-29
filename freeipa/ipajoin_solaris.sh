#!/bin/bash
# Louis Abel
# Solaris IPA Join Script
# It is HIGHLY recommended to compile pam_hbac

# Sources
. ./solaris/vars
. ./solaris/opers

# Calling
pull_certificate
set_defaultdomain
configure_nsswitch
configure_ldap
configure_kerberos
configure_pam
test_ldapuser

