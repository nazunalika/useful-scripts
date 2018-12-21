#!/bin/bash
# Louis Abel
# Solaris IPA Join Script
# It is HIGHLY recommended to compile pam_hbac

# Directory to avoid issues of calling scripts somewhere else and
# it not getting sourced correctly
export DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd )"

# Sources
. ${DIR}/solaris/vars
. ${DIR}/solaris/opers

# Calling
check_current_config
pull_certificate
create_hostobject
set_defaultdomain
configure_nsswitch
configure_ldap
configure_kerberos
configure_pam
test_ldapuser
check_host_keytab
