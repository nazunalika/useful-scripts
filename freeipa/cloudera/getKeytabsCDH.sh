#!/bin/bash
# Created by: @nazunalika - Louis Abel
# Purpose: To retrieve keytabs for Cloudera / Hadoop from FreeIPA
# https://github.com/nazunalika/useful-scripts

# Disclaimer: We do not take responsibilities for breaches or misconfigurations of
#             software. Use at your own risk

# Variables
# This can be anywhere, but it SHOULD be secure with at least 600 permissions
CDHKT="/root/.cdh/cdh.keytab"
CDHUSER="cdh"
IPAREALM="EXAMPLE.COM"
# This can be any server. You could make an array and have it randomly selected
IPASERVER="ipa01.example.com"

# Where is this going?
DESTINATION="$1"
# The full principal for the keytab in question
FULLPRINC="$2"
# Shortened name
PRINC=$(echo $FULLPRINC | sed "s/\@$(echo $IPAREALM)//")

00_kinitUser() {
  # Pick what suits you best, we prefer using a keytab
  # Password based kinit, based on the keytab we created prior!
  # You could also have this in a file somewhere, I guess. Just
  # has to be secured.
  echo ThisIsAWeakPassword | kinit $CDHUSER@$IPAREALM

  # Keytab based kinit, obviously we created it before right? It just needs to be
  # on the right system, deployed in some secure manner
  #kinit -kt $CDHKT $CDHUSER@$IPAREALM
  if [[ $? == "1" ]]; then
    echo FAILED TO KINIT
    exit
  fi
}

01_createPrinc() {
  echo "INFO: Checking for existing principle"
  if ipa service-find $FULLPRINC; then
    echo "INFO: Principle found"
  else
    echo "INFO: Not found, creating"
    ipa service-add $FULLPRINC
  fi
}

02_createServiceAllows() {
  # We need to allow the service to create and retrieve keytabs
  echo "INFO: Ensuring service allows to create and retrieve keytabs"
  ipa service-allow-create-keytab --users=$CDHUSER $FULLPRINC
  ipa service-allow-retrieve-keytab --users=$CDHUSER $FULLPRINC

  # Let's retrieve the keytabs
  if ipa service-show $FULLPRINC | grep 'Keytab' | grep 'False'; then
    echo "INFO: Creating keytab for $FULLPRINC to $DESTINATION"
    ipa-getkeytab -s $IPASERVER -p $PRINC -k $DESTINATION
  else
    echo "INFO: Retriving keytab for $FULLPRINC to $DESTINATION"
    ipa-getkeytab -r -s $IPASERVER -p $PRINC -k $DESTINATION
  fi
}

00_kinitUser
01_createPrinc
02_createServiceAllows

kdestroy
exit 0

