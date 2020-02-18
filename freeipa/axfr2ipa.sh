#!/bin/bash
# This script generates the IPA commands to take the zone transfer of a domain
# to import into freeipa's DNS. This is under the assumption that a zone is
# being moved to another to DNS server to host in a network (eg, moving from
# a standalone DNS server such as bind) to FreeIPA's DNS.

# Replace IPADDR with DNS Server (eg 10.110.0.1)
# Replace DOMAIN with zone domain name (eg example.com)

dig AXFR @IPADDR DOMAIN | egrep "A|CNAME|AAAA" | sort -k5 | awk '{
  if ($4=="CNAME") {
    printf "ipa dnsrecord-add DOMAIN";
    printf " \""$1"\"";
    printf " --cname-hostname=\""$5"\"\n";
  }
  else if ($4=="A") {
    printf "ipa dnsrecord-add DOMAIN";
    printf " \""$1"\"";
    printf " --a-ip-address=\""$5"\""
    printf " --a-create-reverse\n";
  }
  else if ($4=="AAAA") {
    printf "ipa dnsrecord-add DOMAIN";
    printf " \""$1"\"";
    printf " --aaaa-ip-address=\""$5"\""
    printf " --aaaa-create-reverse\n";
  }
}'
