#!/bin/sh
#
# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

# shellcheck source=conf.sh
. ../conf.sh

RNDCCMD="$RNDC -c ../common/rndc.conf -p ${CONTROLPORT} -s"

set -e

status=0
n=1
synth_default=yes

rm -f dig.out.*

dig_with_opts() {
    "$DIG" +tcp +noadd +nosea +nostat +nocmd +dnssec -p "$PORT" "$@"
}

for ns in 2 4 5 6
do
    case $ns in
    2) ad=yes; description="<default>";;
    4) ad=yes; description="no";;
    5) ad=yes; description="yes";;
    6) ad=no; description="yes; dnssec-validation no";;
    *) exit 1;;
    esac
    echo_i "prime negative NXDOMAIN response (synth-from-dnssec ${description};) ($n)"
    ret=0
    dig_with_opts a.example. @10.53.0.${ns} a > dig.out.ns${ns}.test$n || ret=1
    if [ $ad = yes ]
    then
	grep "flags:[^;]* ad[ ;]" dig.out.ns${ns}.test$n > /dev/null || ret=1
    else
	grep "flags:[^;]* ad[ ;]" dig.out.ns${ns}.test$n > /dev/null && ret=1
    fi
    grep "status: NXDOMAIN," dig.out.ns${ns}.test$n > /dev/null || ret=1
    grep "example.*3600.IN.SOA" dig.out.ns${ns}.test$n > /dev/null || ret=1
    [ $ns -eq 2 ] && cp dig.out.ns${ns}.test$n nxdomain.out
    n=$((n+1))
    if [ $ret != 0 ]; then echo_i "failed"; fi
    status=$((status+ret))

    echo_i "prime negative NODATA response (synth-from-dnssec ${description};) ($n)"
    ret=0
    dig_with_opts nodata.example. @10.53.0.${ns} a > dig.out.ns${ns}.test$n || ret=1
    if [ $ad = yes ]
    then
	grep "flags:[^;]* ad[ ;]" dig.out.ns${ns}.test$n > /dev/null || ret=1
    else
	grep "flags:[^;]* ad[ ;]" dig.out.ns${ns}.test$n > /dev/null && ret=1
    fi
    grep "status: NOERROR," dig.out.ns${ns}.test$n > /dev/null || ret=1
    grep "example.*3600.IN.SOA" dig.out.ns${ns}.test$n > /dev/null || ret=1
    [ $ns -eq 2 ] && cp dig.out.ns${ns}.test$n nodata.out
    n=$((n+1))
    if [ $ret != 0 ]; then echo_i "failed"; fi
    status=$((status+ret))

    echo_i "prime wildcard response (synth-from-dnssec ${description};) ($n)"
    ret=0
    dig_with_opts a.wild-a.example. @10.53.0.${ns} a > dig.out.ns${ns}.test$n || ret=1
    if [ $ad = yes ]
    then
	grep "flags:[^;]* ad[ ;]" dig.out.ns${ns}.test$n > /dev/null || ret=1
    else
	grep "flags:[^;]* ad[ ;]" dig.out.ns${ns}.test$n > /dev/null && ret=1
    fi
    grep "status: NOERROR," dig.out.ns${ns}.test$n > /dev/null || ret=1
    grep "a.wild-a.example.*3600.IN.A" dig.out.ns${ns}.test$n > /dev/null || ret=1
    [ $ns -eq 2 ] && sed 's/^a\./b./' dig.out.ns${ns}.test$n > wild.out
    n=$((n+1))
    if [ $ret != 0 ]; then echo_i "failed"; fi
    status=$((status+ret))

    echo_i "prime wildcard CNAME response (synth-from-dnssec ${description};) ($n)"
    ret=0
    dig_with_opts a.wild-cname.example. @10.53.0.${ns} a > dig.out.ns${ns}.test$n || ret=1
    if [ $ad = yes ]
    then
	grep "flags:[^;]* ad[ ;]" dig.out.ns${ns}.test$n > /dev/null || ret=1
    else
	grep "flags:[^;]* ad[ ;]" dig.out.ns${ns}.test$n > /dev/null && ret=1
    fi
    grep "status: NOERROR," dig.out.ns${ns}.test$n > /dev/null || ret=1
    grep "a.wild-cname.example.*3600.IN.CNAME" dig.out.ns${ns}.test$n > /dev/null || ret=1
    [ $ns -eq 2 ] && sed 's/^a\./b./' dig.out.ns${ns}.test$n > wildcname.out
    n=$((n+1))
    if [ $ret != 0 ]; then echo_i "failed"; fi
    status=$((status+ret))

    echo_i "prime insecure negative NXDOMAIN response (synth-from-dnssec ${description};) ($n)"
    ret=0
    dig_with_opts a.insecure.example. @10.53.0.${ns} a > dig.out.ns${ns}.test$n || ret=1
    grep "flags:[^;]* ad[ ;]" dig.out.ns${ns}.test$n > /dev/null && ret=1
    grep "status: NXDOMAIN," dig.out.ns${ns}.test$n > /dev/null || ret=1
    grep "insecure.example.*3600.IN.SOA" dig.out.ns${ns}.test$n > /dev/null || ret=1
    [ $ns -eq 2 ] && cp dig.out.ns${ns}.test$n insecure.nxdomain.out
    n=$((n+1))
    if [ $ret != 0 ]; then echo_i "failed"; fi
    status=$((status+ret))

    echo_i "prime insecure negative NODATA response (synth-from-dnssec ${description};) ($n)"
    ret=0
    dig_with_opts nodata.insecure.example. @10.53.0.${ns} a > dig.out.ns${ns}.test$n || ret=1
    grep "flags:[^;]* ad[ ;]" dig.out.ns${ns}.test$n > /dev/null && ret=1
    grep "status: NOERROR," dig.out.ns${ns}.test$n > /dev/null || ret=1
    grep "insecure.example.*3600.IN.SOA" dig.out.ns${ns}.test$n > /dev/null || ret=1
    [ $ns -eq 2 ] && cp dig.out.ns${ns}.test$n insecure.nodata.out
    n=$((n+1))
    if [ $ret != 0 ]; then echo_i "failed"; fi
    status=$((status+ret))

    echo_i "prime insecure wildcard response (synth-from-dnssec ${description};) ($n)"
    ret=0
    dig_with_opts a.wild-a.insecure.example. @10.53.0.${ns} a > dig.out.ns${ns}.test$n || ret=1
    grep "flags:[^;]* ad[ ;]" dig.out.ns${ns}.test$n > /dev/null && ret=1
    grep "status: NOERROR," dig.out.ns${ns}.test$n > /dev/null || ret=1
    grep "a.wild-a.insecure.example.*3600.IN.A" dig.out.ns${ns}.test$n > /dev/null || ret=1
    [ $ns -eq 2 ] && sed 's/^a\./b./' dig.out.ns${ns}.test$n > insecure.wild.out
    n=$((n+1))
    if [ $ret != 0 ]; then echo_i "failed"; fi
    status=$((status+ret))

    echo_i "prime wildcard CNAME response (synth-from-dnssec ${description};) ($n)"
    ret=0
    dig_with_opts a.wild-cname.insecure.example. @10.53.0.${ns} a > dig.out.ns${ns}.test$n || ret=1
    grep "flags:[^;]* ad[ ;]" dig.out.ns${ns}.test$n > /dev/null && ret=1
    grep "status: NOERROR," dig.out.ns${ns}.test$n > /dev/null || ret=1
    grep "a.wild-cname.insecure.example.*3600.IN.CNAME" dig.out.ns${ns}.test$n > /dev/null || ret=1
    [ $ns -eq 2 ] && sed 's/^a\./b./' dig.out.ns${ns}.test$n > insecure.wildcname.out
    n=$((n+1))
    if [ $ret != 0 ]; then echo_i "failed"; fi
    status=$((status+ret))

    echo_i "prime minimal NXDOMAIN response (synth-from-dnssec ${description};) ($n)"
    ret=0
    dig_with_opts nxdomain.minimal. @10.53.0.${ns} a > dig.out.ns${ns}.test$n || ret=1
    if [ $ad = yes ]
    then
	grep "flags:[^;]* ad[ ;]" dig.out.ns${ns}.test$n > /dev/null || ret=1
    else
	grep "flags:[^;]* ad[ ;]" dig.out.ns${ns}.test$n > /dev/null && ret=1
    fi
    grep "status: NXDOMAIN," dig.out.ns${ns}.test$n > /dev/null || ret=1
    grep "minimal.*3600.IN.SOA" dig.out.ns${ns}.test$n > /dev/null || ret=1
    grep "nxdomaia.minimal.*3600.IN.NSEC.nxdomaiz.minimal. RRSIG NSEC" dig.out.ns${ns}.test$n > /dev/null || ret=1
    [ $ns -eq 2 ] && cp dig.out.ns${ns}.test$n minimal.nxdomain.out
    n=$((n+1))
    if [ $ret != 0 ]; then echo_i "failed"; fi
    status=$((status+ret))

    echo_i "prime black lie NODATA response (synth-from-dnssec ${description};) ($n)"
    ret=0
    dig_with_opts black.minimal. @10.53.0.${ns} a > dig.out.ns${ns}.test$n || ret=1
    if [ $ad = yes ]
    then
	grep "flags:[^;]* ad[ ;]" dig.out.ns${ns}.test$n > /dev/null || ret=1
    else
	grep "flags:[^;]* ad[ ;]" dig.out.ns${ns}.test$n > /dev/null && ret=1
    fi
    grep "status: NOERROR," dig.out.ns${ns}.test$n > /dev/null || ret=1
    grep "minimal.*3600.IN.SOA" dig.out.ns${ns}.test$n > /dev/null || ret=1
    grep 'black.minimal.*3600.IN.NSEC.\\000.black.minimal. RRSIG NSEC' dig.out.ns${ns}.test$n > /dev/null || ret=1
    [ $ns -eq 2 ] && cp dig.out.ns${ns}.test$n black.out
    n=$((n+1))
    if [ $ret != 0 ]; then echo_i "failed"; fi
    status=$((status+ret))
done

echo_i "prime redirect response (+nodnssec) (synth-from-dnssec <default>;) ($n)"
ret=0
dig_with_opts +nodnssec a.redirect. @10.53.0.3 a > dig.out.ns2.test$n || ret=1
grep "flags:[^;]* ad[ ;]" dig.out.ns2.test$n > /dev/null && ret=1
grep "status: NOERROR," dig.out.ns2.test$n > /dev/null || ret=1
grep 'a\.redirect\..*300.IN.A.100\.100\.100\.2' dig.out.ns2.test$n > /dev/null || ret=1
n=$((n+1))
if [ $ret != 0 ]; then echo_i "failed"; fi
status=$((status+ret))

#
# ensure TTL of synthesised answers differs from direct answers.
#
sleep 1

for ns in 2 4 5 6
do
    case $ns in
    2) ad=yes synth=${synth_default} description="<default>";;
    4) ad=yes synth=no description="no";;
    5) ad=yes synth=yes description="yes";;
    6) ad=no synth=no description="yes; dnssec-validation no";;
    *) exit 1;;
    esac
    echo_i "check synthesized NXDOMAIN response (synth-from-dnssec ${description};) ($n)"
    ret=0
    nextpart ns1/named.run > /dev/null
    dig_with_opts b.example. @10.53.0.${ns} a > dig.out.ns${ns}.test$n || ret=1
    if [ ${ad} = yes ]
    then
	grep "flags:[^;]* ad[ ;]" dig.out.ns${ns}.test$n > /dev/null || ret=1
    else
	grep "flags:[^;]* ad[ ;]" dig.out.ns${ns}.test$n > /dev/null && ret=1
    fi
    grep "status: NXDOMAIN," dig.out.ns${ns}.test$n > /dev/null || ret=1
    if [ ${synth} = yes ]
    then
	grep "example.*IN.SOA" dig.out.ns${ns}.test$n > /dev/null || ret=1
	grep "example.*3600.IN.SOA" dig.out.ns${ns}.test$n > /dev/null && ret=1
	nextpart ns1/named.run | grep b.example/A > /dev/null && ret=1
    else
	grep "example.*3600.IN.SOA" dig.out.ns${ns}.test$n > /dev/null || ret=1
	nextpart ns1/named.run | grep b.example/A > /dev/null || ret=1
    fi
    digcomp nxdomain.out dig.out.ns${ns}.test$n || ret=1
    n=$((n+1))
    if [ $ret != 0 ]; then echo_i "failed"; fi
    status=$((status+ret))

    echo_i "check synthesized NODATA response (synth-from-dnssec ${description};) ($n)"
    ret=0
    nextpart ns1/named.run > /dev/null
    dig_with_opts nodata.example. @10.53.0.${ns} aaaa > dig.out.ns${ns}.test$n || ret=1
    if [ ${ad} = yes ]
    then
	grep "flags:[^;]* ad[ ;]" dig.out.ns${ns}.test$n > /dev/null || ret=1
    else
	grep "flags:[^;]* ad[ ;]" dig.out.ns${ns}.test$n > /dev/null && ret=1
    fi
    grep "status: NOERROR," dig.out.ns${ns}.test$n > /dev/null || ret=1
    if [ ${synth} = yes ]
    then
	grep "example.*IN.SOA" dig.out.ns${ns}.test$n > /dev/null || ret=1
	grep "example.*3600.IN.SOA" dig.out.ns${ns}.test$n > /dev/null && ret=1
	nextpart ns1/named.run | grep nodata.example/AAAA > /dev/null && ret=1
    else
	grep "example.*3600.IN.SOA" dig.out.ns${ns}.test$n > /dev/null || ret=1
	nextpart ns1/named.run | grep nodata.example/AAAA > /dev/null || ret=1
    fi
    digcomp nodata.out dig.out.ns${ns}.test$n || ret=1
    n=$((n+1))
    if [ $ret != 0 ]; then echo_i "failed"; fi
    status=$((status+ret))

    echo_i "check synthesized wildcard response (synth-from-dnssec ${description};) ($n)"
    ret=0
    nextpart ns1/named.run > /dev/null
    dig_with_opts b.wild-a.example. @10.53.0.${ns} a > dig.out.ns${ns}.test$n || ret=1
    if [ ${ad} = yes ]
    then
	grep "flags:[^;]* ad[ ;]" dig.out.ns${ns}.test$n > /dev/null || ret=1
    else
	grep "flags:[^;]* ad[ ;]" dig.out.ns${ns}.test$n > /dev/null && ret=1
    fi
    grep "status: NOERROR," dig.out.ns${ns}.test$n > /dev/null || ret=1
    if [ ${synth} = yes ]
    then
	grep "b\.wild-a\.example\..*IN.A" dig.out.ns${ns}.test$n > /dev/null || ret=1
	grep "b\.wild-a\.example\..*3600.IN.A" dig.out.ns${ns}.test$n > /dev/null && ret=1
	nextpart ns1/named.run | grep b.wild-a.example/A > /dev/null && ret=1
    else
	grep "b\.wild-a\.example\..*3600.IN.A" dig.out.ns${ns}.test$n > /dev/null || ret=1
	nextpart ns1/named.run | grep b.wild-a.example/A > /dev/null || ret=1
    fi
    digcomp wild.out dig.out.ns${ns}.test$n || ret=1
    n=$((n+1))
    if [ $ret != 0 ]; then echo_i "failed"; fi
    status=$((status+ret))

    echo_i "check synthesized wildcard CNAME response (synth-from-dnssec ${description};) ($n)"
    ret=0
    nextpart ns1/named.run > /dev/null
    dig_with_opts b.wild-cname.example. @10.53.0.${ns} a > dig.out.ns${ns}.test$n || ret=1
    if [ ${ad} = yes ]
    then
	grep "flags:[^;]* ad[ ;]" dig.out.ns${ns}.test$n > /dev/null || ret=1
    else
	grep "flags:[^;]* ad[ ;]" dig.out.ns${ns}.test$n > /dev/null && ret=1
    fi
    grep "status: NOERROR," dig.out.ns${ns}.test$n > /dev/null || ret=1
    if [ ${synth} = yes ]
    then
	grep "b.wild-cname.example.*IN.CNAME" dig.out.ns${ns}.test$n > /dev/null || ret=1
	grep "b.wild-cname.example.*3600.IN.CNAME" dig.out.ns${ns}.test$n > /dev/null && ret=1
	nextpart ns1/named.run | grep b.wild-cname.example/A > /dev/null && ret=1
    else
	grep "b.wild-cname.example.*3600.IN.CNAME" dig.out.ns${ns}.test$n > /dev/null || ret=1
	nextpart ns1/named.run | grep b.wild-cname.example/A > /dev/null || ret=1
    fi
    grep "ns1.example.*.IN.A" dig.out.ns${ns}.test$n > /dev/null || ret=1
    digcomp wildcname.out dig.out.ns${ns}.test$n || ret=1
    n=$((n+1))
    if [ $ret != 0 ]; then echo_i "failed"; fi
    status=$((status+ret))

    echo_i "check insecure NXDOMAIN response (synth-from-dnssec ${description};) ($n)"
    ret=0
    nextpart ns1/named.run > /dev/null
    dig_with_opts b.insecure.example. @10.53.0.${ns} a > dig.out.ns${ns}.test$n || ret=1
    grep "flags:[^;]* ad[ ;]" dig.out.ns${ns}.test$n > /dev/null && ret=1
    grep "status: NXDOMAIN," dig.out.ns${ns}.test$n > /dev/null || ret=1
    grep "insecure.example.*3600.IN.SOA" dig.out.ns${ns}.test$n > /dev/null || ret=1
    nextpart ns1/named.run | grep b.insecure.example/A > /dev/null || ret=1
    digcomp insecure.nxdomain.out dig.out.ns${ns}.test$n || ret=1
    n=$((n+1))
    if [ $ret != 0 ]; then echo_i "failed"; fi
    status=$((status+ret))

    echo_i "check insecure NODATA response (synth-from-dnssec ${description};) ($n)"
    ret=0
    nextpart ns1/named.run > /dev/null
    dig_with_opts nodata.insecure.example. @10.53.0.${ns} aaaa > dig.out.ns${ns}.test$n || ret=1
    grep "flags:[^;]* ad[ ;]" dig.out.ns${ns}.test$n > /dev/null && ret=1
    grep "status: NOERROR," dig.out.ns${ns}.test$n > /dev/null || ret=1
    grep "insecure.example.*3600.IN.SOA" dig.out.ns${ns}.test$n > /dev/null || ret=1
    nextpart ns1/named.run | grep nodata.insecure.example/AAAA > /dev/null || ret=1
    digcomp insecure.nodata.out dig.out.ns${ns}.test$n || ret=1
    n=$((n+1))
    if [ $ret != 0 ]; then echo_i "failed"; fi
    status=$((status+ret))

    echo_i "check insecure wildcard response (synth-from-dnssec ${description};) ($n)"
    ret=0
    nextpart ns1/named.run > /dev/null
    dig_with_opts b.wild-a.insecure.example. @10.53.0.${ns} a > dig.out.ns${ns}.test$n || ret=1
    grep "flags:[^;]* ad[ ;]" dig.out.ns${ns}.test$n > /dev/null && ret=1
    grep "status: NOERROR," dig.out.ns${ns}.test$n > /dev/null || ret=1
    grep "b\.wild-a\.insecure\.example\..*3600.IN.A" dig.out.ns${ns}.test$n > /dev/null || ret=1
    nextpart ns1/named.run | grep b.wild-a.insecure.example/A > /dev/null || ret=1
    digcomp insecure.wild.out dig.out.ns${ns}.test$n || ret=1
    n=$((n+1))
    if [ $ret != 0 ]; then echo_i "failed"; fi
    status=$((status+ret))

    echo_i "check insecure wildcard CNAME response (synth-from-dnssec ${description};) ($n)"
    ret=0
    nextpart ns1/named.run > /dev/null
    dig_with_opts b.wild-cname.insecure.example. @10.53.0.${ns} a > dig.out.ns${ns}.test$n || ret=1
    grep "flags:[^;]* ad[ ;]" dig.out.ns${ns}.test$n > /dev/null && ret=1
    grep "status: NOERROR," dig.out.ns${ns}.test$n > /dev/null || ret=1
    grep "b.wild-cname.insecure.example.*3600.IN.CNAME" dig.out.ns${ns}.test$n > /dev/null || ret=1
    nextpart ns1/named.run | grep b.wild-cname.insecure.example/A > /dev/null || ret=1
    grep "ns1.insecure.example.*.IN.A" dig.out.ns${ns}.test$n > /dev/null || ret=1
    digcomp insecure.wildcname.out dig.out.ns${ns}.test$n || ret=1
    n=$((n+1))
    if [ $ret != 0 ]; then echo_i "failed"; fi
    status=$((status+ret))

    echo_i "check minimal NXDOMAIN response (synth-from-dnssec ${description};) ($n)"
    ret=0
    nextpart ns1/named.run > /dev/null
    dig_with_opts nxdomaic.minimal. @10.53.0.${ns} a > dig.out.ns${ns}.test$n || ret=1
    if [ ${ad} = yes ]
    then
	grep "flags:[^;]* ad[ ;]" dig.out.ns${ns}.test$n > /dev/null || ret=1
    else
	grep "flags:[^;]* ad[ ;]" dig.out.ns${ns}.test$n > /dev/null && ret=1
    fi
    grep "status: NXDOMAIN," dig.out.ns${ns}.test$n > /dev/null || ret=1
    grep "minimal.*3600.IN.SOA" dig.out.ns${ns}.test$n > /dev/null || ret=1
    nextpart ns1/named.run | grep nxdomaic.minimal/A > /dev/null || ret=1
    digcomp minimal.nxdomain.out dig.out.ns${ns}.test$n || ret=1
    n=$((n+1))
    if [ $ret != 0 ]; then echo_i "failed"; fi
    status=$((status+ret))

    echo_i "check back lie NODATA response (synth-from-dnssec ${description};) ($n)"
    ret=0
    nextpart ns1/named.run > /dev/null
    dig_with_opts black.minimal. @10.53.0.${ns} aaaa > dig.out.ns${ns}.test$n || ret=1
    if [ ${ad} = yes ]
    then
	grep "flags:[^;]* ad[ ;]" dig.out.ns${ns}.test$n > /dev/null || ret=1
    else
	grep "flags:[^;]* ad[ ;]" dig.out.ns${ns}.test$n > /dev/null && ret=1
    fi
    grep "status: NOERROR," dig.out.ns${ns}.test$n > /dev/null || ret=1
    if [ ${synth} = yes ]
    then
	grep "minimal.*IN.SOA" dig.out.ns${ns}.test$n > /dev/null || ret=1
	grep "minimal.*3600.IN.SOA" dig.out.ns${ns}.test$n > /dev/null && ret=1
	nextpart ns1/named.run | grep black.minimal/AAAA > /dev/null && ret=1
    else
	grep "minimal.*3600.IN.SOA" dig.out.ns${ns}.test$n > /dev/null || ret=1
	nextpart ns1/named.run | grep black.minimal/AAAA > /dev/null || ret=1
    fi
    digcomp black.out dig.out.ns${ns}.test$n || ret=1
    n=$((n+1))
    if [ $ret != 0 ]; then echo_i "failed"; fi
    status=$((status+ret))

    echo_i "check 'rndc stats' output for 'covering nsec returned' (synth-from-dnssec ${description};) ($n)"
    ret=0
    ${RNDCCMD} 10.53.0.${ns} stats 2>&1 | sed 's/^/ns6 /' | cat_i
    # 2 views, _bind should always be '0 covering nsec returned'
    count=$(grep "covering nsec returned" ns${ns}/named.stats | wc -l)
    test $count = 2 || ret=1
    zero=$(grep "0 covering nsec returned" ns${ns}/named.stats | wc -l)
    if [ ${synth} = yes ]
    then
	test $zero = 1 || ret=1
    else
	test $zero = 2 || ret=1
    fi
    n=$((n+1))
    if [ $ret != 0 ]; then echo_i "failed"; fi
    status=$((status+ret))

    for synthesized in NXDOMAIN no-data wildcard
    do
	case $synthesized in
	NXDOMAIN) count=1;;
	no-data) count=2;;
	wildcard) count=2;;
	esac
	echo_i "check 'rndc stats' output for 'synthesized a ${synthesized} response' (synth-from-dnssec ${description};) ($n)"
	ret=0
	if [ ${synth} = yes ]
	then
	    grep "$count synthesized a ${synthesized} response" ns${ns}/named.stats > /dev/null || ret=1
	else
	    grep "synthesized a ${synthesized} response" ns${ns}/named.stats > /dev/null && ret=1
	fi
	n=$((n+1))
	if [ $ret != 0 ]; then echo_i "failed"; fi
	status=$((status+ret))
   done
done

echo_i "check redirect response (+dnssec) (synth-from-dnssec <default>;) ($n)"
ret=0
synth=${synth_default}
dig_with_opts b.redirect. @10.53.0.3 a > dig.out.ns2.test$n || ret=1
grep "flags:[^;]* ad[ ;]" dig.out.ns2.test$n > /dev/null || ret=1
grep "status: NXDOMAIN," dig.out.ns2.test$n > /dev/null || ret=1
if [ ${synth} = yes ]
then
    grep "^\....[0-9]*.IN.SOA" dig.out.ns2.test$n > /dev/null || ret=1
    grep "^\..*3600.IN.SOA" dig.out.ns2.test$n > /dev/null && ret=1
else
    grep "^\..*3600.IN.SOA" dig.out.ns2.test$n > /dev/null || ret=1
fi
n=$((n+1))
if [ $ret != 0 ]; then echo_i "failed"; fi
status=$((status+ret))

echo_i "check redirect response (+nodnssec) (synth-from-dnssec <default>;) ($n)"
ret=0
dig_with_opts +nodnssec b.redirect. @10.53.0.3 a > dig.out.ns2.test$n || ret=1
grep "flags:[^;]* ad[ ;]" dig.out.ns2.test$n > /dev/null && ret=1
grep "status: NOERROR," dig.out.ns2.test$n > /dev/null || ret=1
grep 'b\.redirect\..*300.IN.A.100\.100\.100\.2' dig.out.ns2.test$n > /dev/null || ret=1
n=$((n+1))
if [ $ret != 0 ]; then echo_i "failed"; fi
status=$((status+ret))

echo_i "check DNAME handling (synth-from-dnssec yes;) ($n)"
ret=0
dig_with_opts dnamed.example. ns @10.53.0.5 > dig.out.ns5.test$n || ret=1
dig_with_opts a.dnamed.example. a @10.53.0.5 > dig.out.ns5-1.test$n || ret=1
grep "status: NOERROR," dig.out.ns5-1.test$n > /dev/null || ret=1
n=$((n+1))
if [ $ret != 0 ]; then echo_i "failed"; fi
status=$((status+ret))

echo_i "exit status: $status"
[ $status -eq 0 ] || exit 1
