#!/bin/bash
# -*- coding: utf-8 -*-

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
resultdir=$1

# This could be cleaner to use find with a flag to only inculde directories.
# This glob should expand before the loop exectues so the output CSVs we write to the base dir should not matter.
for dailyResultDir in $resultdir/*; do
	$SCRIPT_DIR/dns-results-to-certs-csv-single-day.sh $dailyResultDir $resultdir/$( basename $dailyResultDir )-daily-certs.csv
	$SCRIPT_DIR/clean-dns-results-dir.sh $dailyResultDir
done

for dailyResultCSV in $resultdir/*-daily-certs.csv.no-wildcards.csv; do
	cat $dailyResultCSV >> $resultdir/full-certs.no-wildcards.csv.tmp
done

mv $resultdir/full-certs.no-wildcards.csv.tmp $resultdir/full-certs.no-wildcards.csv




#rm $resultdir/*-daily-certs.csv.no-wildcards.csv
#rm $resultdir/*-daily-certs.csv