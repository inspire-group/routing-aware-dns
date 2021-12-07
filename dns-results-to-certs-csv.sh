#!/bin/bash
# -*- coding: utf-8 -*-

resultdir=$1
outputfile=$2

#aws s3 cp --recursive s3://letsencryptdnsresults/20211120 .
#find $resultdir -type f -name "lookups_summary*.gz" -exec bash -c "gunzip {}" \;
find $resultdir -type f -name "lookups_summary_part*" -exec bash -c "cat {} >> \$(dirname {})/lookups_summary.txt" \;
find $resultdir -type f -name "lookups_summary.txt" -exec bash -c "./lookups_summary_to_csv.py -s {} > {}.csv" \;
find $resultdir -type f -name "lookups_summary.txt.csv" -exec bash -c "sort {} > {}.sorted" \;
touch $outputfile
find $resultdir -type f -name "lookups_summary.txt.csv.sorted" -exec bash -c "./merge_cert_csvs.py -c {} -d $outputfile > $outputfile.tmp ; mv $outputfile.tmp $outputfile" \;
grep "^[^*]" $outputfile > $outputfile.no-wildcards.csv