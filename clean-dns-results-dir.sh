#!/bin/bash
# -*- coding: utf-8 -*-

resultdir=$1

#aws s3 cp --recursive s3://letsencryptdnsresults/20211120 .
find $resultdir -type f -name "lookups_summary_part*.gz.txt" -exec bash -c "rm {}" \;
find $resultdir -type f -name "lookups_summary.txt" -exec bash -c "rm {}" \;
find $resultdir -type f -name "lookups_summary.txt.csv" -exec bash -c "rm {}" \;
find $resultdir -type f -name "lookups_summary.txt.csv.sorted" -exec bash -c "rm {}" \;