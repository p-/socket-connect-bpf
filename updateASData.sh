#!/bin/sh

cd as/
filename=ip2asn-v4-u32.tsv
wget https://iptoasn.com/data/$filename.gz
rm $filename
gunzip $filename.gz
