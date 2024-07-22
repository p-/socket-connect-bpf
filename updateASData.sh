#!/bin/sh

cd as/

download_and_unzip () {
   filename=$1
    wget https://iptoasn.com/data/$filename.gz
    rm $filename
    gunzip $filename.gz
}

download_and_unzip "ip2asn-v4-u32.tsv"
download_and_unzip "ip2asn-v6.tsv"