#!/bin/bash

DB="Q5_${RANDOM}.sqlite"

# add an additional column of year (will be used to compare with the disease data later)
awk -F, '{print $3}' Poll-Data.csv | awk -F- '{print $3}' | paste -d , Poll-Data.csv - > poll_new.tmp

cat tables.sql | sqlite3

rm -f *.sqlite *.tmp
