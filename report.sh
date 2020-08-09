#!/bin/bash

if [ $# -ne 1 ]; then
	echo "Usage: $0 <bobber DB>"
	exit
fi

dump=$(sqlite3 $1 'select * from tracker' | tr -d ' ')

timestamp=$(echo $1 | cut -d '.' -f2- | rev | cut -d '.' -f2- | rev)
filename=$timestamp.csv

echo "userToken,hasAccessed,whenAccessed,sourceIP" > $filename

for i in $dump; do
	userToken=$(echo $i | cut -d '|' -f2)
	hasAccessed=$(echo $i | cut -d '|' -f3)
	whenAccessed=$(echo $i | cut -d '|' -f4)
	sourceIP=$(echo $i | cut -d '|' -f5)
	echo $userToken,$hasAccessed,$whenAccessed,$sourceIP >> $filename
done
