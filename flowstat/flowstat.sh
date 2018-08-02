#!/bin/bash

if [ $# != "3" ]
then
	echo "usage: $0 <input> <output> <process>"
	exit
fi

printf "[-] time: "
date

printf "[-] Compiling ... "
gcc *.c -lpcap -o yuha
printf "Ok\n"

input=$1
output=$2
process=$3

printf "[-] Executing: [./yuha file $input $process $output] ... "
./yuha file $input $process $output 2> "$output-err" 
printf "Ok\n"

printf "[-] time: "
date

cat $output | grep "M1" > "$output-m1"
cat $output | grep "M2" > "$output-m2"
cat $output | grep "process" > "$output-proc"

printf "\n[-] Messages: \n\n"
cat "$output-err"

printf "\n[-] Proccesses: \n\n"
cat "$output-proc"

printf "\n[-] Metric 1 errors: \n\n"
cat "$output-m1"

printf "\n[-] Metric 2 errors: \n\n"
cat "$output-m2"

printf "\n[-] finished\n"
