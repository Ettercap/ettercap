#!/bin/bash

find src include utils plug-ins tests -name "*.h" -o -name "*.c" > uncrustify-list.txt
uncrustify -F uncrustify-list.txt -c misc/uncrustify.cfg --replace --no-backup
rm uncrustify-list.txt

