#!/bin/sh
#set -xe

[ -f get-mac.sh ] && SHARE=../share || SHARE=share # set the relative path to ettercap's "share" directory

wget http://standards.ieee.org/develop/regauth/oui/oui.txt
cat oui.txt |grep "base 16"  > oui #clean unused lines
sed 's/\ \ \ \ \ (base\ 16)\t\t/ /g' -i oui #remove spaces
sed 's/\ \ //g' -i oui #remove initial stuff
sed '/^[0-9A-F]*$/d' -i oui #remove some private lines
mv oui etter.finger.mac
rm oui.txt
echo "the maximum line SHOULD be less than 120 bytes (ec_manuf.c manuf_init function)"
echo "maximum line of the newly generated file"
wc -L etter.finger.mac
dos2unix etter.finger.mac
mv etter.finger.mac $SHARE
