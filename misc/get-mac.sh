wget http://standards.ieee.org/develop/regauth/oui/oui.txt
cat oui.txt |grep "base 16"  > oui #clean unused lines
sed 's/\ \ \ \ \ (base\ 16)\t\t/ /g' -i oui #remove spaces
sed 's/\ \ //g' -i oui #remove initial stuff
sed '/^[0-9A-F]*$/d' -i oui #remove some private lines
mv oui etter.finger.mac
rm oui.txt
