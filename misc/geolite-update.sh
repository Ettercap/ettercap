#!/bin/sh
# set -xe

# geolite-update.sh -- update GeoIP lite databases.
# (C) 2017-2019 Ettercap Development Team.

# Ettercap can use MaxMind's GeoIP databases to look up the country for an IP address.
# This simple shell script helps in downloading and installing the *free* GeoLite
# country databases, which are needed for this feature to actually work.
# You can optionally pass an alternative install path to this script.
# If you rather not, it will install all files to /usr/local/share/GeoIP/.
# Note: In some distributions/operating systems these databases are available
# through their package manager.
# You most likely don't need to use this script if this is the case.

USAGE="USAGE: $(basename $0) [geolite install path]"

# check argument count
if [ $# -gt 1 ]
then
  echo $USAGE
  exit
fi

if [ -z $1 ]
then
    geolite_path="/usr/share/GeoIP"
    download_path="/usr/share/GeoIP/download"
else
    geolite_path=$1
    download_path="$1/download"

fi

# prg="curl --remote-name"
prg="wget --continue --directory-prefix=$download_path"

if [ ! -e $geolite_path ]; then
        echo "Unable to find GeoIP directory: $geolite_path"
        exit 1
fi

echo "Updating/Installing GeoLite databases..."
echo "Note: Not installing GeoLiteCity database (not used by Ettercap)"

[ -d $download_path ] || mkdir $download_path

$prg http://geolite.maxmind.com/download/geoip/database/GeoLiteCountry/GeoIP.dat.gz
if [ ! -e $download_path/GeoIP.dat.gz ]; then
        echo "Unable to find GeoIP.dat.gz!"
        exit 1
fi
gunzip -c $download_path/GeoIP.dat.gz > $geolite_path/GeoIP.dat
rm -f $download_path/GeoIP.dat.gz

# Ettercap doesn't use the GeoLiteCity database... yet.
# Uncomment the following lines if you want to download and install it anyways.
# $prg http://geolite.maxmind.com/download/geoip/database/GeoLiteCity.dat.gz
# if [ ! -e $download_path/GeoLiteCity.dat.gz ]; then
#        echo "Unable to find GeoLiteCity.dat.gz!"
#        exit 1
# fi
# gunzip -c $download_path/GeoLiteCity.dat.gz > $geolite_path/GeoLiteCity.dat
# rm -f $download_path/GeoLiteCity.dat.gz

$prg http://geolite.maxmind.com/download/geoip/database/GeoIPv6.dat.gz
if [ ! -e $download_path/GeoIPv6.dat.gz ]; then
        echo "Unable to find GeoIPv6.dat.gz!"
        exit 1
fi
gunzip -c $download_path/GeoIPv6.dat.gz > $geolite_path/GeoIPv6.dat
rm -f $download_path/GeoIPv6.dat.gz

echo "Done."
