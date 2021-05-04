#! /usr/bin/env bash

install=false;
uninstall=false;
VERSION=plugin-accumulo;
HELP=false;

while getopts ihoud: flag
do
	case "${flag}" in
		d) DIR_ACCUMULO=${OPTARG};;
		i) install=true;;
		u) uninstall=true;;
		o) VERSION+=-2.0;;
		h) HELP=true;
	esac
done

if $HELP
then
	echo "setup_plugin.sh is used to install source files into Apache Accumulo"
	echo -e "        Accumulo must be rebuilt after install in order to build the pelz plugin class files\n"
	echo -e "usage: ./setup_plugin.sh [options]\n"
	echo -e "options:\n"
	echo " -d    Directory containing Accumulo code, must be specified"
	echo " -i    Indicates 'install' of pelz plugin source code -- only installs java sources"
	echo " -u    Indicates 'uninstall' of pelz plugin source code -- only removes java sources"
	echo " -o    Install according to package structures as of the Accumulo 2.0 release"
	echo " -h    Display help"
	exit 0
fi

DIR_PELZ_PLUGIN=$DIR_ACCUMULO/core/src/main/java/org/apache/accumulo/core/pelz/
DIR_PELZ_TESTS=$DIR_ACCUMULO/core/src/test/java/org/apache/accumulo/core/pelz/

if [ -d $DIR_ACCUMULO/"core"/ ]
then
	if $install
	then
		#Install java plugin
		mkdir -p $DIR_PELZ_PLUGIN
		cp $VERSION/PelzCryptoService.java $DIR_PELZ_PLUGIN
		cp pelzPlugin/* $DIR_PELZ_PLUGIN
		#Install plugin tests for Accumulo
		mkdir -p $DIR_PELZ_TESTS
		cp $VERSION/testfiles/PelzCryptoTest.java $DIR_PELZ_TESTS
		cp testfiles/RFilePelzTest.java $DIR_ACCUMULO/core/src/test/java/org/apache/accumulo/core/file/rfile/
		cp testfiles/WriteAheadLogPelzEncryptedIT.java $DIR_ACCUMULO/test/src/main/java/org/apache/accumulo/test/functional/
		echo "Install Complete"
	elif $uninstall
	then
		rm -r $DIR_PELZ_PLUGIN
		rm -r $DIR_PELZ_TESTS
		rm $DIR_ACCUMULO/core/src/test/java/org/apache/accumulo/core/file/rfile/RFilePelzTest.java
		rm $DIR_ACCUMULO/test/src/main/java/org/apache/accumulo/test/functional/WriteAheadLogPelzEncryptedIT.java
		echo "Uninstall Complete"
	else
		echo "No setup or unsetup command provided."
	fi
else
	echo "Accumulo Directory not provided." 
fi
