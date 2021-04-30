#! /usr/bin/env bash

install=false;
uninstall=false;
VERSION=plugin-accumulo;

while getopts ioud: flag
do
	case "${flag}" in
		d) DIR_ACCUMULO=${OPTARG};;
		i) install=true;;
		u) uninstall=true;;
		o) VERSION+=-2.0;;
	esac
done


DIR_PELZ_PLUGIN=$DIR_ACCUMULO/core/src/main/java/org/apache/accumulo/core/pelz/
DIR_PELZ_TESTS=$DIR_ACCUMULO/core/src/test/java/org/apache/accumulo/core/pelz/

if [ -d $DIR_ACCUMULO/"core"/ ]
then
	if $install
	then
		#Install java plugin
		mkdir -p $DIR_PELZ_PLUGIN
		cp PelzCryptoService.java $DIR_PELZ_PLUGIN
		cp pelzPlugin/* $DIR_PELZ_PLUGIN
		#Install plugin tests for Accumulo
		mkdir -p $DIR_PELZ_TESTS
		cp $VERSION/testfiles/PelzCryptoTest.java $DIR_PELZ_TESTS
		cp $VERSION/testfiles/RFilePelzTest.java $DIR_ACCUMULO/core/src/test/java/org/apache/accumulo/core/file/rfile/
		cp $VERSION/testfiles/WriteAheadLogPelzEncryptedIT.java $DIR_ACCUMULO/test/src/main/java/org/apache/accumulo/test/functional/
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
