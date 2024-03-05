#! /usr/bin/env bash

install=false;
uninstall=false;
pykmip_demo=false;
HELP=false;

while getopts d:iuohp flag
do
	case "${flag}" in
		d) DIR_ACCUMULO=${OPTARG};;
		i) install=true;;
		u) uninstall=true;;
		h) HELP=true;;
		p) pykmip_demo=true;
	esac
done

if $HELP
then
	echo "setup_plugin.sh is used to install source files into Apache Accumulo"
	echo -e "\nAccumulo must be rebuilt after install in order to build the pelz plugin class files\n"
	echo -e "usage: ./setup_plugin.sh [options]\n"
	echo -e "options:\n"
	echo " -d    Directory containing Accumulo code, must be specified"
	echo " -i    Indicates 'install' of pelz plugin source code -- only installs java sources"
	echo " -u    Indicates 'uninstall' of pelz plugin source code -- only removes java sources"
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
		cp pelz_plugin/plugin_code/* $DIR_PELZ_PLUGIN
		#Install plugin tests for Accumulo
		mkdir -p $DIR_PELZ_TESTS
		cp pelz_plugin/testfiles/PelzCryptoTest.java $DIR_PELZ_TESTS
		cp pelz_plugin/testfiles/RFilePelzTest.java $DIR_ACCUMULO/core/src/test/java/org/apache/accumulo/core/file/rfile/
		cp pelz_plugin/testfiles/WriteAheadLogPelzEncryptedIT.java $DIR_ACCUMULO/test/src/main/java/org/apache/accumulo/test/functional/
		echo "Install Complete"
    if $pykmip_demo
    then
      #Change PelzCryptoService.java to use serverKeyPath
      sed -i 's/PelzCryptoTest.keyPath(testClass)/PelzCryptoTest.serverKeyPath(testClass)/' $DIR_PELZ_TESTS/PelzCryptoTest.java 
      echo "Demo Setup"
    fi           
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
