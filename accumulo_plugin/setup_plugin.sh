#! /usr/bin/env bash

install=false;
uninstall=false;

while getopts iud: flag
do
  case "${flag}" in
    d) dir_accumulo=${OPTARG};;
    i) install=true;;
    u) uninstall=true;;
  esac
done

dir_accumulo_a="core/src/main/java/org/apache/accumulo/core/cryptoImpl"
dir_accumulo_b="core/src/test/java/org/apache/accumulo/core/crypto"
dir_accumulo_c="core/src/test/java/org/apache/accumulo/core/file/rfile"
dir_accumulo_d="test/src/main/java/org/apache/accumulo/test/functional"

dir_plugin="accumulo_plugin"
dir_pelz_plugin="accumulo_plugin/pelzPlugin"
dir_testfiles="accumulo_plugin/testfiles"

file1="PelzCryptoService.java"
file2="PelzCryptoTest.java"
file3="RFilePelzTest.java"
file4="WriteAheadLogPelzEncryptedIT.java"

if [ -d $dir_accumulo/"core"/ ]
then
  if $install
  then
    cp -r "$dir_pelz_plugin"/ "$dir_accumulo"/"$dir_accumulo_a"/
    cp "$dir_plugin"/"$file1" "$dir_accumulo"/"$dir_accumulo_a"/"$file1"
    cp "$dir_testfiles"/"$file2" "$dir_accumulo"/"$dir_accumulo_b"/"$file2"
    cp "$dir_testfiles"/"$file3" "$dir_accumulo"/"$dir_accumulo_c"/"$file3"
    cp "$dir_testfiles"/"$file4" "$dir_accumulo"/"$dir_accumulo_d"/"$file4"
    echo "Install Complete"
  elif $uninstall
  then
    rm -r "$dir_accumulo"/"$dir_accumulo_a"/"pelzPlugin"/
    rm "$dir_accumulo"/"$dir_accumulo_a"/"$file1"
    rm "$dir_accumulo"/"$dir_accumulo_b"/"$file2"
    rm "$dir_accumulo"/"$dir_accumulo_c"/"$file3"
    rm "$dir_accumulo"/"$dir_accumulo_d"/"$file4"
    echo "Uninstall Complete"
  else
    echo "No setup or unsetup command provided."
  fi
else
  echo "Accumulo Directory not provided." 
fi
