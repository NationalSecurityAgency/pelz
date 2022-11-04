key_file_id=("key1.txt" "key2.txt" "key3.txt" "key4.txt" "key5.txt" "key6.txt")
key=("KIENJCDNHVIJERLMALIDFEKIUFDALJFG" "KALIENGVBIZSAIXKDNRUEHFMDDUHVKAN" "HVIJERLMALIDFKDN" "NGVBIZSAIXKDNRUE" "EKIUFDALVBIZSAIXKDNRUEHV" "ALIENGVBCDNHVIJESAIXEKIU")

for (( i=0; i<6; i++))
do
  printf "%s" ${key[$i]} > ${key_file_id[$i]}
done
