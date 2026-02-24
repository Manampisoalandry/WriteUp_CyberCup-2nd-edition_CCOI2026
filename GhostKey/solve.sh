echo "f9d4eb5e5624e806367ff34eb6985e0c773b11c1331065c365b4dbf13d7bf600245edd792dd53228c8d589d3c1c676da" \
| xxd -r -p > ct.bin

openssl enc -aes-128-cbc -d \
  -K 416e746f696e65204a4f554152590000 \
  -iv 86f9bf558637603f507bfebb70dd1ecf \
  -in ct.bin