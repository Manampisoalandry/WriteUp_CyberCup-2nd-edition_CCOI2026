# GhostKey — Write-up (Solution 3 : OpenSSL)

**Category:** Crypto  
**Difficulty:** Difficile (400 pts)

---

## Contexte

Une transmission chiffrée a été interceptée pendant la CyberCup Ocean Indien. Les analystes confirment :

- **AES en mode CBC**
- La **clé** est liée à l’**identité** d’un individu connecté à la compétition (indice : *Athern*)
- L’**IV** semble être **dérivé** (dans le challenge original) via une fonction de hash — mais ici on dispose directement de l’IV final.

> *“In the intelligence world, identity is the key. Sometimes, literally.”*

Dans cette solution, on utilise l’identité confirmée :
- **Antoine JOUARY**

---

## Données

### Ciphertext (hex)

f9d4eb5e5624e806367ff34eb6985e0c
773b11c1331065c365b4dbf13d7bf600
245edd792dd53228c8d589d3c1c676da



Taille : 48 octets → 3 blocs AES (16 octets chacun) → OK pour AES-CBC.



### (hex)

86f9bf558637603f507bfebb70dd1ecf
Identité (clé source)
Antoine JOUARY


## Principe de la solution OpenSSL

OpenSSL accepte la clé AES via -K en hex.

Or AES-128 exige une clé de 16 octets :

"Antoine JOUARY" fait 14 octets (ASCII)

On complète (padding) à 16 octets avec \x00\x00

Donc :

Clé (ASCII) : Antoine␠JOUARY

Clé (hex 16 bytes) : 416e746f696e65204a4f554152590000

## Outils utilisés

openssl

xxd (pour convertir hex → binaire)

## Étapes de déchiffrement (OpenSSL)
3.1 Convertir le ciphertext hex en binaire

On crée un fichier ct.bin contenant les octets réels.

CT_HEX="f9d4eb5e5624e806367ff34eb6985e0c773b11c1331065c365b4dbf13d7bf600245edd792dd53228c8d589d3c1c676da"
echo -n "$CT_HEX" | xxd -r -p > ct.bin

![alt text](<Screenshot From 2026-02-24 00-55-02.png>)



Optionnel : vérifier la taille (doit être 48) :

wc -c ct.bin

Attendu :

48 ct.bin
3.2 Déchiffrer AES-128-CBC

Commande OpenSSL :

openssl enc -aes-128-cbc -d \
  -K 416e746f696e65204a4f554152590000 \
  -iv 86f9bf558637603f507bfebb70dd1ecf \
  -in ct.bin

![alt text](<Screenshot From 2026-02-24 00-55-28.png>)


-aes-128-cbc : algorithme / mode

-d : decrypt

-K : clé AES en hex (16 bytes → 32 hex chars)

-iv : IV en hex (16 bytes)

-in : fichier binaire chiffré

OpenSSL retire automatiquement le padding PKCS#7 à la fin (dans ce cas typiquement 0x08 répété).

## Variante “one-liner” (sans fichier)
echo -n "f9d4eb5e5624e806367ff34eb6985e0c773b11c1331065c365b4dbf13d7bf600245edd792dd53228c8d589d3c1c676da" \
| xxd -r -p \
| openssl enc -aes-128-cbc -d \
    -K 416e746f696e65204a4f554152590000 \
    -iv 86f9bf558637603f507bfebb70dd1ecf

## FLAG

Eh boommm, la flag est là:

**Flag : CCOI2026{La CyberCup Ocean Indien est top}**

