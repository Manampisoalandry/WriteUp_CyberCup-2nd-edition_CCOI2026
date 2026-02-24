# Broken_signal qrcode — Write-up (zsteg / LSB)

**Category:** Stegano  
**Difficulty:** Medium

---

## Contexte

On nous donne une image : `Broken_signal qrcode.png`.  
Le QR code semble “cassé”, donc on suspecte une **stéganographie** plutôt qu’un simple scan QR.

Objectif : retrouver un flag au format `CCOI26{...}`.

---

## Fichier

### Identification rapide

```bash
file "Broken_signal qrcode.png"

``` 
---
## Outils

zsteg

Pour la premiere etapes, voyons d(abors le format du fichier si c'était vraimement une image ou pas

![alt text](<Screenshot From 2026-02-24 00-30-45.png>) 

D'après cette commande file, on constate du'on a belle et bien un fichier png, Alors on va testé exiftool pour voir les fichier caché sur les metadonnées de l'images

![alt text](<Screenshot From 2026-02-24 00-30-54.png>) 

Nous n'avons pas des fichier caché sur exiftool, testons la commande strings et greper le CCOI26,

![alt text](<Screenshot From 2026-02-24 00-31-20.png>) 

Nope, rien n'affiche, testons aussi la commande strings sans grep,

![alt text](<Screenshot From 2026-02-24 00-31-34.png>) 

Bof, il a affiché quelques chose mais pas la flag,
Puisque qu'on est dans la categorie stegano, testons par zsteg d'abord,

![alt text](<Screenshot From 2026-02-24 00-31-54.png>)

 la flag est là:
## FLAG

Youupiii, la flag est là:

**Flag : CCOI2026{CCOI26{0c01_15_w4tch1ng_y0u}}**

