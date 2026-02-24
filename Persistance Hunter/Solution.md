# Persistence Hunter — Write-up

**Category:** Forensics  
**Difficulty:** Medium  

---

## Contexte

On nous fournit un fichier `challengefile.DAT`.  
L’objectif est de retrouver une **flag** au format `CCOI26{...}`.

L’indice “Persistence” suggère une trace de **persistance Windows**, souvent liée au **registre** (ex : clés `Run`) et parfois via des commandes **PowerShell encodées** (`-Enc`).

---

## 1) Outils utilisés

- `file` (identifier le type de fichier)
- `strings` (extraction de chaînes, notamment UTF-16LE)
- `grep` (filtrage)
- `base64` (décodage)

---

## 2) Méthode / Étapes suivies

### 2.1 Identifier une commande PowerShell encodée

Comme beaucoup d’éléments du registre Windows sont stockés en **UTF-16LE**, on extrait les chaînes en **16-bit little-endian** puis on filtre sur `powershell.exe -enc` :

```bash
file challengefile.DAT
``` 
![alt text](<Screenshot From 2026-02-24 08-28-05.png>)

On constaste c'est un fichier windows plus precisement un fichier register

```bash

strings -a -e l challengefile.DAT | grep -i "powershell.exe -enc"
```
![alt text](<Screenshot From 2026-02-24 08-28-17.png>)


```text
powershell.exe -Enc Q0NPSTI2e1kwdV9EMURfMVRfTTROISEhISF9
```

### 2.2 Décoder le `-Enc`

Le paramètre `-Enc` correspond à une commande encodée en **Base64**.  
On extrait la chaîne Base64 et on la décode :

```bash
echo 'Q0NPSTI2e1kwdV9EMURfMVRfTTROISEhISF9' | base64 -d

``` 
![alt text](<Screenshot From 2026-02-24 08-28-26.png>)

Great jobbb! la flag apparaissait :

## FLAG

Youupiii, la flag est là:

**Flag : CCOI26{Y0u_D1D_1T_M4N!!!!!}**
