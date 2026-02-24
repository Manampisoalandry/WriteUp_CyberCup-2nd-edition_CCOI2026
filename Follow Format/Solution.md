# iNode Never Forgets — Write-up

**Category:** Forensics  
**Difficulty:** Medium  

---

## Contexte

On nous fournit une image disque `challenge.img`.  
Le nom du challenge et l’indice implicite (*inode never forgets*) suggèrent que la flag peut être présente dans :

- un fichier supprimé (toujours récupérable via inode),
- du slack space / espace non alloué,
- ou directement dans des fichiers du volume.

Objectif : retrouver une chaîne au format `CCOI26{...}`.

---

## 1) Outils utilisés

- `strings` (recherche rapide de chaînes)
- `grep` (filtrage)
- `dd` + `xxd` (preuve via extraction autour de l’offset)
- (Optionnel) `mmls`, `fls`, `icat` (validation forensics “propre”)

---

## 2) Méthode / Étapes suivies

Comme c'est une fichier .img, alors la première reflexion, c'est de voir le type du fichier avec la commande file

![alt text](<Screenshot From 2026-02-23 23-35-39.png>)

Après cette commande, nous avons constaté qu'on a une image disque de filesystem ex4 alors celle nous implique de n'est pas monté ou d'utilisé fdisk ou etc.

### 2.1 Recherche de la flag dans l’image

Première étape : extraire les chaînes ASCII présentes dans l’image et filtrer sur le format de flag :

```bash
strings -a -t d challenge.img | grep "CCOI26{"
```

![alt text](<Screenshot From 2026-02-23 23-28-21.png>)

✅ Résultat obtenu :

```text
8913920 CCOI26{iNod3_n3v3r_f0rg3ts_2026}
```

- `8913920` = **offset (en décimal)** dans l’image où la chaîne apparaît.
- La suite = **flag en clair**.

---

### 2.2 Preuve / Validation : extraction autour de l’offset

Pour prouver que la flag est bien contenue dans l’image (et voir le contexte), on extrait quelques octets autour de l’offset `8913920`.

#### a) Extraction brute autour de l’offset

```bash
OFF=8913920
dd if=challenge.img bs=1 skip=$((OFF-200)) count=800 2>/dev/null | xxd
```

Cela affiche un hexdump contenant la chaîne `CCOI26{...}` dans le flux, ce qui confirme la présence réelle de la flag dans l’image.

#### b) Extraction directe de la chaîne (optionnel)

```bash
dd if=challenge.img bs=1 skip=8913920 count=64 2>/dev/null
```

---

## Flag

**` Flag : CCOI26{iNod3_n3v3r_f0rg3ts_2026}`**

---

