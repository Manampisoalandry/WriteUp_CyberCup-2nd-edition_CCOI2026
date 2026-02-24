class Montgomery:
    def __init__(self, a, p):
        """
        Coefficients a et p de la courbe de Montgomery
        """
        self.a = a
        self.p = p
    
    def __repr__(self):
        return f"Courbe de Montgomery définie mod {self.p} avec a = {self.a}"
    
    def x_dbl(self, x):
        """
        Doublement de point en utilisant uniquement la coordonnée x (affine)
        Formule: x([2]P) = (x^2 - 1)^2 / (4*x*(x^2 + a*x + 1))
        """
        x2 = pow(x, 2, self.p)
        numerateur = pow(x2 - 1, 2, self.p)
        denominateur = (4 * x * (x2 + self.a * x + 1)) % self.p
        return (numerateur * pow(denominateur, -1, self.p)) % self.p
    
    def x_add(self, x_p, x_q, x_diff):
        """
        Addition différentielle utilisant uniquement les coordonnées x (affine)
        Étant donné x(P), x(Q), x(P-Q), calculer x(P+Q)
        Formule: x(P+Q) = ((x_p*x_q - 1)^2) / ((x_p - x_q)^2 * x_diff)
        """
        numerateur = pow(x_p * x_q - 1, 2, self.p)
        denominateur = (pow(x_p - x_q, 2, self.p) * x_diff) % self.p
        return (numerateur * pow(denominateur, -1, self.p)) % self.p
    
    def mul_scalaire(self, k, x):
        """
        Échelle de Montgomery pour la multiplication scalaire (x uniquement)
        Entrée: scalaire k et coordonnée x du point P
        Sortie: coordonnée x de [k]P
        """
        if k == 0:
            return None  # Point à l'infini
        if k == 1:
            return x
        
        k = abs(k)
        k_bits = bin(k)[2:]
        
        r0 = x
        r1 = self.x_dbl(x)
        x_base = x
        
        # Échelle de Montgomery
        for i in range(1, len(k_bits)):
            if k_bits[i] == '0':
                r1 = self.x_add(r0, r1, x_base)
                r0 = self.x_dbl(r0)
            else:
                r0 = self.x_add(r0, r1, x_base)
                r1 = self.x_dbl(r1)
        
        return r0

if __name__ == "__main__":
    # E: By² = x³ + A x² + x mod p possède un sous-groupe d'ordre de 172 bits
    # Ordre de E: 2^5 * 5^2 * 7 * 13 * 1993 * 20903 * 331953242759 * 57507525441833983281312841921174328991345888864745913
    # (dernier facteur de 172 bits)
    p = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
    A = 0x76d05e5cbc14de510a438591395c79571fad112b6b69abde209d7fdee0d2ae39
    B = 0x3a22a31949886afc815dbfc44e26780f4a38dcedde05afc0368523a6272f0f7a
    x_gen = 0x357d0cc97c51172ceddd5b0e3398eea57e989eca09c5e8aec025b968e31353e9
    
    courbe = Montgomery(A, p)
    
    with open("flag", "r") as f:
        s = f.read().strip()
    
    cle_secrete = int.from_bytes(s.encode(), "big")
    assert cle_secrete < 57507525441833983281312841921174328991345888864745913
    
    cle_publique = courbe.mul_scalaire(cle_secrete, x_gen)
    print(f"Clé publique: {cle_publique}")
    # 42505452888139451234160619061600404445586246682494761185988888720489385844860