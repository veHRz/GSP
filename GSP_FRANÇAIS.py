import typing as t
import hashlib, base64
good_sizes_for_password = [45, 31, 21, 15]
def toSha256(__chaineCaracteres: str, __convertirLeRenvoiEnChaineDeCaracteres : bool = False) -> bytes | str:
    """
    Cette fonction chiffre avec l'algorithme sha256 la chaîne de caractères donnée en paramètres.
    :param __chaineCaracteres: Chaîne de caractères à chiffrer à l'aide de l'algorithme sha256.
    :param __convertirLeRenvoiEnChaineDeCaracteres: True ou False pour dire si le retour sera converti en chaîne de caractères.
    :return: Renvoie la chaîne chiffrée.
    """
    if __convertirLeRenvoiEnChaineDeCaracteres:
        return hashlib.sha256(__chaineCaracteres.encode('utf-8')).hexdigest()
    return hashlib.sha256(__chaineCaracteres.encode('utf-8')).hexdigest().encode('utf-8')

def toBase64(__octets : bytes, __convertirLeRenvoiEnChaineDeCaracteres : bool = False) -> bytes | str:
    """
    Cette fonction chiffre en base64 l'objet bytes donné en paramètres.
    :param __octets: Un objet de type bytes à convertir en base64.
    :param __convertirLeRenvoiEnChaineDeCaracteres: True ou False pour dire si le retour sera converti en chaîne de caractères.
    :return: Renvoie l'objet de type bytes chiffrer.
    """
    if __convertirLeRenvoiEnChaineDeCaracteres:
        return base64.b64encode(__octets).decode('utf-8')
    return base64.b64encode(__octets)

def halfOfString(__chaineCaracteres: str) -> str:
    """
    Cette fonction renvoie la moitié paire des caractères de la chaîne de caractères passée en paramètre.
    :param __chaineCaracteres: La chaîne à diviser en deux.
    :return: Renvoie la moitié des caractères de la chaîne.
    """
    __new_string = ""
    __pair = True
    for __char in __chaineCaracteres:
        if __pair:
            __new_string += str(__char)
            __pair = False
        else:
            __pair = True
    return __new_string

def createPassword(__mdp : str, __identifiant : str, __site : str, __tailleMdp : t.Literal[45, 31, 21, 15] = 45) -> str:
    """
    Avec cette fonction, vous pouvez créer des mots de passe fortement chiffrer à l'aide des algorithmes sha256 et base64 combinés avec un mot de passe, un identifiant et un site Web que vous indiquez dans les paramètres.
    :param __mdp: Votre mot de passe principal.
    :param __identifiant: Votre indentifiant du site Web.
    :param __site: Le site Web pour lequel vous créez un mot de passe.
    :param __tailleMdp: La taille du mot de passe ne peut être qu'une valeur de cette liste : [45, 31, 21, 15].
    :return: Renvoie un mot de passe qui ne peut pas être déchiffré.
    """
    if __tailleMdp not in good_sizes_for_password:
        raise ValueError("__size_of_password n'est pas dans "+str(good_sizes_for_password))
    elif __tailleMdp == 45:
        return halfOfString(toBase64(toSha256(str(toSha256(__mdp))+str(toSha256(__identifiant))+str(toSha256(__site)))).decode('utf-8'))+'!'
    elif __tailleMdp == 31:
        return halfOfString(toBase64(bytes(halfOfString(toBase64(toSha256(str(toSha256(__mdp))+str(toSha256(__identifiant))+str(toSha256(__site)))).decode('utf-8')), 'utf-8')).decode('utf-8'))+'!'
    elif __tailleMdp == 21:
        return halfOfString(toBase64(bytes(halfOfString(toBase64(bytes(halfOfString(toBase64(toSha256(str(toSha256(__mdp))+str(toSha256(__identifiant))+str(toSha256(__site)))).decode('utf-8')), 'utf-8')).decode('utf-8')), 'utf-8')).decode('utf-8'))+'!'
    elif __tailleMdp == 15:
        return halfOfString(toBase64(bytes(halfOfString(toBase64(bytes(halfOfString(toBase64(bytes(halfOfString(toBase64(toSha256(str(toSha256(__mdp))+str(toSha256(__identifiant))+str(toSha256(__site)))).decode('utf-8')), 'utf-8')).decode('utf-8')), 'utf-8')).decode('utf-8')), 'utf-8')).decode('utf-8'))+'!'
