def toSha256(__string: str, __convert_return_to_string : bool = False):
    """
    Cette fonction chiffre avec l'algorithme sha256 la chaîne de caractères donnée en paramètres.
    :param __string: Chaîne de caractères à chiffrer à l'aide de l'algorithme sha256.
    :param __convert_return_to_string: True ou False pour dire si le retour sera converti en chaîne.
    :return: Renvoie la chaîne chiffrée.
    """
    import hashlib
    if __convert_return_to_string:
        return hashlib.sha256(__string.encode('utf-8')).hexdigest()
    return hashlib.sha256(__string.encode('utf-8')).hexdigest().encode('utf-8')

def toBase64(__bytes : bytes, __convert_return_to_string : bool = False):
    """
    Cette fonction chiffre en base64 l'objet bytes donné en paramètres.
    :param __bytes: Un objet de type bytes à convertir en base64.
    :param __convert_return_to_string: True ou False pour dire si le retour sera converti en chaîne.
    :return: Renvoie l'objet de type bytes chiffrer.
    """
    import base64
    if __convert_return_to_string:
        return base64.b64encode(__bytes).decode('utf-8')
    return base64.b64encode(__bytes)

def halfOfString(__string: str) -> str:
    """
    Cette fonction renvoie la moitié paire des caractères de la chaîne passée en paramètre.
    :param __string: La chaîne à diviser en deux.
    :return: Renvoie la moitié des caractères de la chaîne.
    """
    __new_string = ""
    __pair = True
    for __char in __string:
        if __pair:
            __new_string += str(__char)
            __pair = False
        else:
            __pair = True
    return __new_string


def createPassword(__password : str, __login : str, __site : str, __size_of_password : int = 45) -> str:
    """
    Avec cette fonction, vous pouvez créer des mots de passe fortement chiffrer à l'aide des algorithmes sha256 et base64 combinés avec un mot de passe, un identifiant et un site Web que vous indiquez dans les paramètres.
    :param __password: Votre mot de passe principal.
    :param __login: Votre indentifiant du site Web.
    :param __site: Le site Web pour lequel vous créez un mot de passe.
    :param __size_of_password: La taille du mot de passe ne peut être qu'une valeur de cette liste : [45, 31, 21, 15].
    :return: Renvoie un mot de passe qui ne peut pas être déchiffré.
    """
    __good_values_for_size = [45, 31, 21, 15]
    if __size_of_password not in __good_values_for_size:
        raise ValueError("__size_of_password not in "+str(__good_values_for_size))
    elif __size_of_password == 45:
        return halfOfString(toBase64(toSha256(str(toSha256(__password))+str(toSha256(__login))+str(toSha256(__site)))).decode('utf-8'))+'!'
    elif __size_of_password == 31:
        return halfOfString(toBase64(bytes(halfOfString(toBase64(toSha256(str(toSha256(__password))+str(toSha256(__login))+str(toSha256(__site)))).decode('utf-8')), 'utf-8')).decode('utf-8'))+'!'
    elif __size_of_password == 21:
        return halfOfString(toBase64(bytes(halfOfString(toBase64(bytes(halfOfString(toBase64(toSha256(str(toSha256(__password))+str(toSha256(__login))+str(toSha256(__site)))).decode('utf-8')), 'utf-8')).decode('utf-8')), 'utf-8')).decode('utf-8'))+'!'
    elif __size_of_password == 15:
        return halfOfString(toBase64(bytes(halfOfString(toBase64(bytes(halfOfString(toBase64(bytes(halfOfString(toBase64(toSha256(str(toSha256(__password))+str(toSha256(__login))+str(toSha256(__site)))).decode('utf-8')), 'utf-8')).decode('utf-8')), 'utf-8')).decode('utf-8')), 'utf-8')).decode('utf-8'))+'!'

if __name__ == "__main__":
    """
    Permet à Python d'empêcher l'exécution du code principal lorsque le programme est utilisé comme bibliothèque.
    """
    while 1:
        __tmp_password = input("Saisissez le mot de passe maître (exit pour quitter le programme):\n")
        if __tmp_password == "exit":
            exit()
        __tmp_login = input("Saisissez l'identifiant pour le site web :\n")
        __tmp_site = input("Saisissez l'adresse du site web :\n")
        __tmp_size = int(input("Saisissez la taille du mot de passe (choix entre : 45, 31 ou 21) :\n"))
        print(createPassword(__tmp_password, __tmp_login, __tmp_site, __tmp_size))
