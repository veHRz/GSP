import typing as t
import hashlib, base64
good_sizes_for_password = [45, 31, 21, 15]
def toSha256(__string: str, __convert_return_to_string : bool = False) -> bytes | str:
    """
    This function encrypt with the sha256 algorithm the string give in parameters.
    :param __string: A string to encrypt using sha256 algorithm.
    :param __convert_return_to_string: True or False that the return will be convert to string.
    :return: Return the encrypted string.
    """
    if __convert_return_to_string:
        return hashlib.sha256(__string.encode('utf-8')).hexdigest()
    return hashlib.sha256(__string.encode('utf-8')).hexdigest().encode('utf-8')

def toBase64(__bytes : bytes, __convert_return_to_string : bool = False) -> bytes | str:
    """
    This function encrypt in base64 the bytes object give in parameters.
    :param __bytes: A bytes type object to convert to base64.
    :param __convert_return_to_string: True or False that the return will be convert to string.
    :return: Return the encrypted bytes object.
    """
    if __convert_return_to_string:
        return base64.b64encode(__bytes).decode('utf-8')
    return base64.b64encode(__bytes)

def halfOfString(__string: str) -> str:
    """
    This function returns the even half of the characters of the string passed as parameter.
    :param __string: The string to split into two.
    :return: Returns half of the characters from the string.
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

def createPassword(__password : str, __login : str, __site : str, __size_of_password : t.Literal[45, 31, 21, 15] = 45) -> str:
    """
    With this function you can create strong passwords that are encrypted using sha256 and base64 algorithms combine with a password, a login and a website that you give in the parameters.
    :param __password: Your main password.
    :param __login: Your login into the website.
    :param __site: The website you are creating a password for.
    :param __size_of_password: Password size can only be a value from this list: [45, 31, 21, 15].
    :return: Return a password that cannot be cracked.
    """
    if __size_of_password not in good_sizes_for_password:
        raise ValueError("__size_of_password not in "+str(good_sizes_for_password))
    elif __size_of_password == 45:
        return halfOfString(toBase64(toSha256(str(toSha256(__password))+str(toSha256(__login))+str(toSha256(__site)))).decode('utf-8'))+'!'
    elif __size_of_password == 31:
        return halfOfString(toBase64(bytes(halfOfString(toBase64(toSha256(str(toSha256(__password))+str(toSha256(__login))+str(toSha256(__site)))).decode('utf-8')), 'utf-8')).decode('utf-8'))+'!'
    elif __size_of_password == 21:
        return halfOfString(toBase64(bytes(halfOfString(toBase64(bytes(halfOfString(toBase64(toSha256(str(toSha256(__password))+str(toSha256(__login))+str(toSha256(__site)))).decode('utf-8')), 'utf-8')).decode('utf-8')), 'utf-8')).decode('utf-8'))+'!'
    elif __size_of_password == 15:
        return halfOfString(toBase64(bytes(halfOfString(toBase64(bytes(halfOfString(toBase64(bytes(halfOfString(toBase64(toSha256(str(toSha256(__password))+str(toSha256(__login))+str(toSha256(__site)))).decode('utf-8')), 'utf-8')).decode('utf-8')), 'utf-8')).decode('utf-8')), 'utf-8')).decode('utf-8'))+'!'
