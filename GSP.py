def toSha256(__string: str, __convert_return_to_string : bool = False):
    """
    This function encrypt with the sha256 algorithm the string give in parameters.
    :param __string: A string to encrypt using sha256 algorithm.
    :param __convert_return_to_string: True or False that the return will be convert to string.
    :return: Return the encrypted string.
    """
    import hashlib
    if __convert_return_to_string:
        return hashlib.sha256(__string.encode('utf-8')).hexdigest()
    return hashlib.sha256(__string.encode('utf-8')).hexdigest().encode('utf-8')

def toBase64(__bytes : bytes, __convert_return_to_string : bool = False):
    """
    This function encrypt in base64 the bytes object give in parameters.
    :param __bytes: A bytes type object to convert to base64.
    :param __convert_return_to_string: True or False that the return will be convert to string.
    :return: Return the encrypted bytes object.
    """
    import base64
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


def createPassword(__password : str, __login : str, __site : str, __size_of_password : int = 45) -> str:
    """
    With this function you can create strong passwords that are encrypted using sha256 and base64 algorithms combine with a password, a login and a website that you give in the parameters.
    :param __password: Your main password.
    :param __login: Your login into the website.
    :param __site: The website your are creating a password for.
    :param __size_of_password: Password size can only be a value from this list: [45, 31, 21, 15].
    :return: Return a password that cannot be cracked.
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
    Allows Python to prevent the main code from running when the program is used as a library.
    """
    while 1:
        __tmp_password = input("Enter the master password (exit to leave the program):\n")
        if __tmp_password == "exit":
            exit()
        __tmp_login = input("Enter the login for the website :\n")
        __tmp_site = input("Enter the website address :\n")
        __tmp_size = int(input("Enter the size of the password (choice between: 45, 31 or 21):\n"))
        print(createPassword(__tmp_password, __tmp_login, __tmp_site, __tmp_size))
