import crypt
import sys


def get_shadow_file():
    with open(sys.argv[1], 'r') as f:
        return [line.split(b':') for line in bytes(f.read(), encoding='utf8').splitlines()]


def get_dictionary_hashes():
    with open(sys.argv[2], 'r') as f:
        return bytes(f.read(), encoding='utf8').splitlines()


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print('Usage: cracker <dictionary_file> <linux_password_file>\n')
        exit(1)

    shadow_file = get_shadow_file()
    dictionary_file = get_dictionary_hashes()

    usernames = [entry[0] for entry in shadow_file]
    shas = [entry[1].split(b'$') for entry in shadow_file]

    for i in range(len(usernames)):
        if len(shas[i]) == 4:
            user_hash_ascii = shas[i][3].decode('ascii')

            for password in dictionary_file:
                password_str = str(password, encoding='ascii')
                salt_str = "${}${}".format(shas[i][1].decode('ascii'), shas[i][2].decode('ascii'))
                dict_crypt = crypt.crypt(password_str, salt=salt_str).split('$')[3]

                if user_hash_ascii == dict_crypt:
                    print("{}: {}".format(str(usernames[i], encoding='ascii'), password_str))


