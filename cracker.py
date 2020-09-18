#!/usr/bin/env python3

# Copyright Antony Kellermann 2020
# Usage: ./cracker <dictionary_file> <linux_password_file>

import crypt
import sys

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print('Usage: cracker <dictionary_file> <linux_password_file>\n')
        exit(1)

    with open(sys.argv[1], 'r') as f:
        dictionary_file = bytes(f.read(), encoding='utf8').splitlines()

    with open(sys.argv[2], 'r') as f:
        shadow_file = [line.split(b':') for line in bytes(f.read(), encoding='utf8').splitlines()]
        usernames = [entry[0] for entry in shadow_file]
        hash_data = [entry[1].split(b'$') for entry in shadow_file]

    for i in range(len(usernames)):
        if len(hash_data[i]) == 4:
            user_hash_ascii = hash_data[i][3].decode('ascii')

            for password in dictionary_file:
                password_ascii = str(password, encoding='ascii')
                salt_hash_ascii = "${}${}".format(hash_data[i][1].decode('ascii'), hash_data[i][2].decode('ascii'))
                dict_hash_ascii = crypt.crypt(password_ascii, salt=salt_hash_ascii).split('$')[3]

                if user_hash_ascii == dict_hash_ascii:
                    print("Found passwd for user {}: {}".format(str(usernames[i], encoding='ascii'), password_ascii))
