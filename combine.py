import argparse
import os
import glob

parser = argparse.ArgumentParser()
parser.add_argument('USERNAME_FILE', help='The name of the file to read from')
parser.add_argument('PASSWORD_FILES', nargs='*', help='File path and mask of the password files to import.\nExample:\nC:\Python\*.txt')
parser.add_argument('--output', help='The name of the CSV file to write to', default='passwords.csv')

args = parser.parse_args()

if not os.path.exists(args.USERNAME_FILE):
    print("Error - input filename ({}) does not exist.".format(args.USERNAME_FILE))
    exit(1)

usernames = {}
f_username = open(args.USERNAME_FILE,'r',encoding='UTF-8')
for line in f_username.readlines():
    line = line.strip('\r')
    line = line.strip('\n')
    uname = line.split(':')[0]
    try:
        uname = uname.split('\\')[1]
    except IndexError:
        continue
    hash = line.split(':')[3]
    if '$' not in uname:
        usernames.update({hash: uname})
print("{} usernames collected.".format(len(usernames)))
#print(usernames)
# collect passwords, order by hashes.
passwords = {}

def parse_passwords(inputfile):
    print("Reading from '{}'".format(inputfile))
    f_password = open(inputfile, 'r', encoding='UTF-8')
    pw_to_return = {}
    pw_count = 0
    for line in f_password.readlines():
        pw_count += 1
        line = line.strip('\r')
        line = line.strip('\n')
        hash = line.split(':')[0]
        pw = line.split(':')[1]
        pw_to_return.update({hash: pw})
    print("{} passwords found in {}".format(pw_count, inputfile))
    f_password.close()
    return pw_to_return

#if password contains wildcard, expand.
#for file in glob.glob(args.PASSWORD_FILES):
for password_file in args.PASSWORD_FILES:
    if '*' in password_file:
        # there is more than one file in this particular request.
        # use glob to expand wildcard then parse accordingly.
        for file in glob.glob(password_file):
            passwords.update(parse_passwords(file))
    else:
        passwords.update(parse_passwords(password_file))
print("{} passwords collected.".format(len(passwords)))


combined = []
for hash,password in passwords.items():
    combined.append((usernames[hash], hash, password))


output = open(args.output, 'w', encoding='UTF-8')
for i in combined:
    output.write('{}:{}\n'.format(i[0], i[2]))
output.close()

print("Data combined into {}".format(args.output))