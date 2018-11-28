# Take in a string of username/passwords in the form of:
# "Username:password"
# output passwords based on the following criteria
# password length requirement
# number of Symbols
# number of Capitals
# number of Lowercase
# number of Numbers
import hibp
import hashlib
import argparse
import os

api = hibp.api()
sha1 = hashlib.sha1()

MIN_PASS_LENGTH = 8
# Number of items of complexity that is required.
# this would include capitals, symbols, numbers, lowercase.
MIN_COMPLEXITY = 3
total_failed_complexity = 0
total_failed_known_pw = 0
total_failed_prevalence = 0

parser = argparse.ArgumentParser()
parser.add_argument('INPUT_FILENAME', help='The name of the file to read from.  '
                                           'File must be in the format username:password.  '
                                           '(see \'combine.py\' for combining these passwords together.)')
parser.add_argument('OUTPUT_FILENAME', help='The name of the CSV file to write to', default='passwords.csv')
parser.add_argument('--common', help='Compare passwords to a list of known words.  If no list is specified,'
                                     'a default list of the top 25 are pulled from Wikipedia.',
                    default='common_passwords.txt')
args = parser.parse_args()

if not os.path.exists(args.INPUT_FILENAME):
    print("Error - input filename ({})does not exist.".format(args.INPUT_FILENAME))
    exit(1)
if not os.path.exists(args.common):
    print("INFO - unsafe password list ({})does not exist.".format(args.common))
    unsafe_passwords = None
else:
    unsafe_passwords = open(args.common, 'r', encoding='UTF-8').readlines()

input_file = open(args.INPUT_FILENAME, 'r', encoding='UTF-8')
output = open(args.OUTPUT_FILENAME, 'w', encoding='UTF-8')




# Write the header of the output.
output.write('"{}","{}","{}","{}","{}"\n'.format(
        "Username", "Password", "Meets Complexity?", "Known Bad Password?", "Password Prevalence Score"
    ))

print("Beginning parsing of {}".format(args.INPUT_FILENAME))
# noinspection SpellCheckingInspection
for line in input_file.readlines():
    line = line.strip('\r')
    line = line.strip('\n')
    # split the username:password string.
    user_data = line.split(':')

    # check password length.
    password_length = len(user_data[1])

    # check for existence of password complexity.
    numbers = 0
    symbols = 0
    upper_chars = 0
    lower_chars = 0
    complexity = [0, 0, 0, 0]
    complex_characters = 0
    for i in user_data[1]:
        if i.isnumeric():
            numbers += 1
            complexity[0] = 1
        elif i.isupper():
            upper_chars += 1
            complexity[1] = 1
        elif i.islower():
            lower_chars += 1
            complexity[2] = 1
        else:
            symbols += 1
            complexity[3] = 1

    # Check to see if p/w meets complexity.
    meets_complexity = False
    if sum(complexity) >= MIN_COMPLEXITY and password_length >= MIN_PASS_LENGTH:
        meets_complexity = True
    else:
        total_failed_complexity += 1

    # Check for unsafe password combinations, dictionary unsafe words.
    is_bad_password = False
    bad_string = ""
    for i in unsafe_passwords:
        i = i.strip('\r')
        i = i.strip('\n')
        if str.lower(i) in str.lower(user_data[1]):
            is_bad_password = True
            total_failed_known_pw += 1

    # Check for password prevalence using HIBP Api.
    h = hashlib.sha1(user_data[1].encode('UTF-8'))
    hash_prevalence = api.checkHash(h.hexdigest())
    if hash_prevalence:
        total_failed_prevalence += 1

    # print the results.
    # print('{0:10s} {1:10s} {2:10s} {3:10s} {4:10s} {5:15s} {6:10s}'.format(
    #    "Length", "Upper", "Lower", "Numbers", "Symbols", "Known Bad", "Prevalence", "Result"))
    # print('{0:10s} {1:10s} {2:10s} {3:10s} {4:10s} {5:15s} {6:10s}'.format(
    #    str(password_length).ljust(4), str(upper_chars), str(lower_chars), str(numbers),
    #    str(symbols), str(is_bad_password), str(hash_prevalence), str(meets_complexity)))
    # print("\n")

    # write the results to disk.
    output.write('"{}","{}","{}","{}","{}"\n'.format(
        user_data[0], user_data[1], meets_complexity, is_bad_password, hash_prevalence
    ))


# display totals.
print("All data is written to '{}'".format(args.OUTPUT_FILENAME))
print("Total Passwords That Failed Complexity: {}".format(total_failed_complexity))
print("Total Known Bad Passwords: {}".format(total_failed_known_pw))
print("Total Passwords with Prevalence: {}".format(total_failed_prevalence))
print("\n")

# write totals
output.write('"{}","{}","{}","{}","{}"\n'.format(
    "Totals", "", total_failed_complexity, total_failed_known_pw, total_failed_prevalence))

# cleanup.
input_file.close()
output.close()
