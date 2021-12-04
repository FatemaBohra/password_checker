import requests
import hashlib
import sys

def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    response = requests.get(url)
    if response.status_code != 200:
        raise RuntimeError(f'Error fetching: {response.status_code}, check the api and try again')
    return response


def read_response(response):
    print(response.text)

def get_password_leaks_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes: # h is the tail of our hash, count is num of how many times pass has been hacked
        if h == hash_to_check: # tail == tail of our hashed password
            return count
    return 0

def pwned_api_check(password):
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    firsts5_char, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(firsts5_char)
    print(firsts5_char, tail)
    print(response)
    # return read_response(response)
    return get_password_leaks_count(response, tail)

def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f'{password} was found {count} times...you should probably change pass')
        else:
            print(f'{password} was NOT found. Carry on!')
        return 'done!'

if __name__ == '__main__':
  sys.exit(main(sys.argv[1:]))

# pwned_api_check('123')