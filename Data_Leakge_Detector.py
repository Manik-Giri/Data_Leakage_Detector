import requests
import hashlib
import sys
import argparse
import re
import platform
import os
from bs4 import BeautifulSoup


'''Using GET https://api.pwnedpasswords.com/range/{first 5 hash chars} the k-model allows anonymity as the full hash 
is not getting out of your computer '''


class Color:
    def __init__(self, system_type):
        if system_type == "Windows":
            self.HEADER = ''
            self.OKBLUE = ''
            self.OKGREEN = ''
            self.WARNING = ''
            self.FAIL = ''
            self.ENDC = ''
            self.BOLD = ''
            self.UNDERLINE = ''
            self.BLACK = ''
            self.RED = ''
            self.GREEN = ''
            self.YELLOW = ''
            self.BLUE = ''
            self.MAGENTA = ''
            self.CYAN = ''
            self.WHITE = ''
            self.RESET = ''
        else:
            self.HEADER = '\033[95m'
            self.OKBLUE = '\033[94m'
            self.OKGREEN = '\033[92m'
            self.WARNING = '\033[93m'
            self.FAIL = '\033[91m'
            self.ENDC = '\033[0m'
            self.BOLD = '\033[1m'
            self.UNDERLINE = '\033[4m'
            self.BLACK = '\u001b[30m'
            self.RED = '\u001b[31m'
            self.GREEN = '\u001b[32m'
            self.YELLOW = '\u001b[33m'
            self.BLUE = '\u001b[34m'
            self.MAGENTA = '\u001b[35m'
            self.CYAN = '\u001b[36m'
            self.WHITE = '\u001b[37m'
            self.RESET = '\u001b[0m'
            
normal_color = "\33[00m"
info_color = "\033[1;33m"
red_color = "\033[1;31m"
green_color = "\033[1;32m"
whiteB_color = "\033[1;37m"
detect_color = "\033[1;34m"
banner_color="\033[1;33;40m"
end_banner_color="\33[00m"
system = platform.system()
col = Color(system)
API_URL = 'https://api.pwnedpasswords.com/range/'


def clean():
    if system == "Windows":
        os.system("cls")
    if system == "Linux":
        os.system("clear")


def sha1_hash(to_hash):
    return hashlib.sha1(to_hash.encode('utf-8')).hexdigest().upper()


def passwd_api_check(password):
    sha1 = sha1_hash(password)
    hash_to_api, hash_to_check = sha1[0:5], sha1[5:]
    check_url = API_URL + hash_to_api
    r = requests.get(check_url)
    if r.status_code != 200:
        raise RuntimeError(f'Api is down, error {r.status_code}; Check the api')
    hash_generator = (i.split(':') for i in r.text.splitlines())
    for h, count in hash_generator:
        if h == hash_to_check:
            return count
    return 0


def print_leaks(email_list, email_base):
    if email_list:
        for dic in email_list:
            print(f'The email {col.WARNING}[+]->> {col.RED}{dic["email"]}{col.ENDC} has been leaked with the '
                  f'password {col.WARNING}[+]--> {col.RED}{dic["passwd"]}{col.ENDC}')
    else:
        print(
            f'The email {col.WARNING}[+]->> {col.GREEN}{email_base}{col.ENDC} {col.CYAN}Doesn\'t have any cleartext '
            f'passwords found!{col.ENDC}')


def print_passwd(count, password):
    if count != 0:
        print(
            f'{col.WARNING}Your password {col.RED}{password}{col.WARNING} has been leaked {col.RED}{count}{col.WARNING} times{col.ENDC}')
    else:
        print(
            f'{col.GREEN}Your password {col.WARNING}{password}{col.GREEN} has not been compromised yet!{col.ENDC}')


def check_firefox(email_in, hidden=0):
    regex = '^[a-z0-9.]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$'
    email = re.match(regex, email_in)
    if email:
        email = email.group(0)
        url = 'https://monitor.firefox.com'
        s = requests.Session()
        try:
            r = s.get(url, timeout=12)
            if r.status_code != 200:
                raise Exception(f'Service is down, error {r.status_code}; Check the service')
            soup = BeautifulSoup(r.text, "html.parser")
            csrf = soup.find('input', {'name': '_csrf'})['value']
            email_hash = sha1_hash(email)
            data = {"_csrf": csrf, "pageToken": "", "scannedEmailId": 2, "email": "", "emailHash": email_hash}
            firefox_leaks = s.post(url + "/scan", data, timeout=12)
            if firefox_leaks.status_code != 200:
                raise Exception(f'Service is down, error {r.status_code}; Check the service')
            soup1 = BeautifulSoup(firefox_leaks.text, "html.parser")
            list_breaches = soup1.findAll("div", {"class": "breach-info-wrapper"})
            clean_breaches = []
            for breach in list_breaches:
                data = breach.div.findAll('span')
                for i in data:
                    clean_breaches.append(i.string)
            s.close()
            return print_firefox_leaks(clean_breaches, email)

        except:
            print(f"{col.FAIL}Too many request to firefox from that IP Address try using a proxy or VPN")

    else:
        print("Database breach by name in firefox records is only available for complete email search. Try again with the full email "
              "ex:username@domain.xyz")


def print_firefox_leaks(clean_breaches, email):
    if clean_breaches is None or len(clean_breaches) == 0:
        print(f'The email {col.GREEN}{email}{col.ENDC} is not on firefox records')
    else:
        print(f'The email {col.RED}{email}{col.ENDC} was leaked in:')
        for i in range(int(len(clean_breaches) / 5)):
            print(
                f"\t{col.MAGENTA}{clean_breaches[5 * i]}{col.ENDC}. The {clean_breaches[5 * i + 1]} on {col.BLUE}{clean_breaches[5 * i + 2]}{col.ENDC} the {clean_breaches[5 * i + 3]}  {col.YELLOW}{clean_breaches[5 * i + 4]}")


def print_pass_leaks(email_list, email_base):
    if email_list:
        for dic in email_list:
            password = dic['fields'].get("password", "NoPass")
            hash_pass = dic['fields'].get("passhash", "NoHash")
            domain = dic['fields'].get("domain", "NoDomain")
            print(f'The email {col.WARNING}[+]->> {col.RED}{dic["fields"]["email"]}{col.ENDC} has been leaked:')
            if password != "NoPass":
                print(f"\tpassword {col.WARNING}[+]--> {col.RED}{password}{col.ENDC}")
            if hash_pass != "NoHash":
                print(f"\tThere is a {col.WARNING}hash leaked: {col.RED}{hash_pass}{col.ENDC}")
            if domain != "NoDomain":
                print(f"\tThis leak was part of the: {col.MAGENTA}{domain}{col.ENDC}\n\n")
    else:
        print(
            f"The email {col.WARNING}[+]->> {col.GREEN}{email_base}{col.ENDC} {col.CYAN}Doesn\'t have any cleartext "
            f"passwords found!{col.ENDC}\n")


def pass_leaks(email):
    regex = '^[a-z0-9.]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$'
    url = 'https://scylla.sh/search?q='
    header = {'Accept': 'application/json'}
    full_mail = re.match(regex, email)
    if not full_mail:
        if not '@' in email:
            full_mail = email + "*"
        else:
            full_mail = email
    else:
        full_mail=full_mail.group(0)
    r = requests.get(url + "email:" + full_mail, headers=header)
    data = r.json()
    return print_pass_leaks(data, email)

#Search have I been pwned.
def haveibeenpwned(email):
	print(info_color + "--------------------\nChecking breaches on haveibeenpwned.com...\n--------------------")
	
	email = email.replace("@","%40") #Replace @ with url encode character
	url = "https://haveibeenpwned.com/unifiedsearch/" + email
	headers = {
		'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36', "Accept-Language": "en-US,en;q=0.5"}
	client = requests.Session()
	client.headers.update(headers)
	response = client.get(url, proxies=None)
	total = 0
	try:
		resp_json = json.loads(response.text)

		inicio = 0
		total = 0
		while (inicio != -1):
			inicio = response.text.find("BreachDate", inicio)
			if (inicio != -1):
				total = total + 1
			inicio = response.text.find("BreachDate", inicio+1)

		print(whiteB_color+"Total leaks detected on haveIbeenpwned: " + red_color + str(total))
		cont = 0

		while (cont < total):
			print(whiteB_color +"Leak Detected!!!" + "\n" + red_color + "--> " + resp_json["Breaches"][cont]["Name"] + "\n\t" + red_color + "- Breach Date:" + resp_json["Breaches"][cont]["BreachDate"]+"\n\t- Is Verified? "+ str(resp_json["Breaches"][cont]["IsVerified"]))
			cont = cont + 1
	except:
		pass

	if (total == 0):
		print (green_color + "No breaches detected in have I been pwned")


def parse_firefox_monitor(response):
    start_breachName = response.text.find("breach-title")
    leaks = False
    while start_breachName != -1:
        leaks = True
        print(whiteB_color +"!!! تم الكشف عن ")
        start_breachName = start_breachName + 14
        end_breachName = response.text.find("</span>", start_breachName)
        print(red_color + "--> " + response.text[start_breachName:end_breachName])
        end_key = end_breachName
        start_index = response.text.find("breach-key", end_key) + 12
        while start_index > 12 and (start_index < response.text.find("breach-title", start_breachName + 12) or response.text.find("breach-title", start_breachName + 12) < 12):
            end_index = response.text.find("</span>", start_index)
            start_key = response.text.find("breach-value", end_index) + 14
            end_key = response.text.find("</span>", start_key)
            value = response.text[start_index:end_index]
            key = response.text[start_key:end_key]
            print("\t\t- " + value + " " + key)
            start_index = response.text.find("breach-key", end_key) + 12
        start_breachName = response.text.find("breach-title", end_breachName)
    if not leaks:
        print(green_color + "This email account not appears on Firefox Monitor")


def check_firefox_monitor(email):
    print(info_color + "--------------------\nChecking on Firefox Monitor...\n--------------------")
    # Extract valid csrf token from request.
    url_form = 'https://monitor.firefox.com'
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36', "Accept-Language": "en-US,en;q=0.5"}
    client = requests.Session()
    client.headers.update(headers)
    response = client.get(url_form)
    inicio_csrf = response.text.find("_csrf")
    if (inicio_csrf != -1):
        inicio_csrf = response.text.find("value", inicio_csrf)
        if (inicio_csrf != -1):
            inicio_csrf = inicio_csrf + 7
            fin_csrf = response.text.find("\"", inicio_csrf)
            csrfToken = response.text[inicio_csrf:fin_csrf]
            inicio_scannedEmailId = response.text.find("scannedEmailId")
            inicio_scannedEmailId = response.text.find("value",inicio_scannedEmailId)
            inicio_scannedEmailId = inicio_scannedEmailId+7
            fin_scannedEmailId = response.text.find("\"",inicio_scannedEmailId)
            scannedEmailID = response.text[inicio_scannedEmailId:fin_scannedEmailId]
            emailHash = hashlib.sha1(bytes(email, "utf8"))
            emailHash = emailHash.hexdigest().upper()
            # Do the query
            url = "https://monitor.firefox.com/scan"
            params = {"_csrf": csrfToken, "email": email, "pageToken": "", "scannedEmailId": scannedEmailID, "emailHash": emailHash}
            response = client.post(url, params, proxies=tor_proxy)
            client.close()
            parse_firefox_monitor(response)
    else:
        print(red_color + "Error: It was not possible to access firefox monitor (there is a limit of requests per hour)")


def main():
    parser = argparse.ArgumentParser()
    banner = ''' 
 ____    _  _____  _      _     _____    _    _  __    _    ____ _____ 
|  _ \  / \|_   _|/ \    | |   | ____|  / \  | |/ /   / \  / ___| ____|
| | | |/ _ \ | | / _ \   | |   |  _|   / _ \ | ' /   / _ \| |  _|  _|  
| |_| / ___ \| |/ ___ \  | |___| |___ / ___ \| . \  / ___ \ |_| | |___ 
|____/_/   \_\_/_/   \_\ |_____|_____/_/   \_\_|\_\/_/   \_\____|_____|

 ____  _____ _____ _____ ____ _____ ___  ____  
|  _ \| ____|_   _| ____/ ___|_   _/ _ \|  _ \ 
| | | |  _|   | | |  _|| |     | || | | | |_) |
| |_| | |___  | | | |__| |___  | || |_| |  _ < 
|____/|_____| |_| |_____\____| |_| \___/|_| \_\

{}Which Detects your password or email have been Compromised or not{}
By {}Manik Kumar Giri{}
    
    '''.format(col.WARNING, col.ENDC, col.RED, col.ENDC)
    print(f'{col.OKBLUE}{banner}{col.ENDC}')
    parser.add_argument("-p", "--passwords", nargs='+', type=str, dest='passwords',
                        help="Insert the passwords to check separated by space")
    parser.add_argument("-e", "--email", nargs='+', type=str, dest='emails',
                        help="Insert the emails to check separated by space."
                             " It can check just the username, the complete email or your domain with @domain.xyz")
    args = parser.parse_args()

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    if type(args.passwords) == list:
        for password in args.passwords:
            print_passwd(passwd_api_check(password), password)
	
    elif args.passwords:
        print_passwd(passwd_api_check(args.passwords), args.passwords)

   
    
    elif args.emails:
        listToStr = ' '.join([str(elem) for elem in args.emails])
        haveibeenpwned(listToStr)
        check_firefox_monitor(listToStr)
        #pass_leaks(args.emails)
        #check_firefox(args.emails)


if __name__ == '__main__':
    clean()
    sys.exit(main())

