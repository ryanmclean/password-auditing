import requests

class api():
    uri = ''
    user_agent = ''
    params = {}
    # custom status code information is stored here.
    status_codes = {}
    # the api response is stored in this object.
    response = object

    def __init__(self):
        self.uri = ''
        self.user_agent = "Pwnage-Checker-For-Company"
        self.params = {"User-Agent:": self.user_agent,}
        self.status_codes = {
            # general error codes for most queries.
            # some commands will update these return codes.
            200: "Ok - everything worked.",
            400: "Bad request - the account does not comply with an acceptable format (i.e. its an empty string)",
            403: "Forbidden - no user agent has been specified in the request",
            404: "Not found - the object could not be found and has therefore not been pwned",
            429: "Too many requests - the rate limit has been exceeded",
        }


    def getBreach(self,domain='all'):
        self.uri = 'https://haveibeenpwned.com/api/v2/breaches'
        if domain is not 'all':
            self.params.update({'domain': domain})
        self.response = self.processRequest()


    def checkAccount(self,account,domain='all'):
        self.uri = 'https://haveibeenpwned.com/api/v2/breachedaccount/' + account
        if domain is not 'all':
            self.params.update({'domain': domain})
        self.response = self.processRequest()

    def checkHash(self,hash):
        partial_hash = str.upper(hash[0:5])
        self.uri = 'https://api.pwnedpasswords.com/range/' + partial_hash
        self.status_codes.update({
            200: "Found!",
            404: "Hash not found.  This should never occur.",
        })
        response = self.processRequest()
        if response.status_code is 200:
            temphashes = str(response.content).strip("'").split('\\r\\n')
            hashes = {}
            for i in temphashes:
                i = i.split(":")
                hashes.update({i[0]: i[1]})
            return hashes.get(str(hash[5:]).upper())
        else:
            return '0'

    def checkPastes(self, account):
        self.uri = "https://haveibeenpwned.com/api/v2/pasteaccount/" + account
        self.status_codes.update({
            200: "Ok - everything worked and theres a string array of pwned sites for the account",
            400: "Bad request - the account does not comply with an acceptable format (i.e. its an empty string)",
            403: "Forbidden - no user agent has been specified in the request",
            404: "Not found - the account could not be found and has therefore not been pwned",
            429: "Too many requests - the rate limit has been exceeded",
        })
        self.response = self.processRequest()

    def processRequest(self):
        return requests.get(self.uri,self.params)

