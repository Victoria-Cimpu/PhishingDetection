import requests, json

# Search crt.sh for the given domain
# Based on https://github.com/PaulSec/crt.sh
def search(domain, wildcard=True, expired=True):
    base_url = "https://crt.sh/?q={}&output=json"
    if not expired:
        base_url = base_url + "&exclude=expired"
    if wildcard and "%" not in domain:
        domain = "%.{}".format(domain)
    url = base_url.format(domain)

    ua = 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1'
    req = requests.get(url, headers={'User-Agent': ua})

    if req.ok:
        try:
            content = req.content.decode('utf-8')
            data = json.loads(content)
            return data
        except ValueError:
            data = json.loads("[{}]".format(content.replace('}{', '},{')))
            return data
        except Exception as err:
            print("Error retrieving information.")
    return None

if __name__ == "__main__":
    # get result based on the inputed search url 
    search_url = str(input("Enter the URL : "))
    result = search(search_url)
    url_list = []

    # for each certificate, get the url (common name) 
    for cert in result:
        # can have additional filtering, for example : 
        #if ("Let's Encrypt" in cert["issuer_name"]):
            url_list.append(cert["common_name"])

    # remove duplicates 
    url_list = list(dict.fromkeys(url_list))

    # print the urls 
    print(*url_list, sep='\n')