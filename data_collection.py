import datetime
from bs4 import BeautifulSoup
import requests
import json
import time
from csv import writer
import re

def cal_comp(orgin, new):
    if (orgin == -1 or new == -1) :
        print("Error for DOM analysis")
        return 0.0

    common_elements = set(orgin).intersection(set(new))
    num_common_elements = len(common_elements)
    
    # Find the total number of unique elements in both lists
    total_elements = set(orgin).union(set(new))
    num_total_elements = len(total_elements)
    
    # Calculate the percentage similarity
    if (num_total_elements == 0):
        percentage_similarity = 0.0
    else :
        percentage_similarity = (num_common_elements / num_total_elements) * 100
    return percentage_similarity

def get_elements(elements, key, pattern):
    result_elm = []
    for element in elements:
        temp1 = False
        if (key in str(element)) : 
            temp1 = re.findall(pattern, str(element))
        if (temp1):
            temp2 = temp1[0].replace("'", '"').split('"')[1]
            result_elm.append(temp2)
    return result_elm

def dom_analysis(uuid):
    dom_url = 'https://urlscan.io/dom/' + uuid + '/'
    response_dom = requests.get(dom_url)
    if response_dom.status_code != 200:
        print("DOM URL fail :", dom_url)
        return -1, -1, -1, -1, -1 
    
    # Parse the HTML content with BeautifulSoup
    soup = BeautifulSoup(response_dom.content, 'html.parser')

    # javescript - Extract the javascript links from each element 
    elements = soup.find_all(['script'])
    js_text_elm = get_elements(elements, "src=", "src=[\'\"][^\'\"]*[\'\"]")

    # CSS - Extract the CSS links from each element 
    elements = soup.find_all(['link'])
    css_text_elm = get_elements(elements, "css", "href=[\'\"][^\'\"]*[\'\"]")

    # images - Extract the image links from each element 
    elements = soup.find_all(['img'])
    img_text_elm = get_elements(elements, "src", "src=[\'\"][^\'\"]*[\'\"]")

    # Top X words 
    X = 10
    text_elements = soup.find_all(['nav', 'p', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'span']) #'div'
    scraped_text = ' '.join(element.get_text() for element in text_elements)
    from collections import Counter 
    split_it = scraped_text.split() 
    Counter = Counter(split_it)   
    most_occur = Counter.most_common(X)   
    most_occur_word = []
    for occ in most_occur:
        most_occur_word.append(occ[0]) 

    # number of iframes 
    iframe = len(soup.find_all(['iframe']))

    return js_text_elm, css_text_elm, img_text_elm, most_occur_word, iframe

def get_result(url_to_scan):
    api_key = 'e832d425-2b72-455b-8ca3-0c5cd4c756e4'
    headers = {'API-Key':api_key,'Content-Type':'application/json'}
    data = {"url": url_to_scan, "visibility": "public"}
    response = requests.post('https://urlscan.io/api/v1/scan/',headers=headers, data=json.dumps(data))
    if response.status_code != 200:
        print("URL SCAN fail : ", url_to_scan)
        return -1
    return response.json()

def get_uuid(url_to_scan):
    result = get_result(url_to_scan)
    return result["uuid"]

def getfeatures(url_to_scan, save_file, js_text_elm_b, css_text_elm_b, img_text_elm_b, most_occur_b, is_phish=-1): 
    
    print(url_to_scan)

    result = get_result(url_to_scan)
    if result == -1:
        return -1

    keyword = ["cibc", "bmo", "td", "rbc", "hydroquebec", "bell", "rogers", "cra", "canada", "telus"]
    security_sensitive_words = ["login", "registered", "signin", "auth", "vpn"]
    
    # URL analysis
    URL = result["url"]
    url_len = len(URL)
    num_s_char = len(re.sub('[^\^&*$@]+' ,'', URL))
    prefix = URL.split('/')[0]
    num_s_char = len(re.sub('[^\^&*$@]+' ,'', URL))
    contain_keyword = any(substring in URL for substring in keyword)
    contain_sw = any(substring in URL for substring in security_sensitive_words)
    num_dots = URL.count('.')
    ip_in_url = (re.compile(r'(?:[0-9]{1,3}\.){3}[0-9]{1,3}')).search(URL) != None 
    num_sub_domain = len(URL.split(".")) 
    num_hypens = URL.count('-') 
    https_token = True if (prefix == 'https') else False 
    country = result["country"]

    # wait for api page to be set up 
    time.sleep(20)

    response_api = requests.get(result["api"])
    if response_api.status_code != 200:
        print("URL API fail : ", url_to_scan, result["api"])
        return -1

    result_api = response_api.json()
    cert_iss = result_api["data"]["requests"][0]["response"]["response"]["securityDetails"]["issuer"]
    domain_date = result_api["data"]["requests"][0]["response"]["asn"]["date"]
    domain_date = datetime.datetime.strptime(domain_date, '%Y-%m-%d')
    domain_age = (datetime.datetime.today() - domain_date).days
    redirect_page = result_api["data"]["requests"][0]["request"]["redirectHasExtraInfo"]
    port = result_api["data"]["requests"][0]["response"]["response"]["remotePort"]
    asn = result_api["data"]["requests"][0]["response"]["asn"]["asn"]
    domains_hosted = result_api["data"]["requests"][0]["response"]["response"]["securityDetails"]["sanList"]
    num_domains_hosted = len(domains_hosted)
    
    # dom analysis 
    target_uuid = result["uuid"]
    js_text_elm, css_text_elm, img_text_elm, most_occur, iframe = dom_analysis(target_uuid)
    js_comp = cal_comp(js_text_elm_b, js_text_elm)
    css_comp = cal_comp(css_text_elm_b, css_text_elm)
    img_comp = cal_comp(img_text_elm_b, img_text_elm)
    top_word_comp = cal_comp(most_occur_b, most_occur)

    
    # add results to cvs file 
    add = [URL, url_len, num_s_char, prefix, contain_keyword, contain_sw, num_dots, ip_in_url, num_sub_domain, num_hypens, https_token,
           country, cert_iss, domain_age, redirect_page, port, asn, num_domains_hosted, 
           js_comp, css_comp, img_comp, top_word_comp, iframe]

    if (is_phish != -1):
        add.append(is_phish)

    print(add)

    with open(save_file, 'a', newline='') as f_object:
        writer_object = writer(f_object)
        writer_object.writerow(add)
        f_object.close()
    
    return result["result"]


def get_data(url_to_scan_list, save_file):
    for url in url_to_scan_list:
        url_to_scan = url
        is_phish = 1

        # get the benign url values 
        if ("**--benign--**" in url_to_scan): 
            url_to_scan = url_to_scan.replace("**--benign--**", "").strip()
            is_phish = 0
            uuid_b = get_uuid(url_to_scan)
            # wait for dom page to be set up 
            time.sleep(20)
            js_text_elm_b, css_text_elm_b, img_text_elm_b, most_occur_b, iframe_b = dom_analysis(uuid_b)
            if (uuid_b == -1):
                print("ERROR with b UUID")

        try :
            getfeatures(url_to_scan, save_file, js_text_elm_b, css_text_elm_b, img_text_elm_b, most_occur_b, is_phish)
        except Exception as error:
            print(error)
            print("Failed url :", url_to_scan)

if __name__ == "__main__":
    # open file to read with urls to scan 
    url_file = open('url_to_scan.txt', 'r')
    Lines = url_file.readlines()
    
    url_to_scan_list = []
    # Strips the newline character
    for line in Lines:
        url_to_scan_list.append(line.strip())
        #print("Line{}: {}".format(count, line.strip()))

    print("Data collection started")
    get_data(url_to_scan_list, "data.csv")


