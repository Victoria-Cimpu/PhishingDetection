import time
import pandas as pd
import requests
from csv import writer

import data_collection_get_url as get_url
import data_collection as data_col
import train_model

def get_url_hosted(uuid):
    api_url = 'https://urlscan.io/api/v1/result/' + uuid + '/'
    response_api = requests.get(api_url)
    if response_api.status_code != 200:
        print("URL API fail : ", uuid, result["api"])
        return -1
    result_api = response_api.json()
    domains_hosted = result_api["data"]["requests"][0]["response"]["response"]["securityDetails"]["sanList"]
    return domains_hosted


# get the phishing classification model
import pickle
model_pkl_file = "phish_classifier_model.pkl"  
with open(model_pkl_file, 'rb') as file:  
    model_best = pickle.load(file)

save_file = 'data_test.csv'

# get URLs 
search_url = str(input("Enter the URL : "))
result = get_url.search(search_url)

# send all print messages to log file 
import sys
old_stdout = sys.stdout
log_file = open("phishing_checker_message.log","w")
sys.stdout = log_file

api_url_list = []

# get info about the search url 
uuid_b = data_col.get_uuid(search_url)
if (uuid_b == -1):
  print("ERROR with b UUID")
  exit(0)
time.sleep(20)
url_b = get_url_hosted(uuid_b)
js_text_elm_b, css_text_elm_b, img_text_elm_b, most_occur_b, iframe_b = data_col.dom_analysis(uuid_b)

# get list of urls 
url_list = []
for cert in result:
  # remove FP
  try :
    if cert["common_name"] not in url_b:
        url_list.append(cert["common_name"])
  except Exception as error:
        print(error)

url_list = list(dict.fromkeys(url_list))

# add col names to save file for data 
add = ["URL","url_len","num_s_char","prefix","contain_keyword","contain_sw","num_dots","ip_in_url","num_sub_domain","num_hypens",
       "https_token","country","cert_iss","domain_age","redirect_page","port","asn","num_domains_hosted","js_comp","css_comp","img_comp","top_word_comp","iframe"]
with open(save_file, 'w', newline='') as f_object:
        writer_object = writer(f_object)
        writer_object.writerow(add)
        f_object.close()

count = 0
for url in url_list:
    url_to_scan = url
    
    count += 1
    if count == 40:
        break

    try :
        # will write to local cvs file (save file)
        temp_api_url = data_col.getfeatures(url_to_scan, save_file, js_text_elm_b, css_text_elm_b, img_text_elm_b, most_occur_b)
        if (temp_api_url != -1):
            api_url_list.append(temp_api_url)
    except Exception as error:
        print("ERROR:", error)

dataset = pd.read_csv('data_test.csv')

# Make data continious like training set 
dataset = train_model.make_continuous(dataset)
x_set = dataset.drop('URL', axis=1)

class_probabilities = model_best.predict_proba(x_set)

answer = []
for x in range(len(dataset["URL"])):
    answer.append([dataset["URL"][x], class_probabilities[x][1], api_url_list[x]])
answer.sort(key=lambda x: x[1], reverse=True)

sys.stdout = old_stdout
log_file.close()

# print result
print("URL checked:", search_url)
print("{: <40} {: <40} {: <40}".format("URL", "Confidence", "urlscan link"))
for ans in answer:
    print("{: <40} {: <40} {: <40}".format(*ans))