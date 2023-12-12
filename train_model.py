import pandas as pd
import itertools
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sn

from sklearn.preprocessing import StandardScaler
from sklearn.naive_bayes import CategoricalNB, GaussianNB
from sklearn.linear_model import LogisticRegression

from sklearn.model_selection import (
    cross_validate,
    train_test_split
)

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    confusion_matrix,
    ConfusionMatrixDisplay,
    f1_score,
)

def make_continuous(dataset):
    # make discrete data continuous
    dataset['prefix'] = dataset["prefix"].apply(lambda x : 1 if (x == "http:") else 0)
    dataset['country'] = dataset["country"].apply(lambda x : 1 if (x == "ca") else 0)
    dataset['cert_iss'] = dataset["cert_iss"].apply(lambda x : 1 if ("Entrust" in x) else 0)

    return dataset

def get_x_y_set(dataset):
    dataset = make_continuous(dataset)

    # get x and y sets 
    x_set = dataset.drop('is_phish', axis=1)
    x_set = x_set.drop('URL', axis=1)
    y_set = dataset["is_phish"]

    return x_set, y_set 

# can be used to perform cross validatation 
fold_num = 4
# method that does cross validation with scoring metrics
def cross_val (model, x_set, y_set, fold_num) :
  # select scoring / evaluation metrics
  scoring = ['accuracy', 'precision_weighted', 'precision_micro', 'precision_macro', 'recall_weighted',
             'recall_micro', 'recall_macro', 'f1_weighted', 'f1_micro', 'f1_macro']
  # use cross_validate with the given model, x_set, y_set, fold_num and evaluation metrics
  results = cross_validate(estimator=model,
                               X=x_set,
                               y=y_set,
                               cv=fold_num,
                               scoring=scoring,
                               return_train_score=False)
  return results

def print_results(results):
  print("Mean Validation Accuracy", results['test_accuracy'].mean())
  print("Mean Validation Precision (weighted)", results['test_precision_weighted'].mean())
  print("Mean Validation Recall (weighted)", results['test_recall_weighted'].mean())
  print("Mean Validation F1 Score (weighted)", results['test_f1_weighted'].mean())

if __name__ == "__main__":
    # get test data 
    data = "https://raw.githubusercontent.com/Victoria-Cimpu/UrlPhishingData/main/data.csv"
    dataset = pd.read_csv(data)

    x_set, y_set = get_x_y_set(dataset)

    from sklearn.ensemble import RandomForestClassifier
    model = RandomForestClassifier(max_depth=2, random_state=0)
    #results = cross_val(model_best, x_set, y_set, fold_num)
    #print_results(results)

    model.fit(x_set, y_set)

    # save the phishing classification model as a pickle file
    import pickle
    model_pkl_file = "phish_classifier_model.pkl"  
    with open(model_pkl_file, 'wb') as file:  
        pickle.dump(model, file)