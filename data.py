import pandas as pd
import numpy as np
import torch
from transformers import BertModel, BertTokenizer
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.preprocessing import LabelEncoder
from imblearn.over_sampling import SMOTE
from sklearn.ensemble import HistGradientBoostingClassifier
import pickle
import time
from tqdm import tqdm
from sklearn.metrics import accuracy_score, classification_report
import gc

import dask.dataframe as dd
from dask_ml.model_selection import train_test_split as dask_train_test_split
import dask.array as da
from dask import delayed, compute
import re
from urllib.parse import urlparse
import tld
import dns.resolver
from tld.exceptions import TldDomainNotFound

# 데이터 불러오기
data = pd.read_csv('malicious_phish.csv')
print(data)

# 데이터 전처리
data = data.drop_duplicates(subset=['url']).dropna()

label_mapping = {'benign': 0, 'defacement': 1, 'phishing': 2, 'malware': 3}
data['type_code'] = data["type"].map(label_mapping)

data = data.drop(columns=['type'])
print(data['type_code'].value_counts())

data = data[:100000]
print(data['type_code'].value_counts())

# BERT 모델 로드
bert_model = BertModel.from_pretrained('bert-base-uncased', output_hidden_states=True)
print("model load")

# BERT 토크나이저 준비
tokenizer = BertTokenizer.from_pretrained('bert-base-uncased')
print("tokenizer")

# 추가적인 URL 특징 추출 함수 정의
def get_url_info(url):
    url_info = {}
    
    # URL 길이
    url_info['url_len'] = len(url)

    parsed_tld = None
    
    # 도메인 정보 추출
    try:
        parsed_tld = tld.get_tld(url, as_object=True, fail_silently=False, fix_protocol=True)
    except TldDomainNotFound:
        pass

    # 서브도메인 존재 여부
    def having_Sub_Domain(parsed_tld):
        if parsed_tld is not None:
            subdomain = parsed_tld.subdomain
            if subdomain == "":
                return 0
            return 1
        return 0
    
    if parsed_tld:
        # parsed_tld가 존재하는 경우 도메인 길이 및 TLD 설정
        url_info['domain_len'] = len(parsed_tld.domain)
        url_info['tld'] = parsed_tld.tld
    else:
        # parsed_tld가 None인 경우 기본값 설정
        url_info['domain_len'] = 0
        url_info['tld'] = ""

    url_info['sub_domain'] = having_Sub_Domain(parsed_tld)

    # 파라미터 길이
    parsed_url = urlparse(url)
    url_info['parameter_len'] = len(parsed_url.query)
    
    # IP 주소 존재 여부
    ipv4_pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
    ipv6_pattern = re.compile(r'(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|'
                              r'([0-9a-fA-F]{1,4}:){1,7}:|'
                              r'([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|'
                              r'([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|'
                              r'([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|'
                              r'([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|'
                              r'([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|'
                              r'[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|'
                              r':((:[0-9a-fA-F]{1,4}){1,7}|:)|'
                              r'fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|'
                              r'::(ffff(:0{1,4}){0,1}:){0,1}'
                              r'(([0-9]{1,3}\.){3,3}[0-9]{1,3})|'
                              r'([0-9a-fA-F]{1,4}:){1,4}'
                              r':([0-9]{1,3}\.){3,3}[0-9]{1,3})')
    url_info['having_ip_address'] = 1 if ipv4_pattern.search(url) or ipv6_pattern.search(url) else 0
    
    # 프로토콜
    url_info['protocol'] = 1 if urlparse(url).scheme == "http" else 0
    
    # 비정상 url 여부: DNS 조회로 도메인 유효성 검사
    hostname = parsed_url.hostname
    
    url_info['abnormal_url'] = 0
    if hostname:
        try:
            dns.resolver.resolve(hostname, 'A')
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            url_info['abnormal_url'] = 1
        except Exception as e:
            url_info['abnormal_url'] = 1
    
    return url_info

# URL 특징 추출 함수 정의
def extract_features(url):
    start_time = time.time()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    inputs = tokenizer.encode_plus(url, return_tensors='pt', add_special_tokens=True, max_length=128, truncation=True)
    input_ids = inputs['input_ids']
    attention_mask = inputs.get('attention_mask', None)

    with torch.no_grad():
        outputs = bert_model(input_ids, attention_mask=attention_mask)
        hidden_states = outputs[2]

    token_vecs = [torch.mean(hidden_states[layer][0], dim=0) for layer in range(-4, 0)]
    bert_features = torch.stack(token_vecs).numpy().flatten()

    additional_features_dict = get_url_info(url)
    additional_features = np.array(list(additional_features_dict.values()))
    
    combined_features = np.concatenate([bert_features, additional_features])
    
    end_time = time.time()
    return combined_features

# 모든 URL에 대해 특징 추출
features = np.array([extract_features(url) for url in tqdm(data["url"])])
print("features 추출 완료")

features_reshaped = features.reshape((features.shape[0], -1))
type_code_reshaped = data["type_code"].values.reshape((-1, 1))

print("features_reshaped shape:", features_reshaped.shape)
print("type_code_reshaped shape:", type_code_reshaped.shape)

dataset = np.hstack([features_reshaped, type_code_reshaped])

X = dataset[:, :-1]
y = dataset[:, -1]

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

print(X)
print(y_train)

sm = SMOTE(random_state=42)
X_train, y_train = sm.fit_resample(X_train, y_train)

print("model 시작")
model = HistGradientBoostingClassifier()

print("model fit중")
model.fit(X_train, y_train)

score = model.score(X_test, y_test)
print("X_test 정확도 : ", score)

y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
print("모델의 정확도(y_test):", accuracy)

print(classification_report(y_test, y_pred))

pickle.dump(model, open('model.pkl', 'wb'))