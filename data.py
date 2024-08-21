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

# data = data[:100000]
data = data[:10000]
print(data['type_code'].value_counts())

# BERT 모델 로드
bert_model = BertModel.from_pretrained('bert-base-uncased', output_hidden_states=True)
print("model load")

# BERT 토크나이저 준비
tokenizer = BertTokenizer.from_pretrained('bert-base-uncased')
print("tokenizer")

# URL 구성 요소 추출 함수 정의
def parse_url_components(url):
    # URL 파싱
    parsed_url = urlparse(url)
    
    # 구성 요소 추출
    protocol = parsed_url.scheme
    domain = parsed_url.netloc
    path = parsed_url.path
    params = parsed_url.query
    subdomain = ".".join(parsed_url.netloc.split(".")[:-2])
    
    return protocol, domain, subdomain, path, params


# 각 구성 요소의 특징 추출 함수 정의
def extract_component_features(protocol, domain, subdomain, path, params):
    features = {}
    
    # 프로토콜: http/https
    features['protocol_http'] = 1 if protocol == "http" else 0
    
    # 도메인 길이
    features['domain_len'] = len(domain)
    
    # 서브도메인 존재 여부
    features['has_subdomain'] = 1 if subdomain else 0
    
    # 경로 길이
    features['path_len'] = len(path)
    
    # 파라미터 길이
    features['params_len'] = len(params)
    
    # IP 주소 포함 여부
    features['has_ip_address'] = 1 if re.search(r'\d+\.\d+\.\d+\.\d+', domain) else 0
    
    return features

# URL 특징 추출 함수 정의
def extract_features(url):
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    # BERT 인코딩
    inputs = tokenizer.encode_plus(url, return_tensors='pt', add_special_tokens=True, max_length=128, truncation=True)
    input_ids = inputs['input_ids']
    attention_mask = inputs.get('attention_mask', None)

    with torch.no_grad():
        outputs = bert_model(input_ids, attention_mask=attention_mask)
        hidden_states = outputs[2]

    token_vecs = [torch.mean(hidden_states[layer][0], dim=0) for layer in range(-4, 0)]
    bert_features = torch.stack(token_vecs).numpy().flatten()

    # URL 구성 요소별 특징 추출
    protocol, domain, subdomain, path, params = parse_url_components(url)
    url_component_features = extract_component_features(protocol, domain, subdomain, path, params)
    additional_features = np.array(list(url_component_features.values()))
    
    # 특징 결합
    combined_features = np.concatenate([bert_features, additional_features])
    
    return combined_features


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

# 데이터셋 준비
X = features
y = data['type_code'].values

# 학습 데이터와 나머지 데이터(테스트 + 검증)
X_train, X_temp, y_train, y_temp = train_test_split(X, y, test_size=0.4, random_state=42)

# 테스트와 검증 데이터
X_test, X_val, y_test, y_val = train_test_split(X_temp, y_temp, test_size=0.5, random_state=42)

#데이터 불균형 처리 (오버샘플링)
# SMOTE를 사용하여 학습 데이터를 오버샘플링
sm = SMOTE(random_state=42)
X_train, y_train = sm.fit_resample(X_train, y_train)


print("model 시작")
max_bins = 255  # 히스토그램의 구간 수

model = HistGradientBoostingClassifier()
print("model fit중")
model.fit(X_train, y_train)

# 검증 데이터 모델 성능 평가
y_val_pred = model.predict(X_val)
val_accuracy = accuracy_score(y_val, y_val_pred)
print("모델 검증 정확도(y_val):", val_accuracy)
print(classification_report(y_val, y_val_pred))

# 최종 모델 성능 평가
y_test_pred = model.predict(X_test)
test_accuracy = accuracy_score(y_test, y_test_pred)
print("모델 최종 테스트 정확도(y_test):", test_accuracy)
print(classification_report(y_test, y_test_pred))


# 모델 저장
pickle.dump(model, open('model.pkl', 'wb'))