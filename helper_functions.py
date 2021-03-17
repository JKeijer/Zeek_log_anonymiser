
import pandas as pd
import numpy as np
from collections import Counter
from os import walk
from os import path
import random

from copy import deepcopy

from sklearn.preprocessing import LabelEncoder



# Helper functions

def get_headers_types(log_type,directories):
    headers = []
    types = []
    for log_dir in directories:
        if path.exists(dir_to_parse+str(log_dir)+"/"+log_type):
            with open(dir_to_parse+str(log_dir)+"/"+log_type) as file:
                for i in range(8):
                    line = next(file).strip()
                    if line.startswith("#fields"):
                        headers = line.split("\t")[1:]
                    if line.startswith("#types"):
                        types = line.split("\t")[1:]
            break
    return headers, types

def get_types(df_type,type_list):
    for header in df_type.columns:
        if type_list.get(header) == 'num':
            df_type[header] = pd.to_numeric(df_type[header],errors='coerce')
        else:
            df_type[header] = df_type[header].astype(str)
    return df_type 


dir_to_parse = "logs/"

seperator = "[\t]"

string_list = ['string','addr','string','enum','set[string]','vector[string]','bool']
num_list = ['time','port','interval','count']

# List with columns containing PII.
PII = ['id.orig_h','id.resp_h',
       'mac','assigned_ip',
       'query','answers',
       'tx_hosts','rx_hosts','md5','sha1','sha256',
       'user','password','arg','data_channel.orig_h','data_channel.resp_h',
       'host','uri','filename','username',
       'remote_ip',
       'helo','mailfrom','rcptto','date','from','to','reply_to','msg_id','in_reply_to',
           'server_name','subject','issuer','client_subject','client_issuer',
       'message',
       'certificate.serial','certificate.subject','certificate.issuer','certificate.not_valid_before',
           'certificate.not_valid_after','san.dns','san.uri','san.email','san.ip']

IP_fields = ['id.orig_h','id.resp_h','assigned_ip','answers','data_channel.orig_h','data_channel.resp_h','remote_ip']

sub0_dict = {}
sub1_dict = {}
sub2_dict = {}
sub3_dict = {}
ip_dict = {}




def read_file(file_path,seperator,headers):
    if path.exists(file_path):
        return pd.read_csv(file_path,sep=seperator,names=headers,skiprows=8,
                           skipfooter=1,engine='python')

def get_dataframe(log_type,seperator,filepath):
    headers, types = get_headers_types(log_type,filepath)
    type_list = {}
    for col_header, col_type in zip(headers,types):
        type_list[col_header] = 'num' if col_type in num_list else 'string'
    df_combined = pd.concat(map(lambda x: read_file(dir_to_parse+ str(x)+'/'+log_type,
                                                    seperator,headers), filepath))
    return get_types(df_combined,type_list)

def get_files_and_dirs(dir_to_parse):
    
    def get_filenames(x): 
        _, _, filenames = next(walk(dir_to_parse+str(x)+'/'))
        return filenames
    
    _, directories, _ = next(walk(dir_to_parse))
    filenames = [get_filenames(x) for x in directories]
    flat_filenames = np.unique([item for sublist in filenames for item in sublist])
    return directories, flat_filenames

def highlight_col(df_to_style):
    r = 'background-color: red'
    df1 = pd.DataFrame('', index=df_to_style.index, columns=df_to_style.columns)
    for info in PII:
        if info in df_to_style.columns:
            df1.loc[:,info] = r
    return df1    

def get_subnet_perserving_ip(ip):

    def get_random_subnet(sub,sub_dict):
        random_sub = ""
        if sub in sub_dict:
            random_sub = sub_dict[sub]
        else:
            is_old = True
            while is_old:
                random_sub = str(int(random.random()*256))
                if random_sub not in sub_dict.values():
                    is_old = False
            sub_dict[sub] = random_sub
        return random_sub
    
    if ip in ip_dict:
        random_ip = ip_dict[ip]
    else:
        sub_splits = ip.split('.')
        if len(sub_splits) > 3:
            sub0 = get_random_subnet(sub_splits[0], sub0_dict)
            sub1 = get_random_subnet(sub_splits[1], sub1_dict)
            sub2 = get_random_subnet(sub_splits[2], sub2_dict)
            sub3 = get_random_subnet(sub_splits[3], sub3_dict)
            random_ip = sub0+"."+sub1+"."+sub2+"."+sub3
            ip_dict[ip] = random_ip
        else:
            random_ip = "-"
            ip_dict[ip] = random_ip
    return random_ip

def build_dataframes(chosen_files):
    directories, filenames = get_files_and_dirs(dir_to_parse)
    orig_log_dataframes = {}
    

    for filename in filenames:
        if filename in chosen_files:
            df_log = get_dataframe(filename,seperator,directories)
            orig_log_dataframes[filename] = df_log
    return orig_log_dataframes


def anonymise_dataframes(orig_log_dataframes, chosen_files):
    log_dataframes = deepcopy(orig_log_dataframes)

    for key in log_dataframes:
        if key in chosen_files:
            log_dataframe = log_dataframes[key]
            for column in log_dataframe.columns:
                if column in PII:
                    if column in IP_fields:
                        log_dataframe[column] = [get_subnet_perserving_ip(ip) for ip in log_dataframe[column]]
                    else:
                        log_dataframe[column] = LabelEncoder().fit_transform(log_dataframe[column])
            log_dataframes[key] = log_dataframe
            
    return log_dataframes
