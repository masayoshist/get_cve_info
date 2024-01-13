from flask import Flask, render_template, redirect, request
import urllib.request
import json
import re
import time

## 設定
CVE_INFO_BASE_URL="https://access.redhat.com/security/cve/"
CVE_API_BASE_URL="https://access.redhat.com/hydra/rest/securitydata/cve/"
CVSS_AV = {
    'N' : 'Network',
    'A' : 'Adjacent',
    'L' : 'Local',
    'P' : 'Physical'
}

app = Flask(__name__)

@app.route('/', methods = ["GET" , "POST"])
def index():

    cve_list = [] # sample CVE-2023-0465
    # POSTの処理
    user_cve_list = ""
    user_cve_list_org = ""
    if request.method == 'POST':
        user_cve_list_org = request.form['user_cve_list']
        user_cve_list     = request.form['user_cve_list'].upper()
        cve_list = user_cve_list.split("\r\n")

        # 空の要素を削除
        while '' in cve_list:
            cve_list.remove('')

        # CVE番号の型式チェック
        app.logger.error(cve_list)
        for cve_no in cve_list:
            cve_pattern = re.compile(r'^CVE-\d{4}-\d+$')
            if not cve_pattern.match(cve_no):
                return render_template('index.html', user_cve_list=user_cve_list_org, msg="CVE形式が正しくありません。")

    # CVEリストの情報を取得
    cve_data = []
    for cve_no in cve_list:
        cve_data.append(get_cve_info(cve_no))

    # CVEリストの情報を表示用に整形する
    cve_view_data = convert_cve_data(cve_data)

    return render_template('index.html', user_cve_list=user_cve_list_org, cve_view_data = cve_view_data)

## 個別CVE情報の取得
def get_cve_info(cve_no):

    # UAの偽装
    headers = {"User-Agent" : "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"}

    # リクエスト発行
    url = CVE_API_BASE_URL + cve_no + ".json"
    request = urllib.request.Request(url=url, headers=headers)
    with urllib.request.urlopen(request) as response:
        data = json.loads(response.read().decode("utf-8"))
    time.sleep(0.1) # 0.1秒ウェイト
    return data

## 表示向けにCVE情報の整形
def convert_cve_data(cve_data):
    cve_view_data = []
    for cve_info in cve_data: # CVE情報を1件ずつ処理する。
        cvss_info = perse_cvss3_vector(cve_info["cvss3"]["cvss3_scoring_vector"]) # CVSSベクターをパースする

        for package_state_info in cve_info["package_state"]: # package_stateごとに表示行とする。
            view_row = {
                "name" : cve_info["name"] ,
                "url" : CVE_INFO_BASE_URL + cve_info["name"].lower() ,
                "description" : cve_info["bugzilla"]["description"] ,
                "attack_vector" : CVSS_AV[cvss_info['AV']],
                "product_name" : package_state_info["product_name"] ,
                "package_name" : package_state_info["package_name"] ,
                "fix_state" : package_state_info["fix_state"]
            }
            cve_view_data.append(view_row)
    return cve_view_data

## cvss3_scoring_vectorのパース
## 形式例： CVSS : 3.1/AV : N/AC : L/PR : N/UI : N/S : U/C : N/I : L/A : N
def perse_cvss3_vector(vector_str):
    vector_list = vector_str.split('/')
    vector_dict = {}
    for vector in vector_list:
        trimmed_vector = vector.strip()
        key, value = trimmed_vector.split(':')
        vector_dict[key] = value
    return vector_dict

if __name__ == '__main__':
    app.debug = True
    app.run(host='127.0.0.1', port=8123)