import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import subprocess
import threading
import json
import os
from datetime import datetime
import sys

class VulnerabilityScanner:
    def __init__(self, root):
        self.root = root
        self.root.title("웹 취약점 검사 프로그램")
        self.root.geometry("800x600")
        self.root.resizable(True, True)
        
        # 검사 기록을 저장할 파일
        self.history_file = "scan_history.json"
        self.load_history()
        
        self.setup_ui()
        
    def setup_ui(self):
        # 메인 프레임
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # URL 입력 프레임
        url_frame = ttk.LabelFrame(main_frame, text="URL 검사", padding="10")
        url_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        
        ttk.Label(url_frame, text="검사할 URL:").grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        
        self.url_var = tk.StringVar()
        self.url_entry = ttk.Entry(url_frame, textvariable=self.url_var, width=50)
        self.url_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(0, 10))
        
        self.scan_button = ttk.Button(url_frame, text="검사 시작", command=self.start_scan)
        self.scan_button.grid(row=0, column=2)
        
        # 진행 상태 프레임
        status_frame = ttk.LabelFrame(main_frame, text="검사 상태", padding="10")
        status_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        
        self.status_var = tk.StringVar(value="검사 대기 중...")
        self.status_label = ttk.Label(status_frame, textvariable=self.status_var)
        self.status_label.grid(row=0, column=0, sticky=tk.W)
        
        # 결과 출력 프레임
        result_frame = ttk.LabelFrame(main_frame, text="검사 결과", padding="10")
        result_frame.grid(row=2, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=(0, 5))
        
        self.result_text = scrolledtext.ScrolledText(result_frame, width=50, height=20, wrap=tk.WORD)
        self.result_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # 검사 기록 프레임
        history_frame = ttk.LabelFrame(main_frame, text="검사 기록", padding="10")
        history_frame.grid(row=2, column=1, sticky=(tk.W, tk.E, tk.N, tk.S), padx=(5, 0))
        
        # 기록 리스트박스
        self.history_listbox = tk.Listbox(history_frame, width=30, height=15)
        self.history_listbox.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.history_listbox.bind('<Double-1>', self.show_history_result)
        
        # 스크롤바
        history_scrollbar = ttk.Scrollbar(history_frame, orient="vertical", command=self.history_listbox.yview)
        history_scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        self.history_listbox.configure(yscrollcommand=history_scrollbar.set)
        
        # 기록 삭제 버튼
        clear_history_btn = ttk.Button(history_frame, text="기록 삭제", command=self.clear_history)
        clear_history_btn.grid(row=1, column=0, pady=(5, 0))
        
        # 그리드 가중치 설정
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=2)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(2, weight=1)
        url_frame.columnconfigure(1, weight=1)
        status_frame.columnconfigure(0, weight=1)
        result_frame.columnconfigure(0, weight=1)
        result_frame.rowconfigure(0, weight=1)
        history_frame.columnconfigure(0, weight=1)
        history_frame.rowconfigure(0, weight=1)
        
        self.update_history_list()
    
    def start_scan(self):
        url = self.url_var.get().strip()
        if not url:
            messagebox.showerror("오류", "URL을 입력해주세요.")
            return
        
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
            self.url_var.set(url)
        
        # UI 상태 변경
        self.scan_button.config(state='disabled')
        self.status_var.set("검사 진행 중...")
        self.result_text.delete(1.0, tk.END)
        
        # 별도 스레드에서 검사 실행
        scan_thread = threading.Thread(target=self.run_vulnerability_scan, args=(url,))
        scan_thread.daemon = True
        scan_thread.start()
    
    def run_vulnerability_scan(self, url):
        try:
            # vul.py 실행
            if not os.path.exists('vul.py'):
                self.root.after(0, self.scan_error, "vul.py 파일을 찾을 수 없습니다.")
                return
            
            # vul.py를 subprocess로 실행하고 결과 받기
            process = subprocess.Popen(
                [sys.executable, 'vul.py'],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding='utf-8'
            )
            
            # URL을 stdin으로 전달
            stdout, stderr = process.communicate(input=url + '\n')
            
            if process.returncode == 0:
                # 성공적으로 실행됨
                self.root.after(0, self.scan_complete, url, stdout)
            else:
                # 오류 발생
                error_msg = stderr if stderr else "알 수 없는 오류가 발생했습니다."
                self.root.after(0, self.scan_error, error_msg)
                
        except Exception as e:
            self.root.after(0, self.scan_error, str(e))
    
    def scan_complete(self, url, result):
        # UI 상태 복원
        self.scan_button.config(state='normal')
        self.status_var.set("검사 완료")
        
        # 취약점만 필터링하여 표시
        vulnerabilities = self.extract_vulnerabilities(result)
        
        if vulnerabilities:
            self.result_text.insert(tk.END, f"{url} 취약점 검사 결과\n\n")
            self.result_text.insert(tk.END, vulnerabilities)
        else:
            self.result_text.insert(tk.END, f"{url} 취약점 검사 결과\n\n")
            self.result_text.insert(tk.END, "발견된 취약점이 없습니다.")
        
        # 검사 기록 저장
        self.save_scan_result(url, vulnerabilities if vulnerabilities else "발견된 취약점이 없습니다.")
        self.update_history_list()
    
    def scan_error(self, error_msg):
        # UI 상태 복원
        self.scan_button.config(state='normal')
        self.status_var.set("검사 실패")
        
        self.result_text.insert(tk.END, f"검사 중 오류가 발생했습니다:\n{error_msg}")
        messagebox.showerror("검사 오류", f"검사 중 오류가 발생했습니다:\n{error_msg}")
    
    def extract_vulnerabilities(self, result):
        """결과에서 취약점 관련 내용만 추출"""
        lines = result.split('\n')
        vulnerabilities = []
        
        for line in lines:
          line = line.strip()
					# [취약] 문자열이 포함된 라인만 추출
          if '[취약]' in line:
            vulnerabilities.append(line)
        
        return '\n'.join(vulnerabilities) if vulnerabilities else ""
    
    def load_history(self):
        """검사 기록 로드"""
        try:
            if os.path.exists(self.history_file):
                with open(self.history_file, 'r', encoding='utf-8') as f:
                    self.scan_history = json.load(f)
            else:
                self.scan_history = []
        except:
            self.scan_history = []
    
    def save_scan_result(self, url, result):
        """검사 결과 저장"""
        scan_data = {
            'url': url,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'result': result
        }
        
        # 중복 URL 제거 (최신 결과만 유지)
        self.scan_history = [item for item in self.scan_history if item['url'] != url]
        self.scan_history.insert(0, scan_data)
        
        # 최대 50개 기록만 유지
        self.scan_history = self.scan_history[:50]
        
        try:
            with open(self.history_file, 'w', encoding='utf-8') as f:
                json.dump(self.scan_history, f, ensure_ascii=False, indent=2)
        except:
            pass
    
    def update_history_list(self):
        """기록 리스트 업데이트"""
        self.history_listbox.delete(0, tk.END)
        for item in self.scan_history:
            display_text = f"{item['url']} ({item['timestamp']})"
            self.history_listbox.insert(tk.END, display_text)
    
    def show_history_result(self, event):
        """기록 더블클릭 시 결과 표시"""
        selection = self.history_listbox.curselection()
        if selection:
            index = selection[0]
            if index < len(self.scan_history):
                item = self.scan_history[index]
                self.result_text.delete(1.0, tk.END)
                self.result_text.insert(tk.END, f"{item['url']} 검사 결과\n")
                self.result_text.insert(tk.END, f"검사 시간: {item['timestamp']}\n\n")
                self.result_text.insert(tk.END, item['result'])
    
    def clear_history(self):
        """검사 기록 삭제"""
        if messagebox.askyesno("확인", "모든 검사 기록을 삭제하시겠습니까?"):
            self.scan_history = []
            self.update_history_list()
            self.result_text.delete(1.0, tk.END)
            try:
                if os.path.exists(self.history_file):
                    os.remove(self.history_file)
            except:
                pass

def main():
    root = tk.Tk()
    app = VulnerabilityScanner(root)
    
    # 프로그램 종료 시 정리
    def on_closing():
        root.quit()
        root.destroy()
    
    root.protocol("WM_DELETE_WINDOW", on_closing)
    root.mainloop()

if __name__ == "__main__":
    main()