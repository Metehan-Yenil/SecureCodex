import tkinter as tk
from tkinter import filedialog, messagebox
from google.generativeai import GenerativeModel, configure
from dotenv import load_dotenv
import os
from transformers import pipeline
import torch
from fast_scan import get_suspicious_lines_with_bandit
import subprocess
import json
load_dotenv()
configure(api_key=os.getenv("GOOGLE_API_KEY"))
model = GenerativeModel('gemini-pro')

class CodeScannerApp:
    def __init__(self, root):
        BG_COLOR = "#f0f0f0"
        BUTTON_COLOR = "#4a7a8c"
        TEXT_COLOR = "#333333"
        BUTTON_FONT = ('Arial', 10, 'bold')
        TEXT_FONT = ('Arial', 9)

         
        BUTTON_PADX = 10
        BUTTON_PADY = 5
        self.root = root
        self.root.title("SecureCodex - Güvenlik Tarayıcı")
        self.root.configure(bg=BG_COLOR)
        
         
        main_frame = tk.Frame(root, bg=BG_COLOR)
        main_frame.pack(padx=20, pady=20)
        
        
        self.btn_select = tk.Button(
            main_frame, 
            text="📁 Dosya Seç", 
            command=self.select_file, 
            bg=BUTTON_COLOR, 
            fg="white", 
            font=BUTTON_FONT,
            relief="flat",
            width=20
        )
        self.btn_select.grid(row=0, column=0, padx=BUTTON_PADX, pady=BUTTON_PADY)
        
        self.btn_scan = tk.Button(
            main_frame, 
            text="⚡ Hızlı Tara", 
            command=self.analyze_code, 
            bg=BUTTON_COLOR,
            fg="white",
            font=BUTTON_FONT,
            relief="flat",
            width=20
        )
        self.btn_scan.grid(row=0, column=1, padx=BUTTON_PADX, pady=BUTTON_PADY)
        
        self.btn_open = tk.Button(
            main_frame, 
            text="✏️ Sublime'da Aç", 
            command=self.open_in_sublime, 
            bg=BUTTON_COLOR,
            fg="white",
            font=BUTTON_FONT,
            relief="flat",
            width=20
        )
        self.btn_open.grid(row=0, column=2, padx=BUTTON_PADX, pady=BUTTON_PADY)
        
        
        self.btn_ml = tk.Button(
            main_frame, 
            text="🤖 ML ile Tara", 
            command=self.run_ml_analysis,
            bg=BUTTON_COLOR,
            fg="white",
            font=BUTTON_FONT,
            relief="flat",
            width=20
        )
        self.btn_ml.grid(row=1, column=0, padx=BUTTON_PADX, pady=BUTTON_PADY)
        
        self.btn_learn = tk.Button(
            main_frame, 
            text="🧠 Modeli Eğit", 
            command=self.codebert_start_learning,
            bg=BUTTON_COLOR,
            fg="white",
            font=BUTTON_FONT,
            relief="flat",
            width=20
        )
        self.btn_learn.grid(row=1, column=1, padx=BUTTON_PADX, pady=BUTTON_PADY)
        
         
        self.save_to_dataset = tk.BooleanVar()
        self.checkbox = tk.Checkbutton(
            main_frame, 
            text="📂 Yapay Zeka Tespitlerini Kaydet",
            variable=self.save_to_dataset,
            bg=BG_COLOR,
            font=TEXT_FONT,
            selectcolor=BUTTON_COLOR
        )
        self.checkbox.grid(row=1, column=2, padx=BUTTON_PADX, pady=BUTTON_PADY)
        
        # sonuç metin kutusu
        self.txt_results = tk.Text(root, width=90, height=25, bg="white", fg=TEXT_COLOR, font=TEXT_FONT)
        self.txt_results.pack(padx=20, pady=(0, 20))
        
        # tag konfigürasyonu
        self.txt_results.tag_configure('header', foreground='#2c3e50', font=('Arial', 10, 'bold'))
        self.txt_results.tag_configure('harmful', foreground='#e74c3c')
        self.txt_results.tag_configure('safe', foreground='#27ae60')
        self.txt_results.tag_configure('uncertain', foreground='#f39c12')

    def open_in_sublime(self):
        if not hasattr(self, 'file_path'):
            messagebox.showerror("Hata", "Önce bir dosya seçin!")
            return
        
        sublime_path = "C:\\Program Files\\Sublime Text\\sublime_text.exe"   
        try:
            os.startfile(self.file_path)   
            
        except Exception as e:
            messagebox.showerror("Hata", f"Sublime Text'te açılamadı: {str(e)}")

    def codebert_start_learning(self):
        try:
            # eğitim başlatan komut
            subprocess.run([
                "python", 
                r"C:\\Users\\aksar\\Documents\\Projects\\SecureCodex\deep_test\\codebert_model_egit.py"
            ], check=True)
            
            # modelin metrikleri
            with open("training_metrics.json", "r") as f:
                metrics = json.load(f)
            
            self.txt_results.insert(tk.END, "\n\n✅ Model Eğitimi Tamamlandı!\n", 'header')
            self.txt_results.insert(tk.END, f"• Doğruluk: {metrics['accuracy']:.2f}\n", 'safe')
            self.txt_results.insert(tk.END, f"• Kesinlik: {metrics['precision']:.2f}\n", 'safe')
            self.txt_results.insert(tk.END, f"• Duyarlılık: {metrics['recall']:.2f}\n", 'safe')
            self.txt_results.insert(tk.END, f"• F1 Skoru: {metrics['f1']:.2f}\n", 'safe')
            
        except subprocess.CalledProcessError as e:
            messagebox.showerror("Hata", f"Eğitim sırasında hata oluştu: {str(e)}")
        except FileNotFoundError:
            messagebox.showerror("Hata", "Eğitim metrik dosyası bulunamadı!")
        except Exception as e:
            messagebox.showerror("Hata", f"Beklenmeyen hata: {str(e)}")            

    def run_ml_analysis(self):
        if not hasattr(self, 'file_path'):
            messagebox.showerror("Hata", "Önce bir dosya seçin!")
            return
        
        try:
            # codebert yükleme
            classifier = pipeline(
                "text-classification",
                model="./codebert_malware_detector",
                tokenizer="./codebert_malware_detector",
                device=0 if torch.cuda.is_available() else -1
            )
            
            # okuma ve satırlara ayırma
            with open(self.file_path, "r", encoding='utf-8') as f:
                lines = f.readlines()
            
            self.txt_results.insert(tk.END, "\nML Analiz Sonuçları:\n", 'header')
            
            # Her satırı analiz et
            for line_num, line in enumerate(lines, start=1):
                line = line.strip()
                if not line:
                    continue
                
                result = classifier(line)[0]
                score = result['score']
                predicted_label = result['label']
                
                
                if score > 0.7:
                    if predicted_label == 'LABEL_1':
                        label = "GÜVENLİ"
                        tag = 'safe'
                    else:
                        label = "ZARARLI"
                        tag = 'harmful'
                else:
                    label = "BELİRSİZ"
                    tag = 'uncertain'
                
                 
                self.txt_results.insert(
                    tk.END, 
                    f"Satır {line_num}: {line} → {label} ({score:.2f})\n", 
                    tag
                )
                            
        except Exception as e:
                    messagebox.showerror("Hata", f"ML analizi başarısız: {str(e)}")             
        
    def select_file(self):
        self.file_path = filedialog.askopenfilename(filetypes=[("Python Dosyaları", "*.py")])
        if self.file_path:
            self.txt_results.delete(1.0, tk.END)
            self.txt_results.insert(tk.END, f"Seçilen dosya: {self.file_path}\n")
            
             
            sublime_path = r"C:\Program Files\Sublime Text\sublime_text.exe"
            try:
                subprocess.run([sublime_path, self.file_path], check=True)
            except subprocess.CalledProcessError as e:
                messagebox.showerror("Hata", f"Sublime Text'te açılamadı: {str(e)}")
    
    def analyze_code(self):
        if not hasattr(self, 'file_path'):
            messagebox.showerror("Hata", "Lütfen önce bir dosya seçin!")
            return
        
        try:
            with open(self.file_path, "r", encoding='utf-8') as f:
                code_content = f.read()
                f.seek(0)  # D. okuma imlecini başa al
                code_lines = f.readlines()  # Tüm satırları listeye al
            
            # güvenlik ayarları tehlikeli yazılımlar için gerekli
            from google.generativeai.types import HarmCategory, HarmBlockThreshold
            
            safety_settings = {
                HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT: HarmBlockThreshold.BLOCK_NONE,
                HarmCategory.HARM_CATEGORY_HATE_SPEECH: HarmBlockThreshold.BLOCK_NONE,
                HarmCategory.HARM_CATEGORY_HARASSMENT: HarmBlockThreshold.BLOCK_NONE,
                HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT: HarmBlockThreshold.BLOCK_NONE
            }
            
            # geminiye prompt
            prompt = f"""
            Aşağıdaki Python kodunu satır satır inceleyerek zararlı olabilecek kısımları tespit edin.
            Her bir zararlı satır için JSON formatında cevap verin:
            {{
                "Satir_numarasi": [satır_numarası],
                "Aciklamasi": "Açıklama",
                "Duzeltilmis_hali": "Düzeltilmiş kod (opsiyonel)"
            }}
            
            Örnek çıktı:
            {{
                "Satir_numarasi": 5,
                "Aciklamasi": "os.system kullanımı güvensizdir.",
                "Duzeltilmis_hali": "subprocess.run(['ls', '-l'])"
            }}
            
            Analiz edilecek kod:
            {code_content}
            """
            
            response = model.generate_content(
                prompt,
                safety_settings=safety_settings   
            )
            
             
            self.txt_results.tag_configure('header', foreground='blue', font=('Arial', 10, 'bold'))
            self.txt_results.tag_configure('warning', foreground='red')
            self.txt_results.tag_configure('fixed', foreground='green')
            
            self.txt_results.insert(tk.END, "\nAnaliz Sonuçları:\n", 'header')
            import re
            entries = re.findall(r'\{\s*"Satir_numarasi": (\d+),\s*"Aciklamasi": "([^"]+)",\s*"Duzeltilmis_hali": "([^"]*)"\s*\}', response.text)
            
            if not entries:
                self.txt_results.insert(tk.END, "\n✅ Kodunuzda zararlı bir içerik bulunamadı!", 'header')
                return
            
            self.txt_results.insert(tk.END, "\nAnaliz Sonuçları:\n", 'header')
            for line_num_str, explanation, fixed_code in entries:
                line_num = int(line_num_str)
                if line_num <= 0 or line_num > len(code_lines):
                    continue  # Geçersiz satır numarasını atla
                
                original_line = code_lines[line_num - 1].strip()
                self.txt_results.insert(tk.END, f"\nSatır {line_num}:\n", 'header')
                self.txt_results.insert(tk.END, f"Kod: {original_line}\n", 'warning')
                self.txt_results.insert(tk.END, f"Açıklama: {explanation}\n", 'warning')
                if fixed_code:
                    self.txt_results.insert(tk.END, f"Düzeltilmiş Kod: {fixed_code}\n", 'fixed')

            # Eğer checkbox işaretliyse veri setini güncelle
            if self.save_to_dataset.get():
                self.update_dataset()            
            
        except Exception as e:
            messagebox.showerror("Hata", f"Analiz başarısız: {str(e)}")
    def update_dataset(self):
        """Analiz sonuçlarını veri setine ekler."""
        try:
             
            subprocess.run([
                "python", 
                r"C:\\Users\\aksar\Documents\\Projects\SecureCodex\\deep_test\\self_learning.py", 
                self.file_path,
                "enhanced_dataset.csv"
            ])
        except Exception as e:
            messagebox.showerror("Hata", f"Veri seti güncellenemedi: {str(e)}")        

if __name__ == "__main__":
    root = tk.Tk()
    app = CodeScannerApp(root)
    root.mainloop()