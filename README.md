
# SecureCodex

SecureCodex, Python kodlarını güvenlik açısından analiz eden ve zararlı kodları tespit etmeye yardımcı olan bir makine öğrenimi tabanlı masaüstü uygulamasıdır. Proje, CodeBERT modeliyle eğitilmiş bir sınıflandırıcı kullanır ve kullanıcı dostu bir arayüz sunar.

## Özellikler

- Python dosyalarını satır satır analiz ederek güvenli, zararlı veya belirsiz olarak etiketler.
- Zararlı kod örnekleriyle eğitilmiş CodeBERT tabanlı model.
- Sonuçları kullanıcıya görsel olarak sunar.
- Kendi veri setinizi oluşturup modeli yeniden eğitebilirsiniz.

## Kurulum

1. Gerekli Python paketlerini yükleyin:
    ```sh
    pip install -r requirements.txt
    ```

2. Model dosyalarını ve tokenizer'ı `codebert_malware_detector/` klasörüne yerleştirin.

3. Uygulamayı başlatın:
    ```sh
    python app.py
    ```

## Kullanım

- Uygulama arayüzünden analiz etmek istediğiniz Python dosyasını seçin.
- "Analiz Et" butonuna tıklayarak dosyanın satır satır güvenlik analizini başlatın.
- Sonuçlar ekranda gösterilecektir.

## Model Eğitimi

Kendi veri setinizle modeli eğitmek için:
- [SecureCodex proje2/codebert_model_egit.py](SecureCodex%20proje2/codebert_model_egit.py) dosyasını kullanabilirsiniz.
- Veri setinizi `deep_test/malware_dataset.csv` veya uygun formatta hazırlayın.

## Veri Setleri

- `malware_dataset.csv`, `code_security_dataset.csv`, `veri.csv` gibi dosyalar örnek kod ve etiketler içerir.
- Kendi veri setinizi oluşturmak için [deep_test/convert_df.py](deep_test/convert_df.py) veya [SecureCodex proje2/convert_df.py](SecureCodex%20proje2/convert_df.py) dosyalarını kullanabilirsiniz.


**Not:** Proje, eğitim ve araştırma amaçlıdır. Gerçek dünyada kullanılmadan önce kapsamlı testler yapılmalıdır.
