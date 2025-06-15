from PIL import Image, ImageTk
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import os
import base64
import tkinter as tk
from tkinter import filedialog, messagebox, ttk, simpledialog
import io
import hashlib

class SteganographyApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Aplikasi Steganografi dengan Enkripsi")
        self.root.geometry("800x600")
        self.root.configure(padx=20, pady=20)
        
        self.encryption_mode = "password" 
        
        self.input_image_path = ""
        self.output_image_path = ""
        
        # Frame utama
        self.frame = ttk.Frame(root)
        self.frame.pack(fill="both", expand=True)
        
        # Notebook untuk tab
        self.notebook = ttk.Notebook(self.frame)
        self.notebook.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Tab untuk encode
        self.encode_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.encode_tab, text="Enkripsi & Sembunyikan")
        
        # Tab untuk decode
        self.decode_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.decode_tab, text="Ekstrak & Dekripsi")
        
        self.setup_encode_tab()
        self.setup_decode_tab()
    
    def derive_key_from_password(self, password, salt):
        """Derive kunci 32-byte dari password menggunakan PBKDF2"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 32 bytes untuk ChaCha20Poly1305
            salt=salt,
            iterations=100000,  # Iterasi tinggi untuk keamanan
        )
        return kdf.derive(password.encode('utf-8'))
    
    def get_password_and_derive_key(self, mode="encrypt"):
        """Meminta password dari user dan derive kunci"""
        if mode == "encrypt":
            title = "Enkripsi - Masukkan Password"
            prompt = "Masukkan password untuk enkripsi:"
        else:
            title = "Dekripsi - Masukkan Password" 
            prompt = "Masukkan password untuk dekripsi:"
            
        password = simpledialog.askstring(title, prompt, show='*')
        if not password:
            return None, None
            
        # Salt yang sama akan menghasilkan kunci yang sama untuk password yang sama
        salt = hashlib.sha256(password.encode('utf-8')).digest()[:16]  # 16 bytes salt
        
        key = self.derive_key_from_password(password, salt)
        return key, salt

    def load_or_generate_key(self):
        """Memuat kunci dari file atau menghasilkan kunci baru jika file tidak ada"""
        key_file = "encryption_key.bin"
        
        if os.path.exists(key_file):
            # Muat kunci dari file
            try:
                with open(key_file, "rb") as f:
                    key = f.read()
                if len(key) == 32:  # Pastikan kunci valid (32 byte)
                    return key
                else:
                    print("Kunci tidak valid, menghasilkan kunci baru...")
            except Exception as e:
                print(f"Error membaca kunci: {e}")
        
        # Hasilkan kunci baru
        key = ChaCha20Poly1305.generate_key()
        
        # Simpan kunci ke file
        try:
            with open(key_file, "wb") as f:
                f.write(key)
            print("Kunci baru telah dibuat dan disimpan.")
        except Exception as e:
            print(f"Error menyimpan kunci: {e}")
        
        return key

    def setup_encode_tab(self):
        # Frame untuk preview gambar
        self.encode_preview_frame = ttk.LabelFrame(self.encode_tab, text="Preview Gambar")
        self.encode_preview_frame.grid(row=0, column=0, rowspan=6, padx=10, pady=10, sticky="nsew")
        
        self.encode_image_preview = ttk.Label(self.encode_preview_frame)
        self.encode_image_preview.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Frame untuk input
        self.encode_input_frame = ttk.Frame(self.encode_tab)
        self.encode_input_frame.grid(row=0, column=1, padx=10, pady=10, sticky="nsew")
        
        # Mode enkripsi
        ttk.Label(self.encode_input_frame, text="Mode Enkripsi:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.encryption_mode_var = tk.StringVar(value="password")
        mode_frame = ttk.Frame(self.encode_input_frame)
        mode_frame.grid(row=1, column=0, padx=5, pady=5, sticky="w")
        
        ttk.Radiobutton(mode_frame, text="Password-based (Portable)", 
                       variable=self.encryption_mode_var, value="password",
                       command=self.on_mode_change).pack(side="left")
        ttk.Radiobutton(mode_frame, text="Persistent Key (Legacy)", 
                       variable=self.encryption_mode_var, value="persistent_key",
                       command=self.on_mode_change).pack(side="left")
        
        # Tombol pilih gambar
        ttk.Button(self.encode_input_frame, text="Pilih Gambar", command=self.select_input_image).grid(row=2, column=0, padx=5, pady=5, sticky="w")
        
        # Field untuk pesan
        ttk.Label(self.encode_input_frame, text="Pesan:").grid(row=3, column=0, padx=5, pady=5, sticky="w")
        self.message_text = tk.Text(self.encode_input_frame, width=40, height=10)
        self.message_text.grid(row=4, column=0, padx=5, pady=5, sticky="w")
        
        # Tombol untuk menyimpan
        ttk.Button(self.encode_input_frame, text="Sembunyikan & Simpan", command=self.encode_message).grid(row=5, column=0, padx=5, pady=5, sticky="w")
        
        # Status bar
        self.encode_status_var = tk.StringVar()
        ttk.Label(self.encode_input_frame, textvariable=self.encode_status_var).grid(row=6, column=0, padx=5, pady=5, sticky="w")
        
        # Tombol untuk mengatur ulang kunci (hanya untuk mode persistent key)
        self.reset_key_btn = ttk.Button(self.encode_input_frame, text="Reset Kunci", command=self.reset_key)
        self.reset_key_btn.grid(row=7, column=0, padx=5, pady=5, sticky="w")
        
        # Tombol untuk mengekspor kunci
        self.export_key_btn = ttk.Button(self.encode_input_frame, text="Ekspor Kunci", command=self.export_key)
        self.export_key_btn.grid(row=8, column=0, padx=5, pady=5, sticky="w")
        
        # Tombol untuk mengimpor kunci
        self.import_key_btn = ttk.Button(self.encode_input_frame, text="Impor Kunci", command=self.import_key)
        self.import_key_btn.grid(row=9, column=0, padx=5, pady=5, sticky="w")
        
        # Update visibility berdasarkan mode
        self.update_key_buttons_visibility()

        # Configure grid weights
        self.encode_tab.columnconfigure(0, weight=2)
        self.encode_tab.columnconfigure(1, weight=1)
        self.encode_tab.rowconfigure(0, weight=1)
    
    def setup_decode_tab(self):
        # Frame untuk preview gambar
        self.decode_preview_frame = ttk.LabelFrame(self.decode_tab, text="Preview Gambar")
        self.decode_preview_frame.grid(row=0, column=0, rowspan=6, padx=10, pady=10, sticky="nsew")
        
        self.decode_image_preview = ttk.Label(self.decode_preview_frame)
        self.decode_image_preview.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Frame untuk input
        self.decode_input_frame = ttk.Frame(self.decode_tab)
        self.decode_input_frame.grid(row=0, column=1, padx=10, pady=10, sticky="nsew")
        
        # Tombol pilih gambar
        ttk.Button(self.decode_input_frame, text="Pilih Gambar", command=self.select_decode_image).grid(row=0, column=0, padx=5, pady=5, sticky="w")
        
        # Tombol untuk ekstrak pesan
        ttk.Button(self.decode_input_frame, text="Ekstrak Pesan", command=self.decode_message).grid(row=1, column=0, padx=5, pady=5, sticky="w")
        
        # Field untuk hasil
        ttk.Label(self.decode_input_frame, text="Pesan Terenkripsi:").grid(row=2, column=0, padx=5, pady=5, sticky="w")
        self.decoded_message = tk.Text(self.decode_input_frame, width=40, height=10)
        self.decoded_message.grid(row=3, column=0, padx=5, pady=5, sticky="w")
        
        # Status bar
        self.decode_status_var = tk.StringVar()
        ttk.Label(self.decode_input_frame, textvariable=self.decode_status_var).grid(row=4, column=0, padx=5, pady=5, sticky="w")
        
        # Configure grid weights
        self.decode_tab.columnconfigure(0, weight=2)
        self.decode_tab.columnconfigure(1, weight=1)
        self.decode_tab.rowconfigure(0, weight=1)
    
    def on_mode_change(self):
        """Callback saat mode enkripsi berubah"""
        self.encryption_mode = self.encryption_mode_var.get()
        self.update_key_buttons_visibility()
        
        if self.encryption_mode == "persistent_key":
            # Load kunci persisten
            self.KEY = self.load_or_generate_key()
    
    def update_key_buttons_visibility(self):
        """Update visibility tombol berdasarkan mode enkripsi"""
        if self.encryption_mode == "password":
            # Sembunyikan tombol manajemen kunci untuk mode password
            self.reset_key_btn.grid_remove()
            self.export_key_btn.grid_remove()
            self.import_key_btn.grid_remove()
        else:
            # Tampilkan tombol manajemen kunci untuk mode persistent key
            self.reset_key_btn.grid()
            self.export_key_btn.grid()
            self.import_key_btn.grid()

    def select_input_image(self):
        self.input_image_path = filedialog.askopenfilename(
            filetypes=[
                ("PNG files", "*.png"),
                ("JPEG files", "*.jpg *.jpeg"),
                ("BMP files", "*.bmp"),
                ("All files", "*.*")
            ]
        )
        if self.input_image_path:
            self.display_image(self.input_image_path, self.encode_image_preview)
            self.encode_status_var.set(f"Gambar dipilih: {os.path.basename(self.input_image_path)}")
    
    def select_decode_image(self):
        self.decode_image_path = filedialog.askopenfilename(
            filetypes=[
                ("PNG files", "*.png"),
                ("JPEG files", "*.jpg *.jpeg"),
                ("BMP files", "*.bmp"),
                ("All files", "*.*")
            ]
        )
        if self.decode_image_path:
            self.display_image(self.decode_image_path, self.decode_image_preview)
            self.decode_status_var.set(f"Gambar dipilih: {os.path.basename(self.decode_image_path)}")
    
    def display_image(self, image_path, label):
        img = Image.open(image_path)
        
        # Resize dengan aspect ratio yang sama
        width, height = img.size
        max_width, max_height = 400, 400
        
        if width > max_width or height > max_height:
            scale = min(max_width / width, max_height / height)
            width = int(width * scale)
            height = int(height * scale)
            img = img.resize((width, height), Image.LANCZOS)
        
        photo = ImageTk.PhotoImage(img)
        label.config(image=photo)
        label.image = photo  
    
    def encrypt_message(self, message, password=None):
        """Enkripsi pesan dengan password atau kunci persisten"""
        if self.encryption_mode == "password":
            if password:
                # Derive key dari password
                salt = hashlib.sha256(password.encode('utf-8')).digest()[:16]
                key = self.derive_key_from_password(password, salt)
            else:
                key, salt = self.get_password_and_derive_key("encrypt")
                if not key:
                    return None
        else:
            key = self.KEY
            
        chacha = ChaCha20Poly1305(key)
        nonce = os.urandom(12)  # nonce harus 12 byte
        ciphertext = chacha.encrypt(nonce, message.encode(), None)
        
        # Gabungkan nonce + ciphertext + mode identifier
        if self.encryption_mode == "password":
            # Tambahkan identifier untuk mode password
            result = b"PWD:" + nonce + ciphertext
        else:
            result = b"KEY:" + nonce + ciphertext
            
        return base64.b64encode(result).decode()
    
    def decrypt_message(self, encoded, password=None):
        """Dekripsi pesan dengan password atau kunci persisten"""
        try:
            raw = base64.b64decode(encoded.encode())
            
            # Cek mode enkripsi dari identifier
            if raw.startswith(b"PWD:"):
                # Mode password
                raw = raw[4:]  # Hapus identifier
                if password:
                    salt = hashlib.sha256(password.encode('utf-8')).digest()[:16]
                    key = self.derive_key_from_password(password, salt)
                else:
                    key, salt = self.get_password_and_derive_key("decrypt")
                    if not key:
                        return "Dekripsi dibatalkan"
            elif raw.startswith(b"KEY:"):
                # Mode kunci persisten
                raw = raw[4:]  # Hapus identifier
                key = self.KEY
            else:
                # Backward compatibility - assume old format menggunakan kunci persisten
                key = self.KEY
            
            nonce = raw[:12]
            ciphertext = raw[12:]
            
            chacha = ChaCha20Poly1305(key)
            return chacha.decrypt(nonce, ciphertext, None).decode()
            
        except Exception as e:
            return f"Gagal dekripsi: {str(e)}"
    
    def encode_message(self):
        if not self.input_image_path:
            messagebox.showerror("Error", "Pilih gambar terlebih dahulu!")
            return
        
        message = self.message_text.get("1.0", tk.END).strip()
        if not message:
            messagebox.showerror("Error", "Masukkan pesan terlebih dahulu!")
            return
        
        output_path = filedialog.asksaveasfilename(
            defaultextension=".png",
            filetypes=[("PNG files", "*.png")],
            initialfile="stego_image.png"
        )
        
        if not output_path:
            return
        
        try:
            encrypted = self.encrypt_message(message)
            if encrypted is None:
                self.encode_status_var.set("Enkripsi dibatalkan")
                return
                
            encrypted += "###"  # Marker untuk menandai akhir pesan
            binary_message = ''.join(format(ord(c), '08b') for c in encrypted)
            
            img = Image.open(self.input_image_path)
            if img.mode != 'RGB':
                img = img.convert('RGB')
            pixels = list(img.getdata())
            
            if len(binary_message) > len(pixels) * 3:
                messagebox.showerror("Error", "Pesan terlalu panjang untuk disimpan di gambar ini.")
                return
            
            new_pixels = []
            msg_index = 0
            
            for pixel in pixels:
                r, g, b = pixel
                if msg_index < len(binary_message):
                    r = (r & ~1) | int(binary_message[msg_index])
                    msg_index += 1
                if msg_index < len(binary_message):
                    g = (g & ~1) | int(binary_message[msg_index])
                    msg_index += 1
                if msg_index < len(binary_message):
                    b = (b & ~1) | int(binary_message[msg_index])
                    msg_index += 1
                new_pixels.append((r, g, b))
            
            new_pixels.extend(pixels[len(new_pixels):])
            img.putdata(new_pixels)
            img.save(output_path)
            
            self.encode_status_var.set(f"Pesan berhasil disembunyikan dan disimpan: {os.path.basename(output_path)}")
            messagebox.showinfo("Sukses", "Pesan berhasil disembunyikan dalam gambar!")
        
        except Exception as e:
            self.encode_status_var.set(f"Error: {str(e)}")
            messagebox.showerror("Error", f"Terjadi kesalahan: {str(e)}")
    
    def decode_message(self):
        if not hasattr(self, 'decode_image_path') or not self.decode_image_path:
            messagebox.showerror("Error", "Pilih gambar terlebih dahulu!")
            return
        
        try:
            img = Image.open(self.decode_image_path)
            if img.mode != 'RGB':
                img = img.convert('RGB')
            pixels = list(img.getdata())
            
            binary_message = ''
            for pixel in pixels:
                for color in pixel[:3]:
                    binary_message += str(color & 1)
            
            # Konversi bit ke karakter
            chars = []
            for i in range(0, len(binary_message), 8):
                byte = binary_message[i:i+8]
                if len(byte) == 8:  # Pastikan kita punya 8 bit
                    chars.append(chr(int(byte, 2)))
            
            message = ''.join(chars)
            
            # Cari marker dan dekripsi
            if "###" in message:
                encrypted = message.split("###")[0]
                decrypted = self.decrypt_message(encrypted)
                self.decoded_message.delete("1.0", tk.END)
                self.decoded_message.insert("1.0", decrypted)
                self.decode_status_var.set("Pesan berhasil diekstrak dan didekripsi!")
            else:
                self.decoded_message.delete("1.0", tk.END)
                self.decoded_message.insert("1.0", "Tidak ada pesan tersembunyi.")
                self.decode_status_var.set("Tidak ada pesan tersembunyi.")
        
        except Exception as e:
            self.decode_status_var.set(f"Error: {str(e)}")
            messagebox.showerror("Error", f"Terjadi kesalahan: {str(e)}")
    
    def reset_key(self):
        """Menghasilkan kunci baru dan mengganti yang lama"""
        if self.encryption_mode == "password":
            messagebox.showinfo("Info", "Mode password tidak memerlukan reset kunci.\nKunci di-generate dari password secara otomatis.")
            return
            
        result = messagebox.askyesno("Reset Kunci", 
                                   "Apakah Anda yakin ingin mereset kunci?\n"
                                   "Pesan yang dienkripsi dengan kunci lama tidak dapat didekripsi lagi!")
        if result:
            try:
                # Hapus file kunci lama
                key_file = "encryption_key.bin"
                if os.path.exists(key_file):
                    os.remove(key_file)
                
                # Buat kunci baru
                self.KEY = self.load_or_generate_key()
                messagebox.showinfo("Sukses", "Kunci baru telah dibuat!")
            except Exception as e:
                messagebox.showerror("Error", f"Gagal mereset kunci: {str(e)}")
    
    def export_key(self):
        """Mengekspor kunci ke file"""
        if self.encryption_mode == "password":
            messagebox.showinfo("Info", "Mode password tidak memerlukan ekspor kunci.\nGunakan password yang sama untuk dekripsi.")
            return
            
        output_path = filedialog.asksaveasfilename(
            defaultextension=".key",
            filetypes=[("Key files", "*.key"), ("All files", "*.*")],
            initialfile="encryption_key.key"
        )
        
        if output_path:
            try:
                with open(output_path, "wb") as f:
                    f.write(self.KEY)
                messagebox.showinfo("Sukses", f"Kunci berhasil diekspor ke: {os.path.basename(output_path)}")
            except Exception as e:
                messagebox.showerror("Error", f"Gagal mengekspor kunci: {str(e)}")
    
    def import_key(self):
        """Mengimpor kunci dari file"""
        if self.encryption_mode == "password":
            messagebox.showinfo("Info", "Mode password tidak memerlukan impor kunci.\nGunakan password yang sama untuk dekripsi.")
            return
            
        key_path = filedialog.askopenfilename(
            filetypes=[("Key files", "*.key"), ("Binary files", "*.bin"), ("All files", "*.*")]
        )
        
        if key_path:
            try:
                with open(key_path, "rb") as f:
                    imported_key = f.read()
                
                if len(imported_key) != 32:
                    messagebox.showerror("Error", "File kunci tidak valid! Kunci harus 32 byte.")
                    return
                
                # Simpan kunci yang diimpor
                key_file = "encryption_key.bin"
                with open(key_file, "wb") as f:
                    f.write(imported_key)
                
                # Update kunci yang sedang digunakan
                self.KEY = imported_key
                messagebox.showinfo("Sukses", "Kunci berhasil diimpor!")
            except Exception as e:
                messagebox.showerror("Error", f"Gagal mengimpor kunci: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = SteganographyApp(root)
    root.mainloop()
