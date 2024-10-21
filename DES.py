import tkinter as tk
from threading import Thread, Lock
from queue import Queue
import time

def function_x1(a, b, c):
    x = 0
    for i in range(len(b)):
        x <<= 1
        x |= (a >> (c - b[i])) & 1
    return x
def function_x2(a, b):
    left_half = (a >> 4) & 0xf
    right_half = a & 0xf
    return ((left_half ^ expansion_function(right_half, b)) << 4) | right_half
def expansion_function(a, b):
    t = function_x1(a, expansion_permutation, 4) ^ b
    t0 = (t >> 4) & 0xf
    t1 = t & 0xf
    x1 = ((t0 & 0x8) >> 2) | (t0 & 1)
    y1 = (t0 >> 1) & 0x3
    x2 = ((t1 & 0x8) >> 2) | (t1 & 1)
    y2 = (t1 >> 1) & 0x3
    t0 = S1[x1][y1]
    t1 = S2[x2][y2]
    t = function_x1((t0 << 2) | t1, permutation_4, 4)
    return t

def DES(key, mode='encrypt'):
    global key_part_1, key_part_2
    x = int(key, 2)
    x = function_x1(x, permutation_10, 10)
    left_key = (x >> 5) & 0x1f
    right_key = x & 0x1f
    left_key = ((left_key & 0xf) << 1) | ((left_key & 0x10) >> 4)
    right_key = ((right_key & 0xf) << 1) | ((right_key & 0x10) >> 4)
    key_part_1 = function_x1((left_key << 5) | right_key, permutation_8, 10)
    left_key = ((left_key & 0x07) << 2) | ((left_key & 0x18) >> 3)
    right_key = ((right_key & 0x07) << 2) | ((right_key & 0x18) >> 3)
    key_part_2 = function_x1((left_key << 5) | right_key, permutation_8, 10)
    if mode == 'decrypt':
        key_part_1, key_part_2 = key_part_2, key_part_1

def des_encrypt(plaintext, key):
    DES(key, 'encrypt')
    temp = int(plaintext, 2)
    temp = function_x1(temp, initial_permutation, 8)
    temp = function_x2(temp, key_part_1)
    temp = ((temp & 0xf) << 4) | ((temp >> 4) & 0xf)
    temp = function_x2(temp, key_part_2)
    temp = function_x1(temp, inverse_initial_permutation, 8)
    return bin(temp)[2:].zfill(8)

class DESCracker:
    def __init__(self, plaintext, ciphertext):
        self.plaintext = plaintext
        self.ciphertext = ciphertext
        self.queue = Queue()
        self.lock = Lock()
        self.found_key = None

    def crack(self):
        threads = []
        start_time = time.time()
        def attempt_key(start):
            for i in range(start, 1024, 8):
                for j in range(8):
                    key = format(i + j, '010b')
                    if self.found_key:
                        return
                    encrypted_text = des_encrypt(self.plaintext, key)
                    if encrypted_text == self.ciphertext:
                        with self.lock:
                            if not self.found_key:
                                self.found_key = key
                                elapsed_time = time.time() - start_time
                                print(f"Key found: {key} in {elapsed_time:.2f} seconds")
                                self.queue.put(True)
                        return
        for i in range(8):
            t = Thread(target=attempt_key, args=(i * 128,))
            threads.append(t)
            t.start()
        for t in threads:
            t.join()
        while not self.queue.empty():
            self.queue.get()
class DESApp:
    def __init__(self, root):
        self.root = root
        self.root.title("DES")
        self.create_widgets()

    def create_widgets(self):
        self.key_label = tk.Label(self.root, text="输入10位密钥:")
        self.key_label.grid(row=0, column=0, padx=10, pady=5)
        self.key_entry = tk.Entry(self.root)
        self.key_entry.grid(row=0, column=1, padx=10, pady=5)

        self.plaintext_label = tk.Label(self.root, text="输入8位明文:")
        self.plaintext_label.grid(row=1, column=0, padx=10, pady=5)
        self.plaintext_entry = tk.Entry(self.root)
        self.plaintext_entry.grid(row=1, column=1, padx=10, pady=5)

        self.ciphertext_label = tk.Label(self.root, text="输入8位密文:")
        self.ciphertext_label.grid(row=2, column=0, padx=10, pady=5)
        self.ciphertext_entry = tk.Entry(self.root)
        self.ciphertext_entry.grid(row=2, column=1, padx=10, pady=5)

        self.mode_label = tk.Label(self.root, text="选择模式:")
        self.mode_label.grid(row=3, column=0, padx=10, pady=5)
        self.mode_var = tk.StringVar(value="加密")
        self.encrypt_radio = tk.Radiobutton(self.root, text="加密", variable=self.mode_var, value="加密")
        self.encrypt_radio.grid(row=3, column=1, padx=10, pady=5)
        self.decrypt_radio = tk.Radiobutton(self.root, text="解密", variable=self.mode_var, value="解密")
        self.decrypt_radio.grid(row=3, column=2, padx=10, pady=5)
        self.result_label = tk.Label(self.root, text="")
        self.result_label.grid(row=4, column=0, columnspan=3, padx=10, pady=5)
        self.encrypt_button = tk.Button(self.root, text="加密/解密", command=self.encrypt_or_decrypt)
        self.encrypt_button.grid(row=5, column=0, padx=10, pady=5)
        self.crack_button = tk.Button(self.root, text="破解", command=self.crack_des)
        self.crack_button.grid(row=5, column=1, columnspan=2, padx=10, pady=5)
    def encrypt_or_decrypt(self):
        key = self.key_entry.get()
        plaintext = self.plaintext_entry.get()
        mode = self.mode_var.get()

        if len(key) != 10 or not all(c in '01' for c in key):
            self.result_label.config(text="密钥无效！密钥必须10位")
            return
        if len(plaintext) != 8 or not all(c in '01' for c in plaintext):
            self.result_label.config(text="明文无效！明文必须为8位。")
            return

        if mode == "加密":
            encrypted_text = des_encrypt(plaintext, key)
            self.result_label.config(text=f"Encrypted text: {encrypted_text}")
        else:
            self.result_label.config(text="解密功能尚未实现。")
    def crack_des(self):
        plaintext = self.plaintext_entry.get()
        ciphertext = self.ciphertext_entry.get()
        if len(plaintext) != 8 or not all(c in '01' for c in plaintext):
            self.result_label.config(text="明文无效！明文必须为8位。")
            return
        if len(ciphertext) != 8 or not all(c in '01' for c in ciphertext):
            self.result_label.config(text="密文无效！密文必须8位。")
            return
        cracker = DESCracker(plaintext, ciphertext)
        cracker.crack()
        if cracker.found_key:
            self.result_label.config(text=f"找到: {cracker.found_key}")
        else:
            self.result_label.config(text="未找到密钥。")

permutation_4 = [2, 4, 3, 1]
permutation_8 = [6, 3, 7, 4, 8, 5, 10, 9]
permutation_10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]
initial_permutation = [2, 6, 3, 1, 4, 8, 5, 7]
inverse_initial_permutation = [4, 1, 3, 5, 7, 2, 8, 6]
expansion_permutation = [4, 1, 2, 3, 2, 3, 4, 1]
S1 = [[1, 0, 3, 2], [3, 2, 1, 0], [0, 2, 1, 3], [3, 1, 3, 2]]
S2 = [[0, 1, 2, 3], [2, 0, 1, 3], [3, 0, 1, 0], [2, 1, 0, 3]]
key_part_1, key_part_2 = 0, 0
root = tk.Tk()
app = DESApp(root)
root.mainloop()

