import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import subprocess
import socket
from concurrent.futures import ThreadPoolExecutor
from cryptography.fernet import Fernet  # type: ignore

def switch_frame(frame):
    frame.tkraise()

def generate_key():
    return Fernet.generate_key()

def save_key(key, filename):
    with open(filename, 'wb') as key_file:
        key_file.write(key)

def load_key(filename):
    with open(filename, 'rb') as key_file:
        return key_file.read()

def encrypt_message(message, key):
    fernet = Fernet(key)
    return fernet.encrypt(message.encode())

def decrypt_message(encrypted_message, key):
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_message).decode()

def generate_new_key():
    key = generate_key()
    save_key(key, 'secret.key')
    messagebox.showinfo("Key Generated", "New key has been generated and saved as 'secret.key'")

def encrypt_text():
    key = load_key('secret.key')
    message = enc_message_entry.get("1.0", tk.END).strip()
    if message:
        encrypted_message = encrypt_message(message, key)
        enc_result_text.delete("1.0", tk.END)
        enc_result_text.insert(tk.END, encrypted_message.decode())
    else:
        messagebox.showwarning("No Data", "No text to encrypt.")

def decrypt_text():
    key = load_key('secret.key')
    encrypted_message = enc_message_entry.get("1.0", tk.END).strip()
    try:
        encrypted_message_bytes = encrypted_message.encode()
        decrypted_message = decrypt_message(encrypted_message_bytes, key)
        enc_result_text.delete("1.0", tk.END)
        enc_result_text.insert(tk.END, decrypted_message)
    except Exception as e:
        messagebox.showerror("Decryption Error", f"Failed to decrypt message: {str(e)}")

def save_encrypted_message():
    encrypted_message = enc_result_text.get("1.0", tk.END).strip()
    if encrypted_message:
        filename = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
        if filename:
            with open(filename, 'w') as file:
                file.write(encrypted_message)
            messagebox.showinfo("Saved", f"Encrypted message saved to {filename}")
    else:
        messagebox.showwarning("No Data", "No encrypted message to save.")

def load_encrypted_message():
    filename = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
    if filename:
        with open(filename, 'r') as file:
            encrypted_message = file.read()
        enc_message_entry.delete("1.0", tk.END)
        enc_message_entry.insert(tk.END, encrypted_message)
    else:
        messagebox.showwarning("No File", "No file selected.")

def scan_port(host, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1)
        try:
            s.connect((host, port))
        except (socket.timeout, socket.error):
            return False
        else:
            return True

def scan_ports():
    host = host_entry.get()
    start_port = int(start_port_entry.get())
    end_port = int(end_port_entry.get())
    
    output_text.delete(1.0, tk.END)
    output_text.insert(tk.END, f"Scanning ports {start_port} to {end_port} on {host}...\n")
    progress_bar['value'] = 0
    open_ports = []

    total_ports = end_port - start_port + 1
    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = [executor.submit(scan_port, host, port) for port in range(start_port, end_port + 1)]
        for i, (port, future) in enumerate(zip(range(start_port, end_port + 1), futures)):
            progress_bar['value'] = (i + 1) / total_ports * 100
            root.update_idletasks()
            if future.result():
                open_ports.append(port)

    if open_ports:
        output_text.insert(tk.END, "Open ports:\n")
        for port in open_ports:
            service = common_ports.get(port, "Unknown Service")
            output_text.insert(tk.END, f"Port {port} is open ({service})\n")
    else:
        output_text.insert(tk.END, "No open ports found\n")

    save_button.config(state=tk.NORMAL)

def run_nmap_scan():
    host = host_entry.get()
    options = nmap_options_entry.get().strip()

    if not host:
        messagebox.showwarning("Input Required", "Please enter a host.")
        return

    cmd = ["nmap"]
    if options:
        cmd.extend(options.split())
    cmd.append(host)
    
    output_text.delete(1.0, tk.END)
    output_text.insert(tk.END, f"Running Nmap scan on {host}...\n")
    
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        output_text.insert(tk.END, result.stdout)
        if result.stderr:
            output_text.insert(tk.END, "\nErrors:\n")
            output_text.insert(tk.END, result.stderr)
    except Exception as e:
        messagebox.showerror("Nmap Error", f"Failed to run Nmap scan: {str(e)}")

def save_results():
    file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
    if file_path:
        with open(file_path, 'w') as file:
            file.write(output_text.get(1.0, tk.END))
        messagebox.showinfo("Save Results", f"Results saved to {file_path}")

common_ports = {
    20: "FTP (File Transfer Protocol)",
    21: "FTP (File Transfer Protocol)",
    22: "SSH (Secure Shell)",
    23: "Telnet",
    25: "SMTP (Simple Mail Transfer Protocol)",
    53: "DNS (Domain Name System)",
    80: "HTTP (Hypertext Transfer Protocol)",
    110: "POP3 (Post Office Protocol)",
    143: "IMAP (Internet Message Access Protocol)",
    443: "HTTPS (HTTP Secure)",
    3306: "MySQL",
    3389: "RDP (Remote Desktop Protocol)",
    5900: "VNC (Virtual Network Computing)",
    8080: "HTTP (Alternative Port)",
}

root = tk.Tk()
root.title("Combined Tools")
root.geometry("700x700")

enc_dec_frame = tk.Frame(root)
port_scanner_frame = tk.Frame(root)

for frame in (enc_dec_frame, port_scanner_frame):
    frame.grid(row=0, column=0, sticky='nsew')

tk.Label(enc_dec_frame, text="Encryption/Decryption Tool", font=('Arial', 16, 'bold')).pack(pady=10)

tk.Label(enc_dec_frame, text="Enter text:", font=('Arial', 12)).pack()
enc_message_entry = scrolledtext.ScrolledText(enc_dec_frame, width=60, height=10, wrap=tk.WORD)
enc_message_entry.pack(pady=5)

enc_button_frame = tk.Frame(enc_dec_frame)
enc_button_frame.pack(pady=10)

tk.Button(enc_button_frame, text="Generate New Key", command=generate_new_key, bg='#4CAF50', fg='white').pack(side=tk.LEFT, padx=5)
tk.Button(enc_button_frame, text="Encrypt", command=encrypt_text, bg='#2196F3', fg='white').pack(side=tk.LEFT, padx=5)
tk.Button(enc_button_frame, text="Decrypt", command=decrypt_text, bg='#FF5722', fg='white').pack(side=tk.LEFT, padx=5)
tk.Button(enc_button_frame, text="Save Encrypted Message", command=save_encrypted_message, bg='#FFC107', fg='black').pack(side=tk.LEFT, padx=5)
tk.Button(enc_button_frame, text="Load Encrypted Message", command=load_encrypted_message, bg='#9E9E9E', fg='white').pack(side=tk.LEFT, padx=5)

tk.Label(enc_dec_frame, text="Result:", font=('Arial', 12)).pack()
enc_result_text = scrolledtext.ScrolledText(enc_dec_frame, width=60, height=10, wrap=tk.WORD)
enc_result_text.pack(pady=5)

tk.Label(port_scanner_frame, text="Port Scanning Tool", font=('Arial', 16, 'bold')).pack(pady=10)

tk.Label(port_scanner_frame, text="Host:", font=('Arial', 12)).pack()
host_entry = tk.Entry(port_scanner_frame, width=40, font=('Arial', 12))
host_entry.pack(pady=5)

tk.Label(port_scanner_frame, text="Start Port:", font=('Arial', 12)).pack()
start_port_entry = tk.Entry(port_scanner_frame, width=10, font=('Arial', 12))
start_port_entry.pack(pady=5)

tk.Label(port_scanner_frame, text="End Port:", font=('Arial', 12)).pack()
end_port_entry = tk.Entry(port_scanner_frame, width=10, font=('Arial', 12))
end_port_entry.pack(pady=5)

progress_bar = ttk.Progressbar(port_scanner_frame, orient="horizontal", length=400, mode="determinate")
progress_bar.pack(pady=10)

scan_button_frame = tk.Frame(port_scanner_frame)
scan_button_frame.pack(pady=10)

tk.Button(scan_button_frame, text="Scan Ports", command=scan_ports, bg='#2196F3', fg='white').pack(side=tk.LEFT, padx=5)

tk.Label(port_scanner_frame, text="Nmap Options (e.g., -sV -O):", font=('Arial', 12)).pack(pady=10)
nmap_options_entry = tk.Entry(port_scanner_frame, width=40, font=('Arial', 12))
nmap_options_entry.pack(pady=5)

tk.Button(scan_button_frame, text="Run Nmap Scan", command=run_nmap_scan, bg='#4CAF50', fg='white').pack(side=tk.LEFT, padx=5)

output_text = scrolledtext.ScrolledText(port_scanner_frame, width=60, height=10, wrap=tk.WORD)
output_text.pack(pady=10)

save_button = tk.Button(port_scanner_frame, text="Save Results", command=save_results, bg='#FFC107', fg='black')
save_button.pack(pady=10)
save_button.config(state=tk.DISABLED)

nav_frame = tk.Frame(root)
nav_frame.grid(row=1, column=0, pady=10)

tk.Button(nav_frame, text="Encryption/Decryption Tool", command=lambda: switch_frame(enc_dec_frame)).grid(row=0, column=0, padx=20)
tk.Button(nav_frame, text="Port Scanning Tool", command=lambda: switch_frame(port_scanner_frame)).grid(row=0, column=1, padx=20)

switch_frame(enc_dec_frame)

root.mainloop()
