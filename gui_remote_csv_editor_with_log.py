import paramiko
import pandas as pd
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import os


def log(message):
    """Append message to log window."""
    log_output.insert(tk.END, message + "\n")
    log_output.see(tk.END)
    root.update()


def process_file():
    """Main logic: Connect, fetch, modify, and reupload CSV with logging."""
    ip = entry_ip.get().strip()
    user = entry_user.get().strip()
    key_path = entry_key.get().strip()
    remote_file = entry_remote_path.get().strip()
    local_temp_file = 'temp_file.csv'

    log_output.delete(1.0, tk.END)

    # Input checks
    if not ip:
        messagebox.showerror("Input Error", "Remote IP cannot be empty.")
        return
    if not user:
        messagebox.showerror("Input Error", "Username cannot be empty.")
        return
    if not key_path or not os.path.isfile(key_path):
        messagebox.showerror("Input Error", f"Private key not found: {key_path}")
        return
    if not remote_file:
        messagebox.showerror("Input Error", "Remote file path cannot be empty.")
        return

    try:
        log("[*] Loading private key...")
        try:
            key = paramiko.RSAKey.from_private_key_file(key_path)
        except paramiko.ssh_exception.PasswordRequiredException:
            messagebox.showerror("Key Error", "Private key requires a password.")
            return
        except Exception as e:
            messagebox.showerror("Key Error", f"Error loading private key: {e}")
            return

        log("[*] Connecting to SSH...")
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            ssh.connect(ip, username=user, pkey=key, timeout=10)
        except paramiko.AuthenticationException:
            messagebox.showerror("Connection Error", "Authentication failed.")
            return
        except Exception as e:
            messagebox.showerror("Connection Error", f"SSH connection failed: {e}")
            return

        log("[+] SSH connection established.")

        try:
            sftp = ssh.open_sftp()
        except Exception as e:
            ssh.close()
            messagebox.showerror("SFTP Error", f"SFTP session failed: {e}")
            return

        log(f"[*] Downloading remote file: {remote_file}")
        try:
            sftp.get(remote_file, local_temp_file)
        except Exception as e:
            sftp.close()
            ssh.close()
            messagebox.showerror("File Error", f"Failed to download remote file: {e}")
            return
        log("[+] File downloaded successfully.")

        log("[*] Reading and modifying CSV...")
        try:
            df = pd.read_csv(local_temp_file)
            df = df._append({'Name': 'GUIUser', 'Age': 42, 'Role': 'Engineer'}, ignore_index=True)
            df.to_csv(local_temp_file, index=False)
        except Exception as e:
            sftp.close()
            ssh.close()
            messagebox.showerror("CSV Error", f"Error modifying CSV: {e}")
            return
        log("[+] CSV modified.")

        log("[*] Uploading modified file...")
        try:
            sftp.put(local_temp_file, remote_file)
        except Exception as e:
            messagebox.showerror("Upload Error", f"Upload failed: {e}")
            return
        log("[+] File uploaded back to remote VM.")

        sftp.close()
        ssh.close()
        if os.path.exists(local_temp_file):
            os.remove(local_temp_file)

        log("[✓] Done.")
        messagebox.showinfo("Success", "CSV updated and uploaded successfully!")

    except Exception as e:
        messagebox.showerror("Unexpected Error", str(e))
        log(f"[!] Unexpected error: {e}")


def browse_key():
    """File dialog to choose private key file."""
    try:
        path = filedialog.askopenfilename(filetypes=[("Private Key", "*.pem *.ppk *.key"), ("All files", "*.*")])
        if path:
            entry_key.delete(0, tk.END)
            entry_key.insert(0, path)
    except Exception as e:
        messagebox.showerror("Browse Error", str(e))


# -------------------- GUI Layout --------------------
root = tk.Tk()
root.title("Remote CSV Editor")

tk.Label(root, text="Remote IP").grid(row=0, column=0, sticky="e")
tk.Label(root, text="Username").grid(row=1, column=0, sticky="e")
tk.Label(root, text="Private Key Path").grid(row=2, column=0, sticky="e")
tk.Label(root, text="Remote File Path").grid(row=3, column=0, sticky="e")

entry_ip = tk.Entry(root, width=45)
entry_user = tk.Entry(root, width=45)
entry_key = tk.Entry(root, width=45)
entry_remote_path = tk.Entry(root, width=45)

entry_ip.grid(row=0, column=1, padx=5)
entry_user.grid(row=1, column=1, padx=5)
entry_key.grid(row=2, column=1, padx=5)
entry_remote_path.grid(row=3, column=1, padx=5)

tk.Button(root, text="Browse", command=browse_key).grid(row=2, column=2)
tk.Button(root, text="Run", command=process_file, bg="green", fg="white").grid(row=4, column=1, pady=10)

tk.Label(root, text="Log Output").grid(row=5, column=0, sticky="nw", padx=5)
log_output = scrolledtext.ScrolledText(root, height=15, width=70, wrap=tk.WORD)
log_output.grid(row=5, column=1, columnspan=2, padx=5, pady=5)

root.mainloop()
