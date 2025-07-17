import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import pyperclip
import os
from dotenv import set_key, load_dotenv
from main import fetch_issue_data, extract_issue_fields, print_issue_summary


def run_analysis(jira_tag, output_box, analyze_btn):
    output_box.config(state="normal")
    output_box.delete("1.0", tk.END)
    analyze_btn.config(state="disabled")

    try:
        issue_data = fetch_issue_data(jira_tag)
        extracted_data = extract_issue_fields(issue_data)

        import io
        import sys
        buffer = io.StringIO()
        sys.stdout = buffer
        print_issue_summary(extracted_data)
        sys.stdout = sys.__stdout__
        output = buffer.getvalue()
        output_box.insert(tk.END, output)

    except Exception as e:
        output_box.config(state="normal")
        output_box.delete("1.0", tk.END)
        output_box.insert(tk.END, f"Error: {str(e)}")
        messagebox.showerror("Error", str(e))
       

    output_box.config(state="disabled")
    analyze_btn.config(state="normal")



def credentials_provided():
    dotenv_path = ".env"
    if not os.path.exists(dotenv_path):
        return False
    load_dotenv(dotenv_path, override=True)
    email = os.getenv("JIRA_EMAIL")
    token = os.getenv("JIRA_API_TOKEN")
    return bool(email and token)


def on_submit(entry, output_box, analyze_btn):
    if not credentials_provided():
        messagebox.showerror(
        "Missing Credentials",
        "Please provide your Jira email and API token first.")
        return

    jira_tag = entry.get().strip()
    if not jira_tag:
        messagebox.showwarning(""
        "Input Required",
        "Please enter a Jira tag.") 
        return

    if not jira_tag.startswith(("CSLC-", "CS-")) or not jira_tag.split("-")[1].isdigit():
        messagebox.showwarning(
        "Invalid Input",
        "Invalid Jira tag. Please enter a valid Jira tag in the format 'CSLC-XXXXX'.")
        return

    threading.Thread(target=run_analysis, args=(jira_tag, output_box, analyze_btn)).start()


def on_copy(output_box):
    content = output_box.get("1.0", tk.END)
    pyperclip.copy(content)
    messagebox.showinfo("Copied", "Output copied to clipboard.")


def open_credentials_window():
    def save_credentials():
        email = email_entry.get().strip()
        token = token_entry.get().strip()

        if not email or not token:
            messagebox.showwarning(
            "Missing Data",
            "Please provide both email and API token.")
            return

        dotenv_path = ".env"
        if not os.path.exists(dotenv_path):
            with open(dotenv_path, "w") as f:
                f.write("# Jira Credentials\n")

        # Add double quotes around the value before saving
        set_key(dotenv_path, "JIRA_EMAIL", email)
        set_key(dotenv_path, "JIRA_API_TOKEN", token)

        #load the new credentials
        load_dotenv(dotenv_path, override=True)
        
        messagebox.showinfo(
        "Credentials Saved",
        "The new email and API token were saved.")
        cred_win.destroy()
        root.destroy()
        launch_gui()
        
    cred_win = tk.Toplevel()
    cred_win.title("Set Jira Credentials")
    cred_win.geometry("400x200")
    cred_win.resizable(False, False)

    frame = ttk.Frame(cred_win, padding=20)
    frame.pack(fill="both", expand=True)

    ttk.Label(frame, text="Email:").grid(row=0, column=0, sticky="w", pady=5)
    email_entry = ttk.Entry(frame, width=40)
    email_entry.grid(row=0, column=1, pady=5)

    ttk.Label(frame, text="API Token:").grid(row=1, column=0, sticky="w", pady=5)
    token_entry = ttk.Entry(frame, width=40, show="*")
    token_entry.grid(row=1, column=1, pady=5)

    save_btn = ttk.Button(frame, text="Save", command=save_credentials)
    save_btn.grid(row=2, columnspan=2, pady=15)


def launch_gui():

    global root

    root = tk.Tk()
    root.title("Jira Ticket Analyzer")
    root.geometry("880x600")

    style = ttk.Style(root)
    style.theme_use("vista")

    main_frame = ttk.Frame(root, padding="20")
    main_frame.pack(fill="both", expand=True)

    title_label = ttk.Label(main_frame, text="🔍 Jira Ticket Analyzer", font=("Segoe UI", 18, "bold"))
    title_label.pack(pady=(0, 15))

    form_frame = ttk.Frame(main_frame)
    form_frame.pack(fill="x", pady=5)

    ttk.Label(form_frame, text="Enter Jira Tag (e.g., CSLC-12345):", font=("Segoe UI", 10)).pack(side="left", padx=(0, 10))

    entry = ttk.Entry(form_frame, width=40)
    entry.pack(side="left")

    analyze_btn = ttk.Button(form_frame, text="Analyze", command=lambda: on_submit(entry, output_box, analyze_btn))
    analyze_btn.pack(side="left", padx=10)

    credentials_btn = ttk.Button(form_frame, text="Credentials", command=open_credentials_window)
    credentials_btn.pack(side="left", padx=5)

    output_label = ttk.Label(main_frame, text="Issue Summary:", font=("Segoe UI", 10, "bold"))
    output_label.pack(pady=(20, 5), anchor="w")

    output_box = scrolledtext.ScrolledText(main_frame, wrap=tk.WORD, width=100, height=25, font=("Consolas", 10))
    output_box.pack(fill="both", expand=True)
    output_box.config(state="disabled")

    copy_btn = ttk.Button(main_frame, text="📋 Copy Output", command=lambda: on_copy(output_box))
    copy_btn.pack(pady=10)

    root.mainloop()


if __name__ == "__main__":
    launch_gui()
