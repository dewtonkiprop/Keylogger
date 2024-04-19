import os
import tkinter
import tkinter as tk
from tkinter import filedialog, messagebox, END, scrolledtext
import pyautogui
import sounddevice as sd
import soundfile as sf
from backspace import backspace
from pynput import keyboard
from pynput.keyboard import Key, Listener
import requests
from firebase_admin import credentials, firestore, initialize_app
import tkinter.simpledialog as simpledialog
import numpy
from PIL import Image, ImageTk
import csv
from firebase_admin import auth


# Initialize Firebase Admin SDK
cred = credentials.Certificate("keylogger.json")
initialize_app(cred)
db = firestore.client()
#
# # Initialize Tkinter
# # root = tk.Tk()
# # root.title('Keylogger')
# # root.geometry('400x300')
#
# # Initialize VirusTotal API key
VT_API_KEY = 'INPUT YOUR VIRUSTOTAL API'  # Replace with your VirusTotal API key
#
# Firebase setup
# db = firestore.client()
#
# # Set up the audio recording configuration
fs = 44100  # Sample rate
duration = 5  # seconds
#


def admin_signup():
    email = entry_email.get()
    password = entry_password.get()

    try:
        # Add user details to Firestore collection
        user_data = {
            'email': email,
            'password': password,
            # Add additional user details as needed
        }
        db.collection('admin_users').add(user_data)

        messagebox.showinfo("Success", "Admin account created successfully!")
    except Exception as e:
        messagebox.showerror("Error", str(e))



# def admin_login():
#     email = entry_email.get()
#     password = entry_password.get()
#
#     try:
#         user = auth.sign_in_with_email_and_password(email, password)
#         messagebox.showinfo("Success", "Admin login successful!")
#     except auth.AuthError:
#         messagebox.showerror("Error", "Invalid email or password.")
#     except Exception as e:
#         messagebox.showerror("Error", str(e))

def admin_login():
    email = entry_email.get()
    password = entry_password.get()

    try:
        # Check if the credentials exist in Firestore
        user_ref = db.collection('admin_users').where('email', '==', email).where('password', '==', password).stream()

        # Assuming there is only one matching user
        user_data = next(user_ref).to_dict()


        if user_data:
            # Open a new window or perform additional actions upon successful login
            open_dashboard_window(user_data)
            #messagebox.showinfo("Success", "Admin login successful!")
        else:
            messagebox.showerror("Error", "Invalid email or password.")
    except Exception as e:
        messagebox.showerror("Error", str(e))

def generate_report():
    # Retrieve scan results from Firestore in batches
    scan_results_ref = db.collection('scan_results')
    results = []

    # Paginate through the collection to retrieve all documents
    for doc in scan_results_ref.stream():
        results.append(doc.to_dict())

    if results:
        # Specify the file path for the report
        report_file_path = "scan_report.csv"

        # Write the report to a CSV file
        with open(report_file_path, mode='w', newline='') as file:
            fieldnames = ['URL', 'Result']  # Adjust the fieldnames based on your data
            writer = csv.DictWriter(file, fieldnames=fieldnames)

            writer.writeheader()
            for result in results:
                url = result.get('url', 'N/A')
                scan_result = result.get('result', 'N/A')

                if isinstance(scan_result, dict):
                    # If scan_result is a dictionary, extract 'scan_id' attribute
                    scan_id = scan_result.get('scan_id', 'N/A')
                    if scan_id != 'N/A':
                        detailed_result = get_detailed_result_from_virustotal(scan_id)

                        # Add the detailed result to the CSV file
                        writer.writerow({'URL': url, 'Result': detailed_result if detailed_result else 'No threat found'})
                    else:
                        # If no scan_id is available, indicate that in the report
                        writer.writerow({'URL': url, 'Result': 'No detailed result available'})
                elif isinstance(scan_result, str):
                    # If scan_result is a string, check for 'clean' or 'infected'
                    if scan_result.lower() == 'clean':
                        writer.writerow({'URL': url, 'Result': 'No threat found'})
                    else:
                        writer.writerow({'URL': url, 'Result': 'Threat found'})

        messagebox.showinfo("Success", f"Report generated and saved as '{report_file_path}'.")

    else:
        messagebox.showerror("Error", "No scan results found.")



def get_detailed_result_from_virustotal(scan_id):
    # Query VirusTotal for the detailed result based on the scan ID
    url_report_api = 'https://www.virustotal.com/vtapi/v2/url/report'
    params = {'apikey': VT_API_KEY, 'resource': scan_id}
    response = requests.get(url_report_api, params=params)

    if response.status_code == 200:
        result = response.json()
        if result['response_code'] == 1:
            # Extract relevant information from the detailed result
            scan_result = result.get('positives', 0)
            total_scans = result.get('total', 0)
            scan_date = result.get('scan_date', 'N/A')

            return f'Malicious scans: {scan_result}/{total_scans}, Scan date: {scan_date}'

    return 'Error retrieving detailed result from VirusTotal'


def get_current_user_email():
    pass


def delete_admin(dashboard_window=None):
    # Retrieve the list of admins from Firestore
    admin_ref = db.collection('admin_users')
    admins = [doc.id for doc in admin_ref.stream()]

    if not admins:
        messagebox.showinfo("Info", "No admins to delete.")
        return

    # Create a custom dialog window to select an admin
    delete_admin_dialog = tk.Toplevel(dashboard_window)
    delete_admin_dialog.title("Delete Admin")
    delete_admin_dialog.geometry("300x200")

    # Create a listbox to display the admins
    admin_listbox = tk.Listbox(delete_admin_dialog, selectmode=tk.SINGLE)
    for admin in admins:
        admin_listbox.insert(tk.END, admin)
    admin_listbox.pack(pady=10)

    def confirm_deletion():
        selected_index = admin_listbox.curselection()
        if selected_index:
            selected_admin = admin_listbox.get(selected_index[0])
            messagebox.showinfo("Info", "Action cannot be completed. Deletion of admins is not allowed.")
        else:
            messagebox.showinfo("Info", "Action cannot be completed. No admin selected.")

    # Button to confirm the selection and display a message
    delete_button = tk.Button(delete_admin_dialog, text="OK", command=confirm_deletion)
    delete_button.pack(side=tk.LEFT, padx=10)

    # Button to cancel and close the dialog window
    cancel_button = tk.Button(delete_admin_dialog, text="Cancel", command=delete_admin_dialog.destroy)
    cancel_button.pack(side=tk.RIGHT, padx=10)


# ... (rest of your code)
# Function to handle logout action

# Function to open a new window (dashboard) upon successful login
def open_login_window():
    pass


def open_dashboard_window(user_data):
    dashboard_window = tk.Toplevel(root)
    dashboard_window.title('Admin Dashboard')
    dashboard_window.geometry('1360x723')
    dashboard_window.configure(background='black')

    # dashboard background
    admindashbackground_image = tk.PhotoImage(file='admindashkeyogger.png')
    admindashbackground_label = tk.Label(dashboard_window, image=admindashbackground_image, bd=0)
    admindashbackground_label.photo = admindashbackground_image
    admindashbackground_label.place(x=0, y=0, relwidth=1, relheight=1)


    # Function to handle logout action
    def logout():
        # Destroy the dashboard window
        dashboard_window.destroy()
        # Open the main login window again
        open_login_window()


    # scan url
    def scan_url():
        url = entry_url.get()

        try:
            # Send URL to VirusTotal API for scanning
            scan_result = send_to_virustotal_url_api(url)

            # Display the scan result in the Tkinter window
            display_result(scan_result)

            # Store the scan result in Firestore
            store_result_in_firestore(url, scan_result)

        except Exception as e:
            messagebox.showerror("Error", str(e))

    def send_to_virustotal_url_api(url):
        url_scan_api = 'https://www.virustotal.com/vtapi/v2/url/scan'
        params = {'apikey': VT_API_KEY, 'url': url}
        response = requests.post(url_scan_api, params=params)

        if response.status_code == 200:
            result = response.json()
            if result['response_code'] == 1:
                return f'The URL has been successfully scanned. Scan ID: {result["scan_id"]}'
            else:
                return 'Error scanning the URL.'
        else:
            return 'Error connecting to VirusTotal API.'

    def store_result_in_firestore(url, result):
        doc_ref = db.collection('scan_results').add({
            'url': url,
            'result': result,
        })

    def display_result(result):
        result1_text.config(state=tk.NORMAL)
        result1_text.delete(1.0, tk.END)
        result1_text.insert(tk.END, result)
        result1_text.config(state=tk.DISABLED)

    # Tkinter GUI components
    label_url = tk.Label(dashboard_window, text="Enter URL:", bg='black', fg='red', font=('helvetica', 12, 'bold'))
    label_url.place(x=100, y=50)

    entry_url = tk.Entry(dashboard_window, width=40)
    entry_url.place(x=100, y=80)

    btn_scan = tk.Button(dashboard_window, text="Scan URL", command=scan_url, bg='blue', fg='white', relief=tk.RAISED,
                         activeforeground='white', activebackground='blue')
    btn_scan.place(x=100, y=120)

    # Create the delete button
    btn_delete_admin = tk.Button(dashboard_window, text="Delete Admin", bg='red', fg='white',
                                 command=delete_admin)
    btn_delete_admin.place(x=100, y=160)  # Adjust the coordinates as needed

    result1_text = scrolledtext.ScrolledText(dashboard_window, wrap=tk.WORD, height=15, width=50, fg='white',
                                             bg='black', font=('helvetica', 14, 'bold'))
    result1_text.place(x=100, y=190)

    # "Generate Report" button
    btn_generate_report = tk.Button(dashboard_window, text="Generate Report", bg="orange", fg="white",
                                    command=generate_report)
    btn_generate_report.place(x=1000, y=120, width=120, height=30)

    # scans a file
    # def scan_file2():
    #     file_path = filedialog.askopenfilename(parent=dashboard_window)
    #
    #     if file_path:
    #         api_key = '979cb48901a07427ac7eb72892676533414d75abb85509e8fd7819369b12f6cc'  # Replace with your VirusTotal API key
    #         url = 'https://www.virustotal.com/vtapi/v2/file/scan'
    #
    #         try:
    #             with open(file_path, 'rb') as file:
    #                 files = {'file': (file_path, file)}
    #                 params = {'apikey': api_key}
    #                 response = requests.post(url, files=files, params=params)
    #                 result = response.json()
    #
    #                 # Display results in a new window
    #                 display_results(result)
    #
    #                 # Store results in Firestore
    #                 store_in_firestore(result)
    #
    #         except Exception as e:
    #             messagebox.showerror("Error", f"An error occurred: {str(e)}")


    def scan_file2():
        file_path = filedialog.askopenfilename(parent=dashboard_window)

        if file_path:
            api_key = '979cb48901a07427ac7eb72892676533414d75abb85509e8fd7819369b12f6cc'  # Replace with your VirusTotal API key
            url = 'https://www.virustotal.com/vtapi/v2/file/scan'

            try:
                with open(file_path, 'rb') as file:
                    files = {'file': (file_path, file)}
                    params = {'apikey': api_key}
                    response = requests.post(url, files=files, params=params)
                    result = response.json()

                    # Display results in a new window
                    display_results(result)

                    # Store results in Firestore
                    store_in_firestore(result)

            except Exception as e:
                messagebox.showerror("Error", f"An error occurred: {str(e)}")

    def display_results(result):
        result_window = tk.Toplevel(dashboard_window)
        result_window.title('Scan Results')

        result_text = tk.Text(result_window, wrap="word", height=20, width=60)
        result_text.pack(padx=10, pady=10, fill='both', expand=True)

        scrollbar = tk.Scrollbar(result_window, command=result_text.yview)
        scrollbar.pack(side='right', fill='y')
        result_text['yscrollcommand'] = scrollbar.set

        result_text.insert(END, str(result))
        result_text.config(state='disabled')

    def store_in_firestore(result):
        # Store the result in Firestore collection 'scan_results'
        scan_results_ref = db.collection('scan_results')
        scan_results_ref.add(result)




    def record_audio():
        filename = simpledialog.askstring("Input", "Enter audio filename (without extension):", parent=dashboard_window)
        if filename:
            audio_data = sd.rec(int(fs * duration), samplerate=fs, channels=2)
            sd.wait()
            sf.write(f'{filename}.wav', audio_data, fs)
            messagebox.showinfo("Success", f"Audio recorded and saved as '{filename}.wav'.")

    def retrieve_scan_results():
        # Retrieve scan results from Firestore
        results = []
        scan_results_ref = db.collection('scan_results')
        for doc in scan_results_ref.stream():
            result_data = doc.to_dict()
            results.append(result_data)

        # Display scan results in the Tkinter window
        display_results(results)

    # def display_results(results):
    #     result_text.config(state=tk.NORMAL)
    #     result_text.delete(1.0, tk.END)
    #
    #     for result in results:
    #         # Check if 'url' and 'result' keys exist for URL scans
    #         url = result.get('url', 'N/A')
    #         scan_result = result.get('result', 'N/A')
    #
    #         result_text.insert(tk.END, f"URL: {url}\nResult: {scan_result}\n\n")
    #
    #         # Check if 'file_url' and 'file_scan_result' keys exist for file scans
    #         file_url = result.get('file_url', 'N/A')
    #         file_scan_result = result.get('file_scan_result', 'N/A')
    #
    #         result_text.insert(tk.END, f"File URL: {file_url}\nFile Scan Result: {file_scan_result}\n\n")
    #
    #     result_text.config(state=tk.DISABLED)

    def display_results(results):
        result_text.config(state=tk.NORMAL)
        result_text.delete(1.0, tk.END)

        if isinstance(results, str):
            # If results is a string, directly insert it into the text widget
            result_text.insert(tk.END, results)
        elif isinstance(results, list):
            # If results is a list of dictionaries, iterate over each dictionary
            for result in results:
                if isinstance(result, dict):
                    # Iterate over all keys and values in the dictionary
                    for key, value in result.items():
                        result_text.insert(tk.END, f"{key}: {value}\n")

                    result_text.insert(tk.END, "\n---\n")  # Add a separator between documents
                else:
                    print("Unexpected result format:", result)
        else:
            print("Results content:", results)

        result_text.config(state=tk.DISABLED)

    # Tkinter GUI components


    btn_retrieve = tk.Button(dashboard_window, text=" Scan Report",bg='blue',activebackground='blue',
                            fg='white',activeforeground='white',relief=tk.RAISED ,command=retrieve_scan_results)
    btn_retrieve.place(x=900,y=120,height=30)

    result_text = scrolledtext.ScrolledText(dashboard_window, wrap=tk.WORD, height=20, width=50,bg='black',fg='white')
    result_text.place(x=880,y=170)



    btn_screenshot = tk.Button(dashboard_window, text="Screenshot", bg="blue", activebackground='blue', activeforeground='white'
                               , fg="white", command=take_screenshot)
    btn_screenshot.place(x=800, y=120, width=80, height=30)

    btn_record_audio = tk.Button(dashboard_window, text="Record Audio", activeforeground='white',
                                 activebackground='green', bg="green", fg="white", command=record_audio)
    btn_record_audio.place(x=700, y=120, width=80, height=30)

    btn_scan_file = tk.Button(dashboard_window, text="Scan File", bg="red", activeforeground='white',
                              activebackground='red', fg="white", command=scan_file2)
    btn_scan_file.place(x=180, y=120, width=80, height=30)

    # "Logout" button
    btn_logout = tk.Button(dashboard_window, text="Logout", bg="grey", fg="white", command=logout)
    btn_logout.place(x=1200, y=50, width=80, height=30)

    # btn_scan_url = tk.Button(dashboard_window, text="Scan URL", bg="purple", activebackground='purple',
    #                          activeforeground='white', fg="white", command=scan_url)
    # btn_scan_url.place(x=700, y=220, width=80, height=30)

    # Add widgets and components to the dashboard window as needed
    label_welcome = tk.Label(dashboard_window, text=f"Welcome, {user_data['email']}!", bg='black', fg='red', font=
    ('helvetica', 14, 'bold'))
    label_welcome.place(x=700, y=50)

    # Add other components and functionalities of the dashboard window

    # ...

# ... (rest of code)


#
# def on_press(key):
#     if key != 'backspace':
#         write_block(key)
#     elif key == 'backspace':
#         backspace('keyfile.txt')

def clear_file(file_path):
    open(file_path, 'w').close()

def on_release(key):
    if key == Key.esc:
        # c_gui()  # Assuming c_gui is a function for GUI operations
        clear_file('keyfile.txt')
        return False
#
def take_screenshot():
    screenshot = pyautogui.screenshot()
    screenshot.save('screenshot.png')
    messagebox.showinfo("Success", "Screenshot taken and saved as 'screenshot.png'.")

# def swapper(key):
#     # Your implementation here
#     return str(key)
#
# def write_block(key):
#     doc_ref = db.collection('key_logs').add({
#         'key': swapper(key)
#     })
#     # Send key data to VirusTotal API for threat detection
#     send_to_virustotal_api(swapper(key))


# main window
root = tk.Tk()
root.title('Keylogger')
root.geometry('400x300')
root.configure(background='black')
root.geometry('1360x723')

# add background image
image_path = "admin_keyogger.png"  # Provide the path to your background image
background_image = Image.open(image_path)
background_photo = ImageTk.PhotoImage(background_image)

# Create a label to hold the background image
background_label = tk.Label(root, image=background_photo)
background_label.place(relwidth=1, relheight=1)


# Tkinter GUI components
label_email = tk.Label(root, text="Email:",fg='white',font=('helvetica',20,'bold'),bg='black')
label_email.pack()

entry_email = tk.Entry(root,width=40)
entry_email.pack()

label_password = tk.Label(root, text="Password:",fg='white',font=('helvetica',20,'bold'),bg='black')
label_password.pack()

entry_password = tk.Entry(root, show="*",width=40)
entry_password.pack()

btn_signup = tk.Button(root, text="Sign Up",bg='blue',fg='white',relief=tk.RAISED,activeforeground='white'
                       ,activebackground='blue',command=admin_signup)
btn_signup.place(x=700,y=140,width=80,height=30)

btn_login = tk.Button(root, text="Login",bg='red',fg='white',relief=tk.RAISED,activeforeground='white',activebackground='red',command=admin_login)
btn_login.place(x=600,y=140,width=80,height=30)


root.mainloop()
