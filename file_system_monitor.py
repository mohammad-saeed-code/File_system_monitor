import os
import stat
import datetime
import pwd
import hashlib
import smtplib
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import threading
import PySimpleGUI as sg
import subprocess


obs_lock = threading.RLock()
notification_email = ''
log_file = ""
memory_logs = []
monitored_files = []
obs_map = {}

monitoring_status = False


class file:
    def __init__(self, path):
        try:
            if os.path.exists(path):
                self.path = path
                if os.path.isdir(path):
                    self.file_type = "DIR"
                    self.file_name = os.path.dirname(self.path)
                else:
                    self.file_type = "FILE"
                    self.file_name = os.path.basename(self.path)
        except Exception as e:
            print(f"error loading the file path {e}")

        self.time = None
        self.file_size = None
        self.file_las_mod = None
        self.file_permission_hr = ""
        self.file_owner = None
        self.file_hash = None
        self.file_stat = None
        self.file_mode = None
        self.update()

    def update(self):
        self.time = datetime.datetime.now().strftime("%d/%m/%Y, %H:%M:%S")
        self.file_size = os.path.getsize(self.path)
        self.file_las_mod = datetime.datetime.fromtimestamp(os.path.getmtime(self.path)).strftime("%Y-%m-%d %H:%M:%S")
        self.file_owner = pwd.getpwuid(os.stat(self.path).st_uid).pw_name
        self.file_permission_hr = stat.filemode(os.stat(self.path).st_mode)
        self.file_hash = self.get_hash()
        self.file_stat = os.stat(self.path)
        self.file_mode = self.file_stat.st_mode

    def get_hash(self):
        if os.path.isfile(self.path):
            hash_func = hashlib.md5()
            with open(self.path, 'rb') as f:
                while chunk := f.read(8192):
                    hash_func.update(chunk)
            return hash_func.hexdigest()
        else:
            return "no hash for DIR"

    def get_state(self):
        return {
            "file_name": self.file_name,
            "file_size": self.file_size,
            "file_permission_hr": self.file_permission_hr,
            "file_hash": self.file_hash
        }


class file_Monitor(FileSystemEventHandler):
    def __init__(self, file_object):
        super().__init__()
        self.file_object = file_object

    def on_modified(self, event):
        if event.src_path == self.file_object.path:
            changes,message = detect_change_and_generate_message(self.file_object)
            if changes:
                logging(self.file_object,message)
                system_notification("File monitor notification ", message)
                send_notifications(message, notification_email)

    def on_deleted(self, event):
        message = f"deleted: {event.src_path} at {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        logging(self.file_object, message)
        system_notification("File monitor notification", message)
        send_notifications(message, notification_email)

    def on_moved(self, event):
        message = (f"moved: {event.src_path} to {event.dest_path} at "
                   f"{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        logging(self.file_object, message)
        system_notification("File monitor notification", message)
        send_notifications(message, notification_email)


def detect_change_and_generate_message(file_object):
    old_state = file_object.get_state()
    file_object.update()
    new_state = file_object.get_state()
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    Final_message = f"Here are the changes detected at {timestamp}:\n"
    changes_found = False

    if old_state["file_name"] != new_state["file_name"]:
        Final_message += f"File name was changed from {old_state['file_name']} to {new_state['file_name']} ||  "
        changes_found = True
    if old_state["file_size"] != new_state["file_size"]:
        Final_message += f"File size was changed from {str(old_state['file_size'])} to {str(new_state['file_size'])} ||  "
        changes_found = True
    if old_state["file_permission_hr"] != new_state["file_permission_hr"]:
        Final_message += f"File permissions were changed from {old_state['file_permission_hr']} to {new_state['file_permission_hr']} ||  "
        changes_found = True
    if old_state["file_hash"] != new_state["file_hash"]:
        Final_message += f"File hash was changed from {old_state['file_hash']} to {new_state['file_hash']}  || "
        changes_found = True

    if not changes_found:
        Final_message += "No changes detected.\n"

    print("Final message to be sent:")
    print(Final_message)
    return changes_found,Final_message



def logging(file_object,message=''):

    global log_file

    if not log_file or not os.path.exists(log_file):
        log_file = "logging.txt"
        with open(log_file, 'w') as f:
            header = ("Timestamp | Path | Filename | File owner | File type | "
                      "Filesize | Last Modified | Permissions | File Hash\n")
            f.write(header)


    entry = (f"{file_object.time} | {file_object.path} | {file_object.file_name} | "
             f"{file_object.file_owner} | {file_object.file_type} | "
             f"{file_object.file_size} | {file_object.file_las_mod} | {file_object.file_permission_hr} | "
             f"{file_object.file_hash}")

    if message:
        entry += f"\nChange message: {message}"

    with open(log_file, 'a') as f:
        f.write(entry + "\n")
    memory_logs.append(entry)



def send_notifications(message, recipient):
    from_email = "jackloffy@gmail.com"
    to_emails = [recipient]
    smtp_server = "smtp.gmail.com"
    smtp_port = 587
    smtp_user = "add your gmail account here"
    smtp_password = ""  # add your password here please note your normal gmail password wont work add you need to create a gmail access password
    subject = "File Change Notification"

    msg = MIMEMultipart()
    msg['From'] = from_email
    msg['To'] = ', '.join(to_emails)
    msg['Subject'] = subject

    msg.attach(MIMEText(message, 'html', 'utf-8'))

    try:
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.ehlo()
        server.starttls()
        server.ehlo()
        server.login(smtp_user, smtp_password)
        server.sendmail(from_email, to_emails, msg.as_string())
        server.quit()
        print("Email sent successfully!")
    except Exception as e:
        print("Error sending email:", e)


def system_notification(title,message):
    try:
        subprocess.run(["notify-send", title, message], check=True)
    except Exception as e:
        print("Error sending system notification:", e)

def sms_notification():
    print("in the work")

def change_permissions(file_object, u_read=None, u_write=None, u_execute=None,
                       g_read=None, g_write=None, g_execute=None,
                       o_read=None, o_write=None, o_execute=None):
    new_permissions = file_object.file_mode

    if u_read is not None:
        if u_read:
            new_permissions |= stat.S_IRUSR
        else:
            new_permissions &= ~stat.S_IRUSR

    if u_write is not None:
        if u_write:
            new_permissions |= stat.S_IWUSR
        else:
            new_permissions &= ~stat.S_IWUSR

    if u_execute is not None:
        if u_execute:
            new_permissions |= stat.S_IXUSR
        else:
            new_permissions &= ~stat.S_IXUSR

    if g_read is not None:
        if g_read:
            new_permissions |= stat.S_IRGRP
        else:
            new_permissions &= ~stat.S_IRGRP

    if g_write is not None:
        if g_write:
            new_permissions |= stat.S_IWGRP
        else:
            new_permissions &= ~stat.S_IWGRP

    if g_execute is not None:
        if g_execute:
            new_permissions |= stat.S_IXGRP
        else:
            new_permissions &= ~stat.S_IXGRP

    if o_read is not None:
        if o_read:
            new_permissions |= stat.S_IROTH
        else:
            new_permissions &= ~stat.S_IROTH

    if o_write is not None:
        if o_write:
            new_permissions |= stat.S_IWOTH
        else:
            new_permissions &= ~stat.S_IWOTH

    if o_execute is not None:
        if o_execute:
            new_permissions |= stat.S_IXOTH
        else:
            new_permissions &= ~stat.S_IXOTH

    os.chmod(file_object.path, new_permissions)
    print(f"Permissions updated for {file_object.path}")
    file_object.update()
    logging(file_object)


def fun_path_list(path):
    with open("path_list.txt", 'a') as f:
        f.write(path + "\n")


def remove_path_from_list(target_path, path_list_file="path_list.txt"):

    if not os.path.exists(path_list_file):
        print(f"{path_list_file} does not exist.")
        return

    with open(path_list_file, "r") as f:
        lines = f.readlines()

    remaining_lines = [line for line in lines if line.strip() != target_path]

    with open(path_list_file, "w") as f:
        f.writelines(remaining_lines)

    print(f"Removed {target_path} from {path_list_file}")




def start_monitoring(file_object):
    with obs_lock:
        if file_object in obs_map:
            return
        watchdoggy = file_Monitor(file_object)
        obs = Observer()
        target = file_object.path if file_object.file_type == "DIR" else os.path.dirname(file_object.path)
        obs.schedule(watchdoggy, target, recursive=False)
        obs.start()
        obs_map[file_object] = obs
        print("started monitoring")


def stop_monitoring(file_object):
    with obs_lock:
        obs = obs_map.get(file_object)
        if obs:
            obs.stop()
            obs.join()
            del obs_map[file_object]


def load_old_lists(window):
    global monitored_files
    if os.path.exists("path_list.txt"):
        with open("path_list.txt", "r") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        file_obj = file(line)
                        monitored_files.append(file_obj)
                    except Exception as e:
                        print(f"Error loading file {line}: {e}")
    window['-FILELIST-'].update([f"{f.file_name} ({f.path})" for f in monitored_files])


sg.theme("DarkBlue3")

layout = [
    [sg.Text("File Monitoring Tool", font=("Helvetica", 20), justification='center', expand_x=True)],
    [sg.Button("Add File"), sg.Button("Remove Item"), sg.Button("Change Permissions")],
    [sg.Text("Monitored Items:")],
    [sg.Listbox(values=[], size=(80, 20), key='-FILELIST-', enable_events=True),
     sg.Listbox(values=[], size=(100, 20), key='-LOGLIST-', enable_events=True)],
    [sg.Text("Notification Email:"), sg.Input(key='-EMAIL-', size=(40, 1))],
    [sg.Text("Monitoring Status:"),
     sg.Text("OFF", key="-STATUS-", background_color="red", text_color="white", size=(6, 1))],
    [sg.Button("Test Notification"), sg.Button("Start Monitoring"), sg.Button("Stop Monitoring"), sg.Button("Exit")]
]

window = sg.Window("File Monitoring Tool", layout, size=(1500, 800), finalize=True)
load_old_lists(window)

while True:
    event, values = window.read(timeout=100)
    if event in (sg.WINDOW_CLOSED, "Exit"):
        break

    if event == "Add File":
        file_path = sg.popup_get_file("select file ", no_window=True)
        if file_path and os.path.isfile(file_path):
            try:
                file_object = file(file_path)
                fun_path_list(file_path)
                logging(file_object)
                monitored_files.append(file_object)
                if monitoring_status:
                    window['-FILELIST-'].update([f"{f.file_name} ({f.path})" for f in monitored_files])
                    start_monitoring(file_object)
                    system_notification("File monitor notification ","a new file was add")
            except Exception as e:
                sg.popup_error(f"error adding file: {e}")


    if event == "Remove Item":
        selected = values['-FILELIST-']
        if not selected:
            sg.popup("Please select a file or directory from the list first.")
        else:
            index = window['-FILELIST-'].get_indexes()[0]
            file_to_remove = monitored_files[index]
            stop_monitoring(file_to_remove)
            monitored_files.remove(file_to_remove)
            remove_path_from_list(file_to_remove.path)
            window['-FILELIST-'].update([f"{f.file_name} ({f.path})" for f in monitored_files])
            sg.popup(f"Removed {file_to_remove.file_name} from monitoring.")

    if event == "Change Permissions":
        selected = values['-FILELIST-']
        if not selected:
            sg.popup("Please select a file or directory from the list first.")
        else:
            index = window['-FILELIST-'].get_indexes()[0]
            file_to_change = monitored_files[index]
            mode = file_to_change.file_stat.st_mode
            perm_layout = [
                [sg.Text("Owner Permissions:")],
                [sg.Checkbox("Read", default=bool(mode & stat.S_IRUSR), key='or'),
                 sg.Checkbox("Write", default=bool(mode & stat.S_IWUSR), key='ow'),
                 sg.Checkbox("Execute", default=bool(mode & stat.S_IXUSR), key='ox')],
                [sg.Text("Group Permissions:")],
                [sg.Checkbox("Read", default=bool(mode & stat.S_IRGRP), key='gr'),
                 sg.Checkbox("Write", default=bool(mode & stat.S_IWGRP), key='gw'),
                 sg.Checkbox("Execute", default=bool(mode & stat.S_IXGRP), key='gx')],
                [sg.Text("Others Permissions:")],
                [sg.Checkbox("Read", default=bool(mode & stat.S_IROTH), key='or2'),
                 sg.Checkbox("Write", default=bool(mode & stat.S_IWOTH), key='ow2'),
                 sg.Checkbox("Execute", default=bool(mode & stat.S_IXOTH), key='ox2')],
                [sg.Button("Apply"), sg.Button("Cancel")]
            ]
            perm_window = sg.Window("Change Permissions", perm_layout)
            while True:
                pevent, pvalues = perm_window.read()
                if pevent in (sg.WIN_CLOSED, "Cancel"):
                    break
                if pevent == "Apply":
                    change_permissions(file_to_change,
                                       u_read=pvalues['or'], u_write=pvalues['ow'], u_execute=pvalues['ox'],
                                       g_read=pvalues['gr'], g_write=pvalues['gw'], g_execute=pvalues['gx'],
                                       o_read=pvalues['or2'], o_write=pvalues['ow2'], o_execute=pvalues['ox2'])
                    sg.popup("Permissions updated.")
                    break
            perm_window.close()

    if event == "Test Notification":
        notification_email = values['-EMAIL-']
        if notification_email:
            test_msg = (f"Test Notification: File monitoring tool is working at "
                        f"{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            send_notifications(test_msg, notification_email)
        else:
            sg.popup("Please enter a notification email.")

    if event == "Start Monitoring":
        notification_email = values['-EMAIL-']
        monitoring_status = True
        with obs_lock:
            for file_obj in monitored_files:
                if file_obj not in obs_map:
                    start_monitoring(file_obj)
        sg.popup("Started monitoring for all selected files and directories.")

    if event == "Stop Monitoring":
        with obs_lock:
            for fobj, obs in list(obs_map.items()):
                obs.stop()
                obs.join()
            obs_map.clear()
        monitoring_status = False
        sg.popup("Monitoring stopped.")

    window['-LOGLIST-'].update(memory_logs)
    if monitoring_status:
        window["-STATUS-"].update("ON", background_color="green")
    else:
        window["-STATUS-"].update("OFF", background_color="red")

window.close()

with obs_lock:
    for fobj, obs in list(obs_map.items()):
        obs.stop()
        obs.join()
    obs_map.clear()


