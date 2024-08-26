import scapy.all as scapy
import customtkinter
import nmap
import subprocess
import socket
import sys
import ctypes
from os import listdir


back_app=None    

def runtime_scan():
    hostt = socket.gethostname()
    ip_add = socket.gethostbyname(hostt)
    npaw = nmap.PortScanner()
    npaw.scan(ip_add, "1-1000")
    
    for host in npaw.all_hosts():
        host_ip='Host : %s ' % (host)
        state=('State : %s' % npaw[host].state())
        for proto in npaw[host].all_protocols():
            lport = npaw[host][proto].keys()
    
    opport=''
    
    for ppo in lport:
        opport = opport + str(ppo) + ","
    
    opport_2 = opport[:-1] 
    command = f"nmap -p {opport_2} --script vuln {ip_add}"
    
    result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    result_rel = result.stdout[:-1]
    result_rel = result_rel[result_rel.find('\n')+1:result_rel.rfind('\n')]
    result_rel = result_rel[result_rel.find('\n')+1:]
    
    full_text = host_ip + '\n' + state
    
    global back_app
    back_app = customtkinter.CTk()
    back_app.title("NTLan Scan")
    back_app.geometry("1000x700")
    customtkinter.set_appearance_mode("dark")
    scrollable_frame_2 = customtkinter.CTkScrollableFrame(back_app, orientation="vertical", height=690, width=980)
    scrollable_frame_2.grid(row=0,column=0,padx=0,pady=(0,0))
    
    label_6 = customtkinter.CTkLabel(scrollable_frame_2, text=full_text, fg_color="transparent", justify="left")
    label_6.grid(row=1, column=0, padx=0, pady=(10,0), sticky="nw")
    label_7 = customtkinter.CTkLabel(scrollable_frame_2, text=result_rel, fg_color="transparent", justify="left")
    label_7.grid(row=2, column=0, padx=0, pady=(10,0), sticky="nw")
    label_8 = customtkinter.CTkLabel(scrollable_frame_2, text="Zafiyet Taraması Sonuçları", fg_color="green", justify="left", corner_radius=10)
    label_8.grid(row=0, column=0, padx=0, pady=(10,0), sticky="nw")

    back_app.mainloop()
    
try:
    if not sys.argv[1]:
        pass
    else:
        runtime_scan()
except:
    pass    


app = customtkinter.CTk()
app.title("NTLan Scan")
app.geometry("800x300")
customtkinter.set_appearance_mode("dark")

baslik = customtkinter.CTkLabel(app, text="ARP Taraması", fg_color="#637A9F", text_color="white", width=200, height=30, corner_radius=10, anchor="center")
baslik.grid(row=0, column=0, padx=30, pady=(10,0), sticky="n")

label = customtkinter.CTkLabel(app, text="Ağ içerisinde bulunan cihazları\n\n bulmak için network adresini giriniz:", fg_color="transparent")
label.grid(row=0, column=0,padx=30, pady=(70, 0))


entry = customtkinter.CTkEntry(app, placeholder_text="192.168.1.0/24")
entry.grid(row=1, column=0,padx=55,pady=(50, 0),sticky="wn" )


def new_window():
    new=customtkinter.CTkToplevel(app)
    new.title("Sonuçlar")
    new.geometry("700x300")
    response_text = ""
    for packet in answered_list:
        response_text += str(packet[1].summary()) + "\n"
    w_label = customtkinter.CTkLabel(new, text=response_text ,fg_color="transparent")
    w_label.grid(padx=0, pady=0)

syc=0
def sch_tsk():
    try:
        dosyalar = listdir()
        for j in dosyalar:
            if j == "NTLan_Task.txt":
                global syc
                syc = syc + 1
            else:
                pass
            
        if syc == 0:    
            with open("NTLan_Task.txt", "w") as dosya:
                dosya.write("")
        else: 
            with open("NTLan_Task.txt", "r") as dosya:
                dosya = dosya.read()
                if len(dosya) > 0 :
                    if str(check_var.get()) == "on":
                        with open("NTLan_Task.txt", "w") as dosya:
                            dosya.write("")
                        try:
                            clear_task = f"schtasks /delete /tn NTLan"
                            cls_tsk = subprocess.Popen(clear_task, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, universal_newlines=True)
                            cls_tsk.stdin.write("y" + "\n")
                            cls_tsk.stdin.flush()
                        except:
                            pass
                    else:
                        ctypes.windll.user32.MessageBoxW(0, "Bir gorev bulunuyor once temizleyiniz.", "Hata", 1)
                else:
                    
                    if str(check_var.get()) == "on":
                        with open("NTLan_Task.txt", "w") as dosya:
                            dosya.write("") 
                        try:
                            clear_task = f"schtasks /delete /tn NTLan"
                            cls_tsk = subprocess.Popen(clear_task, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, universal_newlines=True)
                            cls_tsk.stdin.write("y" + "\n")
                            cls_tsk.stdin.flush()
                        except:
                            pass
                    else:
                        with open("NTLan_Task.txt", "w") as dosya: 
                            dosya.write("NTLan")
                        slct_opt = zmn_sc.get()
                        file_path = sys.argv[0]
                        print(file_path)
                        
                        if slct_opt == "Gunluk":
                            task_comm = f"schtasks /create /tn NTLan /tr '{file_path}' /sc daily /st 12:00"    
                        elif slct_opt == "Haftalık":
                            task_comm = f"schtasks /create /tn NTLan /tr '{file_path}' /sc weekly /d MON /st 12:00"
                        elif slct_opt == "Aylık":
                            task_comm = f"schtasks /create /tn NTLan /tr '{file_path}' /sc monthly /d 1 /st 12:00"
                        else:
                            ctypes.windll.user32.MessageBoxW(0, "Bir sorun var...", "Hata", 1)
                        subprocess.run(task_comm, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    except:
        pass

trh = ["Gunluk", "Haftalık", "Aylık"]

button = customtkinter.CTkButton(app, text="Başlat", command=lambda: [param(entry.get()), new_window()])
button.grid(row=2, column=0,padx=55, pady=40, sticky="wn",columnspan=2)

baslik_2 = customtkinter.CTkLabel(app, text="Zafiyet Taraması", fg_color="#637A9F", text_color="white", width=200, height=30, corner_radius=10, anchor="center")
baslik_2.grid(row=0, column=1, padx=30, pady=(10,0), sticky="n")

label_2 = customtkinter.CTkLabel(app, text="Güvenlik açığı taramak istediğiniz \n\ncihazın ip adresini giriniz:", fg_color="transparent")
label_2.grid(row=0, column=1, padx=50, pady=(60, 0))

entry_2 = customtkinter.CTkEntry(app, placeholder_text="192.168.1.101")
entry_2.grid(row=1, column=1, padx=0, pady=(50,0), sticky="n")

baslik_3 = customtkinter.CTkLabel(app, text="Görev Zamanlayıcı", fg_color="#637A9F", text_color="white", width=200, height=30, corner_radius=10, anchor="center")
baslik_3.grid(row=0, column=2, padx=0, pady=(10,0), sticky="n")

label_3 = customtkinter.CTkLabel(app, text="Seçiminize göre otomatik \n\ntarama yaptırabilirsiniz:", fg_color="transparent")
label_3.grid(row=0, column=2, padx=0, pady=(65, 0), sticky="n")

zmn_sc = customtkinter.CTkComboBox(app, values=trh)
zmn_sc.grid(row=1, column=2, padx=0, pady=(50,0), sticky="n")


check_var = customtkinter.StringVar(value="off")
checkbox = customtkinter.CTkCheckBox(app, text="Zamanlanmış görevleri \ntemizle", variable=check_var, onvalue="on", offvalue="off")
checkbox.grid(row=1, column=2, padx=0, pady=10, sticky="n")


button_sch = customtkinter.CTkButton(app, text="Uygula", command=sch_tsk)
button_sch.grid(row=2, column=2,padx=0, pady=(40,0), sticky="n",columnspan=2)

def new_window_2():
    second=customtkinter.CTkToplevel(app)
    second.title("Güvenlik Taraması Sonuçları")
    second.geometry("1000x700")
    scrollable_frame = customtkinter.CTkScrollableFrame(second, orientation="vertical", height=690, width=980)
    scrollable_frame.grid(row=0,column=0,padx=0,pady=(0,0))
    
    for host in npaw.all_hosts():
        host_ip='Host : %s ' % (host)
        state=('State : %s' % npaw[host].state())
        for proto in npaw[host].all_protocols():
            lport = npaw[host][proto].keys()
    
    opport=''
    
    for ppo in lport:
        opport = opport + str(ppo) + ","
    
    opport_2 = opport[:-1]
    command = f"nmap -p {opport_2} --script vuln {entry_2.get()}"
    
    result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    result_rel = result.stdout[:-1]
    result_rel = result_rel[result_rel.find('\n')+1:result_rel.rfind('\n')]
    result_rel = result_rel[result_rel.find('\n')+1:]
    
    full_text = host_ip + '\n' + state
    
    label_4 = customtkinter.CTkLabel(scrollable_frame, text=full_text, fg_color="transparent", justify="left")
    label_4.grid(row=1, column=0, padx=0, pady=(10,0), sticky="nw")
    label_5 = customtkinter.CTkLabel(scrollable_frame, text=result_rel, fg_color="transparent", justify="left")
    label_5.grid(row=2, column=0, padx=0, pady=(10,0), sticky="nw")
    label_6 = customtkinter.CTkLabel(scrollable_frame, text="Zafiyet Taraması Sonuçları", fg_color="green", justify="left", corner_radius=10)
    label_6.grid(row=0, column=0, padx=0, pady=(10,0), sticky="nw")


button_2 = customtkinter.CTkButton(app,text="Başlat",command=lambda: [srch(entry_2.get()), new_window_2()])
button_2.grid(row=2, column=1, padx=0, pady=40,sticky="n")


def param(blck):
    request_arp = scapy.ARP(pdst=blck)
    broadcast_arp = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    combined = broadcast_arp/request_arp
    global answered_list
    (answered_list,unanswered) = scapy.srp(combined,timeout=1)
   
def srch(trgt=None):
    global npaw
    npaw = nmap.PortScanner()
    npaw.scan(entry_2.get(),"1-1000")
    
app.mainloop()