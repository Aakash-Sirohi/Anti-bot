import tkinter as tk
from tkinter import filedialog
from tkinter.filedialog import askopenfilename
from tkinter import messagebox
from scapy.all import *
import sqlite3
import hashlib
from collections import Counter



class App(tk.Tk):
    def __init__(self):
        tk.Tk.__init__(self)
        self._frame = None
        self.switch_frame(StartPage)

    def switch_frame(self, frame_class):
        """Destroys current frame and replaces it with a new one."""
        new_frame = frame_class(self)
        if self._frame is not None:
            self._frame.destroy()
        self._frame = new_frame
        self._frame.pack()


class StartPage(tk.Frame):
    def __init__(self, master):
        tk.Frame.__init__(self, master)
       
        start_label = tk.Label(self, text="Anti-Botnet System \n Please choose ")
        page_1_button = tk.Button(self, text="Signature Based Detection",
                                  command=lambda: master.switch_frame(SignatureBased))
        page_2_button = tk.Button(self, text="Behavior Based Detection",
                                  command=lambda: master.switch_frame(BehaviorBased))
        
        start_label.pack(side="top", fill="x", pady=10)
        page_1_button.pack()
        page_2_button.pack()
	
    


class SignatureBased(tk.Frame):
    def __init__(self, master):
        tk.Frame.__init__(self, master)

        page_1_label = tk.Label(self, text="Signature Based Botnet Detection.Please upload file to check whether it is malicious")
        browse_file = tk.Button(self, text="Browse",
                                 command=self.load_file)
        page_1_label.pack(side="top", fill="x", pady=10)
        browse_file.pack()
        start_button = tk.Button(self, text="Return to start page",
                                 command=lambda: master.switch_frame(StartPage))
        start_button.pack()
		
		
    def load_file(self):
        global bot_name1
        filename = askopenfilename(filetypes=(("Executable File", "*.exe"),
                                           ("All files", "*.*") ))
        if filename:
            try:
                file_label=tk.Label(self,text="File uploaded successfully %s" % filename)
                file_label.pack()
                print(filename)
                new_hash=generate_file_md5(filename)
                print("new hash is %s" % new_hash)
                c.execute("SELECT bot_name from signature_data WHERE hash_value=?",(new_hash,))
                rows=c.fetchall()
                if rows:
                    messagebox.showinfo("Attention", "This file is malicious")
                    for row in rows:
                        bot_name1=row[0]
                    label_malicious=tk.Label(self,text="This file is malicious.It is a bot named %s" % bot_name1)
                    label_malicious.pack()
                    
                else:
                    messagebox.showinfo("Anti Bot System", "This file is safe to work with")
                    label_safe=tk.Label(self,text="This file is not malicious")	
                    label_safe.pack()				
            except:
                return showerror("Open Source File", "Failed to read file\n'%s'" % filename)
 
	    

class BehaviorBased(tk.Frame):
    # global suspicious_dns_answers
    def __init__(self, master):
        tk.Frame.__init__(self, master)

        page_2_label = tk.Label(self, text="Behavior Based Analysis.Please input a pcap file for traffic analysis")
        browse_file = tk.Button(self, text="Browse",command=self.load_pcap)
        
        start_button = tk.Button(self, text="Return to start page",command=lambda: master.switch_frame(StartPage))
        page_2_label.pack(side="top", fill="x", pady=10)
        browse_file.pack()
        start_button.pack()
        
    
		
    def load_pcap(self):
        filename1 = askopenfilename(filetypes=(("Packet Capture Files", "*.pcap"),
                                           ("All files", "*.*") ))
        file_label_1=tk.Label(self,text="File uploaded successfully %s" % filename1)
        file_label_1.pack()
        
        #Check for syn flood
        
        self.syn_flood_detection(filename1)
        
        sniff(offline=filename1,filter="ip", prn = parsing_pcap,store=0)
        print("Reading pcap file")
        file_label_01=tk.Label(self,text="Inspecting DNS Packets")
        file_label_01.pack()
        #Inspecting DNS 
        sniff(offline=filename1,lfilter=lambda x:x.haslayer(DNS), prn = self.suspicious_dns_answers,store=0)
        #Inspecting IRC
        
        sniff(offline=filename1,filter="TCP port 6667", prn = self.identify_irc_traffic,store=0,count=100)
        label_irc_count=tk.Label(self,text="Number of irc packets %d" % count_irc)
        label_irc_count.pack()
        #SYN Packets
        
        sniff(offline=fname1,filter="tcp and tcp.flags.syn==1 and tcp.flags.ack==0", prn = self.syn_flood_detection,store=0,count=100)
    
    
		
    def suspicious_dns_answers(self,pkt):
        
        dns_answer=pkt.ancount		    
        ip_src=pkt[IP].src
        ip_dst=pkt[IP].dst
        timestamp=pkt.time
        if(dns_answer>10):
            file_label_03=tk.Label(self,text="Timestamp {} Source IP {} Destination IP {} Answer Count {}".format(timestamp,ip_src,ip_dst,dns_answer))
            file_label_03.pack()
		
        c.execute("""CREATE TABLE IF NOT EXISTS suspicious_dns_data(ip_src text,ip_dst text,answer_count Integer)""")
	
        c.execute("SELECT IP_Source,IP_Destination,Answer_RR FROM pcap_data1 where Answer_RR>5")
        d=conn.cursor()
        for row in c:
            ip_src=row[0]
            ip_dst=row[1]
            answer_count=row[2]
            d.execute("INSERT INTO suspicious_dns_answers(ip_src,ip_dst,answer_count) VALUES(?,?,?)", (row[0], row[1], row[2]))
		
		
    #function to identify irc traffic
    def identify_irc_traffic(self,pkt):
        print("IRC PACKETS")
        global count_irc
        count_irc=count_irc+1
        if(count_irc==1):
            file_label_004=tk.Label(self,text="IRC communication found on port 6667. If you are not using it, it may be a bot communicating with its C&cC server")
            file_label_004.pack()
            count_irc=count_irc+1
		
        # c.execute("SELECT Timestamp,IP_Source,IP_Destination FROM pcap_data1 where Destination_Port=6667 or Source_Port=6667")
        # for rows in c:
            # print("Timestamp {}".format(row[0]))
            # print(" Source IP Address {}".format(row[1]) )
            # print("Destination IP Address".format(row[2]))
    
    def syn_flood_detection(self,filename):
        count = Counter()
        for pkt in PcapReader(filename):
            if TCP in pkt and pkt[TCP].flags & 2:  # TCP SYN packet
                src = pkt.sprintf('{IP:%IP.src%}{IPv6:%IPv6.src%}')
                count[src] += 1
        label_syn=tk.Label(self,text="Number of SYN PACKETS TO particular IP's are %s" % count)
        label_syn.pack()
        
if __name__ == "__main__":
    #Variable used for counting irc packets
    
    count_irc=0
    #Creating signature database
    conn=sqlite3.connect('bot_detection1.db')
    c=conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS signature_data(
			bot_name text,
			hash_value text
)""")
#Generating hash of files	
    def generate_file_md5(filename, blocksize=128):
        m = hashlib.md5()
        with open(filename, "rb" ) as f:
            while True:
                buf = f.read(blocksize)
                if not buf:
                    break
                m.update( buf )
        return m.hexdigest()
    # Inserting database values for signature based bot detection
    # r_bot=generate_file_md5("rbot.exe")
    # Neris=generate_file_md5("Neris.exe")
    # svchosta=generate_file_md5("svchosta.exe")
    
   
    # c.execute("""INSERT INTO signature_data(bot_name,hash_value)
				# VALUES('rbot',?)""",(r_bot,))
    # c.execute("""INSERT INTO signature_data(bot_name,hash_value)
				# VALUES('Neris',?)""",(Neris,))
    # c.execute("""INSERT INTO signature_data(bot_name,hash_value)
				# VALUES('svchosta',?)""",(svchosta,))
    conn.commit()
    c.execute("""SELECT * FROM signature_data""")
    rows1=c.fetchall()
    for row in rows1:
        print(row)	

#Creating table for behavior based detection

    c.execute("""CREATE TABLE IF NOT EXISTS pcap_data1(
            IP_Source text,
            IP_Destination text,
            Source_Port Integer,
            Destination_Port Integer,
            Timestamp text,
            Protocol text,
            Answer_RR Integer,
            Protocols_in_frame text,
            IP_Flags text,
            Length Integer,
            Next_sequence_number text,
            Sequence_number text,
            TCP_Segment_Len Integer,
            tcp_Flags Integer,
            udp_Length Integer,
            dns_answer_count Integer
)""")
    conn.commit()
    
   

    def parsing_pcap(pkt):
        timestamp=pkt.time
        global answer_count
        if IP in pkt:
            ip_src=pkt[IP].src
            ip_dst=pkt[IP].dst
            ip_proto=pkt[IP].proto
        else:
            ip_src=''
            ip_dst=''
            ip_proto=''
        if TCP in pkt:
            src_port=pkt[TCP].sport
            dst_port=pkt[TCP].dport
            seq_num=pkt[TCP].seq
            tcp_flags=pkt[TCP].flags
        else:
            src_port=''
            dst_port=''
            seq_num=''
            tcp_flags=''
        if pkt.haslayer(DNSRR):
            if isinstance(pkt.an, DNSRR):
                answer_count=pkt.ancount
        else:
            answer_count=''
	
		
        c.execute("""INSERT INTO pcap_data1(IP_Source,IP_Destination,Source_Port,Destination_Port,Timestamp,Protocol,Answer_RR,Protocols_in_frame,IP_Flags,Length,Next_sequence_number,Sequence_number,TCP_Segment_Len,tcp_Flags,udp_Length) 
			   VALUES(?,?,?,?,?,'',?,'','','','',?,'',?,'')""",(ip_src,ip_dst,src_port,dst_port,timestamp,answer_count,seq_num,tcp_flags))	
		
        conn.commit()
       
	
	
	
	
	
	
    app = App()
    app.geometry("480x150")
    app.title("ABS(ANTI BOT SYSTEM FOR DETECTION OF BOTS)")
    app.mainloop()
