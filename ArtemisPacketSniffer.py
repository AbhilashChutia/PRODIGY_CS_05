import tkinter as tk
from tkinter import scrolledtext, messagebox
from scapy.all import sniff, IP, TCP
import threading

class PacketSnifferGUI:
    def __init__(self) -> None:
        self.root = tk.Tk()
        self.root.title("Artemis- Network Packet Sniffer")
        self.root.geometry("600x500")
        self.root.config(bg="#808080")

        self.sniffing = False
        self.sniff_thread = None

        self.setup_ui()

    def setup_ui(self):
        
        self.result_text = scrolledtext.ScrolledText(self.root, wrap=tk.WORD, bg="#101010", fg="white")
        self.result_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        button_frame = tk.Frame(self.root, bg="#808080")
        button_frame.pack(pady=10)

        self.start_button = tk.Button(button_frame, text="Start Analyzing", command=self.start_sniffing, bg="#4caf50", fg="white")
        self.start_button.pack(side=tk.LEFT, padx=5, pady=5)

        self.stop_button = tk.Button(button_frame, text="Stop Analyzing", command=self.stop_sniffing, bg="#f44336", fg="white")
        self.stop_button.pack(side=tk.LEFT, padx=5, pady=5)

        self.clear_button = tk.Button(button_frame, text="Clear", command=self.clear_results, bg="#ff9800", fg="white")
        self.clear_button.pack(side=tk.LEFT, padx=5, pady=5)

    def start_sniffing(self):
        if self.sniffing:
            messagebox.showwarning("Warning", "Sniffing is already in progress.")
            return

        self.result_text.delete(1.0, tk.END)
        self.sniffing = True
        self.sniff_thread = threading.Thread(target=self.sniff_packets)
        self.sniff_thread.start()

    def stop_sniffing(self):
        if not self.sniffing:
            messagebox.showwarning("Warning", "No sniffing process is currently running.")
            return

        self.sniffing = False
        self.sniff_thread.join()

    def sniff_packets(self):
        def packet_sniff(packet):
            if packet.haslayer(IP) and packet.haslayer(TCP):
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                protocol = packet[IP].proto
                payload = str(packet[TCP].payload)

                output_string = (f"Source IP: {src_ip}\n"
                                 f"Destination IP: {dst_ip}\n"
                                 f"Source Port: {src_port}\n"
                                 f"Destination Port: {dst_port}\n"
                                 f"Protocol: {protocol}\n"
                                 f"Payload: {payload[:50]}...\n\n")

                self.result_text.insert(tk.END, output_string)
                self.result_text.see(tk.END)

        sniff(filter="tcp", prn=packet_sniff, store=0, stop_filter=lambda p: not self.sniffing)

    def clear_results(self):
        self.result_text.delete(1.0, tk.END)

    def run(self):
        self.root.mainloop()


if __name__ == '__main__':
    app = PacketSnifferGUI()
    app.run()
