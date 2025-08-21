#!/usr/bin/env python3
"""
Snmap GUI - CustomTkinter
Dark theme (blue/black) GUI for the Super Nmap script.
Features:
 - Select targets from file (-f)
 - Enter single target (-t) or subnet (-ts)
 - Enter custom Nmap flags
 - Start/Stop scan
 - Progress bar and live output
 - Option to save results to JSON

Dependencies:
 - customtkinter (pip install customtkinter)
 - python-nmap (pip install python-nmap)
 - tqdm (optional for CLI)
 - colorama (used in original script, not strictly required here)

Note: running Nmap scans requires nmap installed on the system and proper permissions.
"""

import threading
import queue
import json
import os
import time
from pathlib import Path
from tkinter import filedialog

import customtkinter as ctk
import nmap

# ---------------- Appearance -----------------
ctk.set_appearance_mode("dark")  # dark mode
ctk.set_default_color_theme("blue")  # blue accent

# ---------------- Helpers --------------------

def read_ips(file_path):
    try:
        with open(file_path, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        return []


def run_nmap_scan_single(target, flags, timeout=120):
    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=target, arguments=" ".join(flags), timeout=timeout)
        return nm
    except Exception as e:
        return str(e)


# ---------------- GUI Application -------------
class SnmapGUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Twil-Industries - Super Nmap GUI")
        self.geometry("980x680")
        self.minsize(920, 600)

        # state
        self.targets = []
        self.results = {}
        self.scan_thread = None
        self.queue = queue.Queue()
        self.stop_event = threading.Event()

        # layout frames
        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=2)
        self.grid_rowconfigure(0, weight=1)

        self.sidebar = ctk.CTkFrame(self, width=320, corner_radius=8)
        self.sidebar.grid(row=0, column=0, padx=12, pady=12, sticky="nsew")

        self.main_area = ctk.CTkFrame(self, corner_radius=8)
        self.main_area.grid(row=0, column=1, padx=12, pady=12, sticky="nsew")
        self.main_area.grid_rowconfigure(1, weight=1)

        self._build_sidebar()
        self._build_main()

        # schedule queue processing
        self.after(100, self._process_queue)

    def _build_sidebar(self):
        ctk.CTkLabel(self.sidebar, text="Targets", font=ctk.CTkFont(size=18, weight="bold")).grid(row=0, column=0, padx=12, pady=(12, 6), sticky="w")

        # file selector
        self.file_path_var = ctk.StringVar()
        file_frame = ctk.CTkFrame(self.sidebar, corner_radius=6)
        file_frame.grid(row=1, column=0, padx=12, pady=6, sticky="ew")
        file_frame.grid_columnconfigure(0, weight=1)

        self.file_entry = ctk.CTkEntry(file_frame, textvariable=self.file_path_var, placeholder_text="Select IP file...", state='normal')
        self.file_entry.grid(row=0, column=0, padx=8, pady=8, sticky="ew")
        ctk.CTkButton(file_frame, text="Browse", width=80, command=self._browse_file).grid(row=0, column=1, padx=8, pady=8)

        # single target and subnet
        ctk.CTkLabel(self.sidebar, text="Single IP / Subnet", anchor="w").grid(row=2, column=0, padx=12, pady=(8, 0), sticky="w")
        self.target_var = ctk.StringVar()
        self.subnet_var = ctk.StringVar()
        self.target_entry = ctk.CTkEntry(self.sidebar, textvariable=self.target_var, placeholder_text="192.168.1.10")
        self.target_entry.grid(row=3, column=0, padx=12, pady=6, sticky="ew")
        self.subnet_entry = ctk.CTkEntry(self.sidebar, textvariable=self.subnet_var, placeholder_text="192.168.1.0/24")
        self.subnet_entry.grid(row=4, column=0, padx=12, pady=6, sticky="ew")

        # flags
        ctk.CTkLabel(self.sidebar, text="Nmap Flags", anchor="w").grid(row=5, column=0, padx=12, pady=(8, 0), sticky="w")
        self.flags_var = ctk.StringVar(value="-sS")
        self.flags_entry = ctk.CTkEntry(self.sidebar, textvariable=self.flags_var)
        self.flags_entry.grid(row=6, column=0, padx=12, pady=6, sticky="ew")

        # JSON output
        self.json_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(self.sidebar, text="Save results to JSON", variable=self.json_var, onvalue=True, offvalue=False).grid(row=7, column=0, padx=12, pady=(6,0), sticky="w")
        self.json_path_var = ctk.StringVar()
        self.json_entry = ctk.CTkEntry(self.sidebar, textvariable=self.json_path_var, placeholder_text="results.json")
        self.json_entry.grid(row=8, column=0, padx=12, pady=6, sticky="ew")

        # control buttons
        btn_frame = ctk.CTkFrame(self.sidebar, corner_radius=6)
        btn_frame.grid(row=9, column=0, padx=12, pady=12, sticky="ew")
        btn_frame.grid_columnconfigure((0,1), weight=1)

        self.start_btn = ctk.CTkButton(btn_frame, text="Start Scan", command=self.start_scan)
        self.start_btn.grid(row=0, column=0, padx=6, pady=6, sticky="ew")
        self.stop_btn = ctk.CTkButton(btn_frame, text="Stop", fg_color=("#b71c1c","#b71c1c"), command=self.stop_scan)
        self.stop_btn.grid(row=0, column=1, padx=6, pady=6, sticky="ew")

        # targets list
        ctk.CTkLabel(self.sidebar, text="Resolved Targets", font=ctk.CTkFont(size=14, weight="bold")) .grid(row=10, column=0, padx=12, pady=(6,0), sticky="w")
        self.targets_box = ctk.CTkTextbox(self.sidebar, height=120, state='disabled')
        self.targets_box.grid(row=11, column=0, padx=12, pady=6, sticky="ew")

    def _build_main(self):
        # top controls (status + progress)
        top_frame = ctk.CTkFrame(self.main_area)
        top_frame.grid(row=0, column=0, padx=12, pady=12, sticky="ew")
        top_frame.grid_columnconfigure(1, weight=1)

        self.status_label = ctk.CTkLabel(top_frame, text="Idle", anchor="w")
        self.status_label.grid(row=0, column=0, padx=6, pady=6, sticky="w")

        self.progress = ctk.CTkProgressBar(top_frame)
        self.progress.grid(row=0, column=1, padx=6, pady=6, sticky="ew")

        # output textbox
        ctk.CTkLabel(self.main_area, text="Output", font=ctk.CTkFont(size=16, weight="bold")) .grid(row=1, column=0, padx=12, pady=(6,0), sticky="w")
        self.output_box = ctk.CTkTextbox(self.main_area, wrap='word')
        self.output_box.grid(row=2, column=0, padx=12, pady=6, sticky="nsew")

    def _browse_file(self):
        path = filedialog.askopenfilename(title="Select IP file", filetypes=[("Text files","*.txt"), ("All files","*.*")])
        if path:
            self.file_path_var.set(path)

    def _resolve_targets(self):
        targets = []
        if self.file_path_var.get():
            targets.extend(read_ips(self.file_path_var.get()))
        if self.target_var.get():
            targets.append(self.target_var.get())
        if self.subnet_var.get():
            targets.append(self.subnet_var.get())
        # remove duplicates and empty
        seen = []
        final = []
        for t in targets:
            t = t.strip()
            if not t:
                continue
            if t not in seen:
                seen.append(t)
                final.append(t)
        self.targets = final
        self.targets_box.configure(state='normal')
        self.targets_box.delete("1.0", "end")
        if final:
            for t in final:
                self.targets_box.insert("end", t + "\n")
        self.targets_box.configure(state='disabled')
        return final

    def start_scan(self):
        if self.scan_thread and self.scan_thread.is_alive():
            return
        targets = self._resolve_targets()
        if not targets:
            ctk.messagebox = None
            self._append_output("No targets specified. Use file, single IP or subnet.\n")
            return

        flags_raw = self.flags_var.get().strip()
        flags = flags_raw.split() if flags_raw else ["-sS"]

        # prepare
        self.results = {}
        self.stop_event.clear()
        self.progress.set(0)
        self.status_label.configure(text=f"Scanning 0/{len(targets)}")
        self.start_btn.configure(state='disabled')

        # start thread
        self.scan_thread = threading.Thread(target=self._scan_targets_thread, args=(targets, flags), daemon=True)
        self.scan_thread.start()

    def stop_scan(self):
        if self.scan_thread and self.scan_thread.is_alive():
            self.stop_event.set()
            self._append_output("Stop requested. Waiting for current scan to finish...\n")

    def _scan_targets_thread(self, targets, flags):
        total = len(targets)
        completed = 0
        nm = nmap.PortScanner()

        for target in targets:
            if self.stop_event.is_set():
                break
            self.queue.put(("status", f"Scanning {target} ({completed}/{total})"))
            try:
                # run scan
                nm.scan(hosts=target, arguments=" ".join(flags))
                host_results = None
                if target in nm.all_hosts():
                    host_results = nm[target]
                self.results[target] = host_results
                self.queue.put(("result", (target, host_results)))
            except Exception as e:
                self.results[target] = {"error": str(e)}
                self.queue.put(("result", (target, {"error": str(e)})))

            completed += 1
            self.queue.put(("progress", completed / total))
            time.sleep(0.05)

        # finished
        self.queue.put(("done", None))

    def _process_queue(self):
        try:
            while True:
                item = self.queue.get_nowait()
                kind, payload = item
                if kind == 'status':
                    self.status_label.configure(text=payload)
                elif kind == 'progress':
                    self.progress.set(payload)
                elif kind == 'result':
                    target, host_results = payload
                    self._append_output(f"--- {target} ---\n")
                    if not host_results:
                        self._append_output("  No results or host down\n\n")
                    elif isinstance(host_results, dict) and 'error' in host_results:
                        self._append_output(f"  Error: {host_results['error']}\n\n")
                    else:
                        # minimal pretty output - ports and os
                        if 'osmatch' in host_results:
                            for osm in host_results['osmatch']:
                                self._append_output(f"  OS: {osm.get('name','?')} ({osm.get('accuracy','?')}%)\n")
                        for proto in host_results.all_protocols():
                            ports = host_results[proto].keys()
                            for port in sorted(ports):
                                p = host_results[proto][port]
                                svc = p.get('name','')
                                ver = p.get('version','')
                                state = p.get('state','')
                                reason = p.get('reason','')
                                self._append_output(f"  {proto}/{port}: {state} | {svc} {ver} {(' | reason:'+reason) if reason else ''}\n")
                        # scripts
                        for proto in host_results.all_protocols():
                            for port in host_results[proto].keys():
                                if 'script' in host_results[proto][port]:
                                    for sname, sout in host_results[proto][port]['script'].items():
                                        self._append_output(f"    script {sname}: {sout}\n")
                        self._append_output('\n')
                elif kind == 'done':
                    self._append_output('Scan finished.\n')
                    self._finalize()
        except queue.Empty:
            pass
        finally:
            self.after(150, self._process_queue)

    def _append_output(self, text):
        self.output_box.insert("end", text)
        self.output_box.see("end")

    def _finalize(self):
        # re-enable start button
        self.start_btn.configure(state='normal')
        # save json if needed
        if self.json_var.get():
            path = self.json_path_var.get().strip() or 'results.json'
            try:
                with open(path, 'w') as f:
                    json.dump(self._format_results_for_json(self.results), f, indent=2)
                self._append_output(f"Results saved to {path}\n")
            except Exception as e:
                self._append_output(f"Error saving JSON: {e}\n")

    def _format_results_for_json(self, results):
        formatted = {}
        for target, scan in results.items():
            if not scan:
                formatted[target] = {"error": "No results or host down"}
                continue
            if isinstance(scan, dict) and 'error' in scan:
                formatted[target] = scan
                continue
            # scan is a PortScannerHost object-like dict
            try:
                host_data = {}
                os_guesses = []
                if 'osmatch' in scan:
                    for osm in scan['osmatch']:
                        os_guesses.append({"name": osm.get('name'), "accuracy": osm.get('accuracy')})
                if os_guesses:
                    host_data['OS'] = os_guesses
                ports = []
                for proto in scan.all_protocols():
                    for port in sorted(scan[proto].keys()):
                        p = scan[proto][port]
                        ports.append({
                            'protocol': proto,
                            'port': port,
                            'state': p.get('state'),
                            'service': p.get('name'),
                            'product': p.get('product'),
                            'version': p.get('version'),
                            'reason': p.get('reason')
                        })
                if ports:
                    host_data['ports'] = ports
                # scripts
                scripts = {}
                for proto in scan.all_protocols():
                    for port in scan[proto].keys():
                        if 'script' in scan[proto][port]:
                            for sname, sout in scan[proto][port]['script'].items():
                                scripts.setdefault(str(port), {})[sname] = sout
                if scripts:
                    host_data['scripts'] = scripts
                formatted[target] = host_data
            except Exception as e:
                formatted[target] = {"error": str(e)}
        return formatted


if __name__ == '__main__':
    app = SnmapGUI()
    app.mainloop()
