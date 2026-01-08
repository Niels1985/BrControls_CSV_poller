import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import pandas as pd
import serial
import serial.tools.list_ports
import struct
import subprocess
import threading
import time
import datetime
import sys

# ==========================
#  AUTORISATIE (zoals eerder)
# ==========================
TOEGESTAAN_SERIALS = {
    "38E5-A4DE": "Laptop Niels werk",
    "1234-ABCD": "Laptop testpersoon",
}

def get_volume_serial(drive='C'):
    try:
        output = subprocess.check_output(f'vol {drive}:', shell=True, text=True)
        for line in output.splitlines():
            if "Serial Number" in line:
                return line.strip().split()[-1]
    except Exception:
        return None

serial_id = get_volume_serial()
if serial_id not in TOEGESTAAN_SERIALS:
    tk.Tk().withdraw()
    messagebox.showerror("Licentie", "Deze PC is niet geautoriseerd.")
    sys.exit(1)

SYSTEEM_NAAM = TOEGESTAAN_SERIALS[serial_id]

# ==========================
#  HULPFUNCTIES
# ==========================
def modbus_crc(data: bytes) -> bytes:
    """Modbus RTU CRC16 (little-endian terug)."""
    crc = 0xFFFF
    for pos in data:
        crc ^= pos
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
    return crc.to_bytes(2, byteorder='little')

def get_com_ports():
    return [port.device for port in serial.tools.list_ports.comports()]

def extract_fcode_text(s: str) -> str:
    """Pak functiecode uit COMMTYPE 'xxx (03)' → '03'."""
    s = str(s)
    if "(" in s and ")" in s:
        s = s.split("(")[-1].split(")")[0]
    return s.strip().zfill(2)

def append_log(direction: str, data: bytes):
    """Log TX/RX in HEX met timestamp."""
    ts = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
    prefix = f"{direction} [{ts}]: "
    hexdata = ' '.join(f"{b:02X}" for b in (data or b""))
    log_box.configure(state="normal")
    log_box.insert(tk.END, prefix + hexdata + "\n")
    log_box.see(tk.END)
    log_box.configure(state="disabled")

def export_log():
    fname = filedialog.asksaveasfilename(defaultextension=".txt", initialfile="log.txt")
    if not fname:
        return
    with open(fname, "w", encoding="utf-8") as f:
        f.write(log_box.get("1.0", tk.END))

# ==========================
#  CSV INLEZEN & NORMALISEREN
# ==========================
def laad_csv_pad(pad: str):
    try:
        df = pd.read_csv(pad, sep=';', encoding='cp1252')
    except Exception:
        messagebox.showerror("CSV formaat niet juist", "CSV formaat niet juist, zie documentatie")
        return None

    required = {"WORKREG", "COMMASK", "COMMTYPE", "DATATYPE", "TREND", "enable"}
    if not required.issubset(set(df.columns)):
        messagebox.showerror("CSV formaat niet juist", "CSV formaat niet juist, zie documentatie")
        return None

    # enable filter
    try:
        df = df[df["enable"] == 1].copy()
    except Exception:
        messagebox.showerror("CSV formaat niet juist", "CSV formaat niet juist, zie documentatie")
        return None

    # Normaliseer naar werk-kolommen
    df["Index"]        = df["WORKREG"].astype(int)
    df["CommAsk"]      = df["COMMASK"].astype(int)
    df["FunctionCode"] = df["COMMTYPE"].apply(extract_fcode_text)  # als "03"
    df["Type"]         = df["DATATYPE"].astype(str)                # "Normal"/"DWORD"/"Floating"
    df["Scale"]        = df["TREND"].fillna("").astype(str)
    df["Swap"]         = "NO SWAP"                                 # default
    df["Raw"]          = 0
    df["Scaled"]       = 0.0
    df["CRC"]          = ""

    # Pak alleen de kolommen die de GUI gebruikt
    cols = ["Index", "CommAsk", "FunctionCode", "Type", "Scale", "Swap", "Raw", "Scaled", "CRC"]
    df = df[cols].copy()
    return df

def laad_csv():
    pad = filedialog.askopenfilename(filetypes=[("CSV bestanden", "*.csv")])
    if not pad:
        return
    global df_data
    df = laad_csv_pad(pad)
    if df is None:
        return
    df_data = df
    update_tabel()

# ==========================
#  TYPE/SCALING/INTERPRET
# ==========================
def interpret_data(raw_bytes: bytes, datatype: str, swap: bool):
    """Maak Raw waarde uit data bytes volgens Type & Swap."""
    datatype = str(datatype)
    if datatype == "Normal":
        # 1 register, signed int16
        # swap True → big-endian, anders little-endian (conform eerdere afspraak LSB-MSB)
        return int.from_bytes(raw_bytes, byteorder=("big" if swap else "little"), signed=True)

    if datatype in ("DWORD", "Floating"):
        # 2 registers (4 bytes)
        b = raw_bytes
        if swap:
            b = b[2:4] + b[0:2]   # MSB ←→ LSB
        if datatype == "DWORD":
            return int.from_bytes(b, byteorder="big", signed=False)
        else:  # "Floating"
            try:
                return struct.unpack(">f", b)[0]
            except Exception:
                return 0.0
    # fallback
    return 0

def scale_value(raw, trend: str):
    """Pas Scale (mul/div) toe."""
    try:
        if not trend or trend.strip() == "":
            return raw
        t = trend.lower().strip()
        if t.startswith("div"):
            return raw / float(t.replace("div", ""))
        if t.startswith("mul"):
            return raw * float(t.replace("mul", ""))
    except Exception:
        pass
    return raw

# ==========================
#  GUI CALLBACKS
# ==========================
def update_tabel():
    tree.delete(*tree.get_children())
    if df_data is None or df_data.empty:
        return
    for i, row in df_data.iterrows():
        tree.insert(
            "", "end", iid=i,
            values=(
                int(row["Index"]),
                int(row["CommAsk"]),
                str(row["FunctionCode"]).zfill(2),
                row["Type"],
                row["Scale"],
                row.get("Swap", "NO SWAP"),
                row.get("Raw", 0),
                row.get("Scaled", 0.0),
                row.get("CRC", "")
            ),
            tags=("evenrow" if i % 2 == 0 else "oddrow")
        )

def refresh_com_ports():
    """Poll COM-lijst; update dropdown live."""
    try:
        ports = get_com_ports()
        current = list(com_select['values'])
        if ports != current:
            com_select['values'] = ports
            # Hou huidige selectie vast indien mogelijk
            if com_var.get() not in ports:
                com_var.set(ports[0] if ports else "")
    finally:
        root.after(1500, refresh_com_ports)

def on_double_click(event):
    """Alleen bepaalde kolommen editbaar; met dropdown waar nodig."""
    item = tree.identify_row(event.y)
    column = tree.identify_column(event.x)
    if not item or not column:
        return
    col_index = int(column[1:]) - 1
    kolomnaam = kolommen[col_index]

    # Alleen deze kolommen mogen gewijzigd worden:
    allowed_edits = ["CommAsk", "FunctionCode", "Type", "Scale", "Swap"]
    if kolomnaam not in allowed_edits:
        return

    # Maak editor
    x, y, w, h = tree.bbox(item, column)
    curval = tree.set(item, kolomnaam)

    # Dropdowns
    if kolomnaam == "FunctionCode":
        editor = ttk.Combobox(root, values=["01", "02", "03", "04"], width=max(5, len(curval)))
    elif kolomnaam == "Type":
        editor = ttk.Combobox(root, values=["Normal", "DWORD", "Floating"], width=max(8, len(curval)))
    elif kolomnaam == "Swap":
        editor = ttk.Combobox(root, values=["NO SWAP", "SWAP"], width=max(8, len(curval)))
    else:
        editor = tk.Entry(root)

    editor.place(x=x + tree.winfo_rootx() - root.winfo_rootx(),
                 y=y + tree.winfo_rooty() - root.winfo_rooty(),
                 width=w, height=h)
    editor.insert(0, curval)
    editor.focus_set()

    def commit(_=None):
        new_val = editor.get()
        tree.set(item, kolomnaam, new_val)
        idx = int(item)
        df_data.at[idx, kolomnaam] = (int(new_val) if kolomnaam == "CommAsk" else new_val)
        editor.destroy()

    editor.bind("<Return>", commit)
    editor.bind("<FocusOut>", commit)

# ==========================
#  VERBINDEN/ONTKOPPELEN & UI STATE
# ==========================
def connect_serial():
    global ser, serial_connected
    if serial_connected:
        return
    try:
        port = com_var.get()
        if not port:
            messagebox.showwarning("Geen COM", "Geen COM-poort geselecteerd.")
            return
        ser = serial.Serial(
            port=port,
            baudrate=int(baud_var.get()),
            parity=PARITY_MAP[pariteit_var.get()],
            stopbits=int(stopbits_var.get()),
            bytesize=8,
            timeout=1
        )
        serial_connected = True
    except Exception as e:
        messagebox.showerror("Fout", f"Kan seriële poort niet openen:\n{e}")
        serial_connected = False
    finally:
        update_conn_widgets()

def disconnect_serial():
    global ser, serial_connected, polling
    try:
        if ser and ser.is_open:
            ser.close()
    except Exception:
        pass
    serial_connected = False
    # Stop polling indien actief
    if polling:
        stop_polling_internal()
    update_conn_widgets()

def toggle_connection():
    if serial_connected:
        disconnect_serial()
    else:
        connect_serial()

def update_conn_widgets():
    # Lock/Unlock communicatie-instellingen
    state = "disabled" if serial_connected else "normal"
    com_select.config(state=state)
    baud_select.config(state=state)
    par_select.config(state=state)
    stopbits_select.config(state=state)
    slave_entry.config(state=state)
    timeout_select.config(state=state)
    btn_csv.config(state=state)

    # Knop & lampje
    btn_conn.config(text="Ontkoppelen" if serial_connected else "Verbinden")
    lbl_status.config(text="Verbinding actief" if serial_connected else "Geen verbinding")
    lbl_lamp.config(bg="green" if serial_connected else "#ccc")

    # Poll-knop
    btn_poll.config(state=("normal" if serial_connected else "disabled"))
    if not serial_connected:
        btn_poll.config(text="Start Pollen")

def start_polling():
    """Start poll-thread als niet al bezig en er is verbinding."""
    global polling, poll_thread
    if not serial_connected:
        messagebox.showwarning("Geen verbinding", "Verbind com eerst")
        return
    if polling:
        return  # guard
    polling = True
    btn_poll.config(text="Stop Pollen")
    poll_thread = threading.Thread(target=polling_loop, daemon=True)
    poll_thread.start()

def stop_polling_internal():
    """Stop vlag en UI resetten (intern)."""
    global polling
    polling = False
    btn_poll.config(text="Start Pollen")
    # highlight reset
    for item in tree.get_children():
        tree.item(item, tags=("evenrow" if int(item) % 2 == 0 else "oddrow"))

def toggle_polling():
    if not serial_connected:
        messagebox.showwarning("Geen verbinding", "Verbind com eerst")
        return
    if polling:
        stop_polling_internal()
    else:
        start_polling()

def highlight_row(idx: int):
    for item in tree.get_children():
        tree.item(
            item,
            tags=("highlight",) if int(item) == idx else ("evenrow" if int(item) % 2 == 0 else "oddrow")
        )
    tree.tag_configure("highlight", background="#90ee90")

# ==========================
#  POLLING-LOOP
# ==========================
def polling_loop():
    """Één thread tegelijk; respecteer timeout; stuur TX en verwerk RX."""
    try:
        while polling and serial_connected and ser and ser.is_open:
            if df_data is None or df_data.empty:
                time.sleep(0.2)
                continue

            for i, row in df_data.iterrows():
                if not (polling and serial_connected and ser and ser.is_open):
                    break

                highlight_row(i)

                # Lees de parameters uit de (genormaliseerde) DF
                try:
                    fcode_text = str(row["FunctionCode"]).strip()
                    fcode = int(fcode_text.lstrip("0") or "0")
                    reg   = int(row["CommAsk"])
                    typ   = str(row["Type"])
                    scale = str(row["Scale"])
                    swap  = (str(row.get("Swap", "NO SWAP")).upper() == "SWAP")
                except Exception:
                    df_data.at[i, "CRC"] = "FOUT"
                    tree.set(i, "CRC", "FOUT")
                    time.sleep(0.05)
                    continue

                # Aantal registers
                count = 1 if typ == "Normal" else 2

                #
                # OPBOUW LEESVERZOEK (fc 1/2/3/4). Voor fc3/4 verwachten we bytes=2*count.
                #
                slave = int(slave_var.get())
                if fcode not in (1,2,3,4):
                    # Onbekende fcode → sla over, markeer CRC als FOUT (of laat leeg)
                    df_data.at[i, "CRC"] = "FOUT"
                    tree.set(i, "CRC", "FOUT")
                    continue

                req = bytearray([slave, fcode, (reg >> 8) & 0xFF, reg & 0xFF, 0, count])
                frame = req + modbus_crc(req)

                try:
                    ser.write(frame)
                    append_log("TX", frame)
                except Exception as e:
                    append_log("TX", b"")  # zichtbaar dat write niet lukte
                    df_data.at[i, "CRC"] = "FOUT"
                    tree.set(i, "CRC", "FOUT")
                    time.sleep(0.05)
                    continue

                # Verwachte lengte van antwoord:
                # fc 03/04: slave, fcode, bytecount(=2*count), data(=2*count), CRC(2) => 3 + 2*count + 2
                # fc 01/02: bytecount kan variëren. Voor 1 register (count=1) → bytecount=1
                if fcode in (3,4):
                    expected = 3 + 2*count + 2
                else:  # 1/2
                    expected = 3 + 1 + 2  # minimaal: 1 byte data

                try:
                    resp = ser.read(expected)
                    append_log("RX", resp)
                except Exception:
                    append_log("RX", b"")
                    df_data.at[i, "CRC"] = "FOUT"
                    tree.set(i, "CRC", "FOUT")
                    time.sleep(0.05)
                    continue

                # Validatie basis
                if len(resp) < 5 or resp[0] != slave or resp[1] != fcode:
                    df_data.at[i, "CRC"] = "FOUT"
                    tree.set(i, "CRC", "FOUT")
                    time.sleep(0.05)
                    continue

                # CRC check
                valid_crc = (modbus_crc(resp[:-2]) == resp[-2:])
                df_data.at[i, "CRC"] = "OK" if valid_crc else "FOUT"
                tree.set(i, "CRC", df_data.at[i, "CRC"])
                if not valid_crc:
                    time.sleep( int(timeout_var.get()) / 1000.0 )
                    continue

                # Data bytes pakken
                bytecount = resp[2]
                payload = resp[3:-2]

                # Interpretatie:
                if fcode in (3,4):
                    # register-based (2 bytes per register)
                    if bytecount != 2*count or len(payload) != 2*count:
                        # mismatch → markeer fout
                        df_data.at[i, "CRC"] = "FOUT"
                        tree.set(i, "CRC", "FOUT")
                    else:
                        raw = interpret_data(payload, typ, swap)
                        df_data.at[i, "Raw"] = raw
                        scaled = scale_value(raw, scale)
                        df_data.at[i, "Scaled"] = scaled
                        tree.set(i, "Raw", str(raw))
                        tree.set(i, "Scaled", str(round(float(scaled), 3)))

                else:  # fcode 1/2 → bit based
                    # Simpele interpretatie: neem bit0 van eerste payload-byte als "Raw"
                    # (uit te breiden naar volledige bitmask weergave indien gewenst)
                    if len(payload) >= 1:
                        raw_bit = payload[0] & 0x01
                        df_data.at[i, "Raw"] = raw_bit
                        scaled = scale_value(raw_bit, scale)
                        df_data.at[i, "Scaled"] = scaled
                        tree.set(i, "Raw", str(raw_bit))
                        tree.set(i, "Scaled", str(round(float(scaled), 3)))
                    else:
                        df_data.at[i, "CRC"] = "FOUT"
                        tree.set(i, "CRC", "FOUT")

                # Poll interval
                time.sleep( int(timeout_var.get()) / 1000.0 )

    finally:
        # bij any exit: UI herstellen
        if polling:
            stop_polling_internal()

# ==========================
#  GUI OPBOUW
# ==========================
root = tk.Tk()
root.title(f"Poller – {SYSTEEM_NAAM}")

style = ttk.Style()
style.configure("Custom.Treeview", rowheight=22)
style.configure("Custom.Treeview.Heading", font=('Arial', 9, 'bold'))
style.map("Custom.Treeview", background=[('selected', '#ececec')])

frm = tk.Frame(root)
frm.pack(padx=10, pady=5, fill="x")

# Rij 0
tk.Label(frm, text="COM").grid(row=0, column=0, sticky="w")
com_var = tk.StringVar()
com_select = ttk.Combobox(frm, textvariable=com_var, values=get_com_ports(), width=14)
com_select.grid(row=0, column=1, sticky="w")

tk.Label(frm, text="Baud").grid(row=0, column=2, sticky="w")
baud_var = tk.StringVar(value="9600")
baud_select = ttk.Combobox(frm, textvariable=baud_var,
                           values=["2400","4800","9600","19200","38400","57600","115200"], width=10)
baud_select.grid(row=0, column=3, sticky="w")

tk.Label(frm, text="Pariteit").grid(row=0, column=4, sticky="w")
pariteit_var = tk.StringVar(value="None")
par_select = ttk.Combobox(frm, textvariable=pariteit_var, values=["None","Even","Odd"], width=8)
par_select.grid(row=0, column=5, sticky="w")

tk.Label(frm, text="Stopbits").grid(row=0, column=6, sticky="w")
stopbits_var = tk.StringVar(value="1")
stopbits_select = ttk.Combobox(frm, textvariable=stopbits_var, values=["1","2"], width=5)
stopbits_select.grid(row=0, column=7, sticky="w")

# Rij 1
tk.Label(frm, text="Slave").grid(row=1, column=0, sticky="w")
slave_var = tk.IntVar(value=1)
slave_entry = tk.Spinbox(frm, from_=0, to=254, textvariable=slave_var, width=6)
slave_entry.grid(row=1, column=1, sticky="w")

tk.Label(frm, text="Timeout").grid(row=1, column=2, sticky="w")
timeout_var = tk.StringVar(value="250")
timeout_select = ttk.Combobox(frm, textvariable=timeout_var,
                              values=["125","250","500","1000"], width=6)
timeout_select.grid(row=1, column=3, sticky="w")

btn_csv = tk.Button(frm, text="CSV lijst openen", command=laad_csv)
btn_csv.grid(row=1, column=4, columnspan=1, sticky="w", padx=(6,0))

btn_conn = tk.Button(frm, text="Verbinden", command=toggle_connection)
btn_conn.grid(row=1, column=5, columnspan=1, sticky="w", padx=(6,0))

lbl_lamp = tk.Label(frm, text="", width=2, height=1, bg="#ccc", relief="groove")
lbl_lamp.grid(row=0, column=8, padx=(10,0))
lbl_status = tk.Label(frm, text="Geen verbinding")
lbl_status.grid(row=1, column=8, padx=(10,0), sticky="w")

# Rij 2 (poll-knop)
btn_poll = tk.Button(frm, text="Start Pollen", command=toggle_polling, state="disabled")
btn_poll.grid(row=2, column=0, columnspan=9, pady=(4, 2), sticky="we")

# Tabel
kolommen = ["Index", "CommAsk", "FunctionCode", "Type", "Scale", "Swap", "Raw", "Scaled", "CRC"]
tree = ttk.Treeview(root, columns=kolommen, show="headings", style="Custom.Treeview", selectmode="browse")
tree.tag_configure("evenrow", background="#f2f2f2")
tree.tag_configure("oddrow", background="#ffffff")
tree.tag_configure("highlight", background="#90ee90")
for kol in kolommen:
    tree.heading(kol, text=kol)
    if kol in ["Index", "CommAsk", "FunctionCode"]:
        tree.column(kol, width=70, anchor="center")
    elif kol in ["Raw", "Scaled", "CRC"]:
        tree.column(kol, width=90, anchor="center")
    else:
        tree.column(kol, width=110, anchor="w")
tree.pack(fill="both", expand=True, padx=10, pady=5)

# HEX-LOG
frame_log = tk.Frame(root)
frame_log.pack(fill="x", padx=10, pady=2)
log_box = tk.Text(frame_log, height=8, width=90, bg="white", fg="black",
                  state="disabled", font=("Consolas", 9))
log_box.pack(side="left", fill="both", expand=True)
btn_export = tk.Button(frame_log, text="Export log", command=export_log)
btn_export.pack(side="left", padx=8)

# Disclaimer
lbl_disclaimer = tk.Label(root,
    text="Aan dit programma kunnen geen rechten worden ontleend, ook bestaat er geen ondersteuning",
    fg="gray", font=("Arial", 8))
lbl_disclaimer.pack(pady=(0, 5))

# Bindings
tree.bind("<Double-1>", on_double_click)

# ==========================
#  STATE & START
# ==========================
polling = False
poll_thread = None
serial_connected = False
ser = None
df_data = pd.DataFrame()

PARITY_MAP = {
    "None": serial.PARITY_NONE,
    "Even": serial.PARITY_EVEN,
    "Odd":  serial.PARITY_ODD,
}

# Live COM-refresh
refresh_com_ports()

# Ga lopen
root.mainloop()
