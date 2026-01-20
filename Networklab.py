import tkinter as tk
from tkinter import ttk, messagebox
import socket
import struct
import random
import threading
import queue
import time
import datetime



class GuiLogger:
    def __init__(self, text_widget: tk.Text):
        self.text = text_widget
        self.q = queue.Queue()

    def log(self, level: str, msg: str):
        ts = time.strftime("%H:%M:%S")
        self.q.put(f"[{level}] {ts} {msg}")

    def clear(self):
        self.text.configure(state="normal")
        self.text.delete("1.0", "end")
        self.text.configure(state="disabled")

    def poll(self, root: tk.Tk):
        while True:
            try:
                line = self.q.get_nowait()
            except queue.Empty:
                break
            self.text.configure(state="normal")
            self.text.insert("end", line + "\n")
            self.text.see("end")
            self.text.configure(state="disabled")
        root.after(80, lambda: self.poll(root))



def _encode_qname(name: str) -> bytes:
    parts = name.strip(".").split(".")
    out = b""
    for p in parts:
        if not p:
            continue
        b = p.encode("utf-8")
        if len(b) > 63:
            raise ValueError("Etiqueta DNS demasiado larga")
        out += bytes([len(b)]) + b
    return out + b"\x00"


def _read_name(data: bytes, offset: int):
    """
    Lee un nombre DNS, soporta compresión (punteros 0xC0..).
    Devuelve (name, new_offset)
    """
    labels = []
    jumped = False
    orig_offset = offset

    while True:
        if offset >= len(data):
            raise ValueError("Respuesta DNS truncada (name fuera de rango).")

        length = data[offset]
        if (length & 0xC0) == 0xC0:
            if offset + 1 >= len(data):
                raise ValueError("Respuesta DNS truncada (puntero incompleto).")
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if pointer >= len(data):
                raise ValueError("Puntero de compresión fuera de rango.")
            if not jumped:
                orig_offset = offset + 2
                jumped = True
            offset = pointer
            continue

        if length == 0:
            offset += 1
            break

        offset += 1
        if offset + length > len(data):
            raise ValueError("Respuesta DNS truncada (label).")
        labels.append(data[offset:offset + length].decode("utf-8", errors="replace"))
        offset += length

    name = ".".join(labels) if labels else "."
    return name, (orig_offset if jumped else offset)


def _build_dns_query(qname: str, qtype: int, qclass: int = 1):
    tid = random.randint(0, 65535)
    flags = 0x0100 
    qdcount = 1
    ancount = nscount = arcount = 0

    header = struct.pack("!HHHHHH", tid, flags, qdcount, ancount, nscount, arcount)
    question = _encode_qname(qname) + struct.pack("!HH", qtype, qclass)
    return tid, header + question


def _parse_dns_response(resp: bytes, expected_tid: int):
    if len(resp) < 12:
        raise ValueError("Respuesta DNS demasiado corta.")

    tid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", resp[:12])
    if tid != expected_tid:
        raise ValueError("Transaction ID no coincide (respuesta no esperada).")

    rcode = flags & 0x000F
    if rcode != 0:
        raise ValueError(f"Error DNS (RCODE={rcode}).")

    offset = 12

    for _ in range(qd):
        _, offset = _read_name(resp, offset)
        if offset + 4 > len(resp):
            raise ValueError("Respuesta DNS truncada en question.")
        offset += 4

    answers = []
    for _ in range(an):
        name, offset = _read_name(resp, offset)
        if offset + 10 > len(resp):
            raise ValueError("Respuesta DNS truncada en RR header.")
        rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", resp[offset:offset + 10])
        offset += 10
        if offset + rdlen > len(resp):
            raise ValueError("Respuesta DNS truncada en RDATA.")
        rdata = resp[offset:offset + rdlen]
        offset += rdlen

        answers.append((name, rtype, rclass, ttl, rdata, resp))

    return answers


def dns_query(server_ip: str, qname: str, qtype: int, timeout: float = 3.0, port: int = 53):
    expected_tid, packet = _build_dns_query(qname, qtype)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        s.sendto(packet, (server_ip, port))
        resp, _ = s.recvfrom(4096)

    answers = _parse_dns_response(resp, expected_tid)

    results = []
    for name, rtype, rclass, ttl, rdata, full in answers:
        if rtype == 1 and len(rdata) == 4:
            ip = socket.inet_ntoa(rdata)
            results.append(("A", ip))
        elif rtype == 28 and len(rdata) == 16:
            ip = socket.inet_ntop(socket.AF_INET6, rdata)
            results.append(("AAAA", ip))
        elif rtype == 12: 
            ptr_name, _ = _read_name(full, len(full) - len(rdata))
            try:
               
                ptr = []
                i = 0
                while i < len(rdata):
                    l = rdata[i]
                    if l == 0:
                        i += 1
                        break
                    i += 1
                    ptr.append(rdata[i:i+l].decode("utf-8", errors="replace"))
                    i += l
                results.append(("PTR", ".".join(ptr)))
            except Exception:
                results.append(("PTR", rdata.hex()))

    return results


def ip_to_ptr_name(ip: str) -> str:
    try:
        socket.inet_pton(socket.AF_INET, ip)
        parts = ip.split(".")
        return ".".join(reversed(parts)) + ".in-addr.arpa"
    except OSError:
        pass

    try:
        packed = socket.inet_pton(socket.AF_INET6, ip)
        hexstr = packed.hex()
        nibbles = list(hexstr)
        nibbles.reverse()
        return ".".join(nibbles) + ".ip6.arpa"
    except OSError:
        raise ValueError("IP inválida (no es IPv4 ni IPv6).")



def ntp_query(server: str, timeout: float = 5.0, port: int = 123):
    """
    Devuelve (server_time_utc: datetime, offset_seconds: float)
    """
    msg = b"\x1b" + 47 * b"\0"

    addr_info = socket.getaddrinfo(server, port, socket.AF_UNSPEC, socket.SOCK_DGRAM)
    if not addr_info:
        raise OSError("No se pudo resolver el servidor NTP.")

    last_err = None
    for fam, socktype, proto, canon, sockaddr in addr_info:
        try:
            with socket.socket(fam, socket.SOCK_DGRAM) as s:
                s.settimeout(timeout)
                t0 = time.time()
                s.sendto(msg, sockaddr)
                data, _ = s.recvfrom(512)
                t1 = time.time()
            if len(data) < 48:
                raise ValueError("Respuesta NTP demasiado corta.")

            sec, frac = struct.unpack("!II", data[40:48])
            ntp_time = sec + frac / 2**32

            unix_time = ntp_time - 2208988800
            server_utc = datetime.datetime.utcfromtimestamp(unix_time)

            local_mid = (t0 + t1) / 2.0
            offset = (unix_time - local_mid)

            return server_utc, offset
        except Exception as e:
            last_err = e

    raise last_err if last_err else OSError("No se pudo consultar NTP.")


class NetworkLab(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("NetworkLab (DNS - NTP)")
        self.geometry("980x620")
        self.minsize(900, 560)

        self._build_ui()

    def _build_ui(self):
        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=10, pady=10)

        self.dns_tab = ttk.Frame(nb)
        self.ntp_tab = ttk.Frame(nb)

        nb.add(self.dns_tab, text="DNS")
        nb.add(self.ntp_tab, text="NTP")

        self._build_dns_tab()
        self._build_ntp_tab()

    def _build_dns_tab(self):
        top = ttk.Frame(self.dns_tab, padding=10)
        top.pack(fill="x")

        ttk.Label(top, text="Consulta DNS (libre estándar)").grid(row=0, column=0, columnspan=4, sticky="w", pady=(0, 8))

        ttk.Label(top, text="Nombre (A/AAAA):").grid(row=1, column=0, sticky="w")
        self.dns_name = tk.StringVar(value="www.wikipedia.com")
        ttk.Entry(top, textvariable=self.dns_name, width=45).grid(row=1, column=1, sticky="we", padx=6)

        self.dns_resolve_btn = ttk.Button(top, text="Resolver", command=self.on_dns_resolve)
        self.dns_resolve_btn.grid(row=1, column=2, sticky="we", padx=(10, 0))

        ttk.Label(top, text="IP (PTR/inversa):").grid(row=2, column=0, sticky="w", pady=(8, 0))
        self.dns_ip = tk.StringVar(value="8.8.8.8")
        ttk.Entry(top, textvariable=self.dns_ip, width=45).grid(row=2, column=1, sticky="we", padx=6, pady=(8, 0))

        self.dns_reverse_btn = ttk.Button(top, text="Inversa", command=self.on_dns_reverse)
        self.dns_reverse_btn.grid(row=2, column=2, sticky="we", padx=(10, 0), pady=(8, 0))

        ttk.Label(top, text="Servidor DNS:").grid(row=1, column=3, sticky="w", padx=(18, 0))
        self.dns_server = tk.StringVar(value="8.8.8.8")
        ttk.Entry(top, textvariable=self.dns_server, width=15).grid(row=1, column=4, sticky="w", padx=6)

        ttk.Label(top, text="Timeout (s):").grid(row=2, column=3, sticky="w", padx=(18, 0), pady=(8, 0))
        self.dns_timeout = tk.StringVar(value="3")
        ttk.Entry(top, textvariable=self.dns_timeout, width=15).grid(row=2, column=4, sticky="w", padx=6, pady=(8, 0))

        ttk.Label(top, text="Nota: getaddrinfo/gethostbyaddr (no 'dig') completo. DNS UDP directo a servidor público.").grid(
            row=3, column=0, columnspan=5, sticky="w", pady=(10, 0)
        )

        for c in range(5):
            top.grid_columnconfigure(c, weight=1)

        log_frame = ttk.LabelFrame(self.dns_tab, text="Salida / Log", padding=8)
        log_frame.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        self.dns_log_text = tk.Text(log_frame, wrap="word", state="disabled")
        self.dns_log_text.pack(side="left", fill="both", expand=True)

        scr = ttk.Scrollbar(log_frame, command=self.dns_log_text.yview)
        scr.pack(side="right", fill="y")
        self.dns_log_text.configure(yscrollcommand=scr.set)

        bottom = ttk.Frame(self.dns_tab, padding=(10, 0, 10, 10))
        bottom.pack(fill="x")

        self.dns_clear_btn = ttk.Button(bottom, text="Limpiar", command=lambda: self.dns_logger.clear())
        self.dns_clear_btn.pack(side="right")

        self.dns_logger = GuiLogger(self.dns_log_text)
        self.dns_logger.poll(self)

        self._dns_busy = False

    def _dns_set_busy(self, busy: bool):
        self._dns_busy = busy
        state = "disabled" if busy else "normal"
        self.dns_resolve_btn.configure(state=state)
        self.dns_reverse_btn.configure(state=state)

    def on_dns_resolve(self):
        if self._dns_busy:
            return
        name = self.dns_name.get().strip()
        server = self.dns_server.get().strip()
        try:
            timeout = float(self.dns_timeout.get().strip())
        except ValueError:
            messagebox.showerror("Error", "Timeout DNS inválido.")
            return
        if not name:
            messagebox.showerror("Error", "Introduce un nombre de dominio.")
            return
        if not server:
            messagebox.showerror("Error", "Introduce un servidor DNS (ej: 8.8.8.8).")
            return

        self._dns_set_busy(True)
        self.dns_logger.log("INFO", f"Resolviendo: {name} (DNS={server})")

        def worker():
            try:
                a = dns_query(server, name, 1, timeout=timeout)
                aaaa = dns_query(server, name, 28, timeout=timeout)

                if not a and not aaaa:
                    self.dns_logger.log("ERROR", "Sin respuestas A/AAAA (posible NXDOMAIN o sin registros).")
                else:
                    for t, v in a:
                        self.dns_logger.log("OK", f"A -> {v}")
                    for t, v in aaaa:
                        self.dns_logger.log("OK", f"AAAA -> {v}")

            except Exception as e:
                self.dns_logger.log("ERROR", f"{type(e).__name__}: {e}")
            finally:
                self.after(0, lambda: self._dns_set_busy(False))

        threading.Thread(target=worker, daemon=True).start()

    def on_dns_reverse(self):
        if self._dns_busy:
            return
        ip = self.dns_ip.get().strip()
        server = self.dns_server.get().strip()
        try:
            timeout = float(self.dns_timeout.get().strip())
        except ValueError:
            messagebox.showerror("Error", "Timeout DNS inválido.")
            return
        if not ip:
            messagebox.showerror("Error", "Introduce una IP para inversa (PTR).")
            return

        self._dns_set_busy(True)
        self.dns_logger.log("INFO", f"Resolviendo inversa: {ip} (DNS={server})")

        def worker():
            try:
                ptr_name = ip_to_ptr_name(ip)
                res = dns_query(server, ptr_name, 12, timeout=timeout)
                if not res:
                    self.dns_logger.log("ERROR", "Sin respuesta PTR.")
                else:
                    for t, v in res:
                        self.dns_logger.log("OK", f"PTR -> {v}")
            except Exception as e:
                self.dns_logger.log("ERROR", f"{type(e).__name__}: {e}")
            finally:
                self.after(0, lambda: self._dns_set_busy(False))

        threading.Thread(target=worker, daemon=True).start()

    def _build_ntp_tab(self):
        top = ttk.Frame(self.ntp_tab, padding=10)
        top.pack(fill="x")

        ttk.Label(top, text="Consulta NTP (UDP/123)").grid(row=0, column=0, columnspan=4, sticky="w", pady=(0, 8))

        ttk.Label(top, text="Servidor NTP:").grid(row=1, column=0, sticky="w")
        self.ntp_server = tk.StringVar(value="pool.ntp.org")
        ttk.Entry(top, textvariable=self.ntp_server, width=50).grid(row=1, column=1, sticky="we", padx=6)

        ttk.Label(top, text="Timeout (s):").grid(row=1, column=2, sticky="w", padx=(10, 0))
        self.ntp_timeout = tk.StringVar(value="5")
        ttk.Entry(top, textvariable=self.ntp_timeout, width=10).grid(row=1, column=3, sticky="w", padx=6)

        self.ntp_btn = ttk.Button(top, text="CONSULTAR NTP", command=self.on_ntp_query)
        self.ntp_btn.grid(row=1, column=4, sticky="we", padx=(12, 0))

        ttk.Label(top, text="Nota: Si falla por timeout en el instituto, puede estar bloqueado UDP/123.").grid(
            row=2, column=0, columnspan=5, sticky="w", pady=(10, 0)
        )

        for c in range(5):
            top.grid_columnconfigure(c, weight=1)

        log_frame = ttk.LabelFrame(self.ntp_tab, text="Salida / Log", padding=8)
        log_frame.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        self.ntp_log_text = tk.Text(log_frame, wrap="word", state="disabled")
        self.ntp_log_text.pack(side="left", fill="both", expand=True)

        scr = ttk.Scrollbar(log_frame, command=self.ntp_log_text.yview)
        scr.pack(side="right", fill="y")
        self.ntp_log_text.configure(yscrollcommand=scr.set)

        bottom = ttk.Frame(self.ntp_tab, padding=(10, 0, 10, 10))
        bottom.pack(fill="x")

        self.ntp_clear_btn = ttk.Button(bottom, text="Limpiar", command=lambda: self.ntp_logger.clear())
        self.ntp_clear_btn.pack(side="right")

        self.ntp_logger = GuiLogger(self.ntp_log_text)
        self.ntp_logger.poll(self)

        self._ntp_busy = False

    def _ntp_set_busy(self, busy: bool):
        self._ntp_busy = busy
        self.ntp_btn.configure(state="disabled" if busy else "normal")

    def on_ntp_query(self):
        if self._ntp_busy:
            return

        server = self.ntp_server.get().strip()
        try:
            timeout = float(self.ntp_timeout.get().strip())
        except ValueError:
            messagebox.showerror("Error", "Timeout NTP inválido.")
            return

        if not server:
            messagebox.showerror("Error", "Introduce un servidor NTP (ej: pool.ntp.org).")
            return

        self._ntp_set_busy(True)
        self.ntp_logger.log("INFO", f"Consultando NTP: {server} (timeout={timeout:.1f}s) ...")

        def worker():
            try:
                server_utc, offset = ntp_query(server, timeout=timeout)

                local_now = datetime.datetime.now()

              
                unix_ts = server_utc.replace(tzinfo=datetime.timezone.utc).timestamp()
                server_local = datetime.datetime.fromtimestamp(unix_ts)

                self.ntp_logger.log("OK", f"Hora (local): {local_now.strftime('%Y-%m-%d %H:%M:%S')}")
                self.ntp_logger.log("OK", f"Hora (NTP):   {server_local.strftime('%Y-%m-%d %H:%M:%S')}")
                self.ntp_logger.log("INFO", f"Diferencia vs reloj local: {offset:+.3f} s")

            except Exception as e:
                self.ntp_logger.log("ERROR", f"{type(e).__name__}: {e}")
            finally:
                self.after(0, lambda: self._ntp_set_busy(False))

        threading.Thread(target=worker, daemon=True).start()


if __name__ == "__main__":
    app = NetworkLab()
    app.mainloop()
