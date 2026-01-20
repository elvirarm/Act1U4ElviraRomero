import tkinter as tk
from tkinter import ttk, messagebox
import threading
import queue
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import time


class TkLogStream:
    """
    "Stream" para capturar el debug de smtplib (set_debuglevel)
    y enviarlo a una cola que luego se pinta en el Text del log.
    """
    def __init__(self, q: queue.Queue):
        self.q = q

    def write(self, msg: str):
        msg = msg.rstrip("\n")
        if msg:
            self.q.put(msg)

    def flush(self):
        pass


class MailtrapSMTPApp(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("Envío SMTP (Mailtrap / Sandbox) - Tkinter")
        self.geometry("1100x650")
        self.minsize(1000, 600)

        self.log_queue = queue.Queue()
        self.sending = False

        self._build_ui()
        self._poll_log_queue()

    def _build_ui(self):
        top = ttk.Frame(self, padding=10)
        top.pack(fill="x")

        smtp_box = ttk.LabelFrame(top, text="Configuración SMTP", padding=10)
        smtp_box.pack(side="left", fill="x", expand=True, padx=(0, 10))

        mail_box = ttk.LabelFrame(top, text="Datos del correo", padding=10)
        mail_box.pack(side="left", fill="x", expand=True)

        self.host_var = tk.StringVar(value="sandbox.smtp.mailtrap.io")
        self.port_var = tk.StringVar(value="2525")
        self.user_var = tk.StringVar()
        self.pass_var = tk.StringVar()

        r = 0
        ttk.Label(smtp_box, text="HOST").grid(row=r, column=0, sticky="w")
        ttk.Entry(smtp_box, textvariable=self.host_var, width=35).grid(row=r, column=1, sticky="we", padx=6)
        ttk.Label(smtp_box, text="PORT").grid(row=r, column=2, sticky="w", padx=(10, 0))
        ttk.Entry(smtp_box, textvariable=self.port_var, width=8).grid(row=r, column=3, sticky="w", padx=6)

        r += 1
        ttk.Label(smtp_box, text="USERNAME").grid(row=r, column=0, sticky="w", pady=(6, 0))
        ttk.Entry(smtp_box, textvariable=self.user_var, width=35).grid(row=r, column=1, sticky="we", padx=6, pady=(6, 0))
        ttk.Label(smtp_box, text="PASSWORD").grid(row=r, column=2, sticky="w", padx=(10, 0), pady=(6, 0))
        ttk.Entry(smtp_box, textvariable=self.pass_var, width=20, show="*").grid(row=r, column=3, sticky="w", padx=6, pady=(6, 0))

        for c in range(4):
            smtp_box.grid_columnconfigure(c, weight=1)

        self.from_var = tk.StringVar(value="from@example.com")
        self.to_var = tk.StringVar(value="to@example.com")
        self.subj_var = tk.StringVar(value="Hi Mailtrap")

        r = 0
        ttk.Label(mail_box, text="FROM").grid(row=r, column=0, sticky="w")
        ttk.Entry(mail_box, textvariable=self.from_var, width=30).grid(row=r, column=1, sticky="we", padx=6)
        ttk.Label(mail_box, text="TO").grid(row=r, column=2, sticky="w", padx=(10, 0))
        ttk.Entry(mail_box, textvariable=self.to_var, width=30).grid(row=r, column=3, sticky="we", padx=6)

        r += 1
        ttk.Label(mail_box, text="SUBJECT").grid(row=r, column=0, sticky="w", pady=(6, 0))
        ttk.Entry(mail_box, textvariable=self.subj_var).grid(row=r, column=1, columnspan=3, sticky="we", padx=6, pady=(6, 0))

        for c in range(4):
            mail_box.grid_columnconfigure(c, weight=1)

        notes = ttk.LabelFrame(self, text="Notas", padding=10)
        notes.pack(fill="x", padx=10, pady=(0, 10))

        note_text = (
            "• Este GUI envía usando SMTP sin STARTTLS (sin cifrado).\n"
            "• El cuerpo se envía como HTML (Content-Type: text/html).\n"
            "• Recomendado: usar el puerto 2525 de Mailtrap Sandbox.\n"
            "• El botón ENVIAR se desactiva durante el envío."
        )
        ttk.Label(notes, text=note_text, justify="left").pack(anchor="w")

        center = ttk.Frame(self, padding=(10, 0, 10, 10))
        center.pack(fill="both", expand=True)

        left_box = ttk.LabelFrame(center, text="Cuerpo del correo (HTML)", padding=8)
        left_box.pack(side="left", fill="both", expand=True, padx=(0, 10))

        right_box = ttk.LabelFrame(center, text="Salida / Log (respuestas servidor, info, error)", padding=8)
        right_box.pack(side="left", fill="both", expand=True)

        self.html_text = tk.Text(left_box, wrap="word", undo=True)
        self.html_text.pack(fill="both", expand=True, side="left")

        html_scroll = ttk.Scrollbar(left_box, command=self.html_text.yview)
        html_scroll.pack(side="right", fill="y")
        self.html_text.configure(yscrollcommand=html_scroll.set)

        self.html_text.insert(
            "1.0",
            "<html>\n"
            "  <body>\n"
            "    <h2>Hola!</h2>\n"
            "    <p>Este es un <b>correo de prueba</b> enviado desde Tkinter.</p>\n"
            f"    <p>Fecha/hora: <i>{time.strftime('%Y-%m-%d %H:%M:%S')}</i></p>\n"
            "  </body>\n"
            "</html>\n"
        )

        self.log_text = tk.Text(right_box, wrap="word", state="disabled")
        self.log_text.pack(fill="both", expand=True, side="left")

        log_scroll = ttk.Scrollbar(right_box, command=self.log_text.yview)
        log_scroll.pack(side="right", fill="y")
        self.log_text.configure(yscrollcommand=log_scroll.set)

        bottom = ttk.Frame(self, padding=(10, 0, 10, 10))
        bottom.pack(fill="x")

        self.clear_btn = ttk.Button(bottom, text="Limpiar log", command=self.clear_log)
        self.clear_btn.pack(side="right")

        self.send_btn = ttk.Button(bottom, text="ENVIAR", command=self.on_send)
        self.send_btn.pack(side="right", padx=(0, 10))

    def log(self, level: str, msg: str):
        self.log_queue.put(f"[{level}] {msg}")

    def clear_log(self):
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.configure(state="disabled")

    def _poll_log_queue(self):
        while True:
            try:
                line = self.log_queue.get_nowait()
            except queue.Empty:
                break
            self.log_text.configure(state="normal")
            self.log_text.insert("end", line + "\n")
            self.log_text.see("end")
            self.log_text.configure(state="disabled")

        self.after(80, self._poll_log_queue)

    def set_sending(self, value: bool):
        self.sending = value
        state = "disabled" if value else "normal"
        self.send_btn.configure(state=state)

    def on_send(self):
        if self.sending:
            return

        host = self.host_var.get().strip()
        port_s = self.port_var.get().strip()
        user = self.user_var.get().strip()
        pwd = self.pass_var.get().strip()

        mail_from = self.from_var.get().strip()
        mail_to = self.to_var.get().strip()
        subject = self.subj_var.get().strip()
        html_body = self.html_text.get("1.0", "end").strip()

        if not host or not port_s or not user or not pwd:
            messagebox.showerror("Error", "Faltan datos SMTP (host/port/username/password).")
            return
        if not mail_from or not mail_to:
            messagebox.showerror("Error", "Faltan campos FROM o TO.")
            return
        try:
            port = int(port_s)
        except ValueError:
            messagebox.showerror("Error", "El puerto debe ser un número.")
            return
        if not html_body:
            messagebox.showerror("Error", "El cuerpo HTML está vacío.")
            return

        self.set_sending(True)
        self.log("INFO", "Preparando envío...")

        t = threading.Thread(
            target=self._send_email_worker,
            args=(host, port, user, pwd, mail_from, mail_to, subject, html_body),
            daemon=True
        )
        t.start()

    def _send_email_worker(self, host, port, user, pwd, mail_from, mail_to, subject, html_body):
        debug_stream = TkLogStream(self.log_queue)

        try:
            msg = MIMEMultipart("alternative")
            msg["From"] = mail_from
            msg["To"] = mail_to
            msg["Subject"] = subject

            part_html = MIMEText(html_body, "html", "utf-8")
            msg.attach(part_html)

            self.log("INFO", f"Conectando a {host}:{port} ...")

            with smtplib.SMTP(host, port, timeout=20) as smtp:
                smtp._stdout = debug_stream
                smtp.set_debuglevel(1)

                code, resp = smtp.ehlo()
                self.log("INFO", f"EHLO -> {code} {resp!r}")

                self.log("INFO", "LOGIN ...")
                smtp.login(user, pwd)

                self.log("INFO", "SEND ...")
                smtp.sendmail(mail_from, [mail_to], msg.as_string())

            self.log("OK", "Mensaje enviado. Revisa el Inbox de Mailtrap (Sandbox).")

        except smtplib.SMTPAuthenticationError:
            self.log("ERROR", "Autenticación fallida. Revisa USERNAME/PASSWORD de Mailtrap.")
        except smtplib.SMTPConnectError as e:
            self.log("ERROR", f"No se pudo conectar al servidor SMTP: {e}")
        except Exception as e:
            self.log("ERROR", f"Error inesperado: {type(e).__name__}: {e}")
        finally:
            self.after(0, lambda: self.set_sending(False))


if __name__ == "__main__":
    app = MailtrapSMTPApp()
    app.mainloop()
