import os
import time
import json
import re
import shutil
import subprocess
import glob

import requests


from PySide6.QtCore import Signal, QThread


def find_ffuf():
    """Robustně najde ffuf i tam, kam ho nedá PATH běžícího procesu.

    Na Windows winget nainstaluje ffuf, ale běžící aplikace má ještě starou PATH —
    proto se hledá i v obvyklých instalačních cestách (winget/scoop/choco) a mac/linux."""
    p = shutil.which("ffuf") or shutil.which("ffuf.exe")
    if p:
        return p
    cands = ["/usr/local/bin/ffuf", "/opt/homebrew/bin/ffuf", "/opt/local/bin/ffuf",
             "/usr/bin/ffuf"]
    # macOS/Linux: prostá existence
    for c in cands:
        try:
            if c and os.path.exists(c):
                return c
        except Exception:
            pass
    # Windows: sdílené hledání s toolcheck + rozresolvení symlinku na SPUSTITELNÝ
    # soubor (winget Links\ffuf.exe je symlink → Popen ho neumí spustit, WinError 2)
    try:
        from ..core.toolcheck import _windows_bin_candidates, _resolve_real_exe, _path_present
        wcands = _windows_bin_candidates("ffuf", "ffuf.ffuf")
        real = _resolve_real_exe(wcands)
        if real:
            return real
        for c in wcands:
            if _path_present(c):
                return c
    except Exception:
        pass
    return None


class BatchDownloadWorker(QThread):
    """
    Vlákno pro hromadné stahování.
    Upraveno: Nevyhazuje dialogy, sbírá chyby a posílá souhrnný report na konci.
    """
    progress = Signal(str, int) # filename, procenta
    file_finished = Signal(str) # filename hotov (pro odškrtnutí v GUI)
    finished_report = Signal(int, list) # (počet_úspěšných, seznam_chyb)

    def __init__(self, download_list, output_dir):
        super().__init__()
        self.download_list = download_list
        self.output_dir = output_dir
        self.is_running = True

    def run(self):
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir, exist_ok=True)

        total_files = len(self.download_list)
        success_count = 0
        errors = []
        
        for idx, item in enumerate(self.download_list):
            if not self.is_running:
                break
                
            url = item['url']
            filename = item['filename']
            dest_path = os.path.join(self.output_dir, filename)
            
            try:
                self.progress.emit(f"Stahuji: {filename}...", int((idx / total_files) * 100))
                
                # Timeout a stream pro lepší stabilitu
                response = requests.get(url, stream=True, timeout=20)
                
                # Kontrola status kódu - vyhodí výjimku např. u 404
                response.raise_for_status()
                
                with open(dest_path, 'wb') as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        if not self.is_running:
                            break
                        f.write(chunk)
                
                if self.is_running:
                    success_count += 1
                    self.file_finished.emit(filename)
                    
            except Exception as e:
                # Chybu přidáme do seznamu, ale NEZASTAVUJEME vlákno a NEVYHAZUJEME dialog
                clean_err = str(e).replace(url, "...url...") # Zkrácení erroru
                errors.append(f"{filename}: {clean_err}")

        # Na konci pošleme souhrn
        self.finished_report.emit(success_count, errors)

    def stop(self):
        self.is_running = False



class StderrReader(QThread):
    """
    Reader s přímým přístupem k signálu.
    """
    def __init__(self, process_stderr, signal_reference):
        super().__init__()
        self.stderr = process_stderr
        self.signal_reference = signal_reference 

    def remove_ansi_codes(self, text):
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        return ansi_escape.sub('', text)

    def run(self):
        print("DEBUG: [StderrReader] Start")
        # Regex na progress
        progress_re = re.compile(
            r'Progress:\s*\[(\d+)/(\d+)\].*?(\d+)\s*req/sec.*?Duration:\s*\[(.*?)\]', 
            re.IGNORECASE
        )

        while True:
            try:
                # Blokující čtení - pokud je pipe zavřená, vrátí prázdné bytes
                chunk = self.stderr.read(256)
            except (ValueError, OSError):
                # Pipe byla zavřena
                break
                
            if not chunk:
                # EOF
                break
            
            try:
                text_chunk = chunk.decode('utf-8', errors='ignore')
                parts = text_chunk.split('\r')
                
                for part in parts:
                    clean_line = self.remove_ansi_codes(part).strip()
                    if not clean_line or "Progress:" not in clean_line:
                        continue
                        
                    match = progress_re.search(clean_line)
                    if match:
                        current, total, rps, duration = match.groups()
                        data = {
                            'progress': int(current),
                            'total': int(total),
                            'rps': int(rps),
                            'eta': duration
                        }
                        self.signal_reference.emit(data)
                        
            except Exception as e:
                print(f"DEBUG: [StderrReader] Error: {e}")
        
        # Důležité: Zavřít stream pokud je otevřený
        try:
            self.stderr.close()
        except:
            pass
        print("DEBUG: [StderrReader] Finished")
        


class FfufWorker(QThread):
    """
    Worker s podporou pro sledování přesměrování (-r).
    """
    result_found = Signal(dict)
    finished = Signal()
    log = Signal(str)
    progress_update = Signal(dict)

    def __init__(self, target_url, wordlist, options):
        super().__init__()
        self.target_url = target_url
        self.wordlist = wordlist
        self.options = options
        self.is_running = True
        self.process = None
        self.stderr_reader = None

    def run(self):
        print(f"DEBUG: [FfufWorker] Spouštím pro {self.target_url}")
        command = []

        ffuf_path = find_ffuf()
        if not ffuf_path:
            self.log.emit("❌ Chyba: Nástroj 'ffuf' nebyl nalezen (nainstaluj přes "
                          "Správce aktualizací a restartuj aplikaci).")
            self.finished.emit()
            return

        command.extend([ffuf_path, "-w", self.wordlist, "-u", f"{self.target_url}/FUZZ", "-json"])
        if self.options.get('extensions'): command.extend(["-e", self.options['extensions']])
        if self.options.get('matcher'): command.extend(["-mc", self.options['matcher']])
        if self.options.get('follow_redirects', False): command.append("-r")

        # Debug do logu aplikace (viditelné bez CMD)
        try:
            wl_ok = os.path.isfile(self.wordlist)
            wl_lines = sum(1 for _ in open(self.wordlist, "rb")) if wl_ok else 0
            self.log.emit(f"▶️ ffuf: {ffuf_path}")
            self.log.emit(f"   slovník: {self.wordlist} (existuje={wl_ok}, řádků={wl_lines})")
        except Exception:
            pass

        env = os.environ.copy()
        env["PYTHONUNBUFFERED"] = "1"

        try:
            self.process = subprocess.Popen(
                command, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE, # Musí být PIPE pro reader
                text=False,       
                bufsize=0,        
                env=env
            )
            
            # Start readeru
            self.stderr_reader = StderrReader(self.process.stderr, self.progress_update)
            self.stderr_reader.start()

            # Čtení stdout (výsledky)
            for line in self.process.stdout:
                if not self.is_running: break
                try:
                    line_str = line.decode('utf-8', errors='ignore').strip()
                    if line_str:
                        data = json.loads(line_str)
                        self.result_found.emit(data)
                except json.JSONDecodeError: 
                    pass
            
            print("DEBUG: [FfufWorker] Stdout loop finished, waiting for process...")
            self.process.wait()
            rc = self.process.returncode
            if rc not in (0, None):
                self.log.emit(f"⚠️ ffuf skončil s návratovým kódem {rc} "
                              "(zkontroluj slovník/cíl výše).")
            
            # CRITICAL FIX: Musíme počkat, až skončí reader thread!
            if self.stderr_reader and self.stderr_reader.isRunning():
                print("DEBUG: [FfufWorker] Waiting for StderrReader...")
                self.stderr_reader.wait()
            
            print("DEBUG: [FfufWorker] Process and Reader finished.")
            
        except Exception as e:
            self.log.emit(f"❌ Chyba procesu: {str(e)}")
            print(f"DEBUG: [FfufWorker] Exception: {e}")
        finally:
            print(f"DEBUG: [FfufWorker] Emitting finished for {self.target_url}")
            self.finished.emit()

    def stop(self):
        print("DEBUG: [FfufWorker] Stop requested")
        self.is_running = False
        if self.process: 
            self.process.terminate()
            time.sleep(0.5)
            if self.process.poll() is None:
                self.process.kill()
        
        # I při násilném zastavení musíme počkat na reader
        if self.stderr_reader:
            self.stderr_reader.wait()
            
