"""Headless test navázání (resume) skenu — spustí jen ne-úspěšné cíle×fáze."""
import os, sys, types
os.environ.setdefault("QT_QPA_PLATFORM","minimal"); sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from PySide6.QtCore import QCoreApplication, QTimer
import nmapscanner.workers.scan as scanmod
from nmapscanner.signals import WorkerSignals
from nmapscanner.core.scan_manager import ScanManager
from nmapscanner.core import scan_profiles as sp

T=["10.0.0.1","10.0.0.2"]
def xml_up(ip,tcp=()):
    p="".join(f'<port protocol="tcp" portid="{x}"><state state="open"/><service name="s{x}"/></port>' for x in tcp)
    return f'<?xml version="1.0"?><nmaprun version="7.99"><host><status state="up"/><address addr="{ip}" addrtype="ipv4"/><ports>{p}</ports></host><runstats><finished elapsed="1"/><hosts up="1" down="0" total="1"/></runstats></nmaprun>'
calls={}
def fake_run(cmd,**kw):
    s=" ".join(cmd); tgt=next((t for t in T if t in s),"?")
    ph="online" if "-sn" in cmd else ("udp" if "-sU" in cmd else ("osscan" if "-O" in cmd else ("vuln" if "--script" in cmd else "tcp")))
    calls[(tgt,ph)]=calls.get((tgt,ph),0)+1
    return types.SimpleNamespace(returncode=0, stdout=xml_up(tgt, tcp=(22,) if ph=="tcp" else ()), stderr="")
scanmod.subprocess.run=fake_run

app=QCoreApplication(sys.argv); sig=WorkerSignals(); mgr=ScanManager(sig,max_concurrent=4)
prog={}; sig.phase_progress.connect(lambda ph,c,t: prog.__setitem__(ph,(c,t)))
done={"v":False}; mgr.workflow_finished.connect(lambda: done.__setitem__("v",True))

# RESUME scénář: .1 má vše hotové KROMĚ udp(chyba) a vuln(čeká); .2 má online+tcp hotové, zbytek chybí
enabled={p:True for p in sp.PHASES}
prior_status={
  "10.0.0.1": {"online":"online","tcp":"hotovo","udp":"chyba","osscan":"hotovo"},  # vuln chybí, udp chyba
  "10.0.0.2": {"online":"online","tcp":"hotovo"},  # udp/vuln/osscan chybí
}
ctx={"status":prior_status, "open_ports":{"10.0.0.1":[22],"10.0.0.2":[80]}, "needs_pn":{}}
mgr.start_workflow(T,"master",enabled,"",True,ctx)

def poll(n=[0]):
    mgr.thread_pool.waitForDone(50); app.processEvents(); n[0]+=1
    if done["v"] or n[0]>200: app.quit()
    else: QTimer.singleShot(20,poll)
QTimer.singleShot(0,poll); app.exec()

fails=[]
# .1: jen udp + vuln se měly spustit; online/tcp/osscan NE
for ph in ("online","tcp","osscan"):
    if ("10.0.0.1",ph) in calls: fails.append(f".1/{ph} se NEmělo spustit (bylo hotové), spuštěno {calls[('10.0.0.1',ph)]}x")
for ph in ("udp","vuln"):
    if ("10.0.0.1",ph) not in calls: fails.append(f".1/{ph} se MĚLO spustit (chyba/chybí)")
# .2: online/tcp NE; udp/vuln/osscan ANO
for ph in ("online","tcp"):
    if ("10.0.0.2",ph) in calls: fails.append(f".2/{ph} se NEmělo spustit (hotové)")
for ph in ("udp","vuln","osscan"):
    if ("10.0.0.2",ph) not in calls: fails.append(f".2/{ph} se MĚLO spustit")
# progress totals: online 0/0, tcp 0/0, udp 2/2, osscan 1/1, vuln 2/2
exp={"online":(0,0),"tcp":(0,0),"udp":(2,2),"osscan":(1,1),"vuln":(2,2)}
for ph,(c,t) in exp.items():
    if prog.get(ph)!=(c,t): fails.append(f"progress[{ph}]={prog.get(ph)}, čekáno {(c,t)}")
if not done["v"]: fails.append("workflow_finished neproběhl")
print("calls:",sorted(calls.items()))
print("progress:",prog)
if fails:
    print("❌"); [print("  -",f) for f in fails]; sys.exit(1)
print("✅ RESUME OK — spustily se jen ne-úspěšné cíle×fáze, progress sedí.")
