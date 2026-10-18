"""Drive Argus in headless Chrome over the DevTools protocol: the
alert-IOC-to-documented-verdict walkthrough in docs/DEMO.md. It times each
step and saves screenshots.

It records a verdict and opens a case, so point it at a demo instance, not
production. Needs Google Chrome and the dev dependencies (httpx, websockets).

usage: uv run python scripts/demo_walkthrough.py BASE USER PASSFILE OUTDIR [idx=N] [ioc=VALUE] [shots-only]
  BASE      e.g. http://127.0.0.1:8010
  PASSFILE  a file holding USER's password (never pass it on the command line)
  idx=N     which item of the landscape's triage queue is "the alert" (default 0)
  ioc=VALUE use this value instead of the queue item
"""

import asyncio
import base64
import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import httpx
import websockets

BASE, USER, PASSFILE, OUT = sys.argv[1], sys.argv[2], sys.argv[3], Path(sys.argv[4])
EXTRA = sys.argv[5:] if len(sys.argv) > 5 else []
CHROME = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
PORT = 9333
OUT.mkdir(parents=True, exist_ok=True)


class Cdp:
    def __init__(self, ws):
        self.ws, self.n, self.pending = ws, 0, {}

    async def call(self, method, **params):
        self.n += 1
        i = self.n
        await self.ws.send(json.dumps({"id": i, "method": method, "params": params}))
        while True:
            msg = json.loads(await self.ws.recv())
            if msg.get("id") == i:
                if "error" in msg:
                    raise RuntimeError(f"{method}: {msg['error']}")
                return msg.get("result", {})

    async def js(self, expr):
        r = await self.call("Runtime.evaluate", expression=expr, awaitPromise=True, returnByValue=True)
        if "exceptionDetails" in r:
            raise RuntimeError(r["exceptionDetails"])
        return r["result"].get("value")

    async def wait(self, expr, timeout=20.0):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if await self.js(expr):
                return
            await asyncio.sleep(0.1)
        await self.shot("timeout")
        state = await self.js("location.href + ' | ' + document.body.innerText.slice(0, 600) + ' | pulse=' + document.querySelectorAll('.animate-pulse').length")
        raise TimeoutError(f"{expr} || {state}")

    async def shot(self, name):
        r = await self.call("Page.captureScreenshot", format="png", captureBeyondViewport=False)
        (OUT / f"{name}.png").write_bytes(base64.b64decode(r["data"]))

    async def click_text(self, text, tag="button"):
        for _ in range(50):
            ok = await self.js(
                f"""(() => {{ const el = [...document.querySelectorAll({json.dumps(tag)})]
                    .find(e => e.innerText.trim() === {json.dumps(text)} && !e.disabled);
                  if (!el) return false; el.scrollIntoView({{block: 'center'}}); el.click(); return true; }})()"""
            )
            if ok:
                return
            await asyncio.sleep(0.1)
        names = await self.js(f"[...document.querySelectorAll({json.dumps(tag)})].map(e => e.innerText.trim() + (e.disabled ? '(disabled)' : '')).join(' | ')")
        raise RuntimeError(f"no {tag} with text {text!r}: {names}")

    async def type_into(self, selector, text):
        await self.js(f"document.querySelector({json.dumps(selector)}).focus()")
        await self.call("Input.insertText", text=text)


def login() -> str:
    pw = Path(PASSFILE).read_text().strip()
    with httpx.Client(base_url=BASE) as c:
        r = c.post("/app/api/session", json={"username": USER, "password": pw},
                   headers={"Sec-Fetch-Site": "same-origin"})
        r.raise_for_status()
        return c.cookies["tl_user"]


async def main():
    cookie = login()
    with httpx.Client(base_url=BASE, cookies={"tl_user": cookie}) as c:
        queue = c.get("/app/api/landscape").json()["queue"]
    idx = next((int(a[4:]) for a in EXTRA if a.startswith("idx=")), 0)
    alert = queue[idx]
    ioc = alert["value"].replace("[://]", "://").replace("[.]", ".").replace("hxxp", "http")
    ioc = next((a[4:] for a in EXTRA if a.startswith("ioc=")), ioc)
    print("alert IOC:", alert["type"], ioc)

    prof = tempfile.mkdtemp(prefix="argus-cdp-")
    proc = subprocess.Popen([CHROME, "--headless=new", f"--remote-debugging-port={PORT}", f"--user-data-dir={prof}",
                             "--window-size=1440,1000", "--force-prefers-reduced-motion", "--no-first-run",
                             "--hide-scrollbars", "about:blank"])
    try:
        for _ in range(100):
            try:
                tabs = httpx.get(f"http://127.0.0.1:{PORT}/json").json()
                page = next(t for t in tabs if t["type"] == "page")
                break
            except Exception:
                await asyncio.sleep(0.2)
        async with websockets.connect(page["webSocketDebuggerUrl"], max_size=50_000_000) as ws:
            cdp = Cdp(ws)
            await cdp.call("Page.enable")
            await cdp.call("Network.enable")
            await cdp.call("Emulation.setDeviceMetricsOverride", width=1440, height=1000, deviceScaleFactor=1, mobile=False)
            host = BASE.split("://", 1)[1].split(":")[0]
            await cdp.call("Network.setCookie", name="tl_user", value=cookie, domain=host, path="/", httpOnly=True)
            steps = []
            t0 = time.monotonic()

            def mark(label):
                steps.append((label, time.monotonic() - t0))
                print(f"{time.monotonic() - t0:6.1f}s  {label}")

            # 1. paste the alert's IOC into Search: an exact hit opens the indicator page
            await cdp.call("Page.navigate", url=f"{BASE}/app/search")
            await cdp.wait("!!document.querySelector('input[placeholder^=\"185.220\"]')")
            await cdp.type_into('input[placeholder^="185.220"]', ioc)
            await cdp.call("Input.dispatchKeyEvent", type="keyDown", key="Enter", code="Enter", windowsVirtualKeyCode=13, text="\r")
            await cdp.call("Input.dispatchKeyEvent", type="keyUp", key="Enter", code="Enter", windowsVirtualKeyCode=13)
            await cdp.wait("location.pathname.startsWith('/app/indicators/') && document.body.innerText.includes('Why this score') && document.body.innerText.includes('Pivot') && !document.querySelector('.animate-pulse')")
            mark("indicator page with verdict, score breakdown, pivots, timeline")
            await asyncio.sleep(0.6)
            await cdp.shot("1-indicator")
            await cdp.js("window.scrollTo(0, document.body.scrollHeight * 0.45)")
            await asyncio.sleep(0.4)
            await cdp.shot("2-indicator-context")
            await cdp.js("window.scrollTo(0, 0)")
            if "shots-only" in EXTRA:
                return

            # 2. record the verdict (TP feedback)
            await cdp.click_text("Confirm malicious")
            await cdp.wait("document.body.innerText.includes('Undo analyst verdict')")
            mark("verdict recorded: confirmed malicious")

            # 3. open a case with this indicator as evidence
            await cdp.click_text("Open case")
            await cdp.wait("location.pathname.startsWith('/app/cases/') && document.body.innerText.includes('Write-up')")
            mark("case opened with the indicator as evidence")

            # 4. write the conclusion and save
            await cdp.type_into('textarea[placeholder="Root cause, impact, what was done"]',
                                f"Alert IOC {ioc} confirmed malicious from feed reports; blocked at the edge.")
            await cdp.click_text("Save")
            await cdp.wait("fetch('/api/v1/cases/' + location.pathname.split('/').pop()).then(r => r.json()).then(c => (c.conclusion || '').includes('confirmed malicious'))")
            mark("conclusion saved")
            await asyncio.sleep(0.4)
            await cdp.shot("3-case")

            # 5. the report: fetch the PDF the button links to
            href = await cdp.js("[...document.querySelectorAll('a')].find(a => a.innerText.includes('PDF')).getAttribute('href')")
            status = await cdp.js(f"fetch({json.dumps(href)}).then(async r => r.status + ' ' + r.headers.get('content-type') + ' ' + (await r.arrayBuffer()).byteLength)")
            mark(f"PDF report downloaded ({status})")
            print(json.dumps({"ioc": ioc, "steps": steps, "total_s": round(steps[-1][1], 1)}))
    finally:
        proc.terminate()


asyncio.run(main())
