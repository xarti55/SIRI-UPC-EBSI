// src/main.ts
import { createStoredWallet, runRemainingSteps } from "./voteLogic";

function el(tag: string, attrs: Record<string, any> = {}, ...children: (Node | string)[]) {
  const e = document.createElement(tag);
  for (const k of Object.keys(attrs)) {
    if (k.startsWith("on") && typeof attrs[k] === "function") {
      e.addEventListener(k.slice(2).toLowerCase(), attrs[k]);
    } else if (k === "className") {
      e.className = attrs[k];
    } else {
      e.setAttribute(k, String(attrs[k]));
    }
  }
  for (const c of children) {
    if (typeof c === "string") e.appendChild(document.createTextNode(c));
    else e.appendChild(c);
  }
  return e;
}

async function main() {
  const root = document.getElementById("app")!;
  root.innerHTML = "";

  // Page 1
  const p1 = el("div");
  p1.appendChild(el("h2", {}, "Wallet (page 1)"));
  p1.appendChild(el("p", {}, "A new wallet will be generated in your browser."));
  const didPre = el("pre", { id: "did" }, "Generating...");
  const pubPre = el("pre", { id: "pub" }, "");
  const nextBtn = el("button", {}, "Next");

  p1.appendChild(el("label", {}, "DID:"));
  p1.appendChild(didPre);
  p1.appendChild(el("label", {}, "Public key:"));
  p1.appendChild(pubPre);
  p1.appendChild(el("div", {}, nextBtn));

  // Page 2
  const p2 = el("div", { style: "display:none" });
  p2.appendChild(el("h2", {}, "Vote (page 2)"));
  const form = el("form");
  const options = ["Option A", "Option B", "Option C"];
  options.forEach((o, i) => {
    const id = `opt-${i}`;
    form.appendChild(el("div", {}, el("input", { type: "radio", id, name: "vote", value: String(i) }), el("label", { for: id }, o)));
  });
  const voteBtn = el("button", { type: "button" }, "Vote");
  const status = el("div", {}, "");
  p2.appendChild(form);
  p2.appendChild(el("div", {}, voteBtn));
  p2.appendChild(status);

  root.appendChild(p1);
  root.appendChild(p2);

  // create wallet using same logic as original
  const wallet = await createStoredWallet();
  (didPre as HTMLElement).textContent = wallet.did;
  (pubPre as HTMLElement).textContent = wallet.publicKey;

  nextBtn.addEventListener("click", () => {
    p1.style.display = "none";
    p2.style.display = "";
  });

  voteBtn.addEventListener("click", async () => {
    const fd = new FormData(form as HTMLFormElement);
    const sel = fd.get("vote");
    if (sel == null) {
      (status as HTMLElement).textContent = "Select an option first.";
      return;
    }
    const idx = Number(sel);
    const choices = new Array(options.length).fill(0);
    choices[idx] = 1;

    (status as HTMLElement).textContent = "Submitting vote...";
    try {
      const result = await runRemainingSteps(wallet, choices);
      (status as HTMLElement).textContent = "Vote result: " + JSON.stringify(result);
    } catch (err: any) {
      (status as HTMLElement).textContent = "Error: " + (err?.message ?? String(err));
      console.error(err);
    }
  });
}

main().catch((e) => (document.getElementById("app")!.textContent = String(e)));
