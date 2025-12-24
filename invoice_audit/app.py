from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
import shutil
import os
import json

from audit_blockchain import AuditBlockchain
from extractor import extract_invoice_data

app = FastAPI(title="Invoice Audit Ledger")

ledger = AuditBlockchain()

UPLOAD_DIR = "uploads"
DB_FILE = "invoice_db.json"

os.makedirs(UPLOAD_DIR, exist_ok=True)
if not os.path.exists(DB_FILE):
    with open(DB_FILE, "w") as f:
        json.dump({}, f)

app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/", response_class=HTMLResponse)
def home():
    with open("static/index.html", "r", encoding="utf-8") as f:
        return f.read()


@app.post("/upload-invoice")
async def upload_invoice(file: UploadFile = File(...)):
    path = os.path.join(UPLOAD_DIR, file.filename)

    with open(path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    extracted = extract_invoice_data(path)

    with open(DB_FILE, "r") as f:
        db = json.load(f)

    invoice_id = extracted["invoice_no"]

    db[invoice_id] = {
        "data": extracted,
        "status": "UPLOADED"
    }

    with open(DB_FILE, "w") as f:
        json.dump(db, f, indent=2)

    block = ledger.add_event(
        event_type="INVOICE_UPLOADED",
        reference_id=invoice_id,
        actor="company_a",
        canonical_data=extracted
    )

    return {
        "invoice_id": invoice_id,
        "block_hash": block.hash
    }

@app.post("/approve/{invoice_id}")
def approve(invoice_id: str):
    with open(DB_FILE, "r") as f:
        db = json.load(f)

    if invoice_id not in db:
        raise HTTPException(status_code=404, detail="Invoice not found")

    db[invoice_id]["status"] = "APPROVED"

    with open(DB_FILE, "w") as f:
        json.dump(db, f, indent=2)

    block = ledger.add_event(
        event_type="PAYMENT_APPROVED",
        reference_id=invoice_id,
        actor="company_b",
        canonical_data={"approved": True}
    )

    return {"block_hash": block.hash}

@app.post("/pay/{invoice_id}")
def pay(invoice_id: str):
    with open(DB_FILE, "r") as f:
        db = json.load(f)

    if invoice_id not in db:
        raise HTTPException(status_code=404, detail="Invoice not found")

    db[invoice_id]["status"] = "PAID"

    with open(DB_FILE, "w") as f:
        json.dump(db, f, indent=2)

    block = ledger.add_event(
        event_type="PAYMENT_PROCESSED",
        reference_id=invoice_id,
        actor="payment_gateway",
        canonical_data={"status": "SUCCESS"}
    )

    return {"block_hash": block.hash}

@app.get("/chain")
def view_chain():
    return [b.to_dict() for b in ledger.chain]
