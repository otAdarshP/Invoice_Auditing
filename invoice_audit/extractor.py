import uuid

def extract_invoice_data(file_path):
    # Replace this with DONUT inference later
    return {
        "invoice_no": str(uuid.uuid4())[:8],
        "vendor": "Company A",
        "amount": 125000,
        "currency": "INR",
        "date": "2025-03-01",
    }
