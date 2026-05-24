# ALU Regex Data Extraction — audrey934

A Python program that reads a raw and messy helpdesk export and pulls out useful data using regex. It works as a system that processes large volumes of raw text data returned from an external API. It extracts specific types of structured data from raw text,
validates input to ensure accuracy and safety, and handles realistic variations of data formats as they appear in the real world.


## What it does

Reads a raw text file formatted like a real ALU support platform export and extracts five things:

- **Emails** — sorted into ALU categories or flagged as external, dangerous ones get blocked before they touch anything
- **Credit cards** — masked the moment they're found, fake or weird ones get rejected with a reason
- **Hashtags** — picked up from the ticket tag fields throughout the file
- **Times** — handles both 12hr (9:30 AM) and 24hr (14:05) formats

---

## File structure

```
alu-regex-data-extraction-audrey934/
├── input/
│   └── raw-text.txt
├── src/
│   └── main.py
├── output/
│   └── sample-output.json
└── README.md
```

---

## Security — this part was interesting

The whole idea is that you can't trust what comes in. So:

- Every email gets checked for injection strings like `<script` or `drop table` before anything else happens
- Card numbers get masked immediately — the full number never appears anywhere in the output, only the last 4 digits
- Cards that don't start with a known network prefix (Visa starts with 4, Mastercard 51-55, Amex 34 or 37) get rejected
- Malformed emails that look suspicious get caught and stored as `[removed]` instead of the actual string

---

## ALU email categories

| Category | Domain |
|---|---|
| SI students | @si.alueducation.com |
| Alumni | @alumni.alueducation.com |
| Official staff | @alueducation.com |
| Everything else | other_emails |


## Requirements for Running

Just Python 3. Everything used — re, json, os — comes built into Python already.
Navigate into the src and run it:

```bash
cd src
python main.py
```

It prints a summary to the terminal and saves everything to `output/sample-output.json`.

---
