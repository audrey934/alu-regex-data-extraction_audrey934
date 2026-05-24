import re
import json
import os

base_dir = os.path.dirname(__file__)
INPUT_FILE = os.path.join(base_dir, "../input/raw-text.txt")
OUTPUT_FILE =os.path.join(base_dir, "../output/sample-output.json")

# Extraction Patterns

#Emails (patterns for normal emails and alu specific emails)
email_pattern = r"[a-zA-Z0-9][a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.(?:com|edu|org|rw|net|co)"
alu_si       = r"[a-zA-Z0-9._%+-]+@si\.alueducation\.com$"
alu_alumni   = r"[a-zA-Z0-9._%+-]+@alumni\.alueducation\.com$"
alu_official = r"[a-zA-Z0-9._%+-]+@alueducation\.com$"

#Credit cards
# 3 different cards(visa, mastercard, and amex can all be captured in accordance to each one's unique details)

visa        = r"\b4\d{3}[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}\b" #must start with 4
mastercard  = r"\b5[1-5]\d{2}[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}\b" # start with numbers from 51-55
amex        = r"\b3[47]\d{2}[ -]?\d{6}[ -]?\d{5}\b"#starts with 34,37

card_pattern = f"{visa}|{mastercard}|{amex}"

#hashtag
hashtag_pattern = r"#\w+"

#time
time_pattern = r"\b(?:[01]?\d|2[0-3]):[0-5]\d\s?(?:AM|PM|am|pm)?\b"

# Words that might signal danger
danger = ["<script", "javascript:", "drop table", "<img", "onerror", "alert("]

#Functions for security(run before doing anything with data)

def dangerous(value):
    #Carching both uppercase/lowercase versions of dangerous injections
    v = value.lower()
    for a in danger:
        if a in v:
            return True
    return False

def mask_card(card):
    digits = re.sub(r"\D", "", card)  # Dealing with cards that have spaces or dashes between numbers
    return "**** **** **** " + digits[-4:]

def card_validity(digits):
    # obvious fake e.g 0000 0000 0000 0000
    if len(set(digits)) == 1:
        return False, f"all digits are '{digits[0]}' - fake card"

    # visa starts with 4, always 16 digits
    if digits.startswith("4"):
        if len(digits) != 16:
            return False, f"visa should be 16 digits, got {len(digits)}"
        return True, None

    # mastercard starts with 51 to 55, also 16 digits
    if 51 <= int(digits[:2]) <= 55:
        if len(digits) != 16:
            return False, f"mastercard should be 16 digits, got {len(digits)}"
        return True, None

    # amex starts with 34 or 37, only one thats 15 digits
    if digits[:2] in ("34", "37"):
        if len(digits) != 15:
            return False, f"amex should be 15 digits, got {len(digits)}"
        return True, None

    return False, "doesnt look like visa, mastercard or amex"

def email_check(email):
    if email.count("@") > 1:
        return "more than one @ symbol"
    if "." not in email.split("@")[-1]:
        return "no dot in domain"
    if email.split("@")[0] == "":
        return "nothing before @"
    return "invalid format"
    

def classify_email(email):
    if re.search(alu_si, email, re.IGNORECASE):
        return "alu_si"
    if re.search(alu_alumni, email, re.IGNORECASE):
        return "alu_alumni"
    if re.search(alu_official, email, re.IGNORECASE):
        return "alu_official"
    return "other_emails"

## Extracting
def get_emails(text):
    found = re.findall(email_pattern, text)

    results = {
        "alu_si": [],
        "alu_alumni": [],
        "alu_official": [],
        "other_emails": [],
        "invalid": []
    }

    for email in found:
        # danger check runs first
        if dangerous(email):
            results["invalid"].append({
                "value": "[removed]",
                "reason": "looks suspicious, injection attack possible"
            })
            continue
        category = classify_email(email)
        results[category].append(email)

    # catching bad emails that failed patern
    malformed = re.findall(r"[\w._%+-]*@{2,}[\w._%+-]+|[\w._%+-]+@[\w._%+-]*@[\w._%+-]+", text)
    for bad in malformed:
        bad = bad.strip()
        results["invalid"].append({
            "value": bad,
            "reason": email_check(bad)
        })

    return results
def check_cards(text):
    found = re.findall(r"\b(?:\d[ -]?){13,16}\b", text)
    results = {"accepted": [], "invalid": []}

    for card in found:
        ## remove space or dashes in cards
        digits = re.sub(r"\D", "", card) 
        is_valid, reason = card_validity(digits)

        if not is_valid:
            results["invalid"].append({
             "card": mask_card(card),
             "reason": reason
            })
            continue
        results["accepted"].append(mask_card(card))

    return results


def get_hashtags(text):
    return re.findall(hashtag_pattern, text)

def extract_times(text):
    return re.findall(time_pattern, text)

def main():
     with open(INPUT_FILE, "r", encoding="utf-8") as f:
        text = f.read()

     emails   = get_emails(text)
     cards    = check_cards(text)
     hashtags = get_hashtags(text)
     times    = extract_times(text)

     output = {
      "emails": emails,
      "credit_cards": cards,
      "hashtags": hashtags,
      "times": times
    }
    
    # create output folder if it doesn't exist
     os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
     with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)

     total_emails = (
        len(emails["alu_si"]) +
        len(emails["alu_alumni"]) +
        len(emails["alu_official"]) +
        len(emails["other_emails"])
    )
     print("extraction done!")
     print(f"\nemails: {total_emails} accepted, {len(emails['invalid'])} invalid")
     for r in emails["invalid"]:
         print(f"invalid: '{r['value']}' , {r['reason']}")

     print(f"\ncards: {len(cards['accepted'])} accepted, {len(cards['invalid'])} invalid")
     for r in cards["invalid"]:
         print(f"invalid: '{r['card']}', {r['reason']}")

     print(f"\nhashtags: {len(hashtags)}")
     print(f"times: {len(times)}")
     print(f"\noutput saved to: {OUTPUT_FILE}")

if __name__ == "__main__":
    main()