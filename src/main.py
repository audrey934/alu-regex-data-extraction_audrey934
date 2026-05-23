import re
import json
import os

base_dir = os.path.dirname(__file__)
INPUT_FILE = os.path.join(base_dir, "../input/raw-text.txt")
OUTPUT_FILE =os.path.join(base_dir, "../output/sample-output.json")

# Extraction Patterns

#Emails
email_pattern = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.(?:com|edu|org|rw|net|co)"
alu_si       = r"[a-zA-Z0-9._%+-]+@si\.alueducation\.com$"
alu_alumni   = r"[a-zA-Z0-9._%+-]+@alumni\.alueducation\.com$"
alu_official = r"[a-zA-Z0-9._%+-]+@alueducation\.com$"

#Credit cards
card_pattern = r"\b\d{4} \d{4} \d{4} \d{4}\b"

#phone number
phone_pattern = r"\+[\d\s]{9,16}"

#hashtag
hashtag_pattern = r"#[a-zA-Z]\w*"

#time
time_pattern = r"\b\d{1,2}:\d{2}\s?(?:AM|PM|am|pm)?\b"

# Words that might signal danger
danger = ["<script", "javascript:", "drop table", "<img", "onerror", "alert("]

#Functions for security(run before doing anything with data)

def dangerous(value):
    #Carching both uppercase/lowercase versions of danger
    v = value.lower()
    for a in danger:
        if a in v:
            return True
    return False

def mask_card(card):
    #preventing storage of full card number
    digits = card.replace(" ", "")
    return "**** **** **** " + digits[-4:]

def card_validity(digits):
    #protection against fake cards
    if len(set(digits)) == 1:
        return False
    if len(digits) != 16:
        return False
    return True

def phone_validation(phone):
    digits = re.sub(r"\D", "", phone)
    return len(digits) >= 9

def classify_email(email):
    if re.search(alu_si, email, re.IGNORECASE):
        return "alu_si"
    if re.search(alu_alumni, email, re.IGNORECASE):
        return "alu_alumni"
    if re.search(alu_official, email, re.IGNORECASE):
        return "alu_official"
    return "external"

## Extracting

def get_emails(text):
    found = re.findall(email_pattern, text)

    results = {
        "alu_si": [],
        "alu_alumni": [],
        "alu_official": [],
        "external": [],
        "rejected": []
    }

    for email in found:
        # Security checks due to possibility of dangerous strings
        if dangerous(email):
            results["rejected"].append({
                "value": "[REDACTED]",
                "reason": "injection attempt"
            })
            continue
        #Clasifying emails accordingly
        category = classify_email(email)
        results[category].append(email)

    return results

def get_cards(text):
    found = re.findall(card_pattern, text)
    results = {"valid": [], "rejected": []}

    for card in found:
        digits = card.replace(" ", "")

        if not card_validity(digits):
            results["rejected"].append({
                "card": mask_card(card),
                "reason": "all digits identical"
            })
            continue

        results["valid"].append(mask_card(card))

    return results

def get_phones(text):
    found = re.findall(phone_pattern, text)
    results = {"valid": [], "rejected": []}

    for phone in found:
        if not phone_validation(phone):
            results["rejected"].append({
                "value": phone,
                "reason": "too short"
            })
            continue

        results["valid"].append(phone.strip())

    return results

def get_hashtags(text):
    return re.findall(hashtag_pattern, text)

def get_times(text):
    return re.findall(time_pattern, text)

def main():
     with open(INPUT_FILE, "r", encoding="utf-8") as f:
        text = f.read()

     emails   = get_emails(text)
     cards    = get_cards(text)
     phones   = get_phones(text)
     hashtags = get_hashtags(text)
     times    = get_times(text)

     output = {
      "emails": emails,
      "credit_cards": cards,
      "phone_numbers": phones,
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
        len(emails["external"])
    )

     print("Finished extraction!")
     print(f"emails: {total_emails} valid, {len(emails['rejected'])} rejected")
     print(f"cards: {len(cards['valid'])} valid, {len(cards['rejected'])} rejected")
     print(f"phones: {len(phones['valid'])} valid, {len(phones['rejected'])} rejected")
     print(f"hashtags: {len(hashtags)}")
     print(f"times: {len(times)}")
     print(f"output saved to: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()