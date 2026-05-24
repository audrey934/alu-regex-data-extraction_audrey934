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
card_pattern = r"\b\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}\b"
#pattern allows the common 16-digit credit ceards and also helps to obtain cards having spaces, and dashes


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
    #protection against fake cards
    if len(set(digits)) == 1:
        return False, f"all digits are '{digits[0]}' - fake card"
    if len(digits) != 16:
        return False, f"Card number must have 16 digits, got {len(digits)}"
    return True, None


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
        # Security checks due to possibility of dangerous strings
        if dangerous(email):
            results["invalid"].append({
                "value": "[removed]",
                "reason": "looks suspicious, injection attack possible"
            })
            continue
        #Clasifying emails accordingly
        category = classify_email(email)
        results[category].append(email)

    return results

def check_cards(text):
    found = re.findall(card_pattern, text)
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