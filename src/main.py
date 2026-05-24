import re
import json
import os

base_dir = os.path.dirname(__file__)
INPUT_FILE = os.path.join(base_dir, "../input/raw-text.txt")
OUTPUT_FILE =os.path.join(base_dir, "../output/sample-output.json")

# Extraction Patterns

#Emails (patterns for normal emails and alu specific emails)
email_pattern = r"[a-zA-Z0-9][a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.(?:com|edu|org|rw|net|co)"
alu_si  = r"[a-zA-Z0-9._%+-]+@si\.alueducation\.com$"
alu_alumni = r"[a-zA-Z0-9._%+-]+@alumni\.alueducation\.com$"
alu_official = r"[a-zA-Z0-9._%+-]+@alueducation\.com$"

#Credit cards
# the pattern must capture any card regardless of type(mastercard, Amex, and Visa)
card_pattern = r"\b(?:\d[ -]?){15,16}\b"


#hashtag
hashtag_pattern = r"#\w+"

#time
time_pattern = r"\b(?:[01]?\d|2[0-3]):[0-5]\d\s?(?:AM|PM|am|pm)?\b"

# Words that might signal danger
danger = ["<script", "javascript:", "drop table", "onerror", "alert("]

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

    # if all digits are the same its a fake
    if len(set(digits)) == 1:
        return False, f"fake:card is made up of one repeated digit"

    # figure out what type of card it is based on starting numbers
    first_two = int(digits[:2])

    if 40 <= first_two <= 49:
        card_type = "visa"
        expected_length = 16

    elif 51 <= first_two <= 55:
        card_type = "mastercard"
        expected_length = 16

    elif first_two == 34 or first_two == 37:
        card_type = "amex"
        expected_length = 15

    else:
        return False, "doesnt look like visa, mastercard or amex"

    # checking if the length matches what we expect for that card type
    if len(digits) != expected_length:
        return False, f"{card_type} should have total of {expected_length} digits, it has {len(digits)}"

    return True, None

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
                "email": "[removed]",
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
            "email": bad,
            "reason": email_check(bad)
        })

    return results

def check_cards(text):
    results = {"accepted": [], "invalid": []}
    seen = []

    found = re.findall(card_pattern, text)

    for card in found:
        digits = re.sub(r"\D", "", card)
        masked = mask_card(card)
        if masked in seen:
            continue

        seen.append(masked)

        is_valid, reason = card_validity(digits)
        if not is_valid:
            results["invalid"].append({
                "card": masked,
                "reason": reason
            })
        else:
            results["accepted"].append(masked)

    return results

def get_hashtags(text):
    return re.findall(hashtag_pattern, text)

def extract_times(text):
    valid = re.findall(time_pattern, text)

    #  finding number of incorrect/no-existing times like 23:99 have been rejected by pattern and other checks
    all_times = re.findall(r"\b\d{1,2}:\d{2}\s?(?:AM|PM|am|pm)?\b", text)
    incorrect = len(all_times) - len(valid)
    return valid, incorrect    

def main():
     with open(INPUT_FILE, "r", encoding="utf-8") as f:
        text = f.read()

     emails = get_emails(text)
     cards = check_cards(text)
     hashtags = get_hashtags(text)
     times, incorrect = extract_times(text)

     output = {
      "emails": emails,
      "credit_cards": cards,
      "hashtags": hashtags,
      "times": {"found": times, "rejected_count": incorrect}
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
         print(f"invalid: '{r['email']}' , {r['reason']}")

     print(f"\ncards: {len(cards['accepted'])} accepted, {len(cards['invalid'])} invalid")
     for r in cards["invalid"]:
         print(f"invalid: '{r['card']}', {r['reason']}")
     print(f"\ntimes: {len(times)} found, {incorrect} rejected")
     print(f"\nhashtags: {len(hashtags)}")
     print(f"\noutput saved to: {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
