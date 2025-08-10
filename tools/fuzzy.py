from fastapi import FastAPI 
import csv 
import tldextract
import rapidfuzz as fuzz


def is_same_or_subdomain(input_url, safe_domains):
    input_ext = tldextract.extract(input_url)
    input_base = f"{input_ext.domain}.{input_ext.suffix}"
    full_input = f"{input_ext.subdomain}.{input_base}" if input_ext.subdomain else input_base

    for domain in safe_domains:
        safe_ext = tldextract.extract(domain)
        safe_base = f"{safe_ext.domain}.{safe_ext.suffix}"
        
        if input_base == safe_base or full_input.endswith("." + safe_base):
            return True  
        
    return False


def is_fuzzy_match(input_url, safe_domains, threshold=85):
    input_ext = tldextract.extract(input_url)
    input_base = f"{input_ext.domain}.{input_ext.suffix}"

    for domain in safe_domains:
        safe_ext = tldextract.extract(domain)
        safe_base = f"{safe_ext.domain}.{safe_ext.suffix}"

        similarity = fuzz.partial_ratio(input_base, safe_base)
        if similarity >= threshold:
            return True

    return False

app = FastAPI()

safe = False

@app.get("/check-url")
def checkurl(url: str):
    safe_domains = []
    with open('trancoList.csv', mode='r') as file:    
        csvFile = csv.reader(file)
        for row in csvFile:
            if len(row) > 1:
                safe_domains.append(row[1].strip())
    
    is_safe = is_same_or_subdomain(url, safe_domains)
    return {"safe": is_safe}
    