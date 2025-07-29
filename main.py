from fastapi import FastAPI 
import csv 

app = FastAPI()


safe = False

app.get("/check-url")
def checkurl(url):
    with open('trancoList.csv', mode ='r') as file:    
       csvFile = csv.DictReader(file)
       for lines in csvFile:
            if url in lines:
                return True
            else: 
                return False
    