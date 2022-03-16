"""

Script testing 4.1.5 control from OWASP ASVS 4.0:
'Verify that access controls fail securely including when an exception occurs.'

The script will raise an alert if 
 
"""
import re

def scan(ps, msg, src):

  #alert parameters
  alertRisk= 0
  alertConfidence = 1
  alertTitle = "4.1.5 Verify that access controls fail securely."
  alertDescription = "Verify that access controls fail securely including when an exception occurs."
  url = msg.getRequestHeader().getURI().toString()
  alertParam = ""
  alertAttack = ""
  alertInfo = "https://owasp.org/www-community/Fail_securely"
  alertSolution = ""
  alertEvidence = "" 
  cweID = 285
  wascID = 0

  code = str(msg.getResponseHeader().getStatusCode()) # get status code
  body = str(msg.getResponseBody()) #get response body

  error_pattern = re.compile(r"[4-5][0-9]{2}") #regular expression for codes 400-599

  ssn = re.compile(r"[0-9]{3}-[0-9]{2}-[0-9]{4}")
  email = re.compile(r"^[\w\.=-]+@[\w\.-]+\.[\w]{2,3}$")
  file_path = re.compile(r"\\[^\\]+$")
  zip_code = re.compile(r"^((\d{5}-\d{4})|(\d{5})|([A-Z]\d[A-Z]\s\d[A-Z]\d))$")
  ip = re.compile(r"^\d{1,3}[.]\d{1,3}[.]\d{1,3}[.]\d{1,3}$")
  netid = re.compile(r"^([a-z]{2,3})([2-9]{1,5})$")

  patterns = [ssn, email, file_path, zip_code, ip, netid]

  error_code = re.search(error_pattern,code)

  if (parameters != ""):
    for pat in patterns:
      if (re.search(pat,body) and ():  
        alertEvidence = "Code: " + code
        ps.raiseAlert(alertRisk, alertConfidence, alertTitle, alertDescription, 
        url, alertParam, alertAttack, alertInfo, alertSolution, alertEvidence, cweID, wascID, msg);

