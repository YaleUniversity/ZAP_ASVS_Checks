"""

Script testing 8.3.1 control from OWASP ASVS 4.0:

'Verify that sensitive data is sent to the server in the HTTP message body or
headers, and that query string parameters from any HTTP verb do not contain
sensitive data.'


The script will raise an alert if any parameter value matches the regex for ssn, emails, file paths, zip codes or ip addresses.
 
"""
import re

def get_parameters(url):
  
  try:
    query = str(url.split("?")[1])
    freq = query.count("&")
    values= []
    for x in range(freq - 1):
      sets = query.split('&', 1)
      values.append(sets[0].split('=')[1])
      query = str(sets[1])
    sets = query.split('&', 1)
    values.append(sets[0].split('=')[1])
    values.append(sets[1].split('=')[1])
    return values
  except:
    return ""

def scan(ps, msg, src):

  #alert parameters
  alertRisk= 0
  alertConfidence = 1
  alertTitle = "8.3.1 Verify that sensitive data is sent to the server in the HTTP message body or headers."
  alertDescription = "8.3.1 Verify that sensitive data is sent to the server in the HTTP message body or headers, and that query string parameters from any HTTP verb do not contain sensitive data."
  url = msg.getRequestHeader().getURI().toString()
  alertParam = ""
  alertAttack = ""
  alertInfo = "https://owasp.org/www-community/vulnerabilities/Information_exposure_through_query_strings_in_url"
  alertSolution = ""
  alertEvidence = "" 
  cweID = 319
  wascID = 0

  parameters = get_parameters(url)
  

  ssn = re.compile(r"[0-9]{3}-[0-9]{2}-[0-9]{4}")
  email = re.compile(r"^[\w\.=-]+@[\w\.-]+\.[\w]{2,3}$")
  file_path = re.compile(r"\\[^\\]+$")
  zip_code = re.compile(r"^((\d{5}-\d{4})|(\d{5})|([A-Z]\d[A-Z]\s\d[A-Z]\d))$")
  ip = re.compile(r"^\d{1,3}[.]\d{1,3}[.]\d{1,3}[.]\d{1,3}$")

  patterns = [ssn, email, file_path, zip_code, ip]
  if (parameters != ""):
    for par in parameters:
      for pat in patterns:
        print(par, pat)
        if (re.search(pat,par)):
          alertParam = par
          alertSolution = pat + " = " + par
          alertInfo = "Possible " + pat + " found in url parameter."
          ps.raiseAlert(alertRisk, alertConfidence, alertTitle, alertDescription, 
          url, alertParam, alertAttack, alertInfo, alertSolution, alertEvidence, cweID, wascID, msg);
