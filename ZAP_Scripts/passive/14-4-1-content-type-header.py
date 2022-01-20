"""

Script testing 14.4.1 control from OWASP ASVS 4.0:
'Verify that every HTTP response contains a Content-Type header. Also
specify a safe character set (e.g., UTF-8, ISO-8859-1) if the content types are
text/*, /+xml and application/xml. Content must match with the provided
Content-Type header.'

The script will raise an alert if:
	1. There is no Content-Type header in the HTTP response
	2. The content types are text/*, /+xml and application/xml but safe character sets: UTF-8, ISO-8859-1 are not used

"""

#if header contains "text/", "/+xml", or "application/xml" but does not use UTF-8, ISO-8859-1, return True
def useSafeCharacters(header):
  types = ["text/", "/+xml", "application/xml"]
  for t in types:
    if (t in header and (("charset=utf-8" not in header) and "iso-8859-1" not in header)):
      return True
  return False

def scan(ps, msg, src):

  #find "Content-Type" header
  header = str(msg.getResponseHeader().getHeader("Content-Type"))

  #alert parameters
  alertRisk= 0
  alertConfidence = 1
  alertTitle = "14.4.1 Verify that every HTTP response contains a Content-Type header."
  alertDescription = "The Content-Type representation header is used to indicate the original media type of the resource (before any content encoding is applied for sending)."
  url = msg.getRequestHeader().getURI().toString()
  alertParam = ""
  alertAttack = ""
  alertInfo = "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html"
  solutions = ["Add 'Content-Type' header in HTTP response.", "Specify a safe character set (e.g., UTF-8, ISO-8859-1) if the content types are text/*, /+xml and application/xml"]
  alertSolution = ""
  alertEvidence = "Content-Type: " + header
  cweID = 173
  wascID = 0
  
  #if there is no header, change alert solution
  if (header == "None"):
    alertSolution = solutions[0]

  #if header needs to use safe character sets, change alert solution
  elif (useSafeCharacters(header.lower())):
    alertSolution = solutions[1]

  #if alert solution has changed, raise alert
  if (alertSolution != ""):
    ps.raiseAlert(alertRisk, alertConfidence, alertTitle, alertDescription, 
      url, alertParam, alertAttack, alertInfo, alertSolution, alertEvidence, cweID, wascID, msg);
