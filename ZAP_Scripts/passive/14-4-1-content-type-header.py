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

#return true if:
#xml is in the header but utf-8 and utf-16 are not
#text is in the header but utf-8, utf-16 and iso-8859-1 are not
def useSafeCharacters(header):
  not_utf8 = "utf-8" not in header
  not_utf16 = "utf-16" not in header
  not_iso88591 = "iso-8859-1" not in header
  text = "text/" in header
  xml = "xml"  in header
  
  if xml and (not_utf8 and not_utf16):
    return True
  elif text and ((not_utf8 and not_utf16) and not_iso88591):
    return True
  return False

 
def scan(ps, msg, src):

  #find "Content-Type" header
  header = str(msg.getResponseHeader().getHeader("Content-Type"))

  #alert parameters
  alertRisk= 1
  alertConfidence = 2
  alertTitle = "14.4.1 Verify that every HTTP response contains a Content-Type header."
  alertDescription = "The Content-Type representation header is used to indicate the original media type of the resource (before any content encoding is applied for sending)."
  url = msg.getRequestHeader().getURI().toString()
  alertParam = ""
  alertAttack = ""
  alertInfo = "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html"
  solutions = ["Add 'Content-Type' header in HTTP response.", "Specify a safe character set (UTF-8, UTF-16) if the content types are /+xml or application/xml and (UTF-8, UTF-16, ISO-8859-1) if the content type is text/*"]
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
