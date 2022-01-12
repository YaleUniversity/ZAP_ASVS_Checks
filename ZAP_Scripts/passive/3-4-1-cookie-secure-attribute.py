"""

Script testing 3.4.1 control from OWASP ASVS 4.0:
'Verify that cookie-based session tokens have the 'Secure' attribute set.'

The script will raise an alert if 'Secure' attribute is not present. 

"""

def scan(ps, msg, src):
  """Passively scans the message sent/received through ZAP.

  Args:
    ps (ScriptsPassiveScanner): The helper class to raise alerts and add tags to the message.
    msg (HttpMessage): The HTTP message being scanned.
    src (Source): The HTML source of the message (if any). 

  """

  alertTitle = "3.4.1 Verify that cookie-based session tokens have the 'Secure' attribute set."
  alertDescription = "The secure attribute is an option that can be set by the application server when sending a new cookie to the user within an HTTP Response. The purpose of the secure attribute is to prevent cookies from being observed by unauthorized parties due to the transmission of the cookie in clear text. To accomplish this goal, browsers which support the secure attribute will only send cookies with the secure attribute when the request is going to an HTTPS page. Said in another way, the browser will not send a cookie with the secure attribute set over an unencrypted HTTP request. By setting the secure attribute, the browser will prevent the transmission of a cookie over an unencrypted channel."
  url = msg.getRequestHeader().getURI().toString()
  alertRisk = 0
  alertReliability = 1
  headerCookie = str(msg.getResponseHeader().getHeader("Set-Cookie"))
  print(headerCookie)
  print("msg ", msg)
  alertSolution = "Add 'Secure' attribute when sending cookie."
  alertParam = ""
  alertInfo = ""
  cweID = 614
  wascID = 0

  

  # Test the request and/or response here
  if (True):
    ps.raiseAlert(1, 1, alertTitle, alertDescription, 
      url, alertParam, 'Your attack', alertInfo, 'The solution', '', 0, 0, msg);
