//Script testing 14.2.1 control from OWASP ASVS 4.0:
//'Verify that all components are up to date, preferably using a dependency checker during build or compile time.'

//The script checks loops through all the alerts looking for alerts from RetireJS (pluginId 10003) and changes the title and description to match ASVS requirement 14.2.1
//For the script to work you need to install RetireJS add-on from the marketplace and use it with a spider on your website. Then run this script.

//ASVS Controls
//14.2.1
//4.3.2


extAlert = org.parosproxy.paros.control.Control.getSingleton().
    getExtensionLoader().getExtension(
        org.zaproxy.zap.extension.alert.ExtensionAlert.NAME) 


if (extAlert != null) {
//	var Alert = org.parosproxy.paros.core.scanner.Alert
	var alerts = extAlert.getAllAlerts()
     // cycle thorugh all alerts
	for (var i = 0; i < alerts.length; i++) {
		var alert = alerts[i]
          var id = alert.getPluginId(); // get plugin id for alert
          
          switch (id){ //set up cases for each id to change alert format to match ASVS
            case "40018": //sql injection
              description = alert.getDescription()
              alert.setName("");
              alert.setDescription('TESTETSTETSETSTETTSTE' + description)
              extAlert.updateAlert(alert);
              break;
            case "90029": //soap xml injection
              alert.setName("");
              extAlert.updateAlert(alert);
              break;
            case "90021": //xpath injection
              alert.setName("");
              extAlert.updateAlert(alert);
              break;
            case "40012": //reflected xss
              alert.setName("");
              extAlert.updateAlert(alert);
              break;
            case "40014": //persistent xss
              alert.setName("");
              extAlert.updateAlert(alert);
              break;
            case "40016": //persistent xss
              alert.setName("");
              extAlert.updateAlert(alert);
              break;
            case "40026": //dom based xss
              alert.setName("");
              extAlert.updateAlert(alert);
              break;
            case "40015": //ldap injection
              alert.setName("");
              extAlert.updateAlert(alert);
              break;
            case "90020": //remote os command injection
              alert.setName("");
              extAlert.updateAlert(alert);
              break;
            case "40008": //parameter tampering
              alert.setName("");
              extAlert.updateAlert(alert);
              break;
            case "90024": //generic padding oracle attack
              alert.setName("");
              extAlert.updateAlert(alert);
              break;
            case "4": //rfi
              alert.setName("");
              extAlert.updateAlert(alert);
              break;
            case "90023": //xml external entity attack
              alert.setName("");
              extAlert.updateAlert(alert);
              break;
            case "10003": //up to date components
              description = alert.getDescription()
              info = alert.getOtherInfo()
              alert.setDescription('Using older versions of software packages, for example jquery, may allow for exploitation of e.g. XSS on a website.  '+ description + ' Vulnerable to: \n' +info)
              alert.setName('14.2.1 Verify that all components are up to date, preferably using a dependency checker during build or compile time.')
              extAlert.updateAlert(alert);
              break;
            case "10033": //directory browsing
              description = alert.getDescription()
              alert.setDescription('A directory listing was found, which may reveals sensitive data.')
              alert.setName('4.3.2 Verify that directory browsing is disabled unless deliberately desired. Additionally, applications should not allow discovery or disclosure of file or directory metadata, such as Thumbs.db, .DS_Store, .git or .svn folders.')
              extAlert.updateAlert(alert);
              break;
            default:
              break;
          }
	}
}