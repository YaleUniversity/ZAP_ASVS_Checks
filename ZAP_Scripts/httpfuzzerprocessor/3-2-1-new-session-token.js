/*

Script testing 3.2.1 from OWASP ASVS 4.0:

Verify the application generates a new session token on user authentication.

Once the fuzzer is run 

*/


// Auxiliary variables/constants needed for processing.
var count = 1;
var tokens = [];

function getToken(body){
	try {
		var obj = JSON.parse(body)
  		var token = obj.authentication.token;
          return token;
	} catch (error) {

	}
}

function processMessage(utils, message) {
	message.getRequestHeader().setHeader("X-Unique-Id", count);
	count++;
}

function processResult(utils, fuzzResult){

	//testing variables
     var codes = [200, 201, 202, 203, 204, 205, 206, 207, 208, 209];

     var response_code = fuzzResult.getHttpMessage().getResponseHeader().getStatusCode();
     var response_body = fuzzResult.getHttpMessage().getResponseBody();
	var index = codes.indexOf(response_code);

	var current_token = getToken(response_body);

	var index = tokens.indexOf(current_token);

	//alert info
     var risk= 1;
     var confidence = 1;
     var name = "3.2.1 - Verify the application generates a new session token on user authentication.";
     var description = "3.2.1 - Verify the application generates a new session token on user authentication." + "\n" + "Token repeated: " + current_token + "\n" + "cweID:  " + "384" + "\n" + "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html";
     
     
	if (index != -1){//if current token is in array 
               fuzzResult.addCustomState("Key Custom State", "3.2.1 - Verify the application generates a new session token on user authentication.");
			utils.raiseAlert(risk, confidence, name, description);
        }
	tokens.push(current_token);
	return true;
}

function getRequiredParamsNames(){
	return [];
}

function getOptionalParamsNames(){
	return [];
}

