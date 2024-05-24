package main

import (
	"fmt"
	"net/http"
)

// STS Auth Endpoint returns HTML content that gets render in a webview container
// The webview container expect a POST request to the appru URL with the wresult parameter set to the auth token
// The security token in wresult is later passed back in <wsse:BinarySecurityToken>
// This string is opaque to the enrollment client; the client does not interpret the string.
// The returned HTML content contains a JS script that will perform a POST request to the appru URL automatically
// This will set the wresult parameter to the value of auth token
func STSAuthHandler(w http.ResponseWriter, r *http.Request) {
	// Print querystring

	if r.Method == http.MethodGet {
		fmt.Printf("====================Query String GET:\n%s\n====================", r.URL.RawQuery)
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")

		w.Write([]byte(`
				<h3>MDM Federated Login</h3>
								
				<script>
				function performPost() {
				  var form = document.createElement('form');
				  form.method = 'POST';
				  form.action = "` + r.URL.Query().Get("appru") + `"

				  // Add any form fields or data you want to send
				  var input1 = document.createElement('input');
				  input1.type = 'hidden';
				  input1.name = 'wresult';
				  input1.value = 'tokenmagic'; // this is the token paramenter passed through programmatic enrollment
				  form.appendChild(input1);

				  // Submit the form
				  document.body.appendChild(form);
				  form.submit();
				}


				// Call performPost() when the script is executed
				performPost();
			  	</script>
				`))

		return
	} else if r.Method == http.MethodPost {
		fmt.Printf("====================Query String POST:\n%s\n====================", r.URL.RawQuery)
	}
}
