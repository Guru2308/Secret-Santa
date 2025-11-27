package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"html/template"
	"log"
	"net/http"

	"google.golang.org/api/gmail/v1"
	"google.golang.org/api/option"
)

// EmailTemplate is the HTML template for the email
const EmailTemplate = `
<html dir="ltr" xmlns="http://www.w3.org/1999/xhtml" xmlns:o="urn:schemas-microsoft-com:office:office">
  <head>
    <meta charset="UTF-8">
    <meta content="width=device-width, initial-scale=1" name="viewport">
    <title>Secret Santa Message</title>
    <link href="https://fonts.googleapis.com/css2?family=Changa:wght@200;300;400;500;600;700;800&display=swap" rel="stylesheet">
  </head>
  <body class="body">
    <div dir="ltr" class="es-wrapper-color">
      <table width="100%" cellspacing="0" cellpadding="0" class="es-wrapper">
        <tbody>
          <tr>
            <td valign="top" class="esd-email-paddings">
              <table cellspacing="0" cellpadding="0" align="center" class="es-content esd-header-popover">
                <tbody>
                  <tr>
                    <td align="center">
                      <table width="600" cellspacing="0" cellpadding="0" bgcolor="#f4ece7" align="center" class="es-content-body" style="background-color:#f4ece7">
                        <tbody>
                          <tr>
                            <td align="center" class="esd-block-text">
                              <h1 style="color:#008c7c;line-height:110%">
                                Psst... your Secret Santa has a little message for you!
                              </h1>
                              <h2>{{.Message}}</h2>
                            </td>
                          </tr>
                        </tbody>
                      </table>
                    </td>
                  </tr>
                </tbody>
              </table>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </body>
</html>
`

func SecretMessageHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Unable to parse form data", http.StatusBadRequest)
		return
	}

	// We no longer strictly need EMAIL_PWD for the Gmail API via Service Account,
	// but we still typically check if EMAIL_ADDR is set for context.
	// email := os.Getenv("EMAIL_ADDR") 

	to := r.FormValue("to")
	message := r.FormValue("message")

	// Populate the HTML template
	tmpl, err := template.New("email").Parse(EmailTemplate)
	if err != nil {
		http.Error(w, "Failed to parse email template", http.StatusInternalServerError)
		return
	}

	var bodyBuffer bytes.Buffer
	err = tmpl.Execute(&bodyBuffer, map[string]string{"Message": message})
	if err != nil {
		http.Error(w, "Failed to render email template", http.StatusInternalServerError)
		return
	}

	// Send the email using Gmail API
	err = sendEmailWithGmailAPI(to, bodyBuffer.String())
	if err != nil {
		log.Printf("Failed to send email: %v", err)
		http.Error(w, "Failed to send email: "+err.Error(), http.StatusInternalServerError)
		return
	}
	
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// Function to send email using Gmail API (Service Account)
func sendEmailWithGmailAPI(to string, body string) error {
	ctx := context.Background()

	// 1. Create the Gmail Service using the existing credentials.json
	srv, err := gmail.NewService(ctx, option.WithCredentialsFile("credentials.json"))
	if err != nil {
		return fmt.Errorf("unable to retrieve Gmail client: %v", err)
	}

	// 2. Construct the email message
	// Note: The "From" address is determined by the authenticated Service Account
	// unless Domain-Wide Delegation is configured.
	header := make(map[string]string)
	header["To"] = to
	header["Subject"] = "🎅Secret message from the Secret Santa 🎅"
	header["MIME-Version"] = "1.0"
	header["Content-Type"] = "text/html; charset=\"UTF-8\""

	var msgString string
	for k, v := range header {
		msgString += fmt.Sprintf("%s: %s\r\n", k, v)
	}
	msgString += "\r\n" + body

	// 3. Encode the message to base64url (required by Gmail API)
	rawMessage := base64.URLEncoding.EncodeToString([]byte(msgString))

	gMessage := &gmail.Message{
		Raw: rawMessage,
	}

	// 4. Send the email
	// "me" is a special value indicating the authenticated user (the service account)
	_, err = srv.Users.Messages.Send("me", gMessage).Do()
	if err != nil {
		return fmt.Errorf("unable to send message: %v", err)
	}

	return nil
}