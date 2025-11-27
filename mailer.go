package main

import (
	"bytes"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/smtp"
	"os"
)

var smtpServer = "smtp.gmail.com"
var smtpPort = "587"

// EmailTemplate is the HTML template for the email
const EmailTemplate = `
<html dir="ltr" xmlns="http://www.w3.org/1999/xhtml" xmlns:o="urn:schemas-microsoft-com:office:office">
  <head>
    <meta charset="UTF-8">
    <meta content="width=device-width, initial-scale=1" name="viewport">
    <meta name="x-apple-disable-message-reformatting">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta content="telephone=no" name="format-detection">
    <title></title>
    <!--[if (mso 16)]>
    <style type="text/css">
    a {text-decoration: none;}
    </style>
    <![endif]-->
    <!--[if gte mso 9]><style>sup { font-size: 100% !important; }</style><![endif]-->
    <!--[if gte mso 9]>
<noscript>
         <xml>
           <o:OfficeDocumentSettings>
           <o:AllowPNG></o:AllowPNG>
           <o:PixelsPerInch>96</o:PixelsPerInch>
           </o:OfficeDocumentSettings>
         </xml>
      </noscript>
<![endif]-->
    <!--[if !mso]><!-- -->
    <link href="https://fonts.googleapis.com/css2?family=Changa:wght@200;300;400;500;600;700;800&display=swap" rel="stylesheet">
    <!--<![endif]-->
  </head>
  <body class="body">
    <div dir="ltr" class="es-wrapper-color">
      <!--[if gte mso 9]>
			<v:background xmlns:v="urn:schemas-microsoft-com:vml" fill="t">
				<v:fill type="tile" color="#213049"></v:fill>
			</v:background>
		<![endif]-->
      <table width="100%" cellspacing="0" cellpadding="0" class="es-wrapper">
        <tbody>
          <tr>
            <td valign="top" class="esd-email-paddings">
              <table cellspacing="0" cellpadding="0" align="center" class="es-content esd-header-popover">
                <tbody>
                  <tr>
                    <td align="center" background="https://tlr.stripocdn.email/content/guids/CABINET_e585f666dce8a1411b56958e42b81148bc5b3de704825fafe83d86a62a9e4334/images/bg.png" class="esd-stripe" style="background-image:url(https://tlr.stripocdn.email/content/guids/CABINET_e585f666dce8a1411b56958e42b81148bc5b3de704825fafe83d86a62a9e4334/images/bg.png);background-repeat:no-repeat;background-position:center top">
                      <table width="600" cellspacing="0" cellpadding="0" bgcolor="#f4ece7" align="center" class="es-content-body" style="background-color:#f4ece7">
                        <tbody>
                          <tr>
                            <td align="left" bgcolor="#1c283d" class="esd-structure es-p20" style="background-color:#1c283d">
                              <table cellspacing="0" cellpadding="0" width="100%">
                                <tbody>
                                  <tr>
                                    <td width="560" align="left" class="esd-container-frame">
                                      <table width="100%" cellspacing="0" cellpadding="0">
                                        <tbody>
                                          <tr>
                                            <td align="center" class="esd-block-image" style="font-size:0px">
                                              <a target="_blank">
                                                <img src="https://tlr.stripocdn.email/content/guids/CABINET_e585f666dce8a1411b56958e42b81148bc5b3de704825fafe83d86a62a9e4334/images/xmas.png" alt="" width="130" style="display:block">
                                              </a>
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
                          <tr>
                            <td align="left" class="esd-structure">
                              <table width="100%" cellspacing="0" cellpadding="0">
                                <tbody>
                                  <tr>
                                    <td width="600" valign="top" align="center" class="esd-container-frame">
                                      <table width="100%" cellspacing="0" cellpadding="0">
                                        <tbody>
                                          <tr>
                                            <td align="center" class="esd-block-image" style="font-size:0px">
                                              <a target="_blank">
                                                <img src="https://tlr.stripocdn.email/content/guids/CABINET_e585f666dce8a1411b56958e42b81148bc5b3de704825fafe83d86a62a9e4334/images/bannerchr1.gif" alt="" width="600" class="adapt-img" style="display:block">
                                              </a>
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
                          <tr>
                            <td align="left" bgcolor="#f4ece7" class="esd-structure es-p30t es-p30b es-p20r es-p20l" style="background-color:#f4ece7">
                              <table cellpadding="0" cellspacing="0" width="100%">
                                <tbody>
                                  <tr>
                                    <td width="560" align="center" valign="top" class="esd-container-frame">
                                      <table cellpadding="0" cellspacing="0" width="100%">
                                        <tbody>
                                          <tr>
                                            <td align="center" class="esd-block-text">
                                              <h1 class="es-m-txt-c" style="color:#008c7c;line-height:110%">
                                                Psst... your Secret Santa has a little
                                              </h1>
                                              <h1 class="es-m-txt-c" style="color:#008c7c;line-height:110%">
                                                message for you!
                                              </h1>
                                            </td>
                                          </tr>
                                          <tr>
                                            <td align="center" class="esd-block-text es-p20t es-p20b">
                                              <p>
                                                <h2>{{.Message}}</h2>
                                              </p>
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

	email := os.Getenv("EMAIL_ADDR")
	password := os.Getenv("EMAIL_PWD")

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

	// Compose the email with headers
	body := fmt.Sprintf("Subject: 🎅Secret message from the Secret Santa 🎅\nMIME-Version: 1.0\nContent-Type: text/html; charset=\"UTF-8\"\n\n%s", bodyBuffer.String())

	from := "Secret Santa <secretsanta@qburst.com>"
	// Send the email
	err = sendEmail(email, password, from, to, body)
	if err != nil {
		http.Error(w, "Failed to send email", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
	return
}

// Function to send email using SMTP
func sendEmail(email string, password string, from string, to string, body string) error {
	auth := smtp.PlainAuth("", email, password, smtpServer)

	// Format the email message
	msg := []byte(fmt.Sprintf("From: %s\nTo: %s\n%s", from, to, body))

	// Send the email
	err := smtp.SendMail(smtpServer+":"+smtpPort, auth, email, []string{to}, msg)
	if err != nil {
		log.Println("Error sending email:", err)
		return err
	}
	return nil
}
