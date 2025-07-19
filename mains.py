import smtplib
from email.mime.text import MIMEText

gmail_user = "varuncomkarthik@gmail.com"
gmail_password = "yijtcrbnqkkhctqp"
to = "varunkarthik2808@gmail.com"

msg = MIMEText("Test email from BookSwap app.")
msg["Subject"] = "Test Email"
msg["From"] = gmail_user
msg["To"] = to

server = smtplib.SMTP("smtp.gmail.com", 587)
server.starttls()
server.login(gmail_user, gmail_password)
server.sendmail(gmail_user, to, msg.as_string())
server.quit()
print("Email sent!")