import smtplib, ssl


def send_verification(email, token):

    port = 465  # For SSL
    smtp_server = "smtp.gmail.com"
    sender_email = "supersafepaymentservice@gmail.com"  # Enter your address
    receiver_email = email  # Enter receiver address
    password = "HcH!tM2g*MX&6Em*"
    message = """\
    Subject: Hi there

    This is your 2FA token : %s""" % (token)

    context = ssl.create_default_context()
    with smtplib.SMTP_SSL(smtp_server, port, context=context) as server:
        server.login(sender_email, password)
        server.sendmail(sender_email, receiver_email, message)



