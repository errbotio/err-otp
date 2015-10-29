# OTP 2 factor auth for Errbot (errbot.net)

The goal is to implement OTP compatible flow for Google Authenticator and OpenOTP.

This is working including the qrcode exchange.

### How to install it:

```
!repos install https://github.com/gbin/err-otp.git
```

### How to use it in a nutshell:

Flag a command to require an OTP (as an admin): 
```
!otp_addcmd [command_name] # to protect a command by OTP
```

Send a secret to a user: 
This will send a qrcode to someone so they can scan it with their [freeOTP app](https://play.google.com/store/apps/details?id=org.fedorahosted.freeotp&hl=en) or [google authenticator](https://play.google.com/store/apps/details?id=com.google.android.apps.authenticator2&hl=en).
```
!otp_secret [somebody] 
```

Then when this somebody tries the command, the bot will block it, ask for an OTP and once it is entered by the somebody it should unlock and execute it.

