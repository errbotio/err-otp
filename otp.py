from io import StringIO
import threading


from qrcode import QRCode
import pyotp

from errbot import BotPlugin, botcmd, cmdfilter

def ident(msg):
    if hasattr(msg.frm, 'aclattr'):  # if the identity requires a special field to be used for acl
        return msg.frm.aclattr
    return msg.frm.person  # default

def makeQRCodeMessage(data, mode):
    sio = StringIO()
    qr = QRCode()
    qr.add_data(data)
    qr.print_ascii(out=sio, invert=mode == 'text')
    return '```\n' + '\n'.join(line.lstrip() for line in sio.getvalue().split('\n')) + '\n```\nContent: %s' % data


class OTP(BotPlugin):
    """ This implements One Time Passwords for Errbot.
    """
    def __init__(self, bot):
        super().__init__(bot)
        self.cmds = set()  # set of messages requiring an OTP
        self.lastopts = {}  # list of last OTP with their timestamps.
        self.backlog = []  # backlog of commands awaiting for OTP.
        self.lock = threading.Lock()  # protects the 3 structures.

    @botcmd(admin_only=True)
    def otp_addcmd(self, msg, args):
        """Flag a command as OTP only."""
        with self.lock:
            self.cmds.add(args)
            return "Added '%s' to OTP only commands." % args

    @botcmd(admin_only=True)
    def otp_delcmd(self, msg, args):
        """Authorize a command with no OTP."""
        with self.lock:
            self.cmds.remove(args)
            return "Removed '%s' from OTP only commands." % args

    @botcmd(admin_only=True)
    def otp_cmds(self, msg, args):
        """List commands requiring OTPs."""
        with self.lock:
            return "Commands with mandatory OTP:\n" + '\n'.join(self.cmds)

    @botcmd(admin_only=True)
    def otp_secret(self, msg, args):
        """Send a new secret to somebody"""
        new_secret = pyotp.random_base32()
        with self.lock:
            if 'secrets' in self:
                secrets = self['secrets']
            else:
                secrets = {}
            secrets[args] = new_secret
            self['secrets'] = secrets
        totp = pyotp.TOTP(new_secret)
        url = totp.provisioning_uri(args)
        self.send(self.build_identifier(args), makeQRCodeMessage(url, self._bot.mode), None, 'chat')

        return "New secret set for %s and message sent." % args

    def callback_message(self, msg):
        if msg.type == 'groupchat':
            return
        try:
            otp = int(msg.body)
            self.log.info("Received what looks like an OTP.")
        except ValueError:
            return

    @cmdfilter
    def otpfilter(self, msg, cmd, args, dry_run):
        self.log.info("You are trying to call %s with %s" % (cmd, args))
        with self.lock:
            if cmd in self.cmds:
                self.log.info("This command is protected by OTP.")
                # check if the user has a fresh enough OTP
                # if not ask for one

        return msg, cmd, args
