from io import StringIO
import contextlib
import threading
import datetime

from qrcode import QRCode
import pyotp

from errbot import BotPlugin, botcmd, cmdfilter

# People have to enter an OTP once a day.
OTP_EXPIRATION = datetime.timedelta(days=1)

# if a user fails 10 times at OTP'ing, burn his/her secret
OTP_MAX_NB_FAILS = 10
BEGINNING_OF_TIMES = datetime.datetime(year=datetime.MINYEAR, month=1, day=1)

def ident(msg):
    """ Retreive the relevant identity for OTP from the given message."""
    # if the identity requires a special field to be used for acl
    return msg.frm.aclattr if hasattr(msg.frm, 'aclattr') else msg.frm.person

def makeQRCode(data, mode):
    """ Make a graphical representation of a QRCODE in unicode."""
    sio = StringIO()
    qr_code = QRCode()
    qr_code.add_data(data)
    qr_code.print_ascii(out=sio, invert=mode == 'text')
    return '\n'.join(line.lstrip() for line in sio.getvalue().split('\n'))


def makeQRCodeMessage(data, mode):
    """ Make a chat message with a QRCode in it."""
    return '```\n' + makeQRCode(data, mode) + '\n```\ncontent: %s' % data


class OTP(BotPlugin):
    """ This implements One Time Passwords for Errbot.
    """
    def __init__(self, bot):
        super().__init__(bot)
        self.backlog = []  # backlog of commands awaiting for OTP.
        self.lock = threading.Lock()  # protects storage
        self.bl_lock = threading.Lock()  # protects backlog

    @contextlib.contextmanager
    def stored(self, key):
        """ This is an context helper to ease the mutability of the internal plugin storage.
        """
        value = self[key]
        try:
            yield value
        finally:
            self[key] = value

    def activate(self):
        super().activate()
        if 'cmds' not in self:
            self['cmds'] = set()
        if 'secrets' not in self:
            self['secrets'] = {}

    @botcmd(admin_only=True)
    def otp_zapall(self, msg, args):
        """ DANGER: Removes all the OTP entries. """
        self['cmds'] = set()
        self['secrets'] = {}

    @botcmd(admin_only=True)
    def otp_addcmd(self, msg, args):
        """Flag a command as OTP only."""
        with self.lock:
            with self.stored('cmds') as cmds:
                cmds.add(args)
            return "Added '%s' to OTP only commands." % args

    @botcmd(admin_only=True)
    def otp_delcmd(self, msg, args):
        """Authorize a command with no OTP. (reverse from addcmd)."""
        with self.lock:
            with self.stored('cmds') as cmds:
                if args not in cmds:
                    return "%s is not in the list of OTPed commands" % args
                cmds.remove(args)
                return "Removed '%s' from OTP only commands." % args

    @botcmd(admin_only=True)
    def otp_cmds(self, msg, args):
        """List the current commands requiring OTPs."""
        return "Commands with mandatory OTP:\n" + '\n'.join(self['cmds'])

    @botcmd(admin_only=True)
    def otp_secret(self, msg, args):
        """Send a new secret to somebody"""
        new_secret = pyotp.random_base32()
        with self.lock:
            with self.stored('secrets') as secrets:
                secrets[args] = (new_secret, 0, BEGINNING_OF_TIMES)
        totp = pyotp.TOTP(new_secret)
        url = totp.provisioning_uri(args)
        self.send(self.build_identifier(args), makeQRCodeMessage(url, self._bot.mode), None, 'chat')

        return "New secret set for %s and message sent." % args

    @botcmd(admin_only=True)
    def otp_reset(self, msg, args):
        """Reset the secret of somebody"""
        return self.otp_secret(msg, args)

    def callback_message(self, msg):
        """Check the messages if it received an OTP confirming a command."""
        if msg.type == 'groupchat':
            return
        try:
            otp = int(msg.body)
        except ValueError:
            return

        self.log.info("Received what looks like an OTP.")
        idd = ident(msg)
        if idd not in self['secrets']:
            self.log.info("User %i has no OTP secret, ignore.")
            return
        secret, attempts, _ = self['secrets'][idd]
        totp = pyotp.TOTP(secret)
        self.log.debug("Current OTP:%d" % int(totp.now()))
        if totp.verify(otp):
            self.send(msg.frm, "OTP verified OK.")
            with self.lock:
                with self.stored('secrets') as secrets:
                    secret, attempts, _ = secrets[idd]
                    secrets[idd] = (secret, attempts, datetime.datetime.now())

            with self.bl_lock:
                new_blacklog = []
                for bl_idd, bl_msg, bl_cmd, bl_args in self.backlog:
                    if idd == bl_idd:
                       self.log.info("User %s: processing %s from the OTP backlog." % (bl_idd, bl_cmd))
                       self._bot._process_command(bl_msg, bl_cmd, bl_args, False)  # TODO: enable re_commands too. 
                    else:
                       new_blacklog.append(bl_idd, bl_msg, bl_cmd, bl_args)
                self.backlog = new_blacklog
            return
        return

    @cmdfilter
    def otpfilter(self, msg, cmd, args, dry_run):
        """ This is where the actual filtering is done."""
        self.log.info("You are trying to call %s with %s" % (cmd, args))
        with self.lock:
            if cmd in self['cmds']:
                self.log.info("This command is protected by OTP.")
                idd = ident(msg)
                secrets = self['secrets']
                if idd not in secrets:
                    self.send(msg.frm, "You need to contact your administrator to get an OTP token for those commands.")
                    return None, None, None
                _, _, lastotp = secrets[idd]
                if datetime.datetime.now()- lastotp > OTP_EXPIRATION:
                    self.log.info("%s never OTP'ed or has an expired token." % idd)
                    self.send(msg.frm, "OTP expired, send an OTP directly to the bot to unlock this command.")
                    with self.bl_lock:
                        self.backlog.append((idd, msg, cmd, args))
                    return None, None, None
                self.log.info("OTP ok, allows the command")
        return msg, cmd, args
