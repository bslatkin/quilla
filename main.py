# Copyright 2011-2014 Brett Slatkin
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

#!/usr/bin/env python

import base64
import hashlib
import logging
import os
import random
import re
import struct
import textwrap

# Third-party
from recaptcha.client import captcha

from google.appengine.api import app_identity
from google.appengine.api import mail
from google.appengine.api import taskqueue
from google.appengine.api import users
from google.appengine.ext import db
from google.appengine.ext import webapp
from google.appengine.ext.webapp import mail_handlers
from google.appengine.ext.webapp import template
from google.appengine.ext.webapp import util


# Defines SALT, REFLECTOR_SALT, RECAPTCHA_PUBLIC_KEY, RECAPTCHA_PRIVATE_KEY
from secrets import *

# The timestamp of the current deployment, or a cache buster locally.
VERSION_ID = (
    (os.environ.get('VERSION_ID', '').split('.', 1) + [''])[0]
    or random.randint(0, 10**10))

# The app ID of this deployment
APP_ID = app_identity.get_application_id()

# Default the pretty hostname to the default deployed app URL.
PRETTY_HOSTNAME = (
    PRETTY_HOSTNAME or app_identity.get_default_version_hostname())


def get_contact_target():
  return Target(
      key=db.Key.from_path(Target.kind(), 'contact'),
      name='Contact the administrator',
      message=('Thanks for checking out Quilla. This is a self-hosted '
               'version of the open source project:'),
      website='http://github.com/bslatkin/quilla',
      anonymous=True,
      confirmed=True,
      enabled=True,
      secret=None,
      destination_email=None)


class Target(db.Model):
  """Key name is the target name."""

  @classmethod
  def kind(cls):
    return 'T'

  @classmethod
  def get_by_target_name(cls, target_name):
    """Retrieve a Target entity with no access control."""
    # Try all lower case first.
    target_name = target_name.lower()

    # These are equivalent characters. This happens when someone
    # copied the link by reading it off a screen and got some wrong.
    target_name = (
      target_name
      .replace('0', 'O')
      .replace('1', 'I')
      .replace('l', 'I')
    )

    target = cls.get_by_key_name(target_name)
    if not target:
      # Try all upper case.
      target_name = target_name.upper()
      target = cls.get_by_key_name(target_name)

    if not target and target_name.lower() == 'contact':
      return get_contact_target()

    return target

  destination_email = db.StringProperty()
  name = db.TextProperty()
  website = db.TextProperty()
  message = db.TextProperty()

  secret = db.TextProperty()
  enabled = db.BooleanProperty()
  confirmed = db.BooleanProperty()  # User followed link from email

  creation_time = db.DateTimeProperty(auto_now_add=True)
  update_time = db.DateTimeProperty(auto_now=True)

  # True if anonymous senders allowed (they must solve a captcha), False
  # if they will need to log in through Google Accounts.
  anonymous = db.BooleanProperty(default=True)


class ReflectedSender(db.Model):
  """Key name is a hash of the email field. Parent is Target."""

  @classmethod
  def kind(cls):
    return 'RS'

  email = db.TextProperty()
  creation_time = db.DateTimeProperty(auto_now_add=True)


class ReflectedEmail(db.Model):
  """Uses auto-assign IDs."""

  @classmethod
  def kind(cls):
    return 'E'

  remote_sender = db.ReferenceProperty(ReflectedSender, indexed=False)
  local_target = db.ReferenceProperty(Target, indexed=False)

  # True if the email is going from remote to local. False if the email is
  # going from local to remote.
  inbound = db.BooleanProperty(indexed=False)

  subject = db.TextProperty()
  body = db.TextProperty()
  html = db.TextProperty()
  in_reply_to = db.TextProperty()
  references = db.TextProperty()

  creation_time = db.DateTimeProperty(auto_now_add=True)


###############################################################################

def pretty_encode(data):
  return base64.b32encode(data).strip('=')


def generate_secret():
  return hashlib.sha1(str(random.random())).hexdigest()[:-20]


def create_target(destination_email, assign_fields):
  h = hashlib.sha1()
  h.update(destination_email)
  h.update(SALT)

  for i in xrange(10):
    full_hash = h.digest()
    partial_hash = full_hash[-(i+3):]
    encoded = pretty_encode(partial_hash)
    target_key = db.Key.from_path(Target.kind(), encoded.upper())

    def txn():
      target = db.get(target_key)
      if target:
        raise db.Rollback()
      target = Target(
          key=target_key,
          destination_email=destination_email,
          enabled=False,
          secret=generate_secret())
      assign_fields(target)
      taskqueue.add(
          method='GET',
          url='/work/confirm_email',
          params=dict(target_name=encoded),
          transactional=True,
          queue_name='confirm')
      target.put()
      return target

    target = db.run_in_transaction(txn)
    if target:
      logging.info('Created target: %s, secret=%s',
                   target.key().name(), target.secret)
      return target
    else:
      h.update(str(i))

  return None


def get_target(target_name, secret=None):
  if not target_name:
    return None

  target = Target.get_by_target_name(target_name)

  if not target:
    return None

  # Allow the owner with the secret to always see Targets, even if disabled.
  if target.secret and target.secret == secret:
    return target

  if not target.enabled:
    return None

  return target


class PrettyHandler(webapp.RequestHandler):
  def get(self, target_name):
    secret = self.request.get('secret') or None
    message = self.request.get('message')

    target = get_target(target_name, secret=secret)
    if target and not target.confirmed:
      def txn():
        modified_target = db.get(target.key())
        modified_target.enabled = True
        modified_target.confirmed = True
        modified_target.put()
        return modified_target
      target = db.run_in_transaction(txn)
      logging.info('Confirmed target=%s', target_name)

    user = users.get_current_user()
    login_url = None
    if not user:
      login_url = users.create_login_url('/' + target_name)

    context = {
      'base': self.request.host_url,
      'login_url': login_url,
      'message': message,
      'recaptcha_public_key': RECAPTCHA_PUBLIC_KEY,
      'secret': secret,
      'target_name': target_name,
      'target': target,
      'user': user,
      'version_id': VERSION_ID,
    }

    self.response.out.write(template.render('pretty.html', context))
    if not target:
      self.response.set_status(404)


class EditHandler(webapp.RequestHandler):
  def get(self):
    target_name = self.request.get('id') or None
    secret = self.request.get('secret') or None
    target = get_target(target_name, secret=secret)
    context = {
      'base': self.request.host_url,
      'secret': secret,
      'target_name': target_name,
      'target': target,
      'version_id': VERSION_ID,
    }
    self.response.out.write(template.render('edit_fragment.html', context))

  def post(self):
    action = self.request.get('action', '')
    target_name = self.request.get('target_name')
    email_address = self.request.get('email_address')
    your_name = self.request.get('your_name')
    website = self.request.get('website')
    welcome_message = self.request.get('welcome_message')
    secret = self.request.get('secret')
    anonymous = bool('login_required' not in self.request.params)

    # Required field
    assert your_name

    def assign_fields(target):
      if target_name:
        target.enabled = bool(action != 'disable')
      target.name = your_name
      target.website = website
      target.message = welcome_message
      target.anonymous = anonymous

    if not target_name:
      create_target(email_address, assign_fields)
      return

    target = get_target(target_name, secret)
    if not (target and target.secret and target.secret == secret):
      self.response.set_status(403)
      return

    def txn():
      modified_target = db.get(target.key())
      if not modified_target:
        db.Rollback()
      assign_fields(modified_target)
      modified_target.put()
    db.run_in_transaction(txn)
    logging.info('Modified target=%s', target_name)


class SendHandler(webapp.RequestHandler):
  def get(self):
    target_name = self.request.get('id')
    secret = self.request.get('secret') or None
    target = get_target(target_name, secret=secret)

    user = users.get_current_user()
    login_url = None
    if not user:
      login_url = users.create_login_url('/' + target_name)

    context = {
      'base': self.request.host_url,
      'secret': secret,
      'login_url': login_url,
      'recaptcha_public_key': RECAPTCHA_PUBLIC_KEY,
      'target': target,
      'target_name': target_name,
      'user': user,
      'version_id': VERSION_ID,
    }
    self.response.out.write(template.render('message_fragment.html', context))

  def post(self):
    target_name = self.request.get('id')
    message = self.request.get('email_message') or None
    sender_email = self.request.get('email_address') or ''
    target = get_target(target_name)

    if not target:
      self.response.set_status(404)
      return

    if target.anonymous:
      response = captcha.submit(
          self.request.get('recaptcha_challenge_field'),
          self.request.get('recaptcha_response_field'),
          RECAPTCHA_PRIVATE_KEY,
          self.request.remote_addr)
      if not response.is_valid:
        logging.info('reCaptcha failed: error_code=%s', response.error_code)
        self.response.set_status(400)
        return
      reply_to = sender_email
    else:
      current_user = users.get_current_user()
      if not current_user:
        self.response.set_status(400)
        return
      reply_to = current_user.email()

    taskqueue.add(
        url='/work/send_email',
        params=dict(target_name=target_name,
                    reply_to=reply_to,
                    message=message),
        queue_name='send')
    logging.info('Enqueued email for target=%s', target_name)


class LandingHandler(webapp.RequestHandler):
  def get(self):
    context = {
      'base': self.request.host_url,
      'landing': True,
      'version_id': VERSION_ID,
    }
    self.response.out.write(template.render('landing.html', context))


def wrap_message(message):
  output = []
  for line in message.splitlines():
    if not line:
      # Properly handle extra newlines
      output.append('')
    else:
      output.extend(textwrap.wrap(line, 40))
  return '\n'.join(output)


class ConfirmWorker(webapp.RequestHandler):
  def get(self):
    target_name = self.request.get('target_name')
    target = Target.get_by_target_name(target_name)
    assert target
    context = {
      'prompt_message': wrap_message(target.message),
      'pretty_hostname': PRETTY_HOSTNAME,
      'target': target,
    }
    sender = 'Quilla %s <%s@%s.appspotmail.com>' % (
        target_name, target_name, APP_ID)
    subject = 'Confirm your new Quilla short-link: %s' % target_name
    text_data = template.render('confirm_email.txt', context)
    html_data = template.render('confirm_email.html', context)
    message = mail.EmailMessage(
        sender=sender,
        to=target.destination_email,
        subject=subject,
        body=text_data,
        html=html_data)
    logging.info('Sending confirmation email: sender=%r, to=%r',
                  sender, target.destination_email)
    if self.request.environ.get('SERVER_SOFTWARE').startswith('Dev'):
      logging.info('Created: /%s?secret=%s', target_name, target.secret)
    message.send()


class SendWorker(webapp.RequestHandler):
  def post(self):
    target_name = self.request.get('target_name')
    reply_to = self.request.get('reply_to')
    message = self.request.get('message')

    reply_to_pretty = reply_to or 'Anonymous'

    target = Target.get_by_target_name(target_name)
    assert target and message
    context = {
      'message': wrap_message(message),
      'prompt_message': wrap_message(target.message),
      'reply_to': reply_to_pretty,
      'target': target,
    }
    sender = 'Quilla %s <%s@%s.appspotmail.com>' % (
        target_name, target_name, APP_ID)
    subject = 'New message from %s' % reply_to_pretty
    text_data = template.render('message_email.txt', context)
    html_data = template.render('message_email.html', context)
    kwargs = dict(
        sender=sender,
        to=target.destination_email,
        subject=subject,
        body=text_data,
        html=html_data)
    if reply_to:
      kwargs.update(reply_to=reply_to)

    if target.destination_email:
      logging.info('Sending message: sender=%r, to=%r, reply_to=%r',
                    sender, target.destination_email, reply_to)
      mail.send_mail(**kwargs)
    else:
      del kwargs['to']
      logging.info('Sending message to admin: sender=%r, reply_to=%r',
                    sender, reply_to)
      mail.send_mail_to_admins(**kwargs)

###############################################################################

def extract_email(address):
  the_match = re.search('(\S+@\S+)', address)
  if not the_match:
    return None
  return the_match.group(1).strip('<>"\'')


def create_sender_hash(address):
  x = hashlib.sha1(address)
  x.update(REFLECTOR_SALT)
  return base64.b32encode(x.digest()).lower()


def create_sender_key(target_name, sender_hash):
  target_key = db.Key.from_path(Target.kind(), target_name.upper())
  return db.Key.from_path(
      ReflectedSender.kind(), sender_hash.lower(), parent=target_key)


class ReceiveEmailHandler(mail_handlers.InboundMailHandler):
  def receive(self, message):
    to_address = extract_email(message.to)
    sender_address = extract_email(message.sender)
    if not (to_address and sender_address):
      logging.error('Could not parse address fields: to=%r, sender=%r',
                    message.to, message.sender)
      self.response.set_status(400)
      return

    logging.info('Received email to=%r, from=%r', to_address, sender_address)

    user_name, _ = to_address.split('@', 1)
    target_name, sender_hash = (user_name.split('+', 1) + [''])[:2]
    inbound = bool(not sender_hash)

    target_name = target_name.upper()
    target = Target.get_by_target_name(target_name)
    if not target:
      logging.error('Unknown target_name: %r', target_name)
      self.response.set_status(400)
      return

    if not target.enabled:
      logging.warning('Bouncing email for disabled target %r', target_name)
      self.response.set_status(404)
      return

    if sender_hash:
      # This is outbound: From the Quilla user to an external recipient.
      # Make sure the actual sender email matches the destination address.
      target_address = extract_email(target.destination_email)
      if target_address != sender_address:
        logging.error(
            'Outbound email with target_name=%r, target_address=%r, from=%r, '
            'to=%r not permitted',
            target_name, target_address, sender_address, to_address)
        self.response.set_status(400)
        return
    else:
      # This in inbound: To a Quilla user from an external sender.
      # If the ReflectedSender does not exist, then create it
      sender_hash = create_sender_hash(sender_address)
      remote_key = create_sender_key(target_name, sender_hash)
      ReflectedSender.get_or_insert(
          remote_key.id_or_name(),
          parent=remote_key.parent(),
          email=sender_address)

    def txn():
      plain_text = (list(message.bodies('text/plain')) + [('', '')])[0][1]
      html = (list(message.bodies('text/html')) + [('', '')])[0][1]
      email = ReflectedEmail(
          remote_sender=create_sender_key(target_name, sender_hash),
          local_target=target,
          inbound=inbound,
          subject=message.subject or '',
          body=plain_text.decode() or '',
          html=html.decode() or '',
          in_reply_to=message.original.get('In-Reply-To', ''),
          references=message.original.get('References', ''))
      email.put()

      taskqueue.add(
          method='GET',
          url='/work/reflect_email',
          params=dict(target_name=target_name,
                      email_id=str(email.key().id_or_name())),
          transactional=True,
          queue_name='reflect')

    db.run_in_transaction(txn)


class ReflectEmailWorker(webapp.RequestHandler):
  def get(self):
    target_name = self.request.get('target_name')
    email_id = int(self.request.get('email_id'))

    email = ReflectedEmail.get_by_id(email_id)
    if email is None:
      logging.warning('Received task for non-existent email_id=%d', email_id)
      return

    target = email.local_target
    remote_sender = email.remote_sender
    body = email.body or None
    html = email.html or None

    if email.inbound:
      sender =(
          '"%s (Quilla Reflector: %s)" <%s+%s@%s.appspotmail.com>' % (
              remote_sender.email.replace('@', ' at '), target_name,
              target_name, remote_sender.key().name(), APP_ID))
      to = target.destination_email
    else:
      sender = 'Quilla Reflector: %s <%s@%s.appspotmail.com>' % (
          target_name, target_name, APP_ID)
      to = remote_sender.email

    if ('@%s.appspotmail.com' % APP_ID) in to:
      logging.warning(
          'Loop in email reflection; from=%r, to=%r; dropping message',
          sender, to)
      return

    headers = {}
    if email.in_reply_to:
      headers['In-Reply-To'] = email.in_reply_to
    if email.references:
      headers['References'] = email.references

    # Use kwargs like this because the EmailMessage class breaks if you
    # pass it an 'html' keyword argument that is None.
    kwargs = dict(
      sender=sender,
      to=to,
      subject=email.subject or '')
    if body:
      kwargs.update(body=email.body)
    if html:
      kwargs.update(html=email.html)

    message = mail.EmailMessage(**kwargs)
    if headers:
      message.headers = headers

    logging.info('Sending reflected email: sender=%r, to=%r, headers=%r',
                  message.sender, message.to, headers)
    message.send()

    email.delete()


###############################################################################

class DoNothingHandler(webapp.RequestHandler):
  def get(self):
    pass


app = webapp.WSGIApplication([
  ('/_ah/warmup', DoNothingHandler),
  ('/_ah/mail/.+', ReceiveEmailHandler),
  ('/work/confirm_email', ConfirmWorker),
  ('/work/send_email', SendWorker),
  ('/work/reflect_email', ReflectEmailWorker),
  ('/', LandingHandler),
  ('/edit', EditHandler),
  ('/send', SendHandler),
  ('/(.+)', PrettyHandler),
])


def main():
  util.run_wsgi_app(app)


if __name__ == '__main__':
  main()
