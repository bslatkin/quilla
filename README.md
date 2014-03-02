# Quilla

![Logo](quilla.png)

#### Provides short-links where people can contact you for a purpose:

  - Feedback on my presentation
  - Report a problem with my app
  - Anonymous tips
  - RSVP for my event
  - For sale & classifieds

Each submission on your short-link will send you an email. Replying to a message will contact the person who filled out the form. Your email address will not be revealed until you reply. An example short link for contacting me: http://a.quil.la/FVZ3PMZC

Short-links can be in two modes: captcha or login. In captcha mode, all that's required to send you an email is filling out a captcha. In login mode, users are required to login with their Google Account in order to send you an email.

Quilla is also an email reflector. The short-link URL above can be emailed directly as FVZ3PMZC@quil-la.appspotmail.com. Replies to email messages will be reflected in both directions, allowing you to communicate with someone without revealing your email address.

#### See the live, free version:

**http://a.quil.la/**


# Deployment

Quilla runs on App Engine. [Get the SDK here](https://developers.google.com/appengine/downloads). To deploy, do these things:

Create a secrets.py file in the project directory with these defined:

```python
# Random numbers are good, like hashlib.sha1(uuid.uuid4().hex).hexdigest()
# SECRET! Combined with the target email address to create key names.
SALT = ''
# SECRET! Combined with the target email address to create reflector keys.
REFLECTOR_SALT = ''

# Provision these on http://recaptcha.net
# reCaptcha public key (in javascript)
RECAPTCHA_PUBLIC_KEY = ''
# reCaptcha private key (server-side)
RECAPTCHA_PRIVATE_KEY = ''

# If you are running on a custom domain, list it here:
PRETTY_HOSTNAME = ''
```

Run this command from the project directory:

```shell
appcfg.py --version=prod --application=your-app-id-here update .
```

To make the app work well in production, you're going to need to apply for additional email quota (the default is 100 a day). Sign up for an App Engine app ID, set up billing for that app, then request additional email quota (linked from the "Quota Details" tab).


# About

Copyright 2011-2014 [Brett Slatkin](http://www.onebigfluke.com)

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.


Built using [App Engine](https://developers.google.com/appengine/), [jQuery](http://jquery.com/), [History.js](https://github.com/browserstate/history.js), and [YUI](http://yuilibrary.com/).
