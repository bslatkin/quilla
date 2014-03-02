/* Copyright 2011-2014 Brett Slatkin
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Common
function switchTo(snippet) {
  $('#primary').empty().html(snippet);
}

CURRENT_STATE = null;
POPPED = ('state' in window.history);
INITIAL_URL = window.location.href;

function checkStatesEqual(stateObj) {
  if (stateObj && !CURRENT_STATE || !stateObj && CURRENT_STATE) {
    return false;
  }
  if ($(CURRENT_STATE).size() != $(stateObj).size()) {
    return false;
  }
  var equal = true;
  $.each(stateObj, function(name, value) {
    if (CURRENT_STATE[name] != value) {
      equal = false;
    }
  });
  return equal;
}

function maybePushState(stateObj, location, opt_targetName) {
  if (!window.History.enabled) {
    return;
  }
  if (checkStatesEqual(stateObj)) {
    // console.log('States are equal; doing nothing');
    return false;
  }
  if (!CURRENT_STATE) {
    CURRENT_STATE = stateObj;
    // console.log('Replacing: ' + $.param(stateObj));
    window.History.replaceState(stateObj, $('head>title').text(), location);
  } else {
    var pageTitle = 'Quilla';
    if (opt_targetName) {
      pageTitle += ' \u203A ' + opt_targetName;
    }
    // console.log('Pushing: ' + $.param(stateObj));
    window.History.pushState(stateObj, pageTitle, location);
    CURRENT_STATE = stateObj;
  }
  return true;
}

function validateEmail(email) {
  return email.match(/^[a-zA-Z0-9_\+-\.]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-\.]+$/);
}

// Message form
function switchToMessageForm(targetId) {
  $.ajax({
    type: 'GET',
    url: '/send',
    data: {id: targetId},
    dataType: 'html',
    success: function(data) {
      switchTo(data);
    },
    error: function() {
      // TODO
    }
  });
}

function sendMessage() {
  _gaq.push(['_trackEvent', 'Send', 'Attempt']);

  // Validation.
  var senderEmail = $('#email_address').val() || '';
  if (senderEmail != '') {
    if (!validateEmail(senderEmail)) {
      $('#send-status')
          .addClass('error')
          .text('Please supply a valid email address.');
      $('#email_address').focus();
      return;
    }
  }
  if (!$('#email_message').val()) {
    $('#send-status').addClass('error').text('Please supply a message.');
    $('#email_message').focus();
    return;
  }

  var payload = $('#send_form').serialize()
  $('#send_button').attr('disabled', 'disabled');
  $('#send-status').text('Sending...').removeClass('error');
  $('#send_form').find(':input').blur().attr('disabled', 'disabled');

  $.ajax({
    type: 'POST',
    url: '/send',
    data: payload,
    dataType: 'text',
    success: function(data, statusText, xhr) {
      $('#send_form').addClass('success');
      var messageEl = $('<span class="message-text-confirm">').text(
          $('#email_message').val());
      $('.message-text').empty().append(messageEl);
      $('.submit-section').hide();
      $('.thanks-message').show();
      _gaq.push(['_trackEvent', 'Send', 'Success']);
    },
    error: function() {
      _gaq.push(['_trackEvent', 'Send', 'Error']);
      $('#send_form').find(':input').attr('disabled', null);
      $('#send-status').addClass('error').text('Sorry, try again.');
    }
  });
}

function initMessageForm(targetId, targetName) {
  $('#send_form').find(':input').attr('disabled', null);
  $('#send-status').removeClass('error');
  $('#send_button').click(function(e) {
    e.preventDefault();
    sendMessage();
  });
  $('.create-link').click(function(e) {
    if (window.History.enabled) {
      e.preventDefault();
      switchToSaveForm();
    }
  });
  maybePushState({'view': targetId}, '/' + targetId, targetName);
}

function initLoginForm(targetId, targetName) {
  maybePushState({'view': targetId}, '/' + targetId, targetName);
}

function initNothing() {
  // TODO
}

// Save form
function switchToSaveForm(targetId, userSecret) {
  var targetIdFixed = targetId;
  if (!targetId) {
    targetIdFixed = '';
  }
  $.ajax({
    type: 'GET',
    url: '/edit',
    data: {id: targetIdFixed, secret: userSecret},
    dataType: 'html',
    success: function(data) {
      switchTo(data);
    },
    error: function() {
      // TODO
    }
  });
}

function resetSaveForm(isTargetKnown) {
  $('#creation_form').find(':input').attr('disabled', null);
  if (!isTargetKnown) {
    $('#save-status').removeClass('error').text('');
    $('#creation_form').find(':input:not(input[type=submit])').val('');
    $('#creation_form').find(':input').attr('disabled', null);
  }
}

function saveLink(action) {
  _gaq.push(['_trackEvent', 'Create', 'Error']);
  // Validation.
  var knownTarget = $('#target_id') && $('#target_id').val();
  if (!knownTarget) {
    var email = $('#email_address').val() || '';
    if (!validateEmail(email)) {
      $('#save-status').addClass('error').text('Invalid email address.');
      $('#email_address').focus();
      return;
    }
  }
  if (!$('#your_name').val()) {
    $('#save-status').addClass('error').text('Please supply a purpose.');
    $('#your_name').focus();
    return;
  }
  var website = $('#website').val();
  if (website && website.indexOf('http://') == -1 &&
      website.indexOf('https://') == -1) {
    $('#website').val('http://' + website);
  }

  var payload = 'action=' + action + '&' + $('#creation_form').serialize();
  $('#save-status').removeClass('error').text('Saving...');
  $('#creation_form').find(':input').blur().attr('disabled', 'disabled');
  $.ajax({
    type: 'POST',
    url: '/edit',
    data: payload,
    dataType: 'text',
    success: function(data) {
      _gaq.push(['_trackEvent', 'Create', 'Success']);
      var targetId = $('#target_id');
      if (action == 'disable') {
        // Link was disabled
        $('#save-status').text('Link disabled.');
      } else if (targetId && targetId.val()) {
        // Saving an existing link.
        switchToMessageForm(targetId.val());
      } else {
        // A newly created link.
        $('#save-status').text(
            'Confirmation sent. Be sure to check your spam folder!');
      }
    },
    error: function() {
      _gaq.push(['_trackEvent', 'Create', 'Error']);
      $('#creation_form').find(':input').attr('disabled', null);
      $('#save-status').text('Sorry, try again.');
    }
  });
}

function initSaveForm(targetId, userSecret) {
  // Initing a new edit form, not a known one, so clear all fields to handle
  // when the user refreshes their browser but the agent preserves the fields.
  resetSaveForm(targetId != '');

  if (targetId != '') {
    $('.view-link').click(function(e) {
      e.preventDefault();
      switchToMessageForm(targetId);
    });
  }

  $('#save_button').click(function(e) {
    e.preventDefault();
    saveLink('save');
  });

  $('#delete_button').click(function(e) {
    e.preventDefault();
    var actuallyDisable = confirm(
        'Are you sure you want to disable this short link? ' +
        '(you may re-enable it later)');
    if (actuallyDisable) {
      saveLink('disable');
    }
  });

  if (window.History.enabled) {
    if (targetId && userSecret) {
      maybePushState(
          {'edit': targetId, 'secret': userSecret},
          '/' + targetId + '?secret=' + userSecret);
    } else {
      maybePushState({'edit': ''}, '/');
    }
  }
}

function initFooter() {
  $('.create-link').click(function(e) {
    if (window.History.enabled) {
      e.preventDefault();
      switchToSaveForm();
    }
  });
}

// Global state handlers
function handleChangeState() {
  var state = window.History.getState();
  if (!state) {
    // console.log('Popped: Nothing');
    return;
  }

  state = state.data;
  if (checkStatesEqual(state)) {
    // console.log('Changing to current state; doing nothing');
    return false;
  }

  // console.log('Popping: ' + $.param(state));
  CURRENT_STATE = state;
  if (state.view) {
    switchToMessageForm(state.view);
  }
  if (typeof state.edit != 'undefined') {
    // Edit value will be blanked for new edit form.
    switchToSaveForm(state.edit, state.secret);
  }
}

// Run this immediately without waiting for document.ready.
if (window.History.enabled) {
  window.History.Adapter.bind(window, 'statechange', handleChangeState);
}
