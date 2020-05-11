# WhatsApp Web API JS

This library allows you to make a WhatsApp bot in JS or TS. The library implements the WhatsApp Web API and therefore doesn't use puppeteer, selenium, etc.

The library is based on [Sigalor's WhatsApp Web Python library](https://github.com/sigalor/whatsapp-web-reveng).

## Installation

```bash
npm install -S @noamalffasy/js-whatsapp
```

or

```bash
yarn add @noamalffasy/js-whatsapp
```

## Usage

### Setting up

All parameters are optional.  The following are the default values.  
```js
import Whatsapp from "@noamalffasy/js-whatsapp";

const opts = {
  keysPath: "./keys.json",
  qrPath: "./qrcode.png",
  clientName: "WhatsApp forwarder",
  clientShortName: "WhatsAppForwarder",
  restoreSession: false
}

const wap = new Whatsapp(opts);
```

### Login

By using the code shown above, a QR Code should be generated automatically and put in the current directory.

Once scanned, your keys will be put in the same directory and saved for the next session.

Auto login is supported, in order to login automatically you need to change:

```js
const wap = new Whatsapp();
```

to:

```js
const wap = new Whatsapp({restoreSession: true});
```

### Handle messages

As of now, 2 events are supported: `ready` and `message`.

```js
import Whatsapp from "@noamalffasy/js-whatsapp";

const wap = new Whatsapp();

wap.on("ready", () => {
  // Your code goes here
});

wap.on("message", msg => {
  // Your code goes here
});
```

### Sending text messages

WhatsApp internally uses IDs called Jids:

- **Chats:** [country code][phone number]@s.whatsapp.net
- **Groups:** [country code][phone number of creator]-[timestamp of group creation]@g.us
- **Broadcast Channels:** [timestamp of group creation]@broadcast

If you'd like to see your contacts' and chats' Jids you can access the `contactList` or the `chatList` of the `wap` class.

Once you've got your Jids you can send messages like so:

```js
import Whatsapp from "@noamalffasy/js-whatsapp";

const wap = new Whatsapp();

wap.sendTextMessage("[text to send]", "[jid]");
```

### Sending quoted messages

As of now, the library supports only text messages so the example is only for text.

In order to quote a message you need to get its ID, the sender's Jid and the message's text.

```js
import Whatsapp from "@noamalffasy/js-whatsapp";

const wap = new Whatsapp();

wap.sendQuotedTextMessage(
  "[text to send]",
  "[jid of group or contact to send the message to]",
  "[the jid of the message's sender]",
  "[the quoted message's content]",
  "[the quoted message's ID]"
);
```

## Legal

This code is in no way affiliated with, authorized, maintained, sponsored or endorsed by WhatsApp or any of its affiliates or subsidiaries. This is an independent and unofficial software. Use at your own risk.
