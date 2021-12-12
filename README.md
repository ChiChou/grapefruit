<img src="gui/src/assets/logo.svg" width="300" alt="Grapefruit" style="margin:40px auto; display: block">

# Grapefruit: Runtime Application Instruments for iOS

[![John Discord](https://discord.com/api/guilds/591601634266578944/embed.png)](https://discord.com/invite/pwutZNx)
[![Commits](https://img.shields.io/github/commit-activity/w/chichou/grapefruit?label=Commits)](https://github.com/ChiChou/Grapefruit/commits/master)
[![contributers](https://img.shields.io/github/contributors/chichou/grapefruit)](https://github.com/ChiChou/Grapefruit/graphs/contributors)
[![License](https://img.shields.io/github/license/chichou/grapefruit)](https://github.com/ChiChou/Grapefruit/blob/master/LICENSE)

![Screenshot](images/screenshot.png)

## Get Started

### Dependencies

Grapefruit requires [Node.js](https://nodejs.org/) to be installed. If you can't install the frida-node dependency, please check out the troubleshooting section to [choose another version of Node.js](https://github.com/ChiChou/Grapefruit/wiki/How-do-I-decide-which-version-of-nodejs-to-use%3F).

Setup frida on your iOS device: https://www.frida.re/docs/ios/

> Start `Cydia` and add Frida’s repository by going to `Manage` -> `Sources` -> `Edit` -> `Add` and enter `https://build.frida.re`. You should now be able to find and install the `Frida` package which lets Frida inject JavaScript into apps running on your iOS device. This happens over USB, so you will need to have your USB cable handy, though there’s no need to plug it in just yet.

### Setup

Grapefruit is now on npm as [igf](https://www.npmjs.com/package/igf)! Interprets as iGrapefruit or maybe iOS Graphical Frida

`npm install -g igf`

Now you have the grapefruit cli as `igf`:

```
~ igf --help

Usage: igf [options]

Options:
  -h, --host <string>  hostname (default: "127.0.0.1")
  -p, --port <number>  port of the server side (default: 31337)
  --help               display help for command
```

Default URL for the web UI is `http://localhost:31337`

*Security Warning*

At this moment, grapefruit has no authentication. It's possible to use it to inject arbitrary code to your iPhone for anyone that has the access to the web UI. Please limit it to `localhost` as much as possible. Contribution welcomed.

* [Development Setup](https://github.com/ChiChou/grapefruit/wiki/Development-Setup)
* [Troubleshooting](https://github.com/ChiChou/grapefruit/wiki/Trouble-Shooting)
* [Roadmap](https://github.com/ChiChou/Grapefruit/projects/1)

## Discord Group

If you have experienced anything wrong or want to suggest new features, please join my Discord channel! https://discord.gg/pwutZNx
