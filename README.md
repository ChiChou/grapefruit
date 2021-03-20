<img src="gui/src/assets/logo.svg" width="300" alt="Grapefruit" style="margin:auto; display: block">

# Grapefruit: Runtime Application Instruments for iOS

[![John Discord](https://img.shields.io/discord/591601634266578944?label=Discord)](https://discord.com/invite/pwutZNx)
[![Commits](https://img.shields.io/github/commit-activity/w/chichou/grapefruit?label=Commits)](https://github.com/ChiChou/Grapefruit/commits/master)
[![contributers](https://img.shields.io/github/contributors/chichou/grapefruit)](https://github.com/ChiChou/Grapefruit/graphs/contributors)
[![License](https://img.shields.io/github/license/chichou/grapefruit)](https://github.com/ChiChou/Grapefruit/blob/master/LICENSE)


## Get Started
---
 
Grapefruit requires the following tools to build:

1. [Node.js][node] `LTS`. For Apple Silicon, use Node.js `Current`.
2. [Frida][frida] on computer.
3. For jailbroken iOS [Frida iOS][frida ios].
3. Tmux or Windows Terminal on Windows.

![Screenshot](images/screenshot.png)


## Installing Grapefruit
---

First, you'll want to check out this repository:

`git clone --recurse-submodules https://github.com/ChiChou/Grapefruit`

Install npm packages:

`npm run installdev`



Start development server:

`npm run dev`

Default webpack url is `http://localhost:8080`


## Troubleshooting
---

* [How do I decide which version of nodejs to use?][wiki nodejs version]
* [Frida CRITICAL: No such interface re.frida.HostSession*][frida critical]


## Contact
---

If you have experienced anything wrong or want to suggest new features, please join my [Discord server][discord]!

If you'd like to donate, please take a look at [Patreon][patreon].


## Roadmap
---

In this repository, you can find the [product roadmap][roadmap].


[node]: https://nodejs.org
[patreon]: https://www.patreon.com/codecolorist
[discord]: https://discord.gg/pwutZNx
[roadmap]: https://github.com/ChiChou/Grapefruit/projects/1
[frida]: https://frida.re/docs/installation/
[frida ios]: https://frida.re/docs/ios/#with-jailbreak
[frida critical]: https://github.com/ChiChou/Grapefruit/wiki/Frida-CRITICAL:-No-such-interface-re.frida.HostSession*
[wiki nodejs version]: https://github.com/ChiChou/Grapefruit/wiki/How-do-I-decide-which-version-of-nodejs-to-use%3F
