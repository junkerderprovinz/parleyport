<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset=".github/assets/parleyport-banner-dark.png">
    <img src=".github/assets/parleyport-banner.png" alt="ParleyPort" width="100%">
  </picture>
</p>

<p align="center">
  <a href="https://github.com/junkerderprovinz/parleyport/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/junkerderprovinz/parleyport/ci.yml?branch=main&label=Build&style=for-the-badge&logo=githubactions&logoColor=white" alt="Build" height="36"></a>&nbsp;
  <a href="https://github.com/junkerderprovinz/parleyport/actions/workflows/style.yml"><img src="https://img.shields.io/github/actions/workflow/status/junkerderprovinz/parleyport/style.yml?branch=main&label=Lint&style=for-the-badge&logo=githubactions&logoColor=white" alt="Lint" height="36"></a>&nbsp;
  <a href="https://hub.docker.com/r/junkerderprovinz/parleyport"><img src="https://img.shields.io/docker/pulls/junkerderprovinz/parleyport?style=for-the-badge&logo=docker&logoColor=white&label=Pulls&color=1d99f3" alt="Docker Pulls" height="36"></a>&nbsp;
  <a href="https://hub.docker.com/r/junkerderprovinz/parleyport"><img src="https://img.shields.io/docker/image-size/junkerderprovinz/parleyport/latest?style=for-the-badge&logo=docker&logoColor=white&label=Size&color=1d99f3" alt="Image Size" height="36"></a>&nbsp;
  <a href="https://github.com/junkerderprovinz/parleyport/pkgs/container/parleyport"><img src="https://img.shields.io/badge/Arch-amd64%20%7C%20arm64-success?style=for-the-badge&logo=linux&logoColor=white" alt="Arch" height="36"></a>&nbsp;
  <a href="https://go.dev"><img src="https://img.shields.io/badge/Go-00ADD8?style=for-the-badge&logo=go&logoColor=white" alt="Go" height="36"></a>&nbsp;
  <a href="https://ca.unraid.net/apps/parleyport-1ucelx3086hypv"><img src="https://img.shields.io/badge/Unraid-Template-f15a2c?style=for-the-badge&logo=unraid&logoColor=white" alt="Unraid" height="36"></a>&nbsp;
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-AGPL--3.0-blue?style=for-the-badge&logo=gnu&logoColor=white" alt="License: AGPL-3.0" height="36"></a>
</p>

<p align="center">
ParleyPort is the relay for <b><a href="https://github.com/junkerderprovinz/knightloader">KnightLoader</a></b> and <b><a href="https://github.com/junkerderprovinz/bombvault">BombVault</a></b>. When two of your instances sit on different networks and neither can reach the other, both dial out to ParleyPort and meet there. It passes their messages on without being able to read them, and it runs as one small container that keeps no accounts and stores nothing.
</p>

<!-- download-buttons: written by scripts/gen_download_buttons.py -->
<p align="center">
  <a href="https://ca.unraid.net/apps/parleyport-1ucelx3086hypv"><img src="https://raw.githubusercontent.com/junkerderprovinz/parleyport/main/.github/assets/download-buttons/buttons.svg?v=a82cc8264e34#svgView(viewBox(0,0,841.9,245.3))" alt="Install from Unraid&#x27;s Community Applications" width="160" height="46.618"></a>
  &nbsp;
  <a href="https://hub.docker.com/r/junkerderprovinz/parleyport/"><img src="https://raw.githubusercontent.com/junkerderprovinz/parleyport/main/.github/assets/download-buttons/buttons.svg?v=a82cc8264e34#svgView(viewBox(866,0,841.9,245.3))" alt="Run it with Docker" width="160" height="46.618"></a>
  &nbsp;
  <a href="https://github.com/junkerderprovinz/parleyport/releases/latest"><img src="https://raw.githubusercontent.com/junkerderprovinz/parleyport/main/.github/assets/download-buttons/buttons.svg?v=a82cc8264e34#svgView(viewBox(1732,0,841.9,245.3))" alt="Download the source archive" width="160" height="46.618"></a>
</p>
<!-- /download-buttons -->

<br>

<p align="center">
A one-knight job: I build it, keep it running, work through the issues and add what people ask for, until nothing is missing. It is free, with no accounts, no telemetry, no ads and no paid tier. No asterisk anywhere. Nothing readable ever leaves your own walls. Forged on evenings and weekends, with heart and stubbornness.
</p>

<p align="center">
If it has earned a place on your server or computer, toss a coin to your knight: it helps cover the costs and keeps the project alive. It also makes this knight's heart beat a little faster. Three ways below, whichever suits you.
</p>

<!-- give-buttons: written by scripts/gen_download_buttons.py -->
<p align="center">
  <a href="https://buymeacoffee.com/junkerderprovinz"><img src="https://raw.githubusercontent.com/junkerderprovinz/parleyport/main/.github/assets/download-buttons/buttons.svg?v=a82cc8264e34#svgView(viewBox(2598,0,841.9,245.3))" alt="Buy me a coffee" width="160" height="46.618"></a>
  &nbsp;
  <a href="https://www.paypal.com/donate/?hosted_button_id=76FVV52TKXTUS"><img src="https://raw.githubusercontent.com/junkerderprovinz/parleyport/main/.github/assets/download-buttons/buttons.svg?v=a82cc8264e34#svgView(viewBox(3464,0,841.9,245.3))" alt="PayPal" width="160" height="46.618"></a>
  &nbsp;
  <a href="https://junkerderprovinz.github.io/junkerderprovinz/"><img src="https://raw.githubusercontent.com/junkerderprovinz/parleyport/main/.github/assets/download-buttons/buttons.svg?v=a82cc8264e34#svgView(viewBox(4330,0,841.9,245.3))" alt="Donate with crypto" width="160" height="46.618"></a>
</p>
<!-- /give-buttons -->

<br>

## Table of Contents

1. [What it looks like](#1-what-it-looks-like)
2. [What it does](#2-what-it-does)
3. [Getting started](#3-getting-started)
4. [How AI is used here](#4-how-ai-is-used-here)
5. [Support this project](#5-support-this-project)

<br>

## 1. What it looks like

ParleyPort has no web page of its own. What you see of it is the relay setting in your apps and the container's log.

<p align="center">
  <img src=".github/assets/screenshots/parleyport-1.png" alt="BombVault's relay settings with Own relay selected and the address of a ParleyPort relay filled in" width="100%">
  <br><em>BombVault's relay card pointing at your own ParleyPort; KnightLoader has the same card</em>
</p>

<p align="center">
  <img src=".github/assets/screenshots/parleyport-2.png" alt="A terminal showing the log of the ParleyPort container: the start banner and the line that it is listening on port 8760" width="100%">
  <br><em>The container's log after a start: ready and listening</em>
</p>

<br>

## 2. What it does

KnightLoader and BombVault pair their instances with twelve words. Instances on the same network talk directly. Instances on different networks, behind NAT or a firewall that lets nothing in, need a third point both can dial out to, and that point is a relay. ParleyPort groups the connections that present the same relay key, a hash of your twelve words, and passes their messages between them.

- **It cannot read what it carries.** Every message is sealed with AES-256-GCM under a key derived from the twelve words, and the routing fields are bound into the seal, so a relay can neither open a message nor send it to another instance.
- **It keeps nothing.** No accounts, no database and no record of who connects. Client addresses are left out of its log. What any relay can still see is which instances talk and when, which is the reason to run your own.
- **It brings its own certificate.** Give it a domain and it fetches and renews a Let's Encrypt certificate on port 443, with port 80 left closed. Without a domain it serves plain HTTP on port 8760 for a reverse proxy in front.
- **It is small.** A few megabytes for amd64 and arm64, fine on a small VPS while your instances stay at home.

You probably do not need it: the project relay is the default in both apps, and an instance that is already reachable from outside can serve as the relay itself under **Serve as relay**. ParleyPort is for your own relay without putting a download manager or a backup tool on the open internet.

<br>

## 3. Getting started

On Unraid, install **ParleyPort** from [Community Applications](https://ca.unraid.net/apps/parleyport-1ucelx3086hypv). Anywhere else, for a reverse proxy in front:

```sh
docker run -d --name parleyport -p 8760:8760 junkerderprovinz/parleyport:latest
```

The proxy sends `/relay/connect` to port 8760 with WebSocket upgrades allowed (in Nginx Proxy Manager, switch on **Websockets Support**). To let ParleyPort handle TLS itself instead, set `PARLEYPORT_DOMAIN`, forward port 443 to it and keep its certificates on a volume:

```sh
docker run -d --name parleyport -p 443:443 \
  -e PARLEYPORT_DOMAIN=relay.example.org \
  -v /path/to/parleyport:/var/lib/parleyport \
  junkerderprovinz/parleyport:latest
```

Then, on every instance of the group, open **Settings, Pairing, Relay, Own relay** and enter the address, for example `https://relay.example.org`. The twelve words stay the same, so switching relays needs no new pairing. A relay that ran from the old `knightloader-relay` image can switch images as it is, since ParleyPort still reads its `KL_RELAY_*` variables.

<br>

## 4. How AI is used here

One knight builds this, and AI is one of the tools I work with, the same way I work with an editor or a compiler. It helps me write code and documentation and it checks my work, and that saves me a good many evenings. It does not make the decisions, though. I read and understand everything before it ships, and if something here breaks, that is on me and not on the tool.

You do not have to take my word for it. The code is open and every release note is written by hand. The issue tracker shows how problems actually get handled, including the ones I got wrong the first time. If you find something that is not right, open an issue and I will look at it.

<br>

## 5. Support this project

Bugs, ideas or feature requests? Please [open a GitHub issue](https://github.com/junkerderprovinz/parleyport/issues).

A one-knight job: I build it, keep it running, work through the issues and add what people ask for, until nothing is missing. It is free, with no accounts, no telemetry, no ads and no paid tier. No asterisk anywhere. Nothing readable ever leaves your own walls. Forged on evenings and weekends, with heart and stubbornness.

If it has earned a place on your server or computer, toss a coin to your knight: it helps cover the costs and keeps the project alive. It also makes this knight's heart beat a little faster. Three ways below, whichever suits you.

<!-- give-buttons: written by scripts/gen_download_buttons.py -->
<p align="center">
  <a href="https://buymeacoffee.com/junkerderprovinz"><img src="https://raw.githubusercontent.com/junkerderprovinz/parleyport/main/.github/assets/download-buttons/buttons.svg?v=a82cc8264e34#svgView(viewBox(2598,0,841.9,245.3))" alt="Buy me a coffee" width="160" height="46.618"></a>
  &nbsp;
  <a href="https://www.paypal.com/donate/?hosted_button_id=76FVV52TKXTUS"><img src="https://raw.githubusercontent.com/junkerderprovinz/parleyport/main/.github/assets/download-buttons/buttons.svg?v=a82cc8264e34#svgView(viewBox(3464,0,841.9,245.3))" alt="PayPal" width="160" height="46.618"></a>
  &nbsp;
  <a href="https://junkerderprovinz.github.io/junkerderprovinz/"><img src="https://raw.githubusercontent.com/junkerderprovinz/parleyport/main/.github/assets/download-buttons/buttons.svg?v=a82cc8264e34#svgView(viewBox(4330,0,841.9,245.3))" alt="Donate with crypto" width="160" height="46.618"></a>
</p>
<!-- /give-buttons -->

<br>

<sub>The name ParleyPort, its logo and its branding are not covered by the AGPL-3.0 licence of the code: a fork needs its own name and look.</sub>
