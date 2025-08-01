<p align='center'>
<img src='img/gosearch-logo.png' height=50% width=50%><br>
<i>This project heavily relies on contributors, please see <a href="#contributing">Contributing</a> for more details.</i><br>
<code>go install github.com/ibnaleem/gosearch@latest</code>
</p>

<p align="center">
  <img src="https://github.com/ibnaleem/gosearch/actions/workflows/go.yml/badge.svg?event=push" alt="GitHub Actions Badge"> <img src="https://img.shields.io/github/last-commit/ibnaleem/gosearch"> <img src="https://img.shields.io/github/commit-activity/w/ibnaleem/gosearch"> <img src="https://img.shields.io/github/contributors/ibnaleem/gosearch"> <img alt="Number of websites" src="https://img.shields.io/badge/websites-305-blue"> <img alt="GitHub repo size" src="https://img.shields.io/github/repo-size/ibnaleem/gosearch"> <img alt="GitHub License" src="https://img.shields.io/github/license/ibnaleem/gosearch">
</p>
<hr>

## Overview
<p align='center'>
<img src='img/1.png' height=80% width=80%><br>
<img src='img/2.png' height=80% width=80%><br>
<img src='img/3.png' height=80% width=80%><br>
<img src='img/4.png' height=80% width=80%><br>
</p>

You don't have time searching every profile with a username. Instead, you can leverage concurrency and a binary that does the work for you, and then some.

I initially wrote this project to learn Go, an upcoming programming language used for backend services. I decided to create a Sherlock clone, addressing some of its faults, limitations, and adding more features. This eventually led to a community driven OSINT tool that was [praised in the OSINT letter.](https://osintnewsletter.com/p/62)

GoSearch isn't limited to searching websites; it can search **900k leaked credentials** from [HudsonRock's Cybercrime Intelligence API](https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-username?username=mrrobot), over **3.2 billion leaked credentials** from [ProxyNova's Combination Of Many Breaches API](https://www.proxynova.com/tools/comb/), and **18 billion leaked credentials** from BreachDirectory.org with an API key (see [Use Cases](#use-cases))

## Installation
> [!WARNING]  
> If you are on 32-bit architecture, please [use this branch](https://github.com/ibnaleem/gosearch/tree/32-bit) or GoSearch will fail to build. For an in-depth overview of this issue, please see [#72](https://github.com/ibnaleem/gosearch/issues/72)

> [!WARNING]  
> If you're using Windows Defender, it might mistakenly flag GoSearch as malware. Rest assured, GoSearch is not malicious; you can review the full source code yourself to verify this. For an in-depth overview of this issue, please see [#90](https://github.com/ibnaleem/gosearch/issues/90)
```
$ go install github.com/ibnaleem/gosearch@latest
```
### Unix:
```
$ gosearch -u [username]
```
### Windows
```
C:\Users\Bob> gosearch.exe -u [username]
```
## Use Cases
Ideally, it is best practice to run GoSearch with the `--no-false-positives` flag:
```
$ gosearch -u [USERNAME] --no-false-positives
```
This will display profiles GoSearch is confident exist on a website. GoSearch also allows you to search [BreachDirectory](https://breachdirectory.org) for compromised passwords associated with a specific username. For this, you must [obtain an API key](https://rapidapi.com/rohan-patra/api/breachdirectory) and provide it with the `-b` flag:
```
$ gosearch -u [USERNAME] -b [API-KEY] --no-false-positives
```
If GoSearch finds password hashes, it will attempt to crack them using [Weakpass](https://weakpass.com). The success rate is nearly 100%, as Weakpass uses a large wordlist of common data-wells, which align with the breaches reported by [BreachDirectory](https://breachdirectory.org). Every single password hash that's been found in [BreachDirectory](https://breachdirectory.org) has been cracked by [Weakpass](https://weakpass.com).

If you're not using BreachDirectory, GoSearch will search for breaches on HudsonRock's Cybercrime Intelligence & ProxyNova's Databases, respectively. It will also search common TLDs for any domains associated with a given username. This is done whether BreachDirectory is searched or not.

## I Don't Have a Username
If you're uncertain about a person's username, you could try generating some by using [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy). Note that `username-anarchy` can only run in Unix terminals (Mac/Linux)
```
$ git clone https://github.com/urbanadventurer/username-anarchy
$ cd username-anarchy
$ (username-anarchy) ./username-anarchy firstname lastname
```
## Why `GoSearch`?
`GoSearch` is inspired by [Sherlock](https://github.com/sherlock-project/sherlock), a popular username search tool. However, `GoSearch` improves upon Sherlock by addressing several of its key limitations:

1. Sherlock is Python-based, which makes it slower compared to Go.
2. Sherlock is outdated and lacks updates.
3. Sherlock sometimes reports false positives as valid results.
4. Sherlock frequently misses actual usernames, leading to false negatives.
5. Sherlock does not search HudsonRock's Cybercrime Intelligence database
6. Sherlock does not search ProxyNova's database
7. Sherlock does not search BreachDirectory's database

The primary issue with Sherlock is false negatives—when a username exists on a platform but is not detected. The secondary issue is false positives, where a username is incorrectly flagged as available. `GoSearch` tackles these problems by colour-coding uncertain results as yellow which indicates potential false positives. This allows users to easily filter out irrelevant links.

## Contributing
Please see [CONTRIBUTING.md.](https://github.com/ibnaleem/gosearch/blob/main/CONTRIBUTING.md)

<table><tr><td align="center"><a href="https://github.com/ibnaleem"><img alt="ibnaleem" src="https://avatars.githubusercontent.com/u/134088573?v=4" width="117" /><br />ibnaleem</a></td><td align="center"><a href="https://github.com/shelepuginivan"><img alt="shelepuginivan" src="https://avatars.githubusercontent.com/u/110753839?v=4" width="117" /><br />shelepuginivan</a></td><td align="center"><a href="https://github.com/arealibusadrealiora"><img alt="arealibusadrealiora" src="https://avatars.githubusercontent.com/u/113445322?v=4" width="117" /><br />arealibusadrealiora</a></td></tr><tr><td align="center"><a href="https://github.com/vickychhetri"><img alt="vickychhetri" src="https://avatars.githubusercontent.com/u/82648574?v=4" width="117" /><br />vickychhetri</a></td><td align="center"><a href="https://github.com/olekukonko"><img alt="olekukonko" src="https://avatars.githubusercontent.com/u/2615393?v=4" width="117" /><br />olekukonko</a></td><td align="center"><a href="https://github.com/CptIdea"><img alt="CptIdea" src="https://avatars.githubusercontent.com/u/59538729?v=4" width="117" /><br />CptIdea</a></td></tr><tr><td align="center"><a href="https://github.com/anotherhadi"><img alt="anotherhadi" src="https://avatars.githubusercontent.com/u/112569860?v=4" width="117" /><br />anotherhadi</a></td><td align="center"><a href="https://github.com/paulpogoda"><img alt="paulpogoda" src="https://avatars.githubusercontent.com/u/170966925?v=4" width="117" /><br />paulpogoda</a></td><td align="center"><a href="https://github.com/apps/dependabot"><img alt="dependabot[bot]" src="https://avatars.githubusercontent.com/in/29110?v=4" width="117" /><br />dependabot[bot]</a></td></tr></table>

## LICENSE
This project is licensed under the GNU General Public License - see the [LICENSE](https://github.com/ibnaleem/gosearch/blob/main/LICENSE) file for details.

## Support
[![BuyMeACoffee](https://img.shields.io/badge/Buy%20Me%20a%20Coffee-ffdd00?style=for-the-badge&logo=buy-me-a-coffee&logoColor=black)](https://buymeacoffee.com/gosearch)
[![Thanks.dev](https://img.shields.io/badge/thanks.dev-0a0a0a?style=for-the-badge&logo=tv-time&logoColor=white)](https://thanks.dev/u/gh/ibnaleem)
### Bitcoin
```
bc1qjrtyq8m7urapu7cvmvrrs6m7qkh2jpn5wqezfl
```
## Stargazers Over Time
[![Stargazers over time](https://starchart.cc/ibnaleem/gosearch.svg?variant=adaptive)](https://starchart.cc/ibnaleem/gosearch)
