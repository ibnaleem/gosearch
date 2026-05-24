## Contributing
`GoSearch` relies on the [data.json](https://raw.githubusercontent.com/ibnaleem/gosearch/refs/heads/main/data.json) file which contains a list of websites to search. Users can contribute by adding new sites to expand the tool’s search capabilities. This is where most contributions are needed. The format for adding new sites is as follows:

```json
{
  "name": "Website name",
  "base_url": "https://www.website.com/profiles/{}",
  "url_probe": "optional, see below",
  "errorType": "errorMsg/status_code/profilePresence/unknown",
  "errorMsg/errorCode": "errorMsg",
  "cookies": [
    {
      "name": "cookie name",
      "value": "cookie value"
    }
  ]
}
```

Each entry should include a clear and concise website name to facilitate manual searches, helping avoid duplicate submissions.

### `base_url`
The `base_url` is the URL `GoSearch` uses to search for usernames, unless a `url_probe` is specified (see [`url_probe`](#url_probe)). Your first task is to identify the location of user profiles on a website. For example, on Twitter, user profiles are located at the root path `/`, so you would set `"base_url": "https://twitter.com/{}"`. The `{}` is a *placeholder* that `GoSearch` will automatically replace with the username when performing the search.

### `url_probe`
In some cases, websites may block direct requests for security reasons but offer an API or alternate service to retrieve the same information. The `url_probe` field is used to specify such an API or service URL that checks username availability. Unlike the `base_url`, which is used to directly search for profile URLs, the `url_probe` generates a different API request, but GoSearch will still display the `base_url` in the terminal instead of the API URL since that is not where the profile lives.

### `errorType`
There are 4 error types
1. `status_code` - a specific status code that is returned if a username does not exist (typically `404`)
2. `errorMsg` - a custom error message the website displays that is unique to usernames that do not exist
3. `profilePresence` a custom message the website displays that is unique to usernames that exist.
4. `unknown` - when there is no way of ascertaining the difference between a username that exists and does not exist on the website

#### `status_code`
The easiest to contribute, simply find an existing profile and build the test binary:
```
$ git clone https://github.com/ibnaleem/gosearch.git
$ cd gosearch
$ cd tests
$ go build
```
This will create a `./tests` or `tests.exe` binary, depending on your OS. For `status_code` testing, use the `0` option:
```
$ ./tests https://yourwebsite.com/username-exists 0
[*] Testing URL: https://yourwebsite.com/username-exists
[*] Mode: 0 (Status Code)
[+] Response: 200 OK
```
Where username is the existing username on the website. Then, make the same request with a username that does not exist on the website:
```
$ ./tests https://yourwebsite.com/username-does-not-exist 0
[*] Testing URL: https://yourwebsite.com/username-does-not-exist
[*] Mode: 0 (Status Code)
[+] Response: 404 Not Found
```
Usually, websites send a `200 OK` for profiles that exist, and a `404 Not Found` for ones that do not exist. In some cases, they may throw a `403 Forbidden`, but it does not matter as long as the status code for an existing profile is always different from non-existing profiles. Set `errorType: status_code` and you're done
```json
{
  "name": "Your Website",
  "base_url": "https://www.yourwebsite.com/{}",
  "errorType": "status_code",
}
```

#### `errorMsg`
When websites always return a consistent status code regardless of the profile's existence, we must inspect the response body for any error messages. Usually, these are in the `<title>` tags but sometimes they can exist elsewhere. Simply pass the URL followed by mode `1`:
```
$ ./tests https://yourwebsite.com/username-exists 1
[*] Testing URL: https://yourwebsite.com/username-exists
[*] Mode: 1 (Response Body)
[+] Response: 200 OK
[+] Saved response to response.txt
```
Once again, the first username corresponds to an existing profile, while the second username is for an account that does not exist. Be sure to rename `response.txt` to avoid having my code overwrite it.
```
$ mv response.txt username_found.txt
```
```
$ ./tests https://yourwebsite.com/username-does-not-exists 1
[*] Testing URL: https://yourwebsite.com/username-does-not-exists
[*] Mode: 1 (Response Body)
[+] Response: 200 OK
[+] Saved response to response.txt
```
```
$ mv response.txt username_not_found.txt
```
You’ll need to analyse the response body of `username_not_found.txt` and compare it with `username_found.txt`. Look for any word, phrase, HTML tag, or other unique element that appears only in `username_not_found.txt`. Once you've identified something distinct, add it to the `errorMsg` field under the `errorType` field.
```
$ cat username_found.txt | grep "<title>"
<title>Username | Your Website</title>
```
```
cat username_not_found.txt | grep "<title>"
<title>Your Website</title>
```
In this case, the website's `<title>` tag contains the username of an existing profile, and for non-existing profiles it merely states the website name. Therefore, the `errorMsg` would be `<title>Your Website</title>`:
```json
{
  "name": "Your Website",
  "base_url": "https://www.yourwebsite.com/{}",
  "errorType": "errorMsg",
  "errorMsg": "<title>Your Website</title>",
}
```
#### `profilePresence`
The exact opposite of `errorMsg`; instead of analysing the `username_not_found.txt`'s response body, analyse the `username_found.txt`'s response body to find any word, phrase, HTML tag or other unique element that only appears in `username_found.txt`. Set `"errorType": "profilePresence"` and set the `errorMsg` to what you've found.
#### `response_url`
What if there exists no `profilePresence` or `errorMsg` in the response body? Well, another method is capturing the redirect and examining the redirect URL:
```
$ ./tests https://packagist.org/packages/username-exists/ 2
[*] Testing URL: https://packagist.org/packages/username-exists/
[*] Mode: 2 (Status Code Without Following Redirects)
[+] Response: 301 Moved Permanently
[+] Response URL: https://packagist.org/packages/username-exists/
```
Now for a username that doesn't exist:
```
$ ./tests https://packagist.org/packages/thisdoesnotexist/ 2
[*] Testing URL: https://packagist.org/packages/thisdoesnotexist/
[*] Mode: 2 (Status Code Without Following Redirects)
[+] Response: 301 Moved Permanently
[+] Response URL: https://packagist.org/search/?q=thisdoesnotexist&reason=vendor_not_found
```
The entry for this website would look like this:
```json
{
  "name": "Packagist",
  "base_url": "https://packagist.org/packages/{}/",
  "follow_redirects": true,
  "errorType": "response_url",
  "response_url": "https://packagist.org/search/?q={}&reason=vendor_not_found"
},
```
#### `"unknown"`
Occasionally, the response body may be empty or lack any unique content in both the `username_not_found.txt` and `username_found.txt` files. After trying cookies, using the `www.` subdomain, capturing the redirect, you are left with no answers. In these cases, set the `errorType` to `"unknown"` (as a string).
#### `cookies`
Some websites may require cookies to retrieve specific data, such as error codes or session information. For example, the website `dzen.ru` requires the cookie `zen_sso_checked=1`, which is included in the request headers when making a browser request. To test for cookies and analyze the response, you can use the following Go code:

```go
package main

import (
  "fmt"
  "log"
  "net/http"
  "os"
)

func MakeRequest(url string) {
  client := &http.Client{}

  // Create a new HTTP GET request
  req, err := http.NewRequest("GET", url, nil)
  if err != nil {
    log.Fatalf("Error creating request: %v", err)
  }

  // Create the cookie
  cookie := &http.Cookie{
    Name:  "cookie_name",
    Value: "cookie_value",
  }

  // Add the cookie to the request
  req.AddCookie(cookie)

  // Send the request
  resp, err := client.Do(req)
  if err != nil {
    log.Fatalf("Error making request: %v", err)
  }
  defer resp.Body.Close()

  // Output the response status
  fmt.Println("Response Status:", resp.Status)
}

func main() {
  // Ensure URL is provided as the first argument
  if len(os.Args) < 2 {
    log.Fatal("URL is required as the first argument.")
  }
  url := os.Args[1]
  MakeRequest(url)
}
```

When testing cookies, check the response status and body. For example, if you always receive a `200 OK` response, try adding `www.` before the URL, as some websites redirect based on this:

```
$ curl -I https://pinterest.com/username
HTTP/2 308
...
location: https://www.pinterest.com/username
```
```
$ curl -I https://www.pinterest.com/username
HTTP/2 200
```

Additionally, make sure to use the above code to analyse the response body when including the `www.` subdomain and relevant cookies.

To contribute, follow the template above, open a PR, and I'll merge it if `GoSearch` can successfully detect the accounts.

Thank you for improving GoSearch.

<table><tr><td align="center"><a href="https://github.com/ibnaleem"><img alt="ibnaleem" src="https://avatars.githubusercontent.com/u/134088573?v=4" width="117" /><br />ibnaleem</a></td><td align="center"><a href="https://github.com/shelepuginivan"><img alt="shelepuginivan" src="https://avatars.githubusercontent.com/u/110753839?v=4" width="117" /><br />shelepuginivan</a></td><td align="center"><a href="https://github.com/arealibusadrealiora"><img alt="arealibusadrealiora" src="https://avatars.githubusercontent.com/u/113445322?v=4" width="117" /><br />arealibusadrealiora</a></td><td align="center"><a href="https://github.com/AtahanPoyraz"><img alt="AtahanPoyraz" src="https://avatars.githubusercontent.com/u/129458900?v=4" width="117" /><br />AtahanPoyraz</a></td></tr><tr><td align="center"><a href="https://github.com/vickychhetri"><img alt="vickychhetri" src="https://avatars.githubusercontent.com/u/82648574?v=4" width="117" /><br />vickychhetri</a></td><td align="center"><a href="https://github.com/olekukonko"><img alt="olekukonko" src="https://avatars.githubusercontent.com/u/2615393?v=4" width="117" /><br />olekukonko</a></td><td align="center"><a href="https://github.com/CptIdea"><img alt="CptIdea" src="https://avatars.githubusercontent.com/u/59538729?v=4" width="117" /><br />CptIdea</a></td><td align="center"><a href="https://github.com/yoy123"><img alt="yoy123" src="https://avatars.githubusercontent.com/u/32031720?v=4" width="117" /><br />yoy123</a></td></tr><tr><td align="center"><a href="https://github.com/anotherhadi"><img alt="anotherhadi" src="https://avatars.githubusercontent.com/u/112569860?v=4" width="117" /><br />anotherhadi</a></td><td align="center"><a href="https://github.com/paulpogoda"><img alt="paulpogoda" src="https://avatars.githubusercontent.com/u/170966925?v=4" width="117" /><br />paulpogoda</a></td><td align="center"><a href="https://github.com/apps/dependabot"><img alt="dependabot[bot]" src="https://avatars.githubusercontent.com/in/29110?v=4" width="117" /><br />dependabot[bot]</a></td></tr></table>