# Contributing

There are two ways to contribute to `GoSearch`:

1. [Add a website](#adding-a-website) to `data.json`. This is where most contributions are needed, and you don't need to write any Go.
2. [Add a module](#contributing-a-module) under `internal/modules/` for sources that need more than a yes/no check on a profile URL.

Bug fixes and improvements to existing modules are welcome too. Whatever you send, run the [checks](#before-you-open-a-pr) first, because CI runs the same ones.

---

## Adding a website

`GoSearch` reads its list of websites from [data.json](https://raw.githubusercontent.com/ibnaleem/gosearch/refs/heads/main/data.json). At startup it downloads the copy on `main`, and only falls back to the local `data.json` if the download fails. So a site you add locally won't show up in a normal run until it is merged; see [Testing your entry](#testing-your-entry) for how to check it before then.

Each entry looks like this:

```json
{
  "name": "Website name",
  "base_url": "https://www.website.com/profiles/{}",
  "url_probe": "optional, see below",
  "follow_redirects": true,
  "user_agent": "optional, see below",
  "errorType": "status_code | errorMsg | profilePresence | response_url | unknown",
  "errorMsg": "required for errorMsg and profilePresence",
  "errorCode": 404,
  "response_url": "required for response_url",
  "cookies": [
    {
      "name": "cookie name",
      "value": "cookie value"
    }
  ]
}
```

Only `name`, `base_url` and `errorType` are always required. Leave out any field you don't use. Unknown keys fail the test suite, so a typo like `"error_type"` gets caught before merge.

Give each entry a clear website name. It makes manual searches easier and helps avoid duplicate submissions. Duplicate names (ignoring case) and duplicate `base_url`s are rejected by the tests.

### `base_url`
The `base_url` is the URL `GoSearch` uses to search for usernames, unless a `url_probe` is specified (see [`url_probe`](#url_probe)). Your first task is to find where user profiles live on the website. On Twitter, for example, profiles sit at the root path `/`, so you would set `"base_url": "https://twitter.com/{}"`. The `{}` is a placeholder that `GoSearch` replaces with the username when it searches. Every `base_url` and `url_probe` must contain `{}` and start with `http://` or `https://`.

### `url_probe`
Some websites block direct requests but offer an API or another service that returns the same information. Put that URL in `url_probe`. `GoSearch` sends its request to the `url_probe`, but still prints the `base_url` in the terminal, since that is where the profile actually lives.

### `follow_redirects`
Redirects are followed by default, so `GoSearch` checks the status code and body of the final page. Set `"follow_redirects": false` only when the redirect itself is the signal, for example a site that answers `302` for missing users and `200` for real ones; then put the redirect code in `errorCode`. Test modes `2` and `3` below show you what the site does without redirects.

### `user_agent`
`GoSearch` sends a recent Firefox user agent with every request. A few sites only behave with a different one. Set `user_agent` to override it for that site only.

### `errorType`
There are 5 error types:
1. `status_code`: the website returns a specific status code when a username does not exist (typically `404`)
2. `errorMsg`: the website shows an error message that only appears for usernames that do not exist
3. `profilePresence`: the website shows something that only appears for usernames that do exist
4. `response_url`: the website redirects missing usernames to a specific URL
5. `unknown`: there is no way to tell an existing username from a missing one

For every type except `unknown`, a `4xx` response means "not found". A `429` or `5xx` response is counted as a failed probe and reported separately, so a site that rate-limits you doesn't produce false results.

#### `status_code`
The easiest one to contribute. Find an existing profile and build the test binary. It lives in its own Go module under `tests/`:
```
$ git clone https://github.com/ibnaleem/gosearch.git
$ cd gosearch/tests
$ go build
```
This creates a `./tests` or `tests.exe` binary, depending on your OS. Run it without arguments to see every mode. For `status_code` testing, use mode `0`:
```
$ ./tests https://yourwebsite.com/username-exists 0
[*] Testing URL: https://yourwebsite.com/username-exists
[*] Mode: 0 (Status Code)
[+] Response: 200 OK
```
Here `username-exists` is a real username on the website. Then make the same request with a username that does not exist:
```
$ ./tests https://yourwebsite.com/username-does-not-exist 0
[*] Testing URL: https://yourwebsite.com/username-does-not-exist
[*] Mode: 0 (Status Code)
[+] Response: 404 Not Found
```
Websites usually send `200 OK` for profiles that exist and `404 Not Found` for ones that don't. Some send `403 Forbidden` instead. That's fine, as long as an existing profile never gets the same status code as a missing one. Set `"errorType": "status_code"` and you're done:
```json
{
  "name": "Your Website",
  "base_url": "https://www.yourwebsite.com/{}",
  "errorType": "status_code"
}
```
`errorCode` is optional. Without it, any `4xx` means "not found". If the site uses a non-`4xx` code for missing users, put that code in `errorCode`. If that code is a redirect (`3xx`), also set `"follow_redirects": false`, otherwise `GoSearch` follows it and never sees the code.

#### `errorMsg`
Some websites return the same status code whether the profile exists or not. In that case we have to look at the response body for an error message. It's often inside the `<title>` tag, but it can be anywhere. Pass the URL followed by mode `1`:
```
$ ./tests https://yourwebsite.com/username-exists 1
[*] Testing URL: https://yourwebsite.com/username-exists
[*] Mode: 1 (Response Body)
[+] Response: 200 OK
[+] Saved response to response.txt
```
Rename `response.txt` before the next run, otherwise it gets overwritten:
```
$ mv response.txt username_found.txt
```
Now the same for a username that does not exist:
```
$ ./tests https://yourwebsite.com/username-does-not-exist 1
[*] Testing URL: https://yourwebsite.com/username-does-not-exist
[*] Mode: 1 (Response Body)
[+] Response: 200 OK
[+] Saved response to response.txt
```
```
$ mv response.txt username_not_found.txt
```
Compare `username_not_found.txt` with `username_found.txt`. Look for a word, phrase, HTML tag or anything else that only appears in `username_not_found.txt`. Once you've found it, put it in the `errorMsg` field.
```
$ grep "<title>" username_found.txt
<title>Username | Your Website</title>
```
```
$ grep "<title>" username_not_found.txt
<title>Your Website</title>
```
Here the `<title>` tag holds the username when the profile exists, and only the website name when it doesn't. So the `errorMsg` is `<title>Your Website</title>`:
```json
{
  "name": "Your Website",
  "base_url": "https://www.yourwebsite.com/{}",
  "errorType": "errorMsg",
  "errorMsg": "<title>Your Website</title>"
}
```
To double-check, run mode `4` against the missing username. It asks for the error message and tells you whether it can find it in the response:
```
$ ./tests https://yourwebsite.com/username-does-not-exist 4
```
If the page only differs before a redirect, mode `3` saves the body without following redirects. Use what you find there with `"follow_redirects": false`, since `GoSearch` follows redirects otherwise.

#### `profilePresence`
The exact opposite of `errorMsg`. Instead of studying `username_not_found.txt`, look through `username_found.txt` for a word, phrase, HTML tag or other element that only appears there. Set `"errorType": "profilePresence"` and put what you found in `errorMsg`.

#### `response_url`
What if the body has nothing usable for `errorMsg` or `profilePresence`? You can capture the redirect and look at where it points, using mode `2`:
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
The entry for this website looks like this. `response_url` uses `{}` for the username too. Don't set `follow_redirects` to `false` here, because `GoSearch` has to end up on the redirect target:
```json
{
  "name": "Packagist",
  "base_url": "https://packagist.org/packages/{}/",
  "errorType": "response_url",
  "response_url": "https://packagist.org/search/?q={}&reason=vendor_not_found"
}
```

#### `unknown`
Sometimes the body is empty, or there's nothing unique in either `username_found.txt` or `username_not_found.txt`. You've tried cookies, the `www.` subdomain and the redirect, and you still can't tell them apart. Set `"errorType": "unknown"`. These sites are listed for a manual check, and users can hide them with `-nfp`.

#### `cookies`
Some websites need cookies before they return a useful status code or body. For example, `dzen.ru` needs the cookie `zen_sso_checked=1`, which your browser sends with every request. To test a cookie and look at the response, you can use this Go program:

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

  req, err := http.NewRequest("GET", url, nil)
  if err != nil {
    log.Fatalf("Error creating request: %v", err)
  }

  req.AddCookie(&http.Cookie{
    Name:  "cookie_name",
    Value: "cookie_value",
  })

  resp, err := client.Do(req)
  if err != nil {
    log.Fatalf("Error making request: %v", err)
  }
  defer resp.Body.Close()

  fmt.Println("Response Status:", resp.Status)
}

func main() {
  if len(os.Args) < 2 {
    log.Fatal("URL is required as the first argument.")
  }
  MakeRequest(os.Args[1])
}
```

When testing cookies, check both the status and the body. If you always get `200 OK`, try adding `www.` to the URL, since some websites redirect based on it:

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

Use the program above to check the response body with the `www.` subdomain and any cookies you need.

### Testing your entry

Validate `data.json` from the repository root:
```
$ go test -run TestDataJSON .
```
This catches invalid JSON, unknown keys, duplicate names or URLs, missing `{}` placeholders, and missing `errorMsg` or `response_url` fields.

To see your site in a real run before it's merged, block the `data.json` download (for example by going offline) so `GoSearch` falls back to your local copy, then search for a username you know exists and one you know doesn't:
```
$ go run . -u username-exists
$ go run . -u username-does-not-exist
```

Then open a PR. I'll merge it if `GoSearch` correctly detects both accounts.

---

## Contributing a module

Modules are Go packages under `internal/modules/` that connect `GoSearch` to external APIs or intelligence sources. A `data.json` entry checks whether a username exists on a website. A module does a deeper lookup: credential breaches, social graph data, cryptographic keys, email extraction, and so on.

### When to add a module vs a site entry

| Scenario | Approach |
|---|---|
| Username present/absent on a website | `data.json` entry |
| External API returning structured data about a user | Module |
| Source requires authentication (API key, token) | Module |
| Multi-step HTTP logic that `data.json` cannot express | Module |

### One file per responsibility

Every module gets its own directory under `internal/modules/`, and the package name matches the directory name. Inside that directory, split the code so each file does one thing. Someone reading the folder should be able to tell which file is responsible for what without opening any of them.

A small module that does a single lookup only needs one file:

```
internal/modules/proxynova/
└── proxynova.go
```

When a module does several lookups, give each one its own file, named after what it does. The main file holds the client struct, the constructor, `Name()` and the `Search()` method that calls the others. This is how the GitHub module is laid out:

```
internal/modules/github/
├── github.go               # client, constructor, Name(), Search()
├── email-from-commits.go   # emails pulled from public commits
├── gpg-keys.go             # public GPG keys
├── ssh-keys.go             # public SSH keys
├── social-accounts.go      # linked social accounts
└── mutual-followers.go     # followers who follow back
```

Tests follow the same idea. Put them in a `_test.go` file next to the code they cover, named after what they test, like `search/probe_test.go` or `breachdirectory/output_test.go`.

### Implementing the module

Every module implements the `modules.Module` interface from `internal/modules/module.go`:

```go
type Module interface {
    Name() string
    Search(ctx context.Context, query string) (*Result, error)
}
```

All modules run at the same time. `run.go` gives each one its own `io.Writer`, buffers what it prints, and writes it to the terminal in order once the module finishes. That means your module must print to the writer it is given, never straight to stdout. Otherwise its output gets mixed in with the other modules.

A minimal module looks like this (see `internal/modules/proxynova/proxynova.go` for a complete example):

```go
package yourservice

import (
    "context"
    "fmt"
    "io"
    "net/http"
    "net/url"
    "strings"

    "github.com/ibnaleem/gosearch/internal/config"
    "github.com/ibnaleem/gosearch/internal/file"
    "github.com/ibnaleem/gosearch/internal/modules"
    "github.com/ibnaleem/gosearch/internal/theme"
)

type yourServiceClient struct {
    fileWriter *file.FileWriter
    out        io.Writer
    httpClient *http.Client
}

type yourServiceResponse struct {
    // fields of the service's JSON response
}

func NewYourServiceClient(out io.Writer, fileWriter *file.FileWriter) modules.Module {
    return &yourServiceClient{
        fileWriter: fileWriter,
        out:        out,
        httpClient: config.NewHTTPClient(),
    }
}

func (ysc *yourServiceClient) Name() string {
    return "YourService"
}

func (ysc *yourServiceClient) Search(ctx context.Context, query string) (*modules.Result, error) {
    theme.Cyan("[*] Searching ", query, " on YourService...").Fprintln(ysc.out)

    endpoint := fmt.Sprintf("https://api.yourservice.com/users?q=%s", url.QueryEscape(query))

    response, err := modules.FetchJSON[yourServiceResponse](ctx, ysc.httpClient, endpoint, nil)
    if err != nil {
        return nil, fmt.Errorf("%s(Search): %w", ysc.Name(), err)
    }

    // on not found:
    //     theme.Red("[-] Nothing found on YourService for ", query, ".").Fprintln(ysc.out)
    //     return nil, nil

    var buffer strings.Builder

    theme.Greenf("[+] Found something: %s", response).Fprintln(ysc.out)
    fmt.Fprintf(&buffer, "[+] Found something: %s\n", response)

    if err := ysc.fileWriter.Write(query, buffer.String()); err != nil {
        theme.Redf("[!] Could not write output file: %v", err).Fprintln(ysc.out)
    }

    return &modules.Result{
        Module:  ysc.Name(),
        Summary: "1 result found",
    }, nil
}
```

Rules:
- Take `out io.Writer` as the constructor's first argument and print everything through it with `Fprintln(out)`.
- Build the HTTP client with `config.NewHTTPClient()` so every module gets the same timeouts, TLS settings and proxy support.
- For JSON APIs, use `modules.FetchJSON`. It sets the user agent, passes `ctx`, and turns `429`, `403` and any other `4xx`/`5xx` code except `404` into an error. A `404` body is still decoded, so check the decoded fields to decide whether anything was found. If you build requests yourself, use `http.NewRequestWithContext` so the request stops when the run is cancelled.
- Wrap errors with the module name and the function they came from, like `fmt.Errorf("%s(buildRequest): %w", pnc.Name(), err)`. The runner prints them as-is.
- Escape user input before putting it in a URL: `url.PathEscape` for path segments, `url.QueryEscape` for query values.
- Return `nil, nil` when nothing is found, `nil, err` on failure, and a `*modules.Result` with a short `Summary` on success. The summary appears in the results table at the end of the run.
- Use `theme.Cyan` for status messages, `theme.Greenf` for found results, `theme.Red` for not-found and `theme.Yellow` for skips and warnings.
- Collect findings in a `strings.Builder` and write them once with `fileWriter.Write(query, ...)` so they end up in the saved output. A failed write is a warning, not an error.
- Declare types (client struct, response structs) at the top of the file, before the constructor and methods.
- Receiver names are a short abbreviation of the type, e.g. `pnc` for `proxyNovaClient`, `ghc` for `gitHubClient`.

### Environment variables

If your module needs an API key or token, read it from the environment. `GoSearch` loads a `.env` file from the working directory at startup, so users can keep keys there. Don't hardcode credentials:

```go
apiKey := os.Getenv("YOURSERVICE_API_KEY")
if apiKey == "" {
    theme.Yellow("[*] YOURSERVICE_API_KEY not set, skipping YourService.").Fprintln(ysc.out)
    return nil, nil
}
```

`GITHUB_TOKEN` in the GitHub module works this way. The module runs without it, and uses it for higher rate limits when it's set. Do the same if the service has a free tier. Put the variable name in your PR description so it can be added to the README.

### Wiring into main.go

Import your package and add a constructor function to the list passed to `runModules` in `main.go`. The runner calls it with the writer your module should print to:

```go
import "github.com/ibnaleem/gosearch/internal/modules/yourservice"

// in main(), inside the runModules list:
func(w io.Writer) modules.Module { return yourservice.NewYourServiceClient(w, fileWriter) },
```

Modules run at the same time, but their output and their rows in the results table appear in list order. Put yours in a sensible spot: credential sources near `proxynova` and `breachdirectory`, profile enrichment near `github` and `keybase`. `search` stays last because its output is the longest.

### Testing your module

Run it against a username that exists on the service and one that doesn't:

```
$ go run . -u <known-username>
$ go run . -u <username-that-does-not-exist>
```

Check that:
- Your module's output appears under its own separator and isn't mixed with other modules
- Your module appears in the results table with its summary
- Found results appear in the terminal and in the output file
- If no API key is set, the module skips cleanly without an error or panic

If your module parses or formats anything, add a `_test.go` file for it next to the code (see [One file per responsibility](#one-file-per-responsibility)). Tests must not depend on the live service; use `httptest` or feed in saved responses.

---

## Before you open a PR

CI runs these on every PR. Run them locally first:

```
$ gofmt -l .                # must print nothing
$ go mod tidy -diff         # must print nothing
$ go vet ./...
$ go build ./...
$ go test -race ./...       # includes TestDataJSON
$ cd tests && go vet ./... && go build ./...
```

`tests/` is a separate Go module, so the commands at the root skip it. That's why it has its own line.

### Module PR checklist

- [ ] Package name matches the directory name
- [ ] Each file has one responsibility and is named after it
- [ ] The client implements `modules.Module` and is added to the `runModules` list in `main.go`
- [ ] All output goes through the `out` writer using `theme`, with no bare `fmt.Println` and nothing written to `os.Stdout`
- [ ] Findings are written with `fileWriter.Write`
- [ ] API keys are read from environment variables, not hardcoded
- [ ] Tested against a username that exists on the service and one that does not
- [ ] All the commands in [Before you open a PR](#before-you-open-a-pr) pass

---

Thank you for improving GoSearch.
