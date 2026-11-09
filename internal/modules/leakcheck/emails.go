package leakcheck

// commonEmailDomains are the mainstream consumer providers worth probing. Kept
// short on purpose: every extra domain is another lookup against the API.
var commonEmailDomains = []string{
	"gmail.com",
	"yahoo.com",
	"hotmail.com",
	"outlook.com",
	"icloud.com",
}

// commonEmails builds one address per common provider for the username,
// e.g. "hubwub2012" -> hubwub2012@gmail.com, hubwub2012@yahoo.com, and so on.
func commonEmails(username string) []string {
	emails := make([]string, 0, len(commonEmailDomains))
	for _, domain := range commonEmailDomains {
		emails = append(emails, username+"@"+domain)
	}

	return emails
}
