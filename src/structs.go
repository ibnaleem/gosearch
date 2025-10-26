// File contains structs related to scraping that is used by GoSearch

package main

type Website struct {
	Name            string   `json:"name"`                   
	BaseURL         string   `json:"base_url"`               
	URLProbe        string   `json:"url_probe,omitempty"`    
	FollowRedirects bool     `json:"follow_redirects"`       
	UserAgent       string   `json:"user_agent,omitempty"`   
	ErrorType       string   `json:"errorType"`              
	ErrorMsg        string   `json:"errorMsg,omitempty"`     
	ErrorCode       int      `json:"errorCode,omitempty"`    
	ResponseURL     string   `json:"response_url,omitempty"` 
	Cookies         []Cookie `json:"cookies,omitempty"`     
}

type Data struct {
	Websites []Website `json:"websites"`
}

type Cookie struct {
	Name  string `json:"name"` 
	Value string `json:"value"`
}