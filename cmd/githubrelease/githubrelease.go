package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
)

type githubRelease struct {
	HtmlUrl string `json:"html_url"`
	TagName string `json:"tag_name"`
}

func main() {
	resp, err := http.Get("https://api.github.com/repos/MeneDev/yubi-oath-vpn/releases/latest")
	if err != nil {
		log.Printf("Error: %s", err.Error())
		return
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Error: %s", err.Error())
		return
	}

	release := &githubRelease{}
	err = json.Unmarshal(body, release)
	if err != nil {
		log.Printf("Error: %s", err.Error())
		return
	}

	log.Printf("version: %s url: %s", release.TagName, release.HtmlUrl)
}
