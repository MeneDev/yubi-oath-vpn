package githubreleasemon

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"
)

type GithubReleaseMon interface {
	ReleaseChan() <-chan ReleaseInfo
}

type Release struct {
	HtmlUrl string `json:"html_url"`
	TagName string `json:"tag_name"`
}

type ReleaseInfo struct {
	Release Release
	Error   error
}

func getLatestRelease(url string) (*Release, error) {
	resp, err := http.Get(url)

	if err != nil {
		log.Printf("Error: %s", err.Error())
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Error: %s", err.Error())
		return nil, err
	}

	release := &Release{}
	err = json.Unmarshal(body, release)
	if err != nil {
		log.Printf("Error: %s", err.Error())
		return nil, err
	}

	return release, nil
}

func GithubReleaseMonNew(ctx context.Context, user string, project string) (GithubReleaseMon, error) {

	mon := &githubReleaseMonImpl{
		channel: make(chan ReleaseInfo),
	}
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/latest", user, project)

	go func() {
		defer close(mon.channel)

		for {
			timeout := 1 * time.Hour

			release, e := getLatestRelease(url)
			if e != nil {
				timeout = 1 * time.Minute
				mon.channel <- ReleaseInfo{Error: e}
			} else {
				log.Printf("version: %s url: %s", release.TagName, release.HtmlUrl)
				mon.channel <- ReleaseInfo{Release: *release}
			}

			select {
			case <-ctx.Done():
				return
			case <-time.After(timeout):
			}
		}
	}()

	return mon, nil
}

var _ GithubReleaseMon = (*githubReleaseMonImpl)(nil)

type githubReleaseMonImpl struct {
	channel chan ReleaseInfo
}

func (g *githubReleaseMonImpl) ReleaseChan() <-chan ReleaseInfo {
	return g.channel
}
