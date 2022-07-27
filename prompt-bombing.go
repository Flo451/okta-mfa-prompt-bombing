package main

import (
	"context"
	"fmt"
	"log"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/joho/godotenv"
	"github.com/mitchellh/mapstructure"
	"github.com/okta/okta-sdk-golang/v2/okta"
	"github.com/okta/okta-sdk-golang/v2/okta/query"
)

var (
	locCounter = make(map[string]float64)
	myMapMutex = sync.RWMutex{}
)

func filterUsers(ctx context.Context, client *okta.Client, filterString string) []*okta.User {
	filter := query.NewQueryParams(query.WithSearch(filterString))

	totalUserSet, resp, err := client.User.ListUsers(ctx, filter)
	if err != nil {
		fmt.Printf("Error Getting Users: %v\n", err)
	}

	fmt.Printf("%v\n", resp)
	count := 0
	for resp.HasNextPage() {

		count += 1
		fmt.Printf("Entering %v time as request %+v\n", count, *resp)
		var nextUserSet []*okta.User
		newResp, err := resp.Next(ctx, &nextUserSet)
		if err != nil {
			fmt.Printf("Error Getting next Page: %v\n", err)
		}
		totalUserSet = append(totalUserSet, nextUserSet...)
		resp = newResp
	}

	return totalUserSet
}

func processUser(ctx context.Context, client *okta.Client, orgURL *url.URL, user *okta.User) error {

	time.Sleep(1 * time.Second)
	userEmail := (*user.Profile)["email"].(string)
	countryCode, ok := (*user.Profile)["countryCode"].(string)
	if !ok {
		fmt.Println("Country Code not set for user")
		countryCode = "UNKNOWN"
	}

	myMapMutex.Lock()
	locCounter[countryCode+" Total Users"] += 1
	myMapMutex.Unlock()

	factors, _, err := client.UserFactor.ListFactors(ctx, user.Id)
	if err != nil {
		fmt.Printf("List Factors Error: %s\n", err)
		return err
	}

	if len(factors) == 0 {
		log.Printf("no MFA factors found [%s] for user %s\n", countryCode, userEmail)
		return nil
	}

	var factorFound bool
	var userFactor *okta.UserFactor
	for _, factor := range factors {
		if factor.IsUserFactorInstance() {
			userFactor = factor.(*okta.UserFactor)
			if userFactor.FactorType == "push" {
				factorFound = true
				log.Printf("Found Okta Verify push [%s] for user %s\n", countryCode, userEmail)
				myMapMutex.Lock()
				locCounter[countryCode+" PUSH ENROLLED"] += 1
				myMapMutex.Unlock()
				break
			}
		}
	}

	if !factorFound {
		fmt.Printf("no push-type MFA factor found for user %s\n", userEmail)
		return nil
	}

	result, _, err := client.UserFactor.VerifyFactor(ctx, user.Id, userFactor.Id, okta.VerifyFactorRequest{}, userFactor, nil)
	if err != nil {
		return err
	}

	if result.FactorResult != "WAITING" {
		return fmt.Errorf("expected WAITING status for push status, got %q", result.FactorResult)
	}

	// Parse links to get polling link
	type linksObj struct {
		Poll struct {
			Href string `mapstructure:"href"`
		} `mapstructure:"poll"`
	}
	links := new(linksObj)
	if err := mapstructure.WeakDecode(result.Links, links); err != nil {
		return err
	}
	// Strip the org URL from the fully qualified poll URL
	url, err := url.Parse(strings.Replace(links.Poll.Href, orgURL.String(), "", 1))
	if err != nil {
		return err
	}
	start := time.Now()
	// Code to measure
	for {

		rq := client.CloneRequestExecutor()
		req, err := rq.WithAccept("application/json").WithContentType("application/json").NewRequest("GET", url.String(), nil)
		if err != nil {
			return err
		}
		var result *okta.VerifyUserFactorResponse
		_, err = rq.Do(ctx, req, &result)
		if err != nil {
			return err
		}

		switch result.FactorResult {
		case "WAITING":
		case "SUCCESS":
			log.Printf("%s confirmed Push\n", userEmail)
			locCounter[countryCode+" CONFIRMED PUSH"] += 1
			return nil
		case "REJECTED":
			log.Printf("%s rejected Push\n", userEmail)
			locCounter[countryCode+" REJECTED PUSH"] += 1
			return fmt.Errorf("push verification explicitly rejected")

		case "TIMEOUT":
			duration := time.Since(start)
			fmt.Printf("Push for %s timed out after %v\n", userEmail, duration)
			locCounter[countryCode+" TIMEOUT PUSH"] += 1
			return fmt.Errorf("push verification timed out")

		default:
			return fmt.Errorf("unknown status code")
		}

		select {
		case <-ctx.Done():
			return fmt.Errorf("push verification operation canceled")
		case <-time.After(3 * time.Second):
		}
	}
}

func run(ctx context.Context) error {

	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	token := os.Getenv("OKTA_API_TOKEN")
	oktaDomain := os.Getenv("OKTA_DOMAIN")
	filterQuery := os.Getenv("OKTA_QUERY")
	fmt.Printf("User selection based on: %s", filterQuery)

	orgURL, err := url.Parse(fmt.Sprintf("https://%s", oktaDomain))
	if err != nil {
		return err
	}

	ctx, client, err := okta.NewClient(ctx,
		okta.WithToken(token),
		okta.WithOrgUrl(orgURL.String()),
		okta.WithCache(false),
	)
	if err != nil {
		return fmt.Errorf("error creating client: %s", err)
	}

	filteredUsers := filterUsers(ctx, client, filterQuery)

	var wg = sync.WaitGroup{}
	// How many users to prompt in parallel
	maxGoroutines := 10
	guard := make(chan struct{}, maxGoroutines)

	for index, user := range filteredUsers {
		guard <- struct{}{}
		wg.Add(1)
		go func(n int, user *okta.User) {
			log.Printf("Processing user %v ", n)
			processUser(ctx, client, orgURL, user)
			<-guard
			wg.Done()
		}(index, user)
	}
	wg.Wait()
	return nil
}

func main() {
	run(context.TODO())
	fmt.Println(locCounter)
}
