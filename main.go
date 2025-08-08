package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/michimani/gotwi"
	"github.com/michimani/gotwi/tweet/managetweet"
	"github.com/michimani/gotwi/tweet/searchtweet"
)

type Bot struct {
	client       *gotwi.Client
	clientID     string
	clientSecret string
	accessToken  string
	refreshToken string
}

type OAuth2TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
}

type CelebrityProfile struct {
	Name        string
	CommonNames []string
	Variations  []string
	KnownHandle string
	IsVerified  bool
}

type ScamPatterns struct {
	CelebScamKeywords   []string
	VulnerablePatterns  []string
	SuspiciousPatterns  []string
	TargetedCelebrities []CelebrityProfile
}

type AnalyzedTweet struct {
	Tweet       *searchtweet.Tweet
	Author      *searchtweet.User
	IsScam      bool
	ScamScore   int
	ScamReasons []string
}

type VulnerableUser struct {
	User               *searchtweet.User
	VulnerabilityScore int
	VulnerableReasons  []string
}

func NewBot() (*Bot, error) {
	// Required OAuth 2.0 credentials
	clientID := os.Getenv("TWITTER_CLIENT_ID")
	clientSecret := os.Getenv("TWITTER_CLIENT_SECRET")
	accessToken := os.Getenv("TWITTER_ACCESS_TOKEN")
	refreshToken := os.Getenv("TWITTER_REFRESH_TOKEN")

	if clientID == "" || clientSecret == "" {
		return nil, fmt.Errorf("missing required TWITTER_CLIENT_ID or TWITTER_CLIENT_SECRET")
	}

	bot := &Bot{
		clientID:     clientID,
		clientSecret: clientSecret,
		accessToken:  accessToken,
		refreshToken: refreshToken,
	}

	// Test authentication on startup
	if err := bot.authenticateAndCreateClient(); err != nil {
		return nil, fmt.Errorf("authentication failed on startup: %w", err)
	}

	log.Println("✅ Authentication successful")
	return bot, nil
}

func (b *Bot) authenticateAndCreateClient() error {
	// If we have both access and refresh tokens, try to create client
	if b.accessToken != "" && b.refreshToken != "" {
		client, err := b.createTwitterClient()
		if err == nil {
			// Test the client with a simple API call
			if testErr := b.testAuthentication(client); testErr == nil {
				b.client = client
				log.Println("✅ Using existing tokens successfully")
				return nil
			}
			log.Println("⚠️ Existing tokens failed, attempting refresh...")
		}

		// Try to refresh the token
		if refreshErr := b.refreshAccessToken(); refreshErr == nil {
			return nil
		}
		log.Printf("⚠️ Token refresh failed: %v", refreshErr)
	}

	// If no tokens or refresh failed, need manual setup
	if b.accessToken == "" {
		return fmt.Errorf("no access token available - run with 'setup' command to get tokens")
	}

	return fmt.Errorf("authentication failed - tokens may be invalid")
}

func (b *Bot) createTwitterClient() (*gotwi.Client, error) {
	in := &gotwi.NewClientInput{
		AuthenticationMethod: gotwi.AuthenMethodOAuth2AuthorizationCodeFlow,
		OAuthToken:           b.accessToken,
		RefreshToken:         b.refreshToken,
		ClientID:             b.clientID,
		ClientSecret:         b.clientSecret,
	}

	return gotwi.NewClient(in)
}

func (b *Bot) testAuthentication(client *gotwi.Client) error {
	// Simple test to verify authentication works
	ctx := context.Background()
	p := &searchtweet.SearchRecentInput{
		Query: "hello",
		SearchRecentOption: searchtweet.SearchRecentOption{
			MaxResults: gotwi.Int(10),
		},
	}
	
	_, err := searchtweet.SearchRecent(ctx, client, p)
	return err
}

func (b *Bot) refreshAccessToken() error {
	if b.refreshToken == "" {
		return fmt.Errorf("no refresh token available")
	}

	log.Println("🔄 Refreshing access token...")

	data := url.Values{}
	data.Set("refresh_token", b.refreshToken)
	data.Set("grant_type", "refresh_token")
	data.Set("client_id", b.clientID)

	req, err := http.NewRequest("POST", "https://api.twitter.com/2/oauth2/token", strings.NewReader(data.Encode()))
	if err != nil {
		return fmt.Errorf("failed to create refresh request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(b.clientID, b.clientSecret)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("refresh request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("token refresh failed with status: %d", resp.StatusCode)
	}

	var tokenResp OAuth2TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return fmt.Errorf("failed to decode token response: %w", err)
	}

	// Update bot tokens
	b.accessToken = tokenResp.AccessToken
	if tokenResp.RefreshToken != "" {
		b.refreshToken = tokenResp.RefreshToken
	}

	// Recreate client with new tokens
	newClient, err := b.createTwitterClient()
	if err != nil {
		return fmt.Errorf("failed to create client with new tokens: %w", err)
	}

	// Test the new client
	if err := b.testAuthentication(newClient); err != nil {
		return fmt.Errorf("new tokens failed authentication test: %w", err)
	}

	b.client = newClient
	log.Println("✅ Access token refreshed successfully")
	return nil
}

func (b *Bot) handleAuthenticationError(err error) error {
	if strings.Contains(err.Error(), "401") || strings.Contains(err.Error(), "Unauthorized") {
		log.Println("🔄 Authentication error detected, attempting token refresh...")
		if refreshErr := b.refreshAccessToken(); refreshErr != nil {
			return fmt.Errorf("failed to refresh token after auth error: %w", refreshErr)
		}
		return nil // Successfully refreshed
	}
	return err // Not an auth error
}

func (b *Bot) getScamPatterns() ScamPatterns {
	return ScamPatterns{
		CelebScamKeywords: []string{
			"dm me for prize", "direct message me", "whatsapp me",
			"telegram me", "contact my manager", "send gift card",
			"crypto investment", "bitcoin giveaway", "cash app",
			"venmo me", "zelle me", "paypal me", "amazon gift card",
			"congratulations you won", "you have been selected",
			"exclusive opportunity", "limited time offer",
			"winner announcement", "claim your prize",
			"text me at", "call me at", "reach out privately",
			"private message", "inbox me", "contact me directly",
			"send me your", "give me your", "share your details",
		},
		VulnerablePatterns: []string{
			"god bless", "praying for you", "love you so much",
			"biggest fan", "changed my life", "struggling financially",
			"need help", "unemployed", "retired", "disability",
			"social security", "fixed income", "widow", "widower",
			"elderly", "grandma", "grandpa", "grandmother", "grandfather",
			"senior citizen", "pensioner", "medicare", "medicaid",
			"living alone", "lost my job", "hard times", "financial trouble",
		},
		SuspiciousPatterns: []string{
			"official account", "real account", "verified account",
			"authentic profile", "legitimate account",
		},
		TargetedCelebrities: []CelebrityProfile{
			{
				Name:        "Keanu Reeves",
				CommonNames: []string{"keanu reeves", "keanu", "john wick", "neo"},
				Variations:  []string{"keanureeves", "keanu_reeves", "realkeanu", "officialkeanu", "keanuofficial"},
				KnownHandle: "",
				IsVerified:  false,
			},
			{
				Name:        "Elon Musk",
				CommonNames: []string{"elon musk", "elon", "musk", "tesla ceo", "spacex ceo"},
				Variations:  []string{"elonmusk", "elon_musk", "realelon", "officialelon", "elonofficial", "teslaowner", "spacexowner"},
				KnownHandle: "elonmusk",
				IsVerified:  true,
			},
			{
				Name:        "Kevin Costner",
				CommonNames: []string{"kevin costner", "kevin", "costner"},
				Variations:  []string{"kevincostner", "kevin_costner", "realkevin", "officialkevin", "kevinofficial", "modernwest"},
				KnownHandle: "modernwest",
				IsVerified:  true,
			},
		},
	}
}

func (b *Bot) searchForScamTweets(ctx context.Context) ([]AnalyzedTweet, error) {
	patterns := b.getScamPatterns()
	var allAnalyzedTweets []AnalyzedTweet

	// Focused search queries to avoid rate limits
	queries := []string{
		"(\"dm me\" OR \"direct message me\") (prize OR giveaway OR winner OR congratulations) -is:retweet lang:en",
		"(whatsapp OR telegram) (celebrity OR star OR official OR contact) -is:retweet lang:en",
		"\"gift card\" (send OR buy OR purchase) (amazon OR itunes OR google) -is:retweet lang:en",
		"(\"you won\" OR \"winner selected\" OR \"congratulations\") (dm OR message OR contact) -is:retweet lang:en",
	}

	// Add celebrity-specific queries (limited to avoid rate limits)
	for _, celeb := range patterns.TargetedCelebrities[:2] { // Limit to first 2 celebrities
		for _, name := range celeb.CommonNames[:1] { // Limit to first name variant
			query := fmt.Sprintf("(\"%s\" OR %s) (\"dm me\" OR \"message me\" OR giveaway) -is:retweet lang:en", 
				name, strings.ReplaceAll(name, " ", ""))
			queries = append(queries, query)
		}
	}

	for i, query := range queries {
		log.Printf("Searching query %d/%d: %s", i+1, len(queries), query)

		tweets, err := b.searchTweetsWithRetry(ctx, query)
		if err != nil {
			log.Printf("Error searching tweets for query '%s': %v", query, err)
			continue
		}

		allAnalyzedTweets = append(allAnalyzedTweets, tweets...)
		
		// Rate limiting - stay well within limits
		time.Sleep(3 * time.Second)
	}

	log.Printf("Found %d potential scam tweets", len(allAnalyzedTweets))
	return allAnalyzedTweets, nil
}

func (b *Bot) searchTweetsWithRetry(ctx context.Context, query string) ([]AnalyzedTweet, error) {
	var analyzedTweets []AnalyzedTweet

	p := &searchtweet.SearchRecentInput{
		Query: query,
		SearchRecentOption: searchtweet.SearchRecentOption{
			MaxResults: gotwi.Int(50),
			Expansions: []searchtweet.Expansion{
				searchtweet.ExpansionAuthorID,
			},
			TweetFields: []searchtweet.TweetField{
				searchtweet.TweetFieldCreatedAt,
				searchtweet.TweetFieldAuthorID,
				searchtweet.TweetFieldConversationID,
				searchtweet.TweetFieldPublicMetrics,
				searchtweet.TweetFieldContextAnnotations,
			},
			UserFields: []searchtweet.UserField{
				searchtweet.UserFieldCreatedAt,
				searchtweet.UserFieldDescription,
				searchtweet.UserFieldPublicMetrics,
				searchtweet.UserFieldVerified,
				searchtweet.UserFieldProfileImageURL,
			},
		},
	}

	res, err := searchtweet.SearchRecent(ctx, b.client, p)
	if err != nil {
		// Try to handle authentication errors
		if authErr := b.handleAuthenticationError(err); authErr == nil {
			// Retry after successful token refresh
			res, err = searchtweet.SearchRecent(ctx, b.client, p)
		}
		if err != nil {
			return nil, err
		}
	}

	if res.Data == nil {
		return analyzedTweets, nil
	}

	// Process each tweet
	for _, tweet := range *res.Data {
		var author *searchtweet.User

		// Find the author in includes
		if res.Includes != nil && res.Includes.Users != nil {
			for _, user := range *res.Includes.Users {
				if user.ID == tweet.AuthorID {
					author = &user
					break
				}
			}
		}

		// Analyze if this is likely a scam
		analyzed := b.analyzeTweetForScam(&tweet, author)
		if analyzed.IsScam {
			analyzedTweets = append(analyzedTweets, analyzed)
		}
	}

	return analyzedTweets, nil
}

func (b *Bot) analyzeTweetForScam(tweet *searchtweet.Tweet, author *searchtweet.User) AnalyzedTweet {
	patterns := b.getScamPatterns()
	analyzed := AnalyzedTweet{
		Tweet:  tweet,
		Author: author,
	}

	if author == nil {
		return analyzed
	}

	// Skip legitimate accounts
	if b.isLegitimateAccount(author, patterns.TargetedCelebrities) {
		return analyzed
	}

	// Skip verified accounts unless they have obvious scam content
	if author.Verified != nil && *author.Verified {
		if !b.hasScamContent(tweet, author, patterns) {
			return analyzed
		}
	}

	scamScore := 0
	var reasons []string

	// Check for celebrity impersonation
	impersonationScore, impersonationReason := b.checkCelebrityImpersonation(author, tweet, patterns.TargetedCelebrities)
	scamScore += impersonationScore
	if impersonationReason != "" {
		reasons = append(reasons, impersonationReason)
	}

	// Check account age
	if author.CreatedAt != nil {
		if accountAge := time.Since(*author.CreatedAt); accountAge < 60*24*time.Hour {
			scamScore += 2
			reasons = append(reasons, "new account (less than 60 days)")
		}
	}

	// Check follower patterns
	if author.PublicMetrics != nil {
		followers := author.PublicMetrics.FollowersCount
		following := author.PublicMetrics.FollowingCount

		if followers < 100 && following > 1000 {
			scamScore += 3
			reasons = append(reasons, "suspicious follower ratio")
		}

		if followers < 50 {
			scamScore += 1
			reasons = append(reasons, "very low followers")
		}
	}

	// Check for suspicious username patterns
	if b.hasSuspiciousUsername(author.Username, patterns) {
		scamScore += 2
		reasons = append(reasons, "suspicious username pattern")
	}

	// Check bio for scam keywords
	if author.Description != nil {
		bioText := strings.ToLower(*author.Description)
		for _, keyword := range patterns.CelebScamKeywords {
			if strings.Contains(bioText, keyword) {
				scamScore += 3
				reasons = append(reasons, fmt.Sprintf("scam keyword in bio: %s", keyword))
				break
			}
		}

		// Check for fake verification claims
		for _, suspicious := range patterns.SuspiciousPatterns {
			if strings.Contains(bioText, suspicious) {
				scamScore += 2
				reasons = append(reasons, "fake verification claims")
				break
			}
		}
	}

	// Check tweet content for scam patterns
	tweetText := strings.ToLower(tweet.Text)
	scamKeywordCount := 0
	for _, keyword := range patterns.CelebScamKeywords {
		if strings.Contains(tweetText, keyword) {
			scamKeywordCount++
			scamScore += 2
		}
	}
	if scamKeywordCount > 0 {
		reasons = append(reasons, fmt.Sprintf("scam keywords in tweet (%d found)", scamKeywordCount))
	}

	// Check for celebrity impersonation indicators
	if b.looksLikeCelebImpersonation(author, tweet) {
		scamScore += 3
		reasons = append(reasons, "appears to impersonate celebrity")
	}

	analyzed.ScamScore = scamScore
	analyzed.ScamReasons = reasons
	analyzed.IsScam = scamScore >= 5

	return analyzed
}

func (b *Bot) hasSuspiciousUsername(username string, patterns ScamPatterns) bool {
	// Pattern for usernames with many numbers at the end
	randomPattern := regexp.MustCompile(`^[a-zA-Z]+\d{6,}$`)
	if randomPattern.MatchString(username) {
		return true
	}

	// Pattern for celebrity impersonation attempts
	celebPattern := regexp.MustCompile(`(?i)(official|real|actual|verified).*(celebrity|star|singer|actor|artist)`)
	if celebPattern.MatchString(username) {
		return true
	}

	// Pattern for names with "official" but not verified
	officialPattern := regexp.MustCompile(`(?i)^(official|real|actual)`)
	if officialPattern.MatchString(username) {
		return true
	}

	// Check against known celebrity variations
	usernameToCheck := strings.ToLower(username)
	for _, celeb := range patterns.TargetedCelebrities {
		for _, variation := range celeb.Variations {
			if usernameToCheck == strings.ToLower(variation) {
				// If it matches a celebrity variation but isn't the known handle, it's suspicious
				if celeb.KnownHandle == "" || strings.ToLower(celeb.KnownHandle) != usernameToCheck {
					return true
				}
			}
		}
	}

	return false
}

func (b *Bot) isLegitimateAccount(user *searchtweet.User, celebrities []CelebrityProfile) bool {
	if user == nil {
		return false
	}

	username := strings.ToLower(user.Username)
	for _, celeb := range celebrities {
		if celeb.KnownHandle != "" && strings.ToLower(celeb.KnownHandle) == username {
			if user.Verified != nil && *user.Verified == celeb.IsVerified {
				return true
			}
		}
	}

	return false
}

func (b *Bot) checkCelebrityImpersonation(user *searchtweet.User, tweet *searchtweet.Tweet, celebrities []CelebrityProfile) (int, string) {
	if user == nil {
		return 0, ""
	}

	username := strings.ToLower(user.Username)
	var nameText, bioText string

	if user.Name != nil {
		nameText = strings.ToLower(*user.Name)
	}
	if user.Description != nil {
		bioText = strings.ToLower(*user.Description)
	}

	score := 0
	var reasons []string

	for _, celeb := range celebrities {
		// Check if username matches celebrity variations
		for _, variation := range celeb.Variations {
			if username == strings.ToLower(variation) {
				if celeb.KnownHandle == "" || strings.ToLower(celeb.KnownHandle) != username {
					score += 5
					reasons = append(reasons, fmt.Sprintf("username impersonates %s", celeb.Name))
				}
			}
		}

		// Check if display name contains celebrity name
		for _, commonName := range celeb.CommonNames {
			if strings.Contains(nameText, strings.ToLower(commonName)) {
				if celeb.IsVerified && (user.Verified == nil || !*user.Verified) {
					score += 4
					reasons = append(reasons, fmt.Sprintf("display name suggests %s but not verified", celeb.Name))
				}
			}
		}
	}

	reasonText := ""
	if len(reasons) > 0 {
		reasonText = strings.Join(reasons, "; ")
	}

	return score, reasonText
}

func (b *Bot) hasScamContent(tweet *searchtweet.Tweet, user *searchtweet.User, patterns ScamPatterns) bool {
	tweetText := strings.ToLower(tweet.Text)
	for _, keyword := range patterns.CelebScamKeywords {
		if strings.Contains(tweetText, keyword) {
			return true
		}
	}

	if user.Description != nil {
		bioText := strings.ToLower(*user.Description)
		for _, keyword := range patterns.CelebScamKeywords {
			if strings.Contains(bioText, keyword) {
				return true
			}
		}
	}

	return false
}

func (b *Bot) looksLikeCelebImpersonation(author *searchtweet.User, tweet *searchtweet.Tweet) bool {
	if tweet.ContextAnnotations != nil {
		for _, annotation := range *tweet.ContextAnnotations {
			if annotation.Domain != nil &&
				annotation.Domain.Name != nil &&
				*annotation.Domain.Name == "Person" {
				return true
			}
		}
	}

	if author.Name != nil && author.Verified != nil && !*author.Verified {
		nameText := strings.ToLower(*author.Name)
		celebIndicators := []string{"official", "real", "verified", "authentic"}

		for _, indicator := range celebIndicators {
			if strings.Contains(nameText, indicator) {
				return true
			}
		}
	}

	return false
}

func (b *Bot) findVulnerableEngagement(ctx context.Context, scamTweet AnalyzedTweet) ([]VulnerableUser, error) {
	if scamTweet.Tweet.ConversationID == nil {
		return nil, fmt.Errorf("no conversation ID available")
	}

	query := fmt.Sprintf("conversation_id:%s", *scamTweet.Tweet.ConversationID)

	p := &searchtweet.SearchRecentInput{
		Query: query,
		SearchRecentOption: searchtweet.SearchRecentOption{
			MaxResults: gotwi.Int(100),
			Expansions: []searchtweet.Expansion{
				searchtweet.ExpansionAuthorID,
			},
			TweetFields: []searchtweet.TweetField{
				searchtweet.TweetFieldCreatedAt,
				searchtweet.TweetFieldAuthorID,
			},
			UserFields: []searchtweet.UserField{
				searchtweet.UserFieldCreatedAt,
				searchtweet.UserFieldDescription,
				searchtweet.UserFieldPublicMetrics,
				searchtweet.UserFieldVerified,
			},
		},
	}

	res, err := searchtweet.SearchRecent(ctx, b.client, p)
	if err != nil {
		if authErr := b.handleAuthenticationError(err); authErr == nil {
			res, err = searchtweet.SearchRecent(ctx, b.client, p)
		}
		if err != nil {
			return nil, fmt.Errorf("error searching conversation: %w", err)
		}
	}

	var vulnerableUsers []VulnerableUser

	if res.Data == nil || res.Includes == nil || res.Includes.Users == nil {
		return vulnerableUsers, nil
	}

	// Analyze each user in the conversation
	for _, user := range *res.Includes.Users {
		if scamTweet.Author != nil && user.ID == scamTweet.Author.ID {
			continue
		}

		var userTweets []searchtweet.Tweet
		for _, tweet := range *res.Data {
			if tweet.AuthorID == user.ID {
				userTweets = append(userTweets, tweet)
			}
		}

		vulnerable := b.analyzeUserVulnerability(&user, userTweets)
		if vulnerable.VulnerabilityScore >= 3 {
			vulnerableUsers = append(vulnerableUsers, vulnerable)
		}
	}

	return vulnerableUsers, nil
}

func (b *Bot) analyzeUserVulnerability(user *searchtweet.User, tweets []searchtweet.Tweet) VulnerableUser {
	patterns := b.getScamPatterns()
	vulnerable := VulnerableUser{
		User: user,
	}

	score := 0
	var reasons []string

	// Check bio for vulnerability indicators
	if user.Description != nil {
		bioText := strings.ToLower(*user.Description)
		for _, pattern := range patterns.VulnerablePatterns {
			if strings.Contains(bioText, pattern) {
				score += 2
				reasons = append(reasons, fmt.Sprintf("vulnerable keyword in bio: %s", pattern))
			}
		}
	}

	// Check tweets for vulnerability indicators
	for _, tweet := range tweets {
		tweetText := strings.ToLower(tweet.Text)
		for _, pattern := range patterns.VulnerablePatterns {
			if strings.Contains(tweetText, pattern) {
				score += 1
				reasons = append(reasons, "vulnerable language in tweets")
				break
			}
		}

		trustingPhrases := []string{
			"thank you so much", "god bless you", "you're so kind",
			"i can't believe", "this is amazing", "how do i",
			"what should i do", "please help me",
		}

		for _, phrase := range trustingPhrases {
			if strings.Contains(tweetText, phrase) {
				score += 1
				reasons = append(reasons, "trusting/naive language")
				break
			}
		}
	}

	// Account characteristics
	if user.CreatedAt != nil {
		accountAge := time.Since(*user.CreatedAt)

		if accountAge > 5*365*24*time.Hour && user.PublicMetrics != nil {
			if user.PublicMetrics.FollowersCount < 200 && user.PublicMetrics.TweetCount < 1000 {
				score += 1
				reasons = append(reasons, "older account with low activity")
			}
		}
	}

	if user.PublicMetrics != nil && user.PublicMetrics.FollowersCount < 100 && len(tweets) > 0 {
		score += 1
		reasons = append(reasons, "low followers but engaged")
	}

	vulnerable.VulnerabilityScore = score
	vulnerable.VulnerableReasons = reasons

	return vulnerable
}

func (b *Bot) sendWarningTweet(ctx context.Context, targetUsername string, originalTweetID string) error {
	warningMessages := []string{
		"⚠️ SCAM ALERT: Real celebrities don't DM fans asking for personal info or money. Never share sensitive information, send gift cards, or send money to anyone claiming to be a celebrity. If it seems too good to be true, it probably is. Stay safe! 🛡️",
		"🚨 FRAUD WARNING: This looks like a celebrity impersonation scam. Legitimate celebrities don't ask fans for money, gift cards, or personal information through DMs. Please be cautious and don't share any personal details. Stay safe! 💙",
		"⛔ SCAM DETECTED: Be very careful! Real celebrities and their teams don't contact fans directly asking for money or gift cards. This is a common scam targeting fans. Don't send money or personal information to anyone. Report and block! 🔒",
		"🚨 CELEBRITY IMPERSONATION ALERT: Real celebrities don't ask for gift cards or personal info. If someone claiming to be a celebrity contacts you privately, it's likely a scam! Always verify through official channels. 🛡️",
	}

	messageIndex := int(time.Now().Unix()) % len(warningMessages)
	warningText := fmt.Sprintf("@%s %s", targetUsername, warningMessages[messageIndex])

	p := &managetweet.CreateInput{
		Text: gotwi.String(warningText),
	}

	if originalTweetID != "" {
		p.Reply = &managetweet.CreateInputReply{
			InReplyToTweetID: originalTweetID,
		}
	}

	_, err := managetweet.Create(ctx, b.client, p)
	if err != nil {
		// Try to handle authentication errors
		if authErr := b.handleAuthenticationError(err); authErr == nil {
			_, err = managetweet.Create(ctx, b.client, p)
		}
		if err != nil {
			return fmt.Errorf("failed to send warning tweet: %w", err)
		}
	}

	return nil
}

func (b *Bot) analyzeAndWarn(ctx context.Context) error {
	log.Println("Starting analysis for scam detection...")

	scamTweets, err := b.searchForScamTweets(ctx)
	if err != nil {
		return fmt.Errorf("error searching for scam tweets: %w", err)
	}

	if len(scamTweets) == 0 {
		log.Println("No scam tweets found in this analysis cycle")
		return nil
	}

	warningsSent := 0

	for _, scamTweet := range scamTweets {
		if scamTweet.Author == nil {
			continue
		}

		log.Printf("Analyzing scam tweet from @%s (score: %d): %s",
			scamTweet.Author.Username, scamTweet.ScamScore,
			strings.Join(scamTweet.ScamReasons, ", "))

		// Find vulnerable users engaging with this scam
		vulnerableUsers, err := b.findVulnerableEngagement(ctx, scamTweet)
		if err != nil {
			log.Printf("Error finding vulnerable engagement for tweet %s: %v",
				scamTweet.Tweet.ID, err)
			continue
		}

		for _, vulnerable := range vulnerableUsers {
			log.Printf("Found vulnerable user @%s (score: %d): %s",
				vulnerable.User.Username, vulnerable.VulnerabilityScore,
				strings.Join(vulnerable.VulnerableReasons, ", "))

			// Send warning tweet
			err := b.sendWarningTweet(ctx, vulnerable.User.Username, scamTweet.Tweet.ID)
			if err != nil {
				log.Printf("Error sending warning to @%s: %v", vulnerable.User.Username, err)
			} else {
				log.Printf("✅ Warning sent to @%s", vulnerable.User.Username)
				warningsSent++
			}

			// Rate limiting - don't overwhelm users or hit API limits
			time.Sleep(15 * time.Second)

			// Limit warnings per cycle to avoid spam
			if warningsSent >= 10 {
				log.Printf("Reached warning limit for this cycle (%d warnings sent)", warningsSent)
				return nil
			}
		}

		// Rate limiting between scam tweet analysis
		time.Sleep(5 * time.Second)
	}

	log.Printf("Analysis complete. Sent %d warnings this cycle.", warningsSent)
	return nil
}

func (b *Bot) Run(ctx context.Context) {
	log.Println("🚀 Starting Twitter Anti-Scam Bot...")

	// Create a ticker for periodic runs - 30 minutes to stay within rate limits
	ticker := time.NewTicker(30 * time.Minute)
	defer ticker.Stop()

	// Run analysis immediately on startup
	if err := b.analyzeAndWarn(ctx); err != nil {
		log.Printf("❌ Error in initial analysis: %v", err)
	}

	// Run on schedule
	for {
		select {
		case <-ticker.C:
			log.Println("⏰ Starting scheduled analysis...")
			if err := b.analyzeAndWarn(ctx); err != nil {
				log.Printf("❌ Error in scheduled analysis: %v", err)
			}
		case <-ctx.Done():
			log.Println("🛑 Bot stopped")
			return
		}
	}
}

func validateConfig() error {
	requiredEnvVars := []string{
		"TWITTER_CLIENT_ID",
		"TWITTER_CLIENT_SECRET",
	}

	for _, envVar := range requiredEnvVars {
		if os.Getenv(envVar) == "" {
			return fmt.Errorf("missing required environment variable: %s", envVar)
		}
	}

	if os.Getenv("TWITTER_ACCESS_TOKEN") == "" {
		return fmt.Errorf("missing TWITTER_ACCESS_TOKEN - run with 'setup' command to obtain tokens")
	}

	if os.Getenv("TWITTER_REFRESH_TOKEN") == "" {
		log.Println("⚠️ TWITTER_REFRESH_TOKEN not set - automatic token refresh will not work")
	}

	return nil
}

// OAuth 2.0 setup functions
func generatePKCE() (codeVerifier, codeChallenge string, err error) {
	bytes := make([]byte, 96)
	if _, err := rand.Read(bytes); err != nil {
		return "", "", err
	}
	codeVerifier = base64.RawURLEncoding.EncodeToString(bytes)

	hash := sha256.Sum256([]byte(codeVerifier))
	codeChallenge = base64.RawURLEncoding.EncodeToString(hash[:])

	return codeVerifier, codeChallenge, nil
}

func (b *Bot) generateAuthURL() (string, string, error) {
	codeVerifier, codeChallenge, err := generatePKCE()
	if err != nil {
		return "", "", err
	}

	baseURL := "https://twitter.com/i/oauth2/authorize"
	params := url.Values{}
	params.Add("response_type", "code")
	params.Add("client_id", b.clientID)
	params.Add("redirect_uri", "http://localhost:8080/callback")
	params.Add("scope", "tweet.read tweet.write users.read offline.access")
	params.Add("state", fmt.Sprintf("state-%d", time.Now().Unix()))
	params.Add("code_challenge", codeChallenge)
	params.Add("code_challenge_method", "S256")

	authURL := fmt.Sprintf("%s?%s", baseURL, params.Encode())
	return authURL, codeVerifier, nil
}

func (b *Bot) exchangeCodeForToken(code, codeVerifier string) (*OAuth2TokenResponse, error) {
	data := url.Values{}
	data.Set("code", code)
	data.Set("grant_type", "authorization_code")
	data.Set("client_id", b.clientID)
	data.Set("redirect_uri", "http://localhost:8080/callback")
	data.Set("code_verifier", codeVerifier)

	req, err := http.NewRequest("POST", "https://api.twitter.com/2/oauth2/token", strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(b.clientID, b.clientSecret)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("token exchange failed with status: %d", resp.StatusCode)
	}

	var tokenResp OAuth2TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, err
	}

	return &tokenResp, nil
}

func runOAuth2Setup() {
	log.Println("🔐 Twitter OAuth 2.0 with PKCE Setup")
	log.Println("=====================================")

	clientID := os.Getenv("TWITTER_CLIENT_ID")
	clientSecret := os.Getenv("TWITTER_CLIENT_SECRET")

	if clientID == "" || clientSecret == "" {
		log.Fatal("❌ Please set TWITTER_CLIENT_ID and TWITTER_CLIENT_SECRET environment variables first")
	}

	bot := &Bot{
		clientID:     clientID,
		clientSecret: clientSecret,
	}

	authURL, codeVerifier, err := bot.generateAuthURL()
	if err != nil {
		log.Fatal("❌ Failed to generate auth URL:", err)
	}

	log.Println("📋 Setup Instructions:")
	log.Println("1. Open this URL in your browser:")
	log.Println("   " + authURL)
	log.Println()
	log.Println("2. Authorize the application")
	log.Println("3. Copy the authorization code from the callback URL")
	log.Println("4. Use the code with the exchange function to get tokens")
	log.Println("5. Set the following environment variables:")
	log.Println("   export TWITTER_ACCESS_TOKEN='your_access_token'")
	log.Println("   export TWITTER_REFRESH_TOKEN='your_refresh_token'")
	log.Println()
	log.Printf("🔑 Code Verifier (save this): %s", codeVerifier)
	log.Println()
	log.Println("ℹ️  You can implement a simple callback server or manually extract")
	log.Println("   the authorization code from the redirect URL after authorization.")
}

func main() {
	// Setup logging
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.SetPrefix("[SCAM-BOT] ")

	// Check for setup command
	if len(os.Args) > 1 && os.Args[1] == "setup" {
		runOAuth2Setup()
		return
	}

	// Validate configuration
	if err := validateConfig(); err != nil {
		log.Fatal("❌ Configuration error:", err)
	}

	// Create bot instance
	bot, err := NewBot()
	if err != nil {
		log.Fatal("❌ Failed to create bot:", err)
	}

	// Create context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Run the bot
	bot.Run(ctx)
}