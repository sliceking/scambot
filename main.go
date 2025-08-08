package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/michimani/gotwi"
	"github.com/michimani/gotwi/fields"
	"github.com/michimani/gotwi/resources"
	"github.com/michimani/gotwi/tweet/managetweet"
	managetypes "github.com/michimani/gotwi/tweet/managetweet/types"
	"github.com/michimani/gotwi/tweet/searchtweet"
	searchtypes "github.com/michimani/gotwi/tweet/searchtweet/types"
)

type Bot struct {
	client      *gotwi.Client
	bearerToken string
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
	Tweet       *resources.Tweet
	Author      *resources.User
	IsScam      bool
	ScamScore   int
	ScamReasons []string
}

type VulnerableUser struct {
	User               *resources.User
	VulnerabilityScore int
	VulnerableReasons  []string
}

func NewBot() (*Bot, error) {
	// Required Bearer Token for app-only authentication
	bearerToken := os.Getenv("TWITTER_BEARER_TOKEN")

	if bearerToken == "" {
		return nil, fmt.Errorf("missing required TWITTER_BEARER_TOKEN environment variable")
	}

	bot := &Bot{
		bearerToken: bearerToken,
	}

	// Create client and test authentication on startup
	if err := bot.createTwitterClient(); err != nil {
		return nil, fmt.Errorf("failed to create Twitter client: %w", err)
	}

	if err := bot.testAuthentication(); err != nil {
		return nil, fmt.Errorf("authentication test failed: %w", err)
	}

	log.Println("✅ Authentication successful")
	return bot, nil
}



func (b *Bot) createTwitterClient() error {
	in := &gotwi.NewClientInput{
		AuthenticationMethod: gotwi.AuthenMethodOAuth2BearerToken,
		OAuthToken:           b.bearerToken,
	}

	client, err := gotwi.NewClient(in)
	if err != nil {
		return err
	}

	b.client = client
	return nil
}

func (b *Bot) testAuthentication() error {
	// Simple test to verify authentication works
	ctx := context.Background()
	p := &searchtypes.ListRecentInput{
		Query: "hello",
		MaxResults: 10,
	}

	_, err := searchtweet.ListRecent(ctx, b.client, p)
	return err
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

	p := &searchtypes.ListRecentInput{
		Query: query,
		MaxResults: 50,
		Expansions: fields.ExpansionList{
			fields.ExpansionAuthorID,
		},
		TweetFields: fields.TweetFieldList{
			fields.TweetFieldCreatedAt,
			fields.TweetFieldAuthorID,
			fields.TweetFieldConversationID,
			fields.TweetFieldPublicMetrics,
			fields.TweetFieldContextAnnotations,
		},
		UserFields: fields.UserFieldList{
			fields.UserFieldCreatedAt,
			fields.UserFieldDescription,
			fields.UserFieldPublicMetrics,
			fields.UserFieldVerified,
		},
	}

	res, err := searchtweet.ListRecent(ctx, b.client, p)
	if err != nil {
		return nil, err
	}

	if res.Data == nil {
		return analyzedTweets, nil
	}

	// Process each tweet
	for _, tweet := range res.Data {
		var author *resources.User

		// Find the author in includes
		if len(res.Includes.Users) > 0 {
			for _, user := range res.Includes.Users {
				if gotwi.StringValue(user.ID) == gotwi.StringValue(tweet.AuthorID) {
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

func (b *Bot) analyzeTweetForScam(tweet *resources.Tweet, author *resources.User) AnalyzedTweet {
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
		followers := gotwi.IntValue(author.PublicMetrics.FollowersCount)
		following := gotwi.IntValue(author.PublicMetrics.FollowingCount)

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
	if b.hasSuspiciousUsername(gotwi.StringValue(author.Username), patterns) {
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
	tweetText := strings.ToLower(gotwi.StringValue(tweet.Text))
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

func (b *Bot) isLegitimateAccount(user *resources.User, celebrities []CelebrityProfile) bool {
	if user == nil {
		return false
	}

	username := strings.ToLower(gotwi.StringValue(user.Username))
	for _, celeb := range celebrities {
		if celeb.KnownHandle != "" && strings.ToLower(celeb.KnownHandle) == username {
			if user.Verified != nil && *user.Verified == celeb.IsVerified {
				return true
			}
		}
	}

	return false
}

func (b *Bot) checkCelebrityImpersonation(user *resources.User, tweet *resources.Tweet, celebrities []CelebrityProfile) (int, string) {
	if user == nil {
		return 0, ""
	}

	username := strings.ToLower(gotwi.StringValue(user.Username))
	var nameText string

	if user.Name != nil {
		nameText = strings.ToLower(gotwi.StringValue(user.Name))
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

func (b *Bot) hasScamContent(tweet *resources.Tweet, user *resources.User, patterns ScamPatterns) bool {
	tweetText := strings.ToLower(gotwi.StringValue(tweet.Text))
	for _, keyword := range patterns.CelebScamKeywords {
		if strings.Contains(tweetText, keyword) {
			return true
		}
	}

	if user.Description != nil {
		bioText := strings.ToLower(gotwi.StringValue(user.Description))
		for _, keyword := range patterns.CelebScamKeywords {
			if strings.Contains(bioText, keyword) {
				return true
			}
		}
	}

	return false
}

func (b *Bot) looksLikeCelebImpersonation(author *resources.User, tweet *resources.Tweet) bool {
	if tweet.ContextAnnotations != nil {
		for _, annotation := range tweet.ContextAnnotations {
			if annotation.Domain.Name != nil &&
				gotwi.StringValue(annotation.Domain.Name) == "Person" {
				return true
			}
		}
	}

	if author.Name != nil && author.Verified != nil && !*author.Verified {
		nameText := strings.ToLower(gotwi.StringValue(author.Name))
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

	query := fmt.Sprintf("conversation_id:%s", gotwi.StringValue(scamTweet.Tweet.ConversationID))

	p := &searchtypes.ListRecentInput{
		Query: query,
		MaxResults: 100,
		Expansions: fields.ExpansionList{
			fields.ExpansionAuthorID,
		},
		TweetFields: fields.TweetFieldList{
			fields.TweetFieldCreatedAt,
			fields.TweetFieldAuthorID,
		},
		UserFields: fields.UserFieldList{
			fields.UserFieldCreatedAt,
			fields.UserFieldDescription,
			fields.UserFieldPublicMetrics,
			fields.UserFieldVerified,
		},
	}

	res, err := searchtweet.ListRecent(ctx, b.client, p)
	if err != nil {
		return nil, fmt.Errorf("error searching conversation: %w", err)
	}

	var vulnerableUsers []VulnerableUser

	if len(res.Data) == 0 || len(res.Includes.Users) == 0 {
		return vulnerableUsers, nil
	}

	// Analyze each user in the conversation
	for _, user := range res.Includes.Users {
		if scamTweet.Author != nil && gotwi.StringValue(user.ID) == gotwi.StringValue(scamTweet.Author.ID) {
			continue
		}

		var userTweets []resources.Tweet
		for _, tweet := range res.Data {
			if gotwi.StringValue(tweet.AuthorID) == gotwi.StringValue(user.ID) {
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

func (b *Bot) analyzeUserVulnerability(user *resources.User, tweets []resources.Tweet) VulnerableUser {
	patterns := b.getScamPatterns()
	vulnerable := VulnerableUser{
		User: user,
	}

	score := 0
	var reasons []string

	// Check bio for vulnerability indicators
	if user.Description != nil {
		bioText := strings.ToLower(gotwi.StringValue(user.Description))
		for _, pattern := range patterns.VulnerablePatterns {
			if strings.Contains(bioText, pattern) {
				score += 2
				reasons = append(reasons, fmt.Sprintf("vulnerable keyword in bio: %s", pattern))
			}
		}
	}

	// Check tweets for vulnerability indicators
	for _, tweet := range tweets {
		tweetText := strings.ToLower(gotwi.StringValue(tweet.Text))
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
			if gotwi.IntValue(user.PublicMetrics.FollowersCount) < 200 && gotwi.IntValue(user.PublicMetrics.TweetCount) < 1000 {
				score += 1
				reasons = append(reasons, "older account with low activity")
			}
		}
	}

	if user.PublicMetrics != nil && gotwi.IntValue(user.PublicMetrics.FollowersCount) < 100 && len(tweets) > 0 {
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

	p := &managetypes.CreateInput{
		Text: gotwi.String(warningText),
	}

	if originalTweetID != "" {
		p.Reply = &managetypes.CreateInputReply{
			InReplyToTweetID: originalTweetID,
		}
	}

	_, err := managetweet.Create(ctx, b.client, p)
	if err != nil {
		return fmt.Errorf("failed to send warning tweet: %w", err)
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
			gotwi.StringValue(scamTweet.Author.Username), scamTweet.ScamScore,
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
				gotwi.StringValue(vulnerable.User.Username), vulnerable.VulnerabilityScore,
				strings.Join(vulnerable.VulnerableReasons, ", "))

			// Send warning tweet
			err := b.sendWarningTweet(ctx, gotwi.StringValue(vulnerable.User.Username), gotwi.StringValue(scamTweet.Tweet.ID))
			if err != nil {
				log.Printf("Error sending warning to @%s: %v", gotwi.StringValue(vulnerable.User.Username), err)
			} else {
				log.Printf("✅ Warning sent to @%s", gotwi.StringValue(vulnerable.User.Username))
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
	if os.Getenv("TWITTER_BEARER_TOKEN") == "" {
		return fmt.Errorf("missing required TWITTER_BEARER_TOKEN environment variable")
	}
	return nil
}



func main() {
	// Setup logging
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.SetPrefix("[SCAM-BOT] ")

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

