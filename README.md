# X/Twitter Anti-Scam Bot

An automated bot that monitors X/Twitter for celebrity impersonation scams and warns potential victims.

## Features

- **Celebrity Impersonation Detection**: Identifies fake accounts impersonating celebrities
- **Vulnerability Analysis**: Analyzes users who might be susceptible to scams
- **Automated Warnings**: Sends warning tweets to users engaging with potential scams
- **Real-time Monitoring**: Continuously monitors X/Twitter for new scam activity

## Authentication

This bot uses **X API v2 Bearer Token authentication** for app-only access. This is the simplest and most reliable method for autonomous bots.

### Setup

1. Create a Twitter Developer account at [developer.x.com](https://developer.x.com)
2. Create a new app and generate a **Bearer Token**
3. Set the environment variable:

```bash
export TWITTER_BEARER_TOKEN="your_bearer_token_here"
```

### Required X API Access

The bot requires the following X API v2 endpoints:
- **Tweet search** (`tweet.read` scope)
- **Tweet posting** (`tweet.write` scope) 
- **User information** (`users.read` scope)

## Running the Bot

```bash
# Set your Bearer Token
export TWITTER_BEARER_TOKEN="your_token_here"

# Run the bot
./scambot
```

The bot will:
1. Validate authentication on startup
2. Begin monitoring for scam activity
3. Run analysis cycles every 30 minutes
4. Send warnings to vulnerable users when scams are detected

## How It Works

1. **Scam Detection**: Searches for tweets containing scam keywords and patterns
2. **Account Analysis**: Evaluates accounts for impersonation indicators
3. **Victim Identification**: Finds users engaging with potential scams
4. **Warning Dispatch**: Sends educational warning tweets to at-risk users

## Rate Limiting

The bot is designed to respect X API rate limits:
- 30-minute analysis cycles
- 15-second delays between warning tweets
- Maximum 10 warnings per cycle
- 3-second delays between search queries

## Environment Variables

- `TWITTER_BEARER_TOKEN` (required): Your X API v2 Bearer Token

## Building

```bash
go build
```

## Celebrity Profiles

The bot currently monitors for impersonation of:
- Keanu Reeves
- Elon Musk  
- Kevin Costner

Additional celebrities can be added by modifying the `TargetedCelebrities` list in the code.
