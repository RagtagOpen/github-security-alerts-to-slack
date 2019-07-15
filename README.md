# GitHub Security Alerts to Slack

A webhook receiver, written in Node, to dispatch [GitHub vulnerability alerts](https://help.github.com/en/articles/about-security-alerts-for-vulnerable-dependencies) to [Slack](https://slack.com/) using [Serverless](https://serverless.com/) to deploy to [AWS Lambda](https://aws.amazon.com/lambda/).

## Configuration

First, copy example-serverless.yml to serverless.yml. Then you'll need two things to add to the config:

1. [An "Incoming Webhook" for your Slack workspace](https://get.slack.help/hc/en-us/articles/115005265063-Incoming-WebHooks-for-Slack#set-up-incoming-webhooks)
2. [A unique token for verifying GitHub events](https://www.random.org/passwords/?num=1&len=24&format=html&rnd=new)

We recommend using AWS Parameter Store, with the Secure String option, for securely setting the required environment variables. Our example serverless.yml file expects the following keys in Parameter Store:

| Key                       | Value                                                                                                                     | Notes    |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------- | -------- |
| SLACK_WEBHOOK_URL         | The URL from step 1 above                                                                                                 | Required |
| GITHUB_VERIFICATION_TOKEN | The random string from step 2 above                                                                                       | Required |
| SLACK_CHANNEL_ID          | The ID of a Slack channel to post to (overrides the channel you chose in step 1)                                          | Optional |
| SENTRY_DSN                | If you want to monitor for errors with [Sentry](https://sentry.io/), add a new app and use it's DSN string for this value | Optional |

You can use any keynames you want in Parameter Store, just update your serverless.yml to look for the names you specify.

## Running the app locally

We use [Serverless Offline](https://www.npmjs.com/package/serverless-offline) to emulate Lambda for local testing. To get started, run `npm install` to get all the dependencies installed. Then run `serverless offline`, which will make the app available at `http://localhost:3000/`. We recommend [Postman](https://www.getpostman.com/) for sending requests to the local server.

## Deploying

Once your serverless.yml is configured and you've installed the node dependencies, you can deploy to Lambda by running `serverless deploy`.

## Setting up GitHub

Once you've deployed the app, you can [add a webhook to an organization or repository on GitHub](https://developer.github.com/webhooks/creating/#setting-up-a-webhook). Use the URL that serverless displayed at the end of the deploy script and the random string you generated in step 2 as the "Secret".

## Contributing

We welcome pull requests and new issue reports. You can learn more about getting involved in [Contributing](CONTRIBUTING).
