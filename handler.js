"use strict";
// adapted from https://github.com/serverless/examples/blob/master/aws-node-github-webhook-listener/handler.js

if (process.env.SENTRY_DSN) {
  const Sentry = require("@sentry/node");
  Sentry.init({ dsn: process.env.SENTRY_DSN });
}

const axios = require("axios");
const crypto = require("crypto");

const signString = (key, string, hash) => {
  if (crypto.getHashes().indexOf(hash) === -1) {
    throw new Error(`Unsupported signing hash: ${hash}`);
  }
  return `${hash}=${crypto
    .createHmac(hash, key)
    .update(string, "utf-8")
    .digest("hex")}`;
};
module.exports.signString = signString;

module.exports.klaxon = async (event, context, callback) => {
  const SLACK_WEBHOOK_URL = process.env.SLACK_WEBHOOK_URL;
  const GITHUB_VERIFICATION_TOKEN = process.env.GITHUB_VERIFICATION_TOKEN;
  console.log("token", GITHUB_VERIFICATION_TOKEN);

  if (typeof GITHUB_VERIFICATION_TOKEN !== "string") {
    return callback(null, {
      statusCode: 401,
      headers: { "Content-Type": "text/plain" },
      body: "GITHUB_VERIFICATION_TOKEN is a required environment variable"
    });
  }

  const body = JSON.parse(event.body);
  const { action, alert, repository } = body;
  const { headers } = event;
  const signature = headers["X-Hub-Signature"];

  if (!signature) {
    return callback(null, {
      statusCode: 422,
      headers: { "Content-Type": "text/plain" },
      body: "X-Hub-Signature header not found"
    });
  }

  if (!headers["X-GitHub-Event"]) {
    return callback(null, {
      statusCode: 422,
      headers: { "Content-Type": "text/plain" },
      body: "X-GitHub-Event header not found"
    });
  }

  const signatureHash = signature.split("=").shift();
  console.log("signatureHash", signatureHash);
  console.log(
    "expected",
    signString(GITHUB_VERIFICATION_TOKEN, event.body, signatureHash)
  );
  console.log("got", signature);

  if (
    signString(GITHUB_VERIFICATION_TOKEN, event.body, signatureHash) !==
    signature
  ) {
    return callback(null, {
      statusCode: 401,
      headers: { "Content-Type": "text/plain" },
      body: "X-Hub-Signature header failed verification"
    });
  }

  if (headers["X-GitHub-Event"] === "ping") {
    return callback(null, {
      statusCode: 200,
      headers: { "Content-Type": "text/plain" },
      body: "pong"
    });
  }

  if (headers["X-GitHub-Event"] !== "repository_vulnerability_alert") {
    const response = {
      statusCode: 418,
      headers: { "Content-Type": "text/plain" },
      body: `X-GitHub-Event ${headers["X-GitHub-Event"]} not supported`
    };
    return callback(null, response);
  }

  if (!headers["X-GitHub-Delivery"]) {
    return callback(null, {
      statusCode: 422,
      headers: { "Content-Type": "text/plain" },
      body: "X-GitHub-Delivery header not found"
    });
  }

  /* eslint-disable */
  // console.log("-".repeat(20));
  // console.log(
  //   `X-GitHub-Event ${headers["X-GitHub-Event"]} with action: ${action}`
  // );
  // console.log("Payload", event.body);
  // console.log("-".repeat(20));
  /* eslint-enable */

  const slackColors = { create: "danger", dismiss: "warning", resolve: "good" };
  const slackVerbs = {
    create: "found",
    dismiss: "dismissed",
    resolve: "fixed"
  };
  const slackMessage = {
    attachments: [
      {
        fallback: `A vulnerability in ${alert.affected_package_name} has been ${
          slackVerbs[action]
        } in ${repository.full_name}.`,
        color: slackColors[action],
        title: "GitHub Vulnerability Alert",
        title_link: `${repository.html_url}/network/alerts`,
        text: `A <${alert.external_reference}|vulnerability> with ${
          alert.affected_package_name
        } has been ${slackVerbs[action]} in <${repository.html_url}|${
          repository.full_name
        }>.`
      }
    ],
    username: "GitHub",
    icon_url: "https://ca.slack-edge.com/T35D8CZQR-UA6QSB1JB-946b161caa44-72"
  };

  if (process.env.SLACK_CHANNEL_ID) {
    slackMessage.channel = process.env.SLACK_CHANNEL_ID;
  }

  const slackResponse = await axios.post(SLACK_WEBHOOK_URL, slackMessage);

  return callback(null, {
    statusCode: 200,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      input: event,
      slackMessage: slackMessage,
      slackResponse: {
        status: slackResponse.status,
        statusText: slackResponse.statusText
      }
    })
  });
};
