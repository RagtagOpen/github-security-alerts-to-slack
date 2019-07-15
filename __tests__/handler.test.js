require("dotenv").config();
const klaxon = require("../handler").klaxon;
const signString = require("../handler").signString;

describe("signString tests", () => {
  it("should raise an error when a bad algorithm is passed", () => {
    expect(() => {
      signString(process.env.GITHUB_VERIFICATION_TOKEN, "{}", "foo");
    }).toThrow();
  });
});

describe("klaxon tests", () => {
  const OLD_ENV = process.env;

  beforeEach(() => {
    jest.resetModules();
    process.env = { ...OLD_ENV };
  });

  afterEach(() => {
    process.env = OLD_ENV;
  });

  it("should fail when GITHUB_VERIFICATION_TOKEN is not set", async () => {
    delete process.env.GITHUB_VERIFICATION_TOKEN;
    const callback = jest.fn();
    await klaxon(null, null, callback);
    expect(callback).toBeCalled();
    expect(callback).toBeCalledWith(null, {
      statusCode: 401,
      headers: { "Content-Type": "text/plain" },
      body: "GITHUB_VERIFICATION_TOKEN is a required environment variable"
    });
  });

  it("should fail when signature header missing", async () => {
    const callback = jest.fn();
    await klaxon({ headers: {}, body: "{}" }, null, callback);
    expect(callback).toBeCalled();
    expect(callback).toBeCalledWith(null, {
      statusCode: 422,
      headers: { "Content-Type": "text/plain" },
      body: "X-Hub-Signature header not found"
    });
  });

  it("should fail when event header missing", async () => {
    const callback = jest.fn();
    await klaxon(
      { headers: { "X-Hub-Signature": "testsignature" }, body: "{}" },
      null,
      callback
    );
    expect(callback).toBeCalled();
    expect(callback).toBeCalledWith(null, {
      statusCode: 422,
      headers: { "Content-Type": "text/plain" },
      body: "X-GitHub-Event header not found"
    });
  });

  it("should fail when signature is invalid", async () => {
    const callback = jest.fn();
    await klaxon(
      {
        headers: {
          "X-Hub-Signature": "sha1=testsignature",
          "X-GitHub-Event": "ping"
        },
        body: "{}"
      },
      null,
      callback
    );
    expect(callback).toBeCalled();
    expect(callback).toBeCalledWith(null, {
      statusCode: 401,
      headers: { "Content-Type": "text/plain" },
      body: "X-Hub-Signature header failed verification"
    });
  });

  it("should return pong for ping events", async () => {
    const body = JSON.stringify({});
    const signature = signString(
      process.env.GITHUB_VERIFICATION_TOKEN,
      body,
      "sha1"
    );
    const callback = jest.fn();
    await klaxon(
      {
        headers: {
          "X-Hub-Signature": signature,
          "X-GitHub-Event": "ping"
        },
        body: body
      },
      null,
      callback
    );
    expect(callback).toBeCalled();
    expect(callback).toBeCalledWith(null, {
      statusCode: 200,
      headers: { "Content-Type": "text/plain" },
      body: "pong"
    });
  });

  it("should fail when the event isn't ping or repository_vulnerability_alert", async () => {
    const body = JSON.stringify({});
    const signature = signString(
      process.env.GITHUB_VERIFICATION_TOKEN,
      body,
      "sha1"
    );
    const callback = jest.fn();
    await klaxon(
      {
        headers: {
          "X-Hub-Signature": signature,
          "X-GitHub-Event": "test"
        },
        body: body
      },
      null,
      callback
    );
    expect(callback).toBeCalled();
    expect(callback).toBeCalledWith(null, {
      statusCode: 418,
      headers: { "Content-Type": "text/plain" },
      body: "X-GitHub-Event test not supported"
    });
  });

  it("should fail when delivery header missing", async () => {
    const body = JSON.stringify({});
    const signature = signString(
      process.env.GITHUB_VERIFICATION_TOKEN,
      body,
      "sha1"
    );
    const callback = jest.fn();
    await klaxon(
      {
        headers: {
          "X-Hub-Signature": signature,
          "X-GitHub-Event": "repository_vulnerability_alert"
        },
        body: body
      },
      null,
      callback
    );
    expect(callback).toBeCalled();
    expect(callback).toBeCalledWith(null, {
      statusCode: 422,
      headers: { "Content-Type": "text/plain" },
      body: "X-GitHub-Delivery header not found"
    });
  });

  it("should send notification to slack for new vulnerabilities", async () => {
    const body = JSON.stringify({
      action: "create",
      alert: {
        id: 123456789,
        affected_package_name: "foobar",
        external_reference: "https://example.com/foobar",
        external_identifier: "CVE-2019-10744"
      },
      repository: {
        full_name: "test/TestProject",
        html_url: "https://example.com/test/TestProject"
      }
    });
    const signature = signString(
      process.env.GITHUB_VERIFICATION_TOKEN,
      body,
      "sha1"
    );
    const event = {
      headers: {
        "X-Hub-Signature": signature,
        "X-GitHub-Event": "repository_vulnerability_alert",
        "X-GitHub-Delivery": "123456789"
      },
      body: body
    };
    const callback = jest.fn();
    await klaxon(event, null, callback);
    expect(callback).toBeCalled();
    expect(callback).toBeCalledWith(null, {
      statusCode: 200,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        input: event,
        slackMessage: {
          attachments: [
            {
              fallback:
                "A vulnerability in foobar has been found in test/TestProject.",
              color: "danger",
              title: "GitHub Vulnerability Alert",
              title_link: "https://example.com/test/TestProject/network/alerts",
              text:
                "A <https://example.com/foobar|vulnerability> with foobar has been found in <https://example.com/test/TestProject|test/TestProject>."
            }
          ],
          username: "GitHub",
          icon_url:
            "https://ca.slack-edge.com/T35D8CZQR-UA6QSB1JB-946b161caa44-72"
        },
        slackResponse: {
          status: 200,
          statusText: "OK"
        }
      })
    });
  });

  it("should send notification to slack for dismissed vulnerabilities", async () => {
    const body = JSON.stringify({
      action: "dismiss",
      alert: {
        id: 123456789,
        affected_package_name: "foobar",
        external_reference: "https://example.com/foobar",
        external_identifier: "CVE-2019-10744"
      },
      repository: {
        full_name: "test/TestProject",
        html_url: "https://example.com/test/TestProject"
      }
    });
    const signature = signString(
      process.env.GITHUB_VERIFICATION_TOKEN,
      body,
      "sha1"
    );
    const event = {
      headers: {
        "X-Hub-Signature": signature,
        "X-GitHub-Event": "repository_vulnerability_alert",
        "X-GitHub-Delivery": "123456789"
      },
      body: body
    };
    const callback = jest.fn();
    await klaxon(event, null, callback);
    expect(callback).toBeCalled();
    expect(callback).toBeCalledWith(null, {
      statusCode: 200,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        input: event,
        slackMessage: {
          attachments: [
            {
              fallback:
                "A vulnerability in foobar has been dismissed in test/TestProject.",
              color: "warning",
              title: "GitHub Vulnerability Alert",
              title_link: "https://example.com/test/TestProject/network/alerts",
              text:
                "A <https://example.com/foobar|vulnerability> with foobar has been dismissed in <https://example.com/test/TestProject|test/TestProject>."
            }
          ],
          username: "GitHub",
          icon_url:
            "https://ca.slack-edge.com/T35D8CZQR-UA6QSB1JB-946b161caa44-72"
        },
        slackResponse: {
          status: 200,
          statusText: "OK"
        }
      })
    });
  });

  it("should send notification to slack for fixed vulnerabilities", async () => {
    const body = JSON.stringify({
      action: "resolve",
      alert: {
        id: 123456789,
        affected_package_name: "foobar",
        external_reference: "https://example.com/foobar",
        external_identifier: "CVE-2019-10744"
      },
      repository: {
        full_name: "test/TestProject",
        html_url: "https://example.com/test/TestProject"
      }
    });
    const signature = signString(
      process.env.GITHUB_VERIFICATION_TOKEN,
      body,
      "sha1"
    );
    const event = {
      headers: {
        "X-Hub-Signature": signature,
        "X-GitHub-Event": "repository_vulnerability_alert",
        "X-GitHub-Delivery": "123456789"
      },
      body: body
    };
    const callback = jest.fn();
    await klaxon(event, null, callback);
    expect(callback).toBeCalled();
    expect(callback).toBeCalledWith(null, {
      statusCode: 200,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        input: event,
        slackMessage: {
          attachments: [
            {
              fallback:
                "A vulnerability in foobar has been fixed in test/TestProject.",
              color: "good",
              title: "GitHub Vulnerability Alert",
              title_link: "https://example.com/test/TestProject/network/alerts",
              text:
                "A <https://example.com/foobar|vulnerability> with foobar has been fixed in <https://example.com/test/TestProject|test/TestProject>."
            }
          ],
          username: "GitHub",
          icon_url:
            "https://ca.slack-edge.com/T35D8CZQR-UA6QSB1JB-946b161caa44-72"
        },
        slackResponse: {
          status: 200,
          statusText: "OK"
        }
      })
    });
  });

  it("should send notification to slack in the SLACK_CHANNEL_ID channel", async () => {
    process.env.SLACK_CHANNEL_ID = "testchannel";
    const body = JSON.stringify({
      action: "resolve",
      alert: {
        id: 123456789,
        affected_package_name: "foobar",
        external_reference: "https://example.com/foobar",
        external_identifier: "CVE-2019-10744"
      },
      repository: {
        full_name: "test/TestProject",
        html_url: "https://example.com/test/TestProject"
      }
    });
    const signature = signString(
      process.env.GITHUB_VERIFICATION_TOKEN,
      body,
      "sha1"
    );
    const event = {
      headers: {
        "X-Hub-Signature": signature,
        "X-GitHub-Event": "repository_vulnerability_alert",
        "X-GitHub-Delivery": "123456789"
      },
      body: body
    };
    const callback = jest.fn();
    await klaxon(event, null, callback);
    expect(callback).toBeCalled();
    expect(callback).toBeCalledWith(null, {
      statusCode: 200,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        input: event,
        slackMessage: {
          attachments: [
            {
              fallback:
                "A vulnerability in foobar has been fixed in test/TestProject.",
              color: "good",
              title: "GitHub Vulnerability Alert",
              title_link: "https://example.com/test/TestProject/network/alerts",
              text:
                "A <https://example.com/foobar|vulnerability> with foobar has been fixed in <https://example.com/test/TestProject|test/TestProject>."
            }
          ],
          username: "GitHub",
          icon_url:
            "https://ca.slack-edge.com/T35D8CZQR-UA6QSB1JB-946b161caa44-72",
          channel: "testchannel"
        },
        slackResponse: {
          status: 200,
          statusText: "OK"
        }
      })
    });
    delete process.env.SLACK_CHANNEL_ID;
  });
});
