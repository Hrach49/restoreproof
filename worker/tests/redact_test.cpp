#include <rp/redact.hpp>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <catch2/generators/catch_generators_range.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <string>
#include <string_view>

using Catch::Matchers::ContainsSubstring;

namespace {

// One row of a decision table: what goes in, what must come out.
struct Row {
    std::string_view input;
    std::string_view expected;
};

// Checks one row of a table through rp::redact.
void check_row(const Row& row)
{
    CAPTURE(row.input);
    CHECK(rp::redact(row.input) == row.expected);
}

} // namespace

// Failure paths first: text that must NOT change. Over-redaction is tolerated
// by design, but these are the cases where it would hide useful information
// or where a naive match (a name used as a value, a longer name) would fire.
TEST_CASE("redact leaves text without secrets unchanged", "[redact]")
{
    const std::string_view text = GENERATE(values<std::string_view>({
        "",
        "hello world",
        "GET /v8/Organizations HTTP/1.1\r\nHost: veeam.example.invalid\r\n\r\n",
        "Content-Type: application/json",
        // A name used as a value, not as a key.
        "grant_type=password",
        "grant_type=password&username=bob",
        "grant_type=refresh_token",
        R"({"grant_type":"password"})",
        R"({"grant_type": "refresh_token", "scope": "x"})",
        R"(["password", "client_secret"])",
        "username=bob",
        "passwords are hashed",
        "the password is not logged",
        // Not the header name exactly: another header that contains it.
        "X-Authorization-Hint: x",
        "X-Authorization: x",
        "Authorizations: x",
        "Authorization-Hint: x",
        // Keys that don't END in a name, or that run into it without a
        // separator.
        "password_hint=x",
        "passwords=x",
        "xpassword=x",
        "mypassword=x",
        "password2=x",
        R"({"password_hint":"x"})",
        R"({"passwords":"x"})",
        R"({"xpassword":"x"})",
        R"({"authorization_url":"https://login.example.invalid"})",
        // Empty values: nothing to hide.
        "password=",
        "password=&username=bob",
        "https://h/cb?client_secret=#frag",
        "Authorization:",
        "Authorization:   ",
        "Authorization:\r\nHost: a",
        R"({"password":)",
        R"({"password": )",
        R"({"password":,"a":1})",
        // Graph error codes stay readable: "code" is not a secret name, even
        // though an OAuth authorization code travels as code=.
        R"({"error":{"code":"ErrorItemNotFound","message":"The specified object was not found in the store."}})",
        // Names that start with a token name but go on.
        "signature=x",
        "sigma=1",
        R"({"signature":"x"})",
        "design=x",
        "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "id_tokens=x",
        "tempauthority=x",
        // The colon form needs a value.
        "password:",
        "password:   \nnext",
        "password_hint: x",
        // '@' outside a URL's userinfo.
        "https://host/a@b",
        "https://host/path?mail=a@b.c",
        "https://host#a@b",
        "https://host",
        "https://@host/x",
        "mailto:a@b.c",
        "see https://host and bob@example.com",
        R"({"url":"https://host/x","owner":"bob@example.com"})",
        // Non-ASCII UTF-8 (Cyrillic "password: test").
        "\xD0\x9F\xD0\xB0\xD1\x80\xD0\xBE\xD0\xBB\xD1\x8C: \xD1\x82\xD0\xB5\xD1\x81\xD1\x82",
    }));
    CAPTURE(text);
    CHECK(rp::redact(text) == text);
}

TEST_CASE("redact keeps text with embedded NULs and high bytes byte for byte", "[redact]")
{
    const std::string text("a\0b\xFF\x80 password_hint=\0x", 22);
    REQUIRE(text.size() == 22);
    CHECK(rp::redact(text) == text);
}

TEST_CASE("redact replaces the whole Authorization header value, any scheme", "[redact]")
{
    check_row(GENERATE(values<Row>({
        {"Authorization: Bearer abc.def", "Authorization: [REDACTED]"},
        {"authorization:Basic dXNlcjpwYXNz", "authorization:[REDACTED]"},
        {"AUTHORIZATION: Bearer x\r\nHost: a", "AUTHORIZATION: [REDACTED]\r\nHost: a"},
        {"Authorization: NTLM TlRMTVNTUAAB", "Authorization: [REDACTED]"},
        {"Authorization :\t Bearer a b c", "Authorization :\t [REDACTED]"},
        {"Authorization: Bearer x \nAccept: */*", "Authorization: [REDACTED]\nAccept: */*"},
        {"GET / HTTP/1.1\r\nAuthorization: Bearer a.b.c\r\nHost: h\r\n\r\n",
         "GET / HTTP/1.1\r\nAuthorization: [REDACTED]\r\nHost: h\r\n\r\n"},
        // A value with non-ASCII bytes and an '&' goes whole.
        {"Authorization: Basic \xD0\xBF&x\nnext", "Authorization: [REDACTED]\nnext"},
        // Up to the end of the line, even when more follows on it: a header
        // map logged on one line loses its later entries (fail safe).
        {"headers: {Authorization: Bearer x, Accept: y}\nnext",
         "headers: {Authorization: [REDACTED]\nnext"},
    })));
}

TEST_CASE("redact replaces the whole Proxy-Authorization header value", "[redact]")
{
    check_row(GENERATE(values<Row>({
        {"Proxy-Authorization: Basic dXNlcjpwYXNz", "Proxy-Authorization: [REDACTED]"},
        {"proxy-authorization:Negotiate abc\r\nHost: a",
         "proxy-authorization:[REDACTED]\r\nHost: a"},
        {"PROXY-AUTHORIZATION : x", "PROXY-AUTHORIZATION : [REDACTED]"},
    })));
}

TEST_CASE("redact replaces every secret header in a text", "[redact]")
{
    check_row(GENERATE(values<Row>({
        {"Authorization: a\nProxy-Authorization: b\nAuthorization: c\n",
         "Authorization: [REDACTED]\nProxy-Authorization: [REDACTED]\nAuthorization: [REDACTED]\n"},
    })));
}

TEST_CASE("redact replaces secret values in URL query strings", "[redact]")
{
    check_row(GENERATE(values<Row>({
        // First parameter after '?'.
        {"https://h/token?client_secret=s3cr3t", "https://h/token?client_secret=[REDACTED]"},
        {"https://h/token?password=p&a=1", "https://h/token?password=[REDACTED]&a=1"},
        // Middle.
        {"/x?a=1&refresh_token=r.r-r_r&b=2", "/x?a=1&refresh_token=[REDACTED]&b=2"},
        // Last.
        {"/x?a=1&access_token=eyJ0eXAi.eyJhdWQi.sig", "/x?a=1&access_token=[REDACTED]"},
        // After '#' (implicit flow), and a value ending at '#'.
        {"https://h/cb#access_token=tok&token_type=Bearer",
         "https://h/cb#access_token=[REDACTED]&token_type=Bearer"},
        {"/x?password=p#frag", "/x?password=[REDACTED]#frag"},
        // Inside a log line: the value ends at whitespace, '"' or ','.
        {"GET /x?client_secret=abc HTTP/1.1", "GET /x?client_secret=[REDACTED] HTTP/1.1"},
        {R"(url="/x?password=abc", status=200)", R"(url="/x?password=[REDACTED]", status=200)"},
        {"url=/x?password=abc,next", "url=/x?password=[REDACTED],next"},
    })));
}

TEST_CASE("redact replaces secret values in form-encoded bodies", "[redact]")
{
    check_row(GENERATE(values<Row>({
        {"grant_type=password&username=bob&password=hunter2&client_id=c&client_secret=s",
         "grant_type=password&username=bob&password=[REDACTED]&client_id=c&client_secret=[REDACTED]"},
        {"grant_type=refresh_token&refresh_token=0.AAA-bbb_ccc&client_secret=s",
         "grant_type=refresh_token&refresh_token=[REDACTED]&client_secret=[REDACTED]"},
        // '&' in a value is %26 in a form body, so the value goes whole.
        {"password=a%26b&x=1", "password=[REDACTED]&x=1"},
        {"password=a%20b%3Dc", "password=[REDACTED]"},
        {"password=a+b", "password=[REDACTED]"},
        // Non-ASCII.
        {"password=\xD0\xBF\xD0\xB0\xD1\x80&x=1", "password=[REDACTED]&x=1"},
        // Backslashes: in a single-quoted value, and in an unquoted one.
        {"password='a\\b'&x=1", "password='[REDACTED]'&x=1"},
        {"password=a\\b&x=1", "password=[REDACTED]&x=1"},
        // Spaces around '=' (a hand-written log line).
        {"password = hunter2", "password = [REDACTED]"},
        {"password=\thunter2 next", "password=\t[REDACTED] next"},
    })));
}

TEST_CASE("redact matches key names in any case", "[redact]")
{
    check_row(GENERATE(values<Row>({
        {"Client_Secret=x", "Client_Secret=[REDACTED]"},
        {"PassWord=y&a=1", "PassWord=[REDACTED]&a=1"},
        {"ACCESS_TOKEN=z", "ACCESS_TOKEN=[REDACTED]"},
        {"Refresh_Token=z", "Refresh_Token=[REDACTED]"},
        {R"({"PassWord":"x"})", R"({"PassWord":"[REDACTED]"})"},
        {R"({"AUTHORIZATION":"Bearer x"})", R"({"AUTHORIZATION":"[REDACTED]"})"},
        {R"({"Client_SECRET":"x"})", R"({"Client_SECRET":"[REDACTED]"})"},
    })));
}

// A key that ends in a name after a separator ('_', '-', '.' or any other
// non-alphanumeric byte) is treated as that name: "new_password" is as secret
// as "password".
TEST_CASE("redact treats a key ending in a secret name as secret", "[redact]")
{
    check_row(GENERATE(values<Row>({
        {"new_password=x&a=1", "new_password=[REDACTED]&a=1"},
        {"old-password=x", "old-password=[REDACTED]"},
        {"db.password=x", "db.password=[REDACTED]"},
        {"app_client_secret=x", "app_client_secret=[REDACTED]"},
        {"ms_refresh_token=x", "ms_refresh_token=[REDACTED]"},
        {R"({"new_password":"x"})", R"({"new_password":"[REDACTED]"})"},
        {R"({"veeam.password":"x"})", R"({"veeam.password":"[REDACTED]"})"},
        {R"({"Proxy-Authorization":"Basic x"})", R"({"Proxy-Authorization":"[REDACTED]"})"},
        {R"({"id_access_token":1})", R"({"id_access_token":"[REDACTED]"})"},
    })));
}

TEST_CASE("redact replaces secret string values in JSON at any nesting", "[redact]")
{
    check_row(GENERATE(values<Row>({
        // Top level, each of the five names.
        {R"({"password":"hunter2"})", R"({"password":"[REDACTED]"})"},
        {R"({"client_secret":"s","client_id":"c"})", R"({"client_secret":"[REDACTED]","client_id":"c"})"},
        {R"({"refresh_token":"r"})", R"({"refresh_token":"[REDACTED]"})"},
        {R"({"token_type":"Bearer","access_token":"eyJ.eyJ.sig","expires_in":3599})",
         R"({"token_type":"Bearer","access_token":"[REDACTED]","expires_in":3599})"},
        {R"({"authorization":"Bearer x"})", R"({"authorization":"[REDACTED]"})"},
        // Nested object.
        {R"({"user":{"name":"bob","password":"p"},"ok":true})",
         R"({"user":{"name":"bob","password":"[REDACTED]"},"ok":true})"},
        {R"({"headers":{"Authorization":"Bearer x","Accept":"*/*"}})",
         R"({"headers":{"Authorization":"[REDACTED]","Accept":"*/*"}})"},
        // Inside an array of objects.
        {R"({"items":[{"refresh_token":"a"},{"refresh_token":"b"}]})",
         R"({"items":[{"refresh_token":"[REDACTED]"},{"refresh_token":"[REDACTED]"}]})"},
        // Deeply nested.
        {R"({"a":{"b":[{"c":{"d":[[{"client_secret":"s"}]]}}]}})",
         R"({"a":{"b":[{"c":{"d":[[{"client_secret":"[REDACTED]"}]]}}]}})"},
    })));
}

TEST_CASE("redact consumes JSON string values exactly, escapes included", "[redact]")
{
    check_row(GENERATE(values<Row>({
        // An escaped quote doesn't end the value.
        {R"({"access_token":"a\"b","x":1})", R"({"access_token":"[REDACTED]","x":1})"},
        // An escaped backslash before the closing quote does end it.
        {R"({"password":"a\\","x":1})", R"({"password":"[REDACTED]","x":1})"},
        {R"({"password":"a\\\"b\\","x":1})", R"({"password":"[REDACTED]","x":1})"},
        {R"({"password":"A\n\t","x":1})", R"({"password":"[REDACTED]","x":1})"},
        // Characters that end a key=value value don't end a JSON string.
        {R"({"password":"a&b c,d#e}f]g","x":1})", R"({"password":"[REDACTED]","x":1})"},
        // Non-ASCII.
        {"{\"password\":\"\xD0\xBF\xD0\xB0\xD1\x80\xD0\xBE\xD0\xBB\xD1\x8C\",\"x\":1}",
         R"({"password":"[REDACTED]","x":1})"},
        {R"({"password":"","x":1})", R"({"password":"[REDACTED]","x":1})"},
    })));
}

TEST_CASE("redact allows whitespace around the JSON colon", "[redact]")
{
    check_row(GENERATE(values<Row>({
        {R"({"client_secret" : "x"})", R"({"client_secret" : "[REDACTED]"})"},
        {R"({"password":   "x"})", R"({"password":   "[REDACTED]"})"},
        {"{\n  \"password\"\n    :\n\t\"x\"\n}", "{\n  \"password\"\n    :\n\t\"[REDACTED]\"\n}"},
        {"{\r\n  \"password\": 5\r\n}", "{\r\n  \"password\": \"[REDACTED]\"\r\n}"},
    })));
}

// Any JSON value type becomes the string "[REDACTED]": a number, a literal or
// a whole object or array can hold a secret as well as a string can.
TEST_CASE("redact replaces non-string JSON values with a redacted string", "[redact]")
{
    check_row(GENERATE(values<Row>({
        {R"({"password":1234,"x":1})", R"({"password":"[REDACTED]","x":1})"},
        {R"({"password":-1.5e3})", R"({"password":"[REDACTED]"})"},
        {R"({"password":null,"x":1})", R"({"password":"[REDACTED]","x":1})"},
        {R"({"password":true})", R"({"password":"[REDACTED]"})"},
        {R"({"password":1234 ,"x":1})", R"({"password":"[REDACTED]" ,"x":1})"},
        {R"({"password":{"a":"}","b":{"c":[1]}},"x":1})", R"({"password":"[REDACTED]","x":1})"},
        {R"({"password":[1,"]",[2],{"a":"["}],"x":1})", R"({"password":"[REDACTED]","x":1})"},
        {R"({"authorization":{"scheme":"Bearer","token":"t"}})", R"({"authorization":"[REDACTED]"})"},
        {R"([{"password":7},{"password":[]}])", R"([{"password":"[REDACTED]"},{"password":"[REDACTED]"}])"},
    })));
}

TEST_CASE("redact replaces every occurrence and every kind of secret in one text", "[redact]")
{
    check_row(GENERATE(values<Row>({
        {"password=a&password=b", "password=[REDACTED]&password=[REDACTED]"},
        {R"({"password":"a","nested":{"password":"b"}})",
         R"({"password":"[REDACTED]","nested":{"password":"[REDACTED]"}})"},
        {"POST /token HTTP/1.1\r\nAuthorization: Basic x\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n"
         "grant_type=password&password=p&client_secret=s",
         "POST /token HTTP/1.1\r\nAuthorization: [REDACTED]\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n"
         "grant_type=password&password=[REDACTED]&client_secret=[REDACTED]"},
        {"request /x?access_token=t body {\"refresh_token\":\"r\",\"client_secret\":7}",
         "request /x?access_token=[REDACTED] body {\"refresh_token\":\"[REDACTED]\",\"client_secret\":\"[REDACTED]\"}"},
        // A key=value inside a JSON string is still a key=value.
        {R"({"url":"https://h/?password=abc&a=1"})", R"({"url":"https://h/?password=[REDACTED]&a=1"})"},
    })));
}

// A JSON body logged as a JSON string (a request body inside a log record):
// its quotes are escaped. The value's end is hard to find reliably at that
// level, so everything up to the end of the enclosing string goes.
TEST_CASE("redact redacts to the end of the enclosing string for escaped JSON", "[redact]")
{
    check_row(GENERATE(values<Row>({
        {R"({"body":"{\"password\":\"abc\",\"user\":\"bob\"}","status":200})",
         R"({"body":"{\"password\":\"[REDACTED]\"","status":200})"},
        {R"({"body":"{\"client_secret\" : 5}"})", R"({"body":"{\"client_secret\" : \"[REDACTED]\""})"},
        {R"({"body":"{\"password\":\"a\\\"b\"}"})", R"({"body":"{\"password\":\"[REDACTED]\""})"},
        // Escaped twice: a logged record inside another logged string.
        {R"({"log":"{\"body\":\"{\\\"password\\\":\\\"abc\\\"}\"}","x":1})",
         R"({"log":"{\"body\":\"{\\\"password\\\":\"[REDACTED]\"","x":1})"},
        // Unterminated: to the end.
        {R"({"body":"{\"password\":\"abc)", R"({"body":"{\"password\":\"[REDACTED]\")"},
    })));
}

// An even run of backslashes before a quote is escaped backslashes, not an
// escaped quote: the quote is real. Treating it as escaped (while the closing
// quote search pairs the backslashes) left the secret after it in the output.
TEST_CASE("redact reads an even run of backslashes before a quote as a real quote", "[redact]")
{
    check_row(GENERATE(values<Row>({
        {R"({\\"password\\":\\"SECRET1\\"})", R"({\\"password\\":"[REDACTED]"})"},
        {R"(password=\\"SECRET2")", R"(password="[REDACTED]")"},
        {R"(password: \\\\"SECRET3" x)", R"(password: "[REDACTED]" x)"},
    })));
}

TEST_CASE("redact hides a quoted secret behind any number of backslashes", "[redact]")
{
    // Every mix of 0-4 backslashes before the key's closing quote and before
    // each of the value's quotes. The secret holds a comma and a space, which
    // end an unquoted value, so a value cut short there shows up too.
    const int key_run = GENERATE(range(0, 5));
    const int value_run = GENERATE(range(0, 5));
    const std::string format = GENERATE(as<std::string>{}, "{K\"passwordK\":V\"SE,C RETV\"}",
                                         "{K\"passwordK\" : V\"SE,C RETV\", \"x\": 1}",
                                         "password=V\"SE,C RETV\" user=bob",
                                         "password: V\"SE,C RETV\" user=bob");
    std::string input;
    for (const char c : format) {
        if (c == 'K' || c == 'V') {
            input.append(static_cast<std::size_t>(c == 'K' ? key_run : value_run), '\\');
        } else {
            input += c;
        }
    }
    CAPTURE(input);
    const std::string out = rp::redact(input);
    CAPTURE(out);
    CHECK_THAT(out, ContainsSubstring("[REDACTED]"));
    for (const std::string_view part : {"SE", "RET"}) {
        CHECK(out.find(part) == std::string::npos);
    }
}

// A truncated body must not leak its tail: an unterminated value is redacted
// to the end of the text.
TEST_CASE("redact redacts an unterminated JSON value to the end of the text", "[redact]")
{
    check_row(GENERATE(values<Row>({
        {R"({"password":"abc)", R"({"password":"[REDACTED]")"},
        {R"({"password":"abc\)", R"({"password":"[REDACTED]")"},
        {R"({"password":"a\"b, \"x\": 1})", R"({"password":"[REDACTED]")"},
        {R"({"password":{"a":"b")", R"({"password":"[REDACTED]")"},
        {R"({"password":{"a":"}")", R"({"password":"[REDACTED]")"},
        {R"({"password":["a", [1])", R"({"password":"[REDACTED]")"},
        {R"({"password":12)", R"({"password":"[REDACTED]")"},
    })));
}

TEST_CASE("redact replaces a quoted value after = or : up to its matching quote", "[redact]")
{
    check_row(GENERATE(values<Row>({
        {R"(password="hunter2")", R"(password="[REDACTED]")"},
        {R"(password = "hunter 2" next)", R"(password = "[REDACTED]" next)"},
        {"client_secret='a b'&x=1", "client_secret='[REDACTED]'&x=1"},
        {R"(password="ab\"cd" user=bob)", R"(password="[REDACTED]" user=bob)"},
        {R"(client_secret='a\'b c' x)", R"(client_secret='[REDACTED]' x)"},
        {R"(password: "hunter 2", user: bob)", R"(password: "[REDACTED]", user: bob)"},
        {R"(password="")", R"(password="[REDACTED]")"},
        // Unterminated: to the end of the text.
        {R"(password="abc def)", R"(password="[REDACTED]")"},
        {"password='abc\ndef", "password='[REDACTED]'"},
        // A quoted value inside a JSON string: its quotes are escaped, so the
        // rest of the enclosing string goes.
        {R"({"cmd":"login password=\"a b\" now","x":1})", R"({"cmd":"login password=\"[REDACTED]\"","x":1})"},
    })));
}

TEST_CASE("redact replaces the value after a secret key name and a colon", "[redact]")
{
    check_row(GENERATE(values<Row>({
        {"password: hunter2", "password: [REDACTED]"},
        {"Password: hunter2\r\nnext", "Password: [REDACTED]\r\nnext"},
        {"client_secret: abc", "client_secret: [REDACTED]"},
        {"refresh_token:abc def", "refresh_token:[REDACTED]"},
        {"ACCESS_TOKEN :\tx", "ACCESS_TOKEN :\t[REDACTED]"},
        {"new_password: x\nnext", "new_password: [REDACTED]\nnext"},
        // To the end of the line, like a header.
        {"{password: hunter2, user: bob}\nnext", "{password: [REDACTED]\nnext"},
        {"password: a\rb\nnext", "password: [REDACTED]\nnext"},
    })));
}

// A scheme contains a space ("Bearer x"), so this value runs to the end of the
// line even in a query string.
TEST_CASE("redact replaces an authorization=value to the end of the line", "[redact]")
{
    check_row(GENERATE(values<Row>({
        {"Authorization=Bearer tok123", "Authorization=[REDACTED]"},
        {"authorization=Bearer tok123\nnext", "authorization=[REDACTED]\nnext"},
        {"/x?authorization=abc&a=1\nnext", "/x?authorization=[REDACTED]\nnext"},
        {R"(authorization="Bearer x" rest)", R"(authorization="[REDACTED]" rest)"},
        {"x_authorization=Bearer y", "x_authorization=[REDACTED]"},
    })));
}

TEST_CASE("redact replaces tokens that travel in URLs", "[redact]")
{
    check_row(GENERATE(values<Row>({
        // Graph's pre-authenticated downloadUrl.
        {"https://t.sharepoint.com/_layouts/15/download.aspx?UniqueId=1&tempauth=eyJ0eXAi.x.y&ApiVersion=2.0",
         "https://t.sharepoint.com/_layouts/15/download.aspx?UniqueId=1&tempauth=[REDACTED]&ApiVersion=2.0"},
        {R"({"@microsoft.graph.downloadUrl":"https://h/d.aspx?tempauth=eyJ&x=1"})",
         R"({"@microsoft.graph.downloadUrl":"https://h/d.aspx?tempauth=[REDACTED]&x=1"})"},
        // The Location of a /content 302 (W2.2), and HttpClient's debug line
        // for the GET that follows it.
        {"Location: https://t-my.sharepoint.com/personal/a_t_com/_layouts/15/download.aspx?UniqueId=x&Translate=false&tempauth=v1.eyJ0eXAi.eyJhdWQi.abc&ApiVersion=2.0",
         "Location: https://t-my.sharepoint.com/personal/a_t_com/_layouts/15/download.aspx?UniqueId=x&Translate=false&tempauth=[REDACTED]&ApiVersion=2.0"},
        {"GET https://t.sharepoint.com/sites/s/_layouts/15/download.aspx?tempauth=v1.abc attempt 1/5: HTTP 403 in 12 ms",
         "GET https://t.sharepoint.com/sites/s/_layouts/15/download.aspx?tempauth=[REDACTED] attempt 1/5: HTTP 403 in 12 ms"},
        // Azure SAS.
        {"https://a.blob.core.windows.net/c/b?sv=2021-08-06&sr=b&sig=abc%2Fdef%3D&se=2026",
         "https://a.blob.core.windows.net/c/b?sv=2021-08-06&sr=b&sig=[REDACTED]&se=2026"},
        // OAuth.
        {"client_assertion_type=urn:x&client_assertion=eyJ.eyJ.sig&scope=s",
         "client_assertion_type=urn:x&client_assertion=[REDACTED]&scope=s"},
        {"https://h/cb#id_token=eyJ&state=1", "https://h/cb#id_token=[REDACTED]&state=1"},
        // Any case, and the suffix rule.
        {"TempAuth=x&SIG=y", "TempAuth=[REDACTED]&SIG=[REDACTED]"},
        {"x_sig=abc", "x_sig=[REDACTED]"},
        // As JSON keys.
        {R"({"id_token":"eyJ","sig":1,"client_assertion":"a","tempauth":"t","my_id_token":"m"})",
         R"({"id_token":"[REDACTED]","sig":"[REDACTED]","client_assertion":"[REDACTED]","tempauth":"[REDACTED]","my_id_token":"[REDACTED]"})"},
    })));
}

TEST_CASE("redact replaces the userinfo of a URL", "[redact]")
{
    check_row(GENERATE(values<Row>({
        {"https://admin:hunter2@host/path", "https://[REDACTED]@host/path"},
        {"http://u:p@h", "http://[REDACTED]@h"},
        {"ftp://user@host?x=1", "ftp://[REDACTED]@host?x=1"},
        {"https://h#x", "https://h#x"},
        // An unencoded '@' in the password: up to the last '@' of the authority.
        {"https://u:p@ss@h/x@y", "https://[REDACTED]@h/x@y"},
        {"https://a:b@h1 and https://c:d@h2/", "https://[REDACTED]@h1 and https://[REDACTED]@h2/"},
        {R"({"url":"https://u:p%40x@h/"})", R"({"url":"https://[REDACTED]@h/"})"},
    })));
}

// A bare '\r' can't end a header on the wire, so it doesn't end the value.
TEST_CASE("redact ends a header value only at CRLF, LF or the end", "[redact]")
{
    check_row(GENERATE(values<Row>({
        {"Authorization: Bearer a\rb\r\nHost: h", "Authorization: [REDACTED]\r\nHost: h"},
        {"Authorization: Bearer a\rb", "Authorization: [REDACTED]"},
        {"Authorization: x\r", "Authorization: [REDACTED]"},
    })));
}

TEST_CASE("redact finds a secret in deeply nested JSON", "[redact]")
{
    constexpr int kDepth = 500;
    std::string input;
    std::string expected;
    for (int i = 0; i < kDepth; ++i) {
        input += R"({"a":[)";
    }
    expected = input;
    input += R"({"password":"deep-secret"})";
    expected += R"({"password":"[REDACTED]"})";
    for (int i = 0; i < kDepth; ++i) {
        input += "]}";
        expected += "]}";
    }
    CHECK(rp::redact(input) == expected);
}

TEST_CASE("redact handles a megabyte of input in one pass", "[redact]")
{
    constexpr std::size_t kSize = 1024 * 1024;

    SECTION("with nothing to redact")
    {
        std::string input(kSize, 'a');
        for (std::size_t i = 0; i < kSize; i += 13) {
            input[i] = "\"{[:= \\"[i % 7];
        }
        CHECK(rp::redact(input) == input);
    }
    SECTION("with a secret every few bytes")
    {
        std::string input;
        while (input.size() < kSize) {
            input += R"({"password":"s3cret"},password=s3cret&https://u:s3cret@h/ Authorization: s3cret)"
                     "\n";
        }
        const std::string output = rp::redact(input);
        CHECK_THAT(output, !ContainsSubstring("s3cret"));
        CHECK_THAT(output, ContainsSubstring(R"({"password":"[REDACTED]"},password=[REDACTED]&)"));
    }
    SECTION("with names that almost match")
    {
        std::string input;
        while (input.size() < kSize) {
            input += "password passwords \"password\" grant_type=password authorization signature "
                     "https://host/a@b ";
        }
        CHECK(rp::redact(input) == input);
    }
    SECTION("with an unterminated value at the start")
    {
        std::string input = R"({"password":)" + std::string(kSize, '[');
        CHECK(rp::redact(input) == R"({"password":"[REDACTED]")");
    }
}

TEST_CASE("is_secret_header names Authorization and Proxy-Authorization in any case", "[redact]")
{
    const auto [name, secret] = GENERATE(table<std::string_view, bool>({
        {"Authorization", true},
        {"authorization", true},
        {"AUTHORIZATION", true},
        {"aUtHoRiZaTiOn", true},
        {"Proxy-Authorization", true},
        {"proxy-authorization", true},
        {"PROXY-AUTHORIZATION", true},
        {"", false},
        {"Content-Type", false},
        {"X-Authorization", false},
        {"Authorizations", false},
        {"Authorizatio", false},
        {"Proxy-Authenticate", false},
        {"WWW-Authenticate", false},
        {"Authorization ", false},
        {"Cookie", false},
    }));
    CAPTURE(name);
    CHECK(rp::is_secret_header(name) == secret);
}

// W2.1: Graph access tokens and client assertions are JWTs; one can turn up
// in a log line without a key in front of it (a URL, a copied header, an
// error message). Failure paths first: text that looks a little like one.
TEST_CASE("redact leaves text that only resembles a JWT or a bearer token unchanged",
          "[redact][jwt]")
{
    const std::string_view text = GENERATE(values<std::string_view>({
        // Not starting with eyJ, or eyJ run into a preceding token character.
        "abc.def.ghi",
        "xeyJhbGciOiJQUzI1NiJ9.e30.sig",
        "_eyJhbGciOiJQUzI1NiJ9.e30.sig",
        "-eyJhbGciOiJQUzI1NiJ9.e30.sig",
        // Case matters: base64 of '{"' is eyJ.
        "EYJhbGciOiJQUzI1NiJ9.e30.sig",
        // Only one part, or nothing after the first dot.
        "eyJhbGciOiJQUzI1NiJ9",
        "eyJhbGciOiJQUzI1NiJ9.",
        "eyJhbGciOiJQUzI1NiJ9. next",
        "eyJ",
        // A bearer scheme without a token, or with auth-params (WWW-Authenticate).
        "Bearer",
        "Bearer ",
        R"({"token_type":"Bearer","expires_in":3599})",
        R"(WWW-Authenticate: Bearer realm="", authorization_uri="https://login.microsoftonline.com/common/oauth2/authorize", client_id="00000003-0000-0000-c000-000000000000")",
        R"(Bearer error="insufficient_claims", claims="e30=")",
        "Bearer error=invalid_token",
        // The known auth-param names only, in any case.
        R"(Bearer Realm="x")",
        R"(Bearer scope="Mail.Read")",
        R"(Bearer resource_metadata="https://h/x")",
        // "bearer" run into a word.
        "nobearer abc",
        "Bearers abc",
        // Names that start with pfx but go on, or end in it without a separator.
        "pfxfile=x",
        "mypfx=x",
        "RP_GRAPH_CERT_PFX_BASE64 is not set",
        "the pfx does not open",
    }));
    CAPTURE(text);
    CHECK(rp::redact(text) == text);
}

TEST_CASE("redact replaces a raw JWT, signed or unsigned, wherever it stands", "[redact][jwt]")
{
    check_row(GENERATE(values<Row>({
        // Signed (three parts).
        {"eyJhbGciOiJQUzI1NiJ9.eyJhdWQiOiJ4In0.c2lnbmF0dXJl", "[REDACTED]"},
        {"token eyJhbGciOiJQUzI1NiJ9.eyJhdWQiOiJ4In0.c2ln-_x end",
         "token [REDACTED] end"},
        // Unsigned: an empty third part, or only two parts.
        {"eyJhbGciOiJub25lIn0.e30.", "[REDACTED]"},
        {"eyJhbGciOiJub25lIn0.e30. next", "[REDACTED] next"},
        {"eyJhbGciOiJub25lIn0.e30", "[REDACTED]"},
        // Five parts (JWE): every part goes.
        {"eyJhbGciOiJSU0EifQ.a.b.c.d rest", "[REDACTED] rest"},
        // In a URL without a secret key name, in quotes, after punctuation.
        {"https://h/cb?token=eyJhbGciOiJQUzI1NiJ9.e30.sig&state=1",
         "https://h/cb?token=[REDACTED]&state=1"},
        {R"({"assertion_hint":"eyJhbGciOiJQUzI1NiJ9.e30.sig"})",
         R"({"assertion_hint":"[REDACTED]"})"},
        {"(eyJhbGciOiJQUzI1NiJ9.e30.sig)", "([REDACTED])"},
        {"a.eyJhbGciOiJQUzI1NiJ9.e30.sig", "a.[REDACTED]"},
        // Two in one text.
        {"eyJa.eyJb.c and eyJd.e", "[REDACTED] and [REDACTED]"},
    })));
}

TEST_CASE("redact replaces the token after a Bearer scheme", "[redact][jwt]")
{
    check_row(GENERATE(values<Row>({
        {"Bearer abc123", "Bearer [REDACTED]"},
        {"bearer abc123 next", "bearer [REDACTED] next"},
        {"BEARER   a-b.c_d~e+f/g==", "BEARER   [REDACTED]"},
        {"Bearer\tabc", "Bearer\t[REDACTED]"},
        {"sent Bearer abc, then", "sent Bearer [REDACTED], then"},
        {"Bearer abc==", "Bearer [REDACTED]"},
        {R"("Bearer abc")", R"("Bearer [REDACTED]")"},
        {"Bearer eyJhbGciOiJQUzI1NiJ9.e30.sig", "Bearer [REDACTED]"},
        // Padding, or a character no auth-param name holds, then a quote:
        // a token, not `name="value"`.
        {R"({"hdr":"Bearer dGVzdHRva2Vu=="})", R"({"hdr":"Bearer [REDACTED]"})"},
        {R"(sent "Bearer abcd==" ok)", R"(sent "Bearer [REDACTED]" ok)"},
        {R"("Bearer ab/c=")", R"("Bearer [REDACTED]")"},
        {R"("Bearer a+b.c=")", R"("Bearer [REDACTED]")"},
        {"Bearer abc==def", "Bearer [REDACTED]"},
        // A token of characters outside token68 still goes up to whitespace or
        // a quote: over-redacting is preferred to leaking.
        {"Bearer abc!def ok", "Bearer [REDACTED] ok"},
        // A name followed by one '=' is an auth-param only if it is a known
        // one: an opaque token padded with one '=' goes, before a quote too.
        {R"({"auth":"Bearer dGVzdHM="})", R"({"auth":"Bearer [REDACTED]"})"},
        {R"(sent "Bearer q83vEjRWeJCrze8SNFZ4kKvN7xI0VniQq83vEjRWeJA=" to x)",
         R"(sent "Bearer [REDACTED]" to x)"},
        {"Bearer token=abc", "Bearer [REDACTED]"},
        {"Bearer dGVzdHM=abc", "Bearer [REDACTED]"},
        // A secret key name inside the token whose value stays inside it: the
        // whole token goes.
        {"Bearer abc.sig=def", "Bearer [REDACTED]"},
        {"Bearer password=hunter2", "Bearer [REDACTED]"},
    })));
}

// Review of W2.1: the Bearer and JWT rules ran before the key rules, took a
// following secret key's name as (part of) the token, and left its value in
// the clear, where main's key rules had hidden it. A key whose value reaches
// past the token is the key rules' to redact.
TEST_CASE("redact leaves a secret key after Bearer or a JWT to the key rules", "[redact][jwt]")
{
    check_row(GENERATE(values<Row>({
        {"Bearer password = hunter2", "Bearer password = [REDACTED]"},
        {"token_type: Bearer refresh_token: 0.AXYZsecretvalue",
         "token_type: Bearer refresh_token: [REDACTED]"},
        {"x Bearer client_secret: s3cr3t", "x Bearer client_secret: [REDACTED]"},
        {"Bearer access_token: tok123 more", "Bearer access_token: [REDACTED]"},
        {"Bearer Authorization: Basic dXNlcjpwYXNz", "Bearer Authorization: [REDACTED]"},
        // What comes before the key in the token still goes.
        {"Bearer tok.password = hunter2", "Bearer [REDACTED]password = [REDACTED]"},
        // A JWT ends before the part the key starts in.
        {"eyJabc.def.password=hunter2", "[REDACTED].password=[REDACTED]"},
        {"eyJabc.def.x_password: s3cr3t", "[REDACTED].x_password: [REDACTED]"},
        // Fewer than two parts left: no JWT, the key rule still hides the value.
        {"eyJabc.password=hunter2", "eyJabc.password=[REDACTED]"},
        // A key inside a JWT part whose value stays inside the JWT: all of it goes.
        {"eyJabc.def.sig", "[REDACTED]"},
    })));
}

TEST_CASE("redact treats pfx and pfx_base64 as secret key names", "[redact][jwt]")
{
    check_row(GENERATE(values<Row>({
        {"pfx=MIIKsecret&a=1", "pfx=[REDACTED]&a=1"},
        {"cert_pfx=MIIK", "cert_pfx=[REDACTED]"},
        {"RP_GRAPH_CERT_PFX_BASE64=MIIKsecret", "RP_GRAPH_CERT_PFX_BASE64=[REDACTED]"},
        {R"({"pfx":"MIIK"})", R"({"pfx":"[REDACTED]"})"},
        {R"({"graph_cert_pfx_base64":"MIIK"})", R"({"graph_cert_pfx_base64":"[REDACTED]"})"},
        {"pfx_base64: MIIK", "pfx_base64: [REDACTED]"},
    })));
}

// W2.5: a restore body carries Veeam's organisation app certificate as a
// Base64 PFX and its one-time password (docs/decisions.md 2026-09-30).
// "applicationCertificatePassword" doesn't end in "password" after a
// separator, so it needs a name of its own.
TEST_CASE("redact treats applicationCertificate and its password as secret key names",
          "[redact]")
{
    check_row(GENERATE(values<Row>({
        {R"({"applicationCertificate":"MIIKsecret","applicationId":"1fd2"})",
         R"({"applicationCertificate":"[REDACTED]","applicationId":"1fd2"})"},
        {R"({"applicationCertificatePassword":"pw+/=","officeRegion":"Worldwide"})",
         R"({"applicationCertificatePassword":"[REDACTED]","officeRegion":"Worldwide"})"},
        {R"({ "ApplicationCertificate" : "MIIK" , "applicationcertificatepassword": "pw" })",
         R"({ "ApplicationCertificate" : "[REDACTED]" , "applicationcertificatepassword": "[REDACTED]" })"},
        {"applicationCertificate=MIIKsecret&a=1", "applicationCertificate=[REDACTED]&a=1"},
        {"applicationCertificatePassword=pw&a=1", "applicationCertificatePassword=[REDACTED]&a=1"},
        {"applicationCertificatePassword: pw", "applicationCertificatePassword: [REDACTED]"},
        // Escaped inside a logged JSON string.
        {R"("{\"applicationCertificate\":\"MIIK\"}")", R"("{\"applicationCertificate\":\"[REDACTED]\"")"},
        // The thumbprint and the app ID stay readable.
        {R"({"applicationCertificateThumbprint":"AC3220B5"})",
         R"({"applicationCertificateThumbprint":"AC3220B5"})"},
        {R"({"applicationId":"1fd2609d"})", R"({"applicationId":"1fd2609d"})"},
    })));
}

TEST_CASE("the JWT start and base64url alphabet are the ones the recorder shares", "[redact]")
{
    STATIC_REQUIRE(rp::kJwtStart == "eyJ");
    for (const char c : std::string_view{"azAZ09-_"}) {
        CHECK(rp::is_base64url(c));
    }
    for (const char c : std::string_view{".=+/ \"%"}) {
        CHECK_FALSE(rp::is_base64url(c));
    }
}
