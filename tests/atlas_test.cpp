#include <cassert>
#include <deque>
#include <iostream>
#include "atlas/atlas.hpp"

struct Fake : atlas::Transport {
  std::deque<atlas::HttpResponse> replies;
  std::vector<std::string> urls, bodies, auths;
  atlas::HttpResponse send(const std::string&, const std::string& url, const std::vector<std::string>& h, const std::string& body) override {
    urls.push_back(url);
    bodies.push_back(body);
    for (auto& x : h) if (x.rfind("Authorization:", 0) == 0) auths.push_back(x);
    auto r = replies.front();
    replies.pop_front();
    return r;
  }
};

static atlas::Client make(Fake& f, int* slept) {
  atlas::Client::Options o;
  o.issuer = "https://auth.example.com/";
  o.client_id = "client_game";
  o.transport = &f;
  o.sleep = [slept](std::chrono::seconds s) { *slept += static_cast<int>(s.count()); };
  return atlas::Client(o);
}

int main() {
  {  // device flow: pending, slow_down (+5s), then tokens
    Fake f;
    int slept = 0;
    auto c = make(f, &slept);
    f.replies = {{200, R"({"device_code":"dc","user_code":"WDJB-MJHT","verification_uri":"https://x/d","expires_in":600,"interval":5})"},
                 {400, R"({"error":"authorization_pending"})"},
                 {400, R"({"error":"slow_down"})"},
                 {200, R"({"access_token":"at","refresh_token":"rt","expires_in":3600,"scope":"openid"})"}};
    auto code = c.start_device_flow();
    assert(code.user_code == "WDJB-MJHT" && code.interval == 5);
    assert(f.urls[0] == "https://auth.example.com/oauth2/device_authorization");
    auto t = c.poll_device_flow(code);
    assert(t.access_token == "at" && t.refresh_token == "rt" && t.expires_in == 3600);
    assert(slept == 5 + 5 + 10);
    assert(f.bodies[1].find("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code") == 0);
  }
  {  // denial
    Fake f;
    int slept = 0;
    auto c = make(f, &slept);
    f.replies = {{400, R"({"error":"access_denied","error_description":"No."})"}};
    atlas::DeviceCode code;
    code.device_code = "dc";
    try { c.poll_device_flow(code); assert(false); } catch (const atlas::Error& e) { assert(e.code() == "access_denied" && e.status() == 400); }
  }
  {  // expiry
    Fake f;
    int slept = 0;
    auto c = make(f, &slept);
    for (int i = 0; i < 20; ++i) f.replies.push_back({400, R"({"error":"authorization_pending"})"});
    atlas::DeviceCode code;
    code.expires_in = 10;
    code.interval = 5;
    try { c.poll_device_flow(code); assert(false); } catch (const atlas::Error& e) { assert(e.code() == "expired_token"); }
  }
  {  // userinfo sends bearer; refresh; nested json skipped
    Fake f;
    int slept = 0;
    auto c = make(f, &slept);
    f.replies = {{200, R"({"sub":"user_1","org":{"a":["]","}"]},"email_verified":true})"},
                 {200, R"({"access_token":"new","expires_in":60})"}};
    auto u = c.userinfo("tok");
    assert(u["sub"] == "user_1" && u["email_verified"] == "true");
    assert(f.auths[0] == "Authorization: Bearer tok");
    assert(c.refresh("rt").access_token == "new");
  }
  {  // REST
    Fake f;
    atlas::RestClient r("sk_test_1", &f);
    f.replies = {{200, "{}"}, {404, R"({"code":"NOT_FOUND","message":"No such user"})"}};
    r.request("GET", "/v1/users?limit=1");
    assert(f.urls[0] == "https://api.atlasauth.net/v1/users?limit=1" && f.auths[0] == "Authorization: Bearer sk_test_1");
    try { r.request("GET", "/v1/users/x"); assert(false); } catch (const atlas::Error& e) { assert(e.code() == "NOT_FOUND" && e.status() == 404); }
  }
  {  // bad json
    try { atlas::parse_flat_json("[1]"); assert(false); } catch (const atlas::Error&) {}
  }
  std::cout << "ok\n";
}
