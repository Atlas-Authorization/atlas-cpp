// Atlas C++ client: OAuth device flow and the REST API. Header-only, C++17, no dependencies.
// HTTP is behind Transport; atlas/curl_transport.hpp provides a libcurl one.
#pragma once
#include <chrono>
#include <cstdlib>
#include <functional>
#include <map>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace atlas {

struct HttpResponse {
  int status = 0;
  std::string body;
};

// One request. `headers` are "Name: value" pairs. `body` is sent as is.
class Transport {
 public:
  virtual ~Transport() = default;
  virtual HttpResponse send(const std::string& method, const std::string& url,
                            const std::vector<std::string>& headers, const std::string& body) = 0;
};

class Error : public std::runtime_error {
 public:
  Error(std::string code, const std::string& message, int status = 0)
      : std::runtime_error(message), code_(std::move(code)), status_(status) {}
  const std::string& code() const { return code_; }
  int status() const { return status_; }

 private:
  std::string code_;
  int status_;
};

// Flat JSON object reader: string, number and boolean members, which is what the OAuth
// endpoints return. Nested values are skipped. Returns members as strings.
inline std::map<std::string, std::string> parse_flat_json(const std::string& s) {
  std::map<std::string, std::string> out;
  size_t i = 0;
  auto ws = [&] { while (i < s.size() && (s[i] == ' ' || s[i] == '\n' || s[i] == '\r' || s[i] == '\t')) ++i; };
  auto str = [&]() -> std::string {
    std::string r;
    ++i;  // opening quote
    while (i < s.size() && s[i] != '"') {
      char c = s[i++];
      if (c == '\\' && i < s.size()) {
        char e = s[i++];
        switch (e) {
          case 'n': r += '\n'; break;
          case 't': r += '\t'; break;
          case 'r': r += '\r'; break;
          case 'u': if (i + 4 <= s.size()) { r += static_cast<char>(std::strtol(s.substr(i, 4).c_str(), nullptr, 16)); i += 4; } break;
          default: r += e;
        }
      } else {
        r += c;
      }
    }
    ++i;  // closing quote
    return r;
  };
  auto skip = [&] {  // skip a nested {...} or [...]
    int depth = 0;
    while (i < s.size()) {
      char c = s[i];
      if (c == '"') { str(); continue; }
      if (c == '{' || c == '[') ++depth;
      if (c == '}' || c == ']') { if (--depth == 0) { ++i; return; } }
      ++i;
    }
  };
  ws();
  if (i >= s.size() || s[i] != '{') throw Error("invalid_response", "Expected a JSON object.");
  ++i;
  while (true) {
    ws();
    if (i >= s.size()) throw Error("invalid_response", "Unterminated JSON object.");
    if (s[i] == '}') break;
    if (s[i] == ',') { ++i; continue; }
    if (s[i] != '"') throw Error("invalid_response", "Expected a member name.");
    std::string key = str();
    ws();
    if (i >= s.size() || s[i] != ':') throw Error("invalid_response", "Expected ':'.");
    ++i;
    ws();
    if (i >= s.size()) throw Error("invalid_response", "Unterminated JSON object.");
    if (s[i] == '"') out[key] = str();
    else if (s[i] == '{' || s[i] == '[') skip();
    else {
      size_t j = i;
      while (i < s.size() && s[i] != ',' && s[i] != '}') ++i;
      std::string v = s.substr(j, i - j);
      while (!v.empty() && (v.back() == ' ' || v.back() == '\n' || v.back() == '\r')) v.pop_back();
      out[key] = v;
    }
  }
  return out;
}

inline std::string url_encode(const std::string& v) {
  static const char* hex = "0123456789ABCDEF";
  std::string r;
  for (unsigned char c : v) {
    if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') r += static_cast<char>(c);
    else { r += '%'; r += hex[c >> 4]; r += hex[c & 15]; }
  }
  return r;
}

struct DeviceCode {
  std::string device_code, user_code, verification_uri, verification_uri_complete;
  int expires_in = 600;
  int interval = 5;
};

struct Tokens {
  std::string access_token, refresh_token, id_token, scope;
  long long expires_in = 0;
};

class Client {
 public:
  struct Options {
    std::string issuer;     // https://auth.example.com
    std::string client_id;  // public OAuth application
    std::string scope = "openid profile email offline_access";
    Transport* transport = nullptr;
    // Replaced in tests so polling does not sleep.
    std::function<void(std::chrono::seconds)> sleep = [](std::chrono::seconds s) { std::this_thread::sleep_for(s); };
  };

  explicit Client(Options o) : o_(std::move(o)) {
    if (o_.issuer.empty() || o_.client_id.empty() || !o_.transport) throw Error("invalid_options", "issuer, client_id and transport are required.");
    while (!o_.issuer.empty() && o_.issuer.back() == '/') o_.issuer.pop_back();
  }

  DeviceCode start_device_flow() {
    auto d = post_form("/oauth2/device_authorization", {{"client_id", o_.client_id}, {"scope", o_.scope}});
    DeviceCode c;
    c.device_code = d["device_code"];
    c.user_code = d["user_code"];
    c.verification_uri = d["verification_uri"];
    c.verification_uri_complete = d["verification_uri_complete"];
    if (d.count("expires_in")) c.expires_in = std::atoi(d["expires_in"].c_str());
    if (d.count("interval")) c.interval = std::atoi(d["interval"].c_str());
    return c;
  }

  // Blocks until the user approves or denies, or the code expires. Honours slow_down.
  Tokens poll_device_flow(const DeviceCode& code) {
    int interval = code.interval < 1 ? 1 : code.interval;
    int waited = 0;
    while (waited <= code.expires_in) {
      o_.sleep(std::chrono::seconds(interval));
      waited += interval;
      auto r = o_.transport->send("POST", o_.issuer + "/oauth2/token", form_headers(),
                                  encode({{"grant_type", "urn:ietf:params:oauth:grant-type:device_code"},
                                          {"device_code", code.device_code},
                                          {"client_id", o_.client_id}}));
      auto d = parse(r);
      if (r.status < 400) return tokens(d);
      const std::string e = d["error"];
      if (e == "authorization_pending") continue;
      if (e == "slow_down") { interval += 5; continue; }
      throw Error(e.empty() ? "error" : e, d["error_description"], r.status);
    }
    throw Error("expired_token", "The device code expired.");
  }

  Tokens refresh(const std::string& refresh_token) {
    auto d = post_form("/oauth2/token", {{"grant_type", "refresh_token"}, {"refresh_token", refresh_token}, {"client_id", o_.client_id}});
    return tokens(d);
  }

  // The player's profile claims (sub, email, ...), as strings.
  std::map<std::string, std::string> userinfo(const std::string& access_token) {
    auto r = o_.transport->send("GET", o_.issuer + "/oauth2/userinfo", {"Authorization: Bearer " + access_token, "Accept: application/json"}, "");
    auto d = parse(r);
    if (r.status >= 400) throw Error(d["error"].empty() ? "error" : d["error"], d["error_description"], r.status);
    return d;
  }

  void revoke(const std::string& refresh_token) {
    o_.transport->send("POST", o_.issuer + "/oauth2/revoke", form_headers(),
                       encode({{"token", refresh_token}, {"token_type_hint", "refresh_token"}, {"client_id", o_.client_id}}));
  }

 private:
  using Form = std::vector<std::pair<std::string, std::string>>;
  static std::string encode(const Form& f) {
    std::string r;
    for (auto& kv : f) { if (!r.empty()) r += '&'; r += url_encode(kv.first) + '=' + url_encode(kv.second); }
    return r;
  }
  static std::vector<std::string> form_headers() { return {"Content-Type: application/x-www-form-urlencoded", "Accept: application/json"}; }
  static std::map<std::string, std::string> parse(const HttpResponse& r) {
    try { return parse_flat_json(r.body); } catch (const Error&) { throw Error("invalid_response", "The server answered with something that is not JSON.", r.status); }
  }
  std::map<std::string, std::string> post_form(const std::string& path, const Form& f) {
    auto r = o_.transport->send("POST", o_.issuer + path, form_headers(), encode(f));
    auto d = parse(r);
    if (r.status >= 400) throw Error(d["error"].empty() ? "error" : d["error"], d["error_description"], r.status);
    return d;
  }
  static Tokens tokens(std::map<std::string, std::string>& d) {
    Tokens t;
    t.access_token = d["access_token"];
    if (t.access_token.empty()) throw Error("invalid_response", "The token response had no access_token.");
    t.refresh_token = d["refresh_token"];
    t.id_token = d["id_token"];
    t.scope = d["scope"];
    t.expires_in = d.count("expires_in") ? std::atoll(d["expires_in"].c_str()) : 3600;
    return t;
  }
  Options o_;
};

// The Backend REST API with a secret key: any endpoint, JSON in, response out.
class RestClient {
 public:
  RestClient(std::string secret_key, Transport* transport, std::string base_url = "https://api.atlasauth.net")
      : key_(std::move(secret_key)), t_(transport), base_(std::move(base_url)) {
    if (key_.empty() || !t_) throw Error("invalid_options", "secret_key and transport are required.");
  }

  // e.g. request("GET", "/v1/users?limit=10") or request("POST", "/v1/users", R"({"email_address":"a@b.c"})").
  // Throws Error for a 4xx/5xx (code from the error body when present).
  HttpResponse request(const std::string& method, const std::string& path, const std::string& json_body = "") {
    std::vector<std::string> h = {"Authorization: Bearer " + key_, "Accept: application/json"};
    if (!json_body.empty()) h.push_back("Content-Type: application/json");
    auto r = t_->send(method, base_ + path, h, json_body);
    if (r.status >= 400) {
      std::string code = "error", msg = "Request failed.";
      try { auto d = parse_flat_json(r.body); if (!d["code"].empty()) code = d["code"]; if (!d["message"].empty()) msg = d["message"]; } catch (const Error&) {}
      throw Error(code, msg, r.status);
    }
    return r;
  }

 private:
  std::string key_;
  Transport* t_;
  std::string base_;
};

}  // namespace atlas
