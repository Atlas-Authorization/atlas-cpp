// libcurl Transport. Link with libcurl (vcpkg feature "curl").
#pragma once
#include <curl/curl.h>
#include "atlas.hpp"

namespace atlas {

class CurlTransport : public Transport {
 public:
  HttpResponse send(const std::string& method, const std::string& url, const std::vector<std::string>& headers,
                    const std::string& body) override {
    CURL* c = curl_easy_init();
    if (!c) throw Error("transport", "curl_easy_init failed.");
    std::string out;
    curl_slist* list = nullptr;
    for (auto& h : headers) list = curl_slist_append(list, h.c_str());
    curl_easy_setopt(c, CURLOPT_URL, url.c_str());
    curl_easy_setopt(c, CURLOPT_CUSTOMREQUEST, method.c_str());
    curl_easy_setopt(c, CURLOPT_HTTPHEADER, list);
    if (!body.empty()) {
      curl_easy_setopt(c, CURLOPT_POSTFIELDS, body.c_str());
      curl_easy_setopt(c, CURLOPT_POSTFIELDSIZE, static_cast<long>(body.size()));
    }
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, &CurlTransport::write);
    curl_easy_setopt(c, CURLOPT_WRITEDATA, &out);
    curl_easy_setopt(c, CURLOPT_TIMEOUT, 30L);
    CURLcode rc = curl_easy_perform(c);
    long status = 0;
    curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &status);
    curl_slist_free_all(list);
    curl_easy_cleanup(c);
    if (rc != CURLE_OK) throw Error("transport", curl_easy_strerror(rc));
    return {static_cast<int>(status), out};
  }

 private:
  static size_t write(char* p, size_t s, size_t n, void* u) {
    static_cast<std::string*>(u)->append(p, s * n);
    return s * n;
  }
};

}  // namespace atlas
