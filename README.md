# Atlas for C++

Header-only C++17 client for Atlas: the OAuth **device flow** (consoles, TVs, handhelds, native tools) and the **REST API**. No dependencies; HTTP is a small `Transport` interface, with a libcurl implementation included.

## Install

vcpkg: `vcpkg install atlas-auth[curl]`, then in CMake `find_package(atlas-auth CONFIG REQUIRED)` and link `atlas::atlas-auth`. Or copy `include/atlas`.

## Device flow

```cpp
#include <atlas/atlas.hpp>
#include <atlas/curl_transport.hpp>

atlas::CurlTransport http;
atlas::Client::Options o;
o.issuer = "https://auth.example.com";
o.client_id = "client_console";
o.transport = &http;
atlas::Client atlas(o);

auto code = atlas.start_device_flow();
show(code.user_code, code.verification_uri);       // or a QR code of verification_uri_complete
auto tokens = atlas.poll_device_flow(code);        // blocks; honours slow_down; throws atlas::Error on denial/expiry
auto me = atlas.userinfo(tokens.access_token);     // me["sub"], me["email"]
```

Store `tokens.refresh_token` in the platform's secure storage and call `refresh()` when the access token expires; `revoke()` on sign-out.

## REST API

```cpp
atlas::RestClient api(getenv("ATLAS_SECRET_KEY"), &http);
auto users = api.request("GET", "/v1/users?limit=10");   // users.body is JSON
```

Keep secret keys on servers, never in a shipped game. Errors throw `atlas::Error` with `code()` and `status()`.

## Tests

`cmake -S . -B build && cmake --build build && ctest --test-dir build`
