# 极客时间第一课


### 02 | JWT Generation and Verification

- Generate JWT tokens with the following claims: `sub`, `aud`.
- Generated JWT tokens should pass the verification on [jwt.io](https://jwt.io/).

```bash
cargo run jwt sign --sub acme --aud device1
cargo run jwt verify --token eyJ0eXXXXX.eyJhdXXXXX.XXXXX --sub acme --aud device1
```
token is the result generated from sign.

### 03 | HTTP Server

- Add directory index support to the HTTP server from the course.
- Note `templates` is not bundled into the binary, the following command should be run from the project root.

```bash
$env:RUST_LOG="info"; cargo run -- http serve
run on windows
RUST_LOG="info" cargo run -- http serve
run on Mac
check the test.rest file for test of the directory index entry
```

#   r c l i - q u e s t i o n 2 - 3 
 
 
