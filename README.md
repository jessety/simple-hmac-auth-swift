#  simple-hmac-auth-swift

Swift framework for interfacing with APIs that implement [simple-hmac-auth](https://github.com/jessety/simple-hmac-auth).

[![ci](https://github.com/jessety/simple-hmac-auth-swift/workflows/ci/badge.svg)](https://github.com/jessety/simple-hmac-auth-swift/actions)
[![license](https://img.shields.io/github/license/jessety/simple-hmac-auth-swift.svg)](https://github.com/jessety/simple-hmac-auth-swift/blob/main/LICENSE)

## Usage

```swift
import SimpleHMACAuth

// Instantiate the class

let simpleHMAC = SimpleHMACAuth(apiKey: "API_KEY", secret: "SECRET")

// Create a request

let request = URLRequest(url: URL(string: "https://api.example.org/v1/items/")!)

// Sign the request

let signedRequest = try simpleHMAC.sign(request)

// Send the request

let task = session.dataTask(with: signedRequest) { (data, response, error) in
    
    // ...
}

task.resume()
```

## License

MIT © Jesse Youngblood
