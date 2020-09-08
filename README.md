#  simple-hmac-auth-swift

Swift framework for interfacing with APIs that implement [simple-hmac-auth](https://github.com/jessety/simple-hmac-auth).

## Usage

```swift
import SimpleHMACAuth

// Instansiate the class

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
