//
//  SimpleHMACAuth.swift
//  SimpleHMACAuth
//
//  Created by Jesse Youngblood on 4/15/20.
//  Copyright © 2020 Jesse Youngblood. All rights reserved.
//

import Foundation
import CommonCrypto

public class SimpleHMACAuth {
    
    /// API key to authenticate with
    public var apiKey: String?
    
    /// Secret key to authenticate with
    public var secret: String?
    
    /// Algorithm to generate HMAC hash with
    public var algorithm: HMACAlgorithm = .sha256
    
    public enum HMACAlgorithm: String {
        case sha256 = "sha256"
        case sha512 = "sha512"
    }
    
    enum RequestSigningError: Error {
        case missingAPIKey
        case missingSecret
        case invalidAlgorithm
        case invalidURL
    }
    
    fileprivate let dateFormatter: DateFormatter
    
    /// Instantiate with an API key and secret
    /// - Parameters:
    ///   - apiKey: API key
    ///   - secret: Secret key
    public convenience init(apiKey: String, secret: String) {
        self.init()
        
        self.apiKey = apiKey
        self.secret = secret
    }
    
    /// Instantiate
    public init() {
        self.dateFormatter = DateFormatter()
        self.dateFormatter.dateFormat = "EEE, dd MMM yyyy HH:mm:ss zzz"
    }
    
    /// Returns a signed version of an input request
    /// - Parameter request: Request to sign
    /// - Throws: If the request, API key, secret, or algorithm are invalid
    /// - Returns: Signed version of the request
    public func sign(_ request: URLRequest) throws -> URLRequest {
        
        guard let signedRequest = (request as NSURLRequest).mutableCopy() as? NSMutableURLRequest else {
            throw RequestSigningError.invalidURL
        }
        
        guard let apiKey = self.apiKey else {
            throw RequestSigningError.missingAPIKey
        }
        
        guard let secret = self.secret else {
            throw RequestSigningError.missingSecret
        }
        
        // Add the "Authorization" header
        
        signedRequest.addValue("api-key \(apiKey)", forHTTPHeaderField: "Authorization")
        
        // Confirm the "Date" header exists, and add it if not
        
        if signedRequest.value(forHTTPHeaderField: "Date") == nil {
            
            signedRequest.addValue(self.dateFormatter.string(from: Date()), forHTTPHeaderField: "Date")
        }
        
        // If this request has a body but does not yet have the "Content-Length" header, calculate and append it
        
        if let data = signedRequest.httpBody, signedRequest.value(forHTTPHeaderField: "Content-Length") == nil {
            
            signedRequest.addValue("\(data.count)", forHTTPHeaderField: "Content-Length")
        }
        
        // Canonicalize the request
        
        let canonicalized = try self.canonicalize(signedRequest as URLRequest)
        
        // Generate a signature from the canonicalized representation of the request
        
        let signature = try self.signature(canonicalized: canonicalized, secret: secret, algorithm: algorithm);
        
        // Append the "Signature" header
        
        signedRequest.addValue("simple-hmac-auth \(algorithm.rawValue) \(signature)", forHTTPHeaderField: "Signature")
        
        return signedRequest as URLRequest
    }
    
    /// Generate a string for a request
    /// - Parameter request: Request to sign
    /// - Throws: Throws if request is invalid
    /// - Returns: Signed request
    internal func canonicalize(_ request: URLRequest) throws -> String {
        
        guard let url = request.url else {
            throw RequestSigningError.invalidURL
        }
        
        let method = (request.httpMethod ?? "GET").uppercased()
        var path = url.path
        let queryString = url.query != nil ? "?\(url.query!)" : ""
        let allHeaders = request.allHTTPHeaderFields ?? [String : String]()
        let data = request.httpBody ?? Data()
        
        if let component = URLComponents(string: url.absoluteString) {
            path = component.path
        }
        
        // Only sign these headers
        
        let allowedHeaders = [
            "authorization",
            "date",
            "content-length",
            "content-type"
        ]
        
        // Create a new list of headers, with the keys all lower case
        
        var headers = [String: String]();
        
        for (key, value) in allHeaders {
            
            let lowerCaseKey = key.lowercased()
            
            if allowedHeaders.contains(lowerCaseKey) == false {
                continue
            }
            
            if lowerCaseKey == "content-length" && value == "0" {
                continue
            }
            
            headers[lowerCaseKey] = value;
        }
        
        // Sort the header keys alphabetically
        
        let headerKeys = headers.keys.sorted()
        
        // Create a string of all headers, arranged alphabetically, seperated by newlines
        
        var headerString = ""
        
        for (index, key) in headerKeys.enumerated() {
            
            guard let value = headers[key] else {
                continue
            }
            
            headerString += "\(key):\(value)"
            
            if index != headerKeys.count - 1 {
                headerString += "\n"
            }
        }
        
        // Hash the data payload
        
        var digest = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        data.withUnsafeBytes { bytes in
            _ = CC_SHA256(bytes.baseAddress, CC_LONG(data.count), &digest)
        }
        
        let dataHash = Data(digest).map { String(format: "%02hhx", $0) }.joined()
        
        // Combine all components of this request into a string
        
        let components: [String] = [method, path, queryString, headerString, dataHash]
        
        return components.joined(separator: "\n");
    }
    
    /// Generate a HMAC hash for a canonicalized request
    /// - Parameters:
    ///   - canonicalized: canonicalized version of a request
    ///   - secret: Secret key
    ///   - algorithm: Algorithm to use to generate the hmac
    /// - Throws: If algorithm is not supported
    /// - Returns: Signature for the request
    internal func signature(canonicalized: String, secret: String, algorithm: HMACAlgorithm) throws -> String {
        
        let supportedAlgorithms = ["sha1":   (kCCHmacAlgSHA1,   CC_SHA1_DIGEST_LENGTH),
                                   "sha256": (kCCHmacAlgSHA256, CC_SHA256_DIGEST_LENGTH),
                                   "sha512": (kCCHmacAlgSHA512, CC_SHA512_DIGEST_LENGTH)]
        
        guard let (algorithmKey, digestLength) = supportedAlgorithms[algorithm.rawValue] else {
            throw RequestSigningError.invalidAlgorithm
        }
        
        var digest = [UInt8](repeating: 0, count: Int(digestLength))
        
        CCHmac(CCHmacAlgorithm(algorithmKey), secret, secret.count, canonicalized, canonicalized.count, &digest)
        
        let data = Data(digest)
        
        return data.map { String(format: "%02hhx", $0) }.joined()
    }
}
