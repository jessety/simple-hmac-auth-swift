//
//  SimpleHMACAuthTests.swift
//  SimpleHMACAuthTests
//
//  Created by Jesse Youngblood on 4/16/20.
//  Copyright © 2020 Jesse Youngblood. All rights reserved.
//

import XCTest
@testable import SimpleHMACAuth

class SimpleHMACAuthTests: XCTestCase {
    
    override func setUpWithError() throws {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }
    
    override func tearDownWithError() throws {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }
    
    func testCanonicalizationSimple() throws {
        
        let request = URLRequest(url: URL(string: "https://api.example.org/")!)
        
        let client = SimpleHMACAuth()
        
        let canonicalized = try client.canonicalize(request)
        
        let exemplar = "GET\n/\n\n\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        
        XCTAssertEqual(canonicalized, exemplar)
    }
    
    func testCanonicalizationAdvanced() throws {
        
        var request = URLRequest(url: URL(string: "https://api.example.org/v1/items/?test=true&yes=affirmative")!)
        
        request.httpMethod = "POST"
        request.httpBody = String("{\"test\":true}").data(using: String.Encoding.utf8);
        request.addValue("application/json", forHTTPHeaderField: "content-type")
        request.addValue("13", forHTTPHeaderField: "content-length")
        
        request.addValue("Tue, 20 Apr 2016 18:48:24 GMT", forHTTPHeaderField: "date")
        request.addValue("api-key SAMPLE_API_KEY", forHTTPHeaderField: "authorization")
        request.addValue("additional-header", forHTTPHeaderField: "some-message")
        
        let simpleHMAC = SimpleHMACAuth()
        
        let canonicalized = try simpleHMAC.canonicalize(request)
        
        let exemplar = "POST\n/v1/items/\n?test=true&yes=affirmative\nauthorization:api-key SAMPLE_API_KEY\ncontent-length:13\ncontent-type:application/json\ndate:Tue, 20 Apr 2016 18:48:24 GMT\n6fd977db9b2afe87a9ceee48432881299a6aaf83d935fbbe83007660287f9c2e"
        
        XCTAssertEqual(canonicalized, exemplar)
    }
    
    func testSigningRequestSimple() throws {
        
        let simpleHMAC = SimpleHMACAuth(apiKey: "SAMPLE_API_KEY", secret: "SECRET")
        
        var request = URLRequest(url: URL(string: "https://api.example.org/")!)
        request.addValue("Tue, 20 Apr 2016 18:48:24 GMT", forHTTPHeaderField: "Date")
        
        // XCTAssertEqual(try client.canonicalize(request), "GET\n/\n\ndate:Tue, 20 Apr 2016 18:48:24 GMT\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        
        let signed = try simpleHMAC.sign(request)
        
        XCTAssertEqual(signed.value(forHTTPHeaderField: "Authorization"), "api-key SAMPLE_API_KEY")
        XCTAssertEqual(signed.value(forHTTPHeaderField: "Signature"), "simple-hmac-auth sha256 e5358d92d76a94caf7799d2d23767b9b9cf3b56703ac48fed5baece0323a0afb")
    }
    
    func testSigningRequestAdvanced() throws {
        
        let simpleHMAC = SimpleHMACAuth(apiKey: "SAMPLE_API_KEY", secret: "SECRET")
        
        var request = URLRequest(url: URL(string: "https://api.example.org/v1/items/?test=true&yes=affirmative")!)
        
        request.httpMethod = "POST"
        request.httpBody = String("{\"test\":true}").data(using: String.Encoding.utf8);
        request.addValue("application/json", forHTTPHeaderField: "content-type")
        request.addValue("13", forHTTPHeaderField: "content-length")
        
        request.addValue("Tue, 20 Apr 2016 18:48:24 GMT", forHTTPHeaderField: "date")
        request.addValue("additional-header", forHTTPHeaderField: "some-message")
        
        let signed = try simpleHMAC.sign(request)
        
        XCTAssertEqual(signed.value(forHTTPHeaderField: "Authorization"), "api-key SAMPLE_API_KEY")
        XCTAssertEqual(signed.value(forHTTPHeaderField: "Signature"), "simple-hmac-auth sha256 29c743d9d943de5524e4400554f80a44e950430a2780a32077e1cb82de32f534")
    }
    
    func testSigningRequestAdvancedAdditional() throws {
        
        let simpleHMAC = SimpleHMACAuth(apiKey: "TEST_KEY", secret: "TEST_SECRET")
        simpleHMAC.algorithm = .sha512
        
        var request = URLRequest(url: URL(string: "https://api.example.org/v1/items/?test=true&yes=affirmative&a=1&b=2")!)
        
        request.httpMethod = "PUT"
        request.httpBody = String("{\"test\":true}").data(using: String.Encoding.utf8);
        request.addValue("application/json", forHTTPHeaderField: "Content-Type")
        
        // Omitted to confirm it'll be generated correctly
        // request.addValue("13", forHTTPHeaderField: "Content-Length")
        
        request.addValue("Tue, 20 Apr 2016 18:48:24 GMT", forHTTPHeaderField: "Date")
        
        let signed = try simpleHMAC.sign(request)
        
        XCTAssertEqual(signed.value(forHTTPHeaderField: "Authorization"), "api-key TEST_KEY")
        XCTAssertEqual(signed.value(forHTTPHeaderField: "Signature"), "simple-hmac-auth sha512 3d1dc988949fe4940194eb571261ae8c107940ea8bb39d13116c61ab8d0b74b8c2f8eaa6313f5cbfe984e1ff8ee6bde7dbbe4bb78021ea917150e7c6cfdc08c1")
    }
}
