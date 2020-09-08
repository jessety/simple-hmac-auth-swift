//
//  ContentView.swift
//  SimpleHMACAuth/Example
//
//  Created by Jesse Youngblood on 9/3/20.
//  Copyright © 2020 Jesse Youngblood. All rights reserved.
//

import SwiftUI
import SimpleHMACAuth

let simpleHMAC = SimpleHMACAuth(apiKey: "API_KEY", secret: "SECRET")

func makeRequest(_ request: URLRequest) throws {
    
    let signedRequest = try simpleHMAC.sign(request)
    
    let session = URLSession(configuration: .default)
    
    let task = session.dataTask(with: signedRequest) { (data, response, error) in
        
        guard error == nil else {
            
            print("Error retrieving: \(error!)")
            return
        }
        
        guard let response = response as? HTTPURLResponse else {
            
            print("Error retrieving: could not process response")
            return
        }
        
        guard response.statusCode == 200 else {
            
            print("Error retrieving: got back status code \(response.statusCode):")
            return
        }
        
        guard let data = data else {
            
            print("Error retrieving: could not process data")
            return
        }
        
        print("Got back \(data):", String(data: data, encoding: .utf8)!)
    }
    
    task.resume()
}

func getRequest() {

    let request = URLRequest(url: URL(string: "http://localhost:8000/v1/items/")!)
    
    do {
        try makeRequest(request)
    } catch {
        print("GET request failed")
    }
}

func postRequest() {
    
    var request = URLRequest(url: URL(string: "http://localhost:8000/v1/items/")!)
    
    request.httpMethod = "POST"
    request.httpBody = "{\"test\":true}".data(using: .utf8)
    request.setValue("application/json", forHTTPHeaderField: "content-type")
    
    do {
        try makeRequest(request)
    } catch {
        print("POST request failed")
    }
}

struct ContentView: View {
    var body: some View {
        List {
            Button(action: getRequest) {
                Text("Make GET request")
            }
            Button(action: postRequest) {
                Text("Make POST request")
            }
        }
    }
}

struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView()
    }
}
