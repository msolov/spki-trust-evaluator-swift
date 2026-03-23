//
//  ContentView.swift
//  SPKITrustEvaluator
//
//  Main SwiftUI view for the SPKI pinning test application.
//  Provides a simple UI description while SPKI validation
//  is performed by the networking components.
//

import SwiftUI

struct ContentView: View {
    var body: some View {
        NavigationStack {
            VStack(alignment: .leading, spacing: 16) {
                Text("SPKI Trust Evaluator")
                    .font(.title2)
                    .fontWeight(.semibold)

                Text("This project checks the server SPKI hash against the expected pinned value and prints the result in the Xcode console.")
                    .font(.body)
                    .foregroundStyle(.secondary)

                VStack(alignment: .leading, spacing: 8) {
                    Label("Single-host debug test", systemImage: "network")
                    Label("Compare server SPKI with pinned SPKI", systemImage: "checkmark.shield")
                    Label("See detailed output in the console", systemImage: "terminal")
                }
                .font(.subheadline)

                Spacer()
            }
            .padding()
            .navigationTitle("SPKI Test")
        }
        .onAppear {
            Network.shared.validatePinnedConnection()
        }
    }
}

#Preview {
    ContentView()
}
