///
/// Network layer for the SPKI pinning test app.
/// Builds a custom Alamofire session with an SPKI-based trust evaluator
/// and runs a test request against the configured host.
///
import Foundation
import Alamofire

/// Builds an Alamofire session configured with a custom SPKI-based server trust evaluator for the target host.
final class Network {

    static let shared = Network()

    private let session: Session

    private init() {
        let evaluators: [String: ServerTrustEvaluating] = [
            "https://your.server.host": SPKIHashTrustEvaluator()
        ]

        let manager = ServerTrustManager(
            allHostsMustBeEvaluated: false,
            evaluators: evaluators
        )

        let configuration = URLSessionConfiguration.af.default
        configuration.timeoutIntervalForRequest = 10
        configuration.timeoutIntervalForResource = 15
        configuration.waitsForConnectivity = false

        session = Session(
            configuration: configuration,
            serverTrustManager: manager
        )
    }
    
    /// Sends a test request to the configured endpoint and prints connection and validation details to the Xcode console.
    func validatePinnedConnection() {
        let url = "https://your.server.host:443/"
        print("🚀 Testing URL:", url)

        session.request(url)
            .validate()
            .response { response in

                if let host = response.request?.url?.host {
                    print("🌐 Connected host:", host)
                }

                if let statusCode = response.response?.statusCode {
                    print("📡 HTTP status:", statusCode)
                }

                switch response.result {
                case .success:
                    print("✅ Request succeeded")
                case .failure(let error):
                    let nsError = error as NSError
                    print("❌ Request failed")
                    print("Domain:", nsError.domain)
                    print("Code:", nsError.code)
                    print("Description:", error.localizedDescription)
                    print("UserInfo:", nsError.userInfo)
                }

                print("RESULT:", response)
            }
    }
}
