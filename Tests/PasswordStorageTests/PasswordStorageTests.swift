import XCTest
@testable import PasswordStorage

final class PasswordStorageTests: XCTestCase {

    @PasswordStorage("MyPassword", service: "TestApp", accessGroup: "com.example.app") private var genericPass: String?
    @InternetPasswordStorage("MyPassword", server:"github.com", protocolType: "https", accessGroup: "com.example.app") private var internetPass: String?

    override func setUpWithError() throws {
        try super.setUpWithError()
        genericPass = nil
    }

    override func tearDownWithError() throws {
        try super.tearDownWithError()
        genericPass = nil
    }

    func testStoreGenericPassword() {
        XCTAssertNil(self.genericPass)
        let password = "GD9!3Ef3avJc2G.z"
        self.genericPass = password
        XCTAssertEqual(self.genericPass, password)

        let updatePassword = "!Y*KKT4eFFjG.*mX"
        self.genericPass = updatePassword
        XCTAssertEqual(self.genericPass, updatePassword)

        self.genericPass = nil
        XCTAssertNil(self.genericPass)
    }

    func testStoreInternetPassword() {
        XCTAssertNil(self.internetPass)
        let password = "GD9!3Ef3avJc2G.z"
        self.internetPass = password
        XCTAssertEqual(self.internetPass, password)        

        let updatePassword = "!Y*KKT4eFFjG.*mX"
        self.internetPass = updatePassword
        XCTAssertEqual(self.internetPass, updatePassword)

        self.internetPass = nil
        XCTAssertNil(self.internetPass)
    }

    static var allTests = [
        ("testStoreGenericPassword", testStoreGenericPassword),
    ]
}
